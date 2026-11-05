"""Bounded HTTP/1.1 client with address pinning and no ambient proxy support."""

import asyncio
import ipaddress
import json
import socket
import ssl
import time
import zlib
from contextlib import asynccontextmanager
from urllib.parse import urljoin, urlsplit

from llmrt.config import TargetConfig


class BudgetExceeded(Exception):
    pass


class TransportError(Exception):
    pass


class Budget:
    def __init__(self, config: TargetConfig):
        self.config = config
        self.used = 0
        self.reserved = 0
        self.model_units = 0
        self.tokens = 0
        self.cost_upper_bound = 0.0
        self.lock = asyncio.Lock()
        self.deadline = time.monotonic() + config.max_duration_seconds

    @asynccontextmanager
    async def reserve(self, model_request=False):
        calls = (self.config.model_calls_per_request or 0) if model_request else 0
        tokens = (self.config.tokens_per_request_upper_bound or 0) if model_request else 0
        cost = (self.config.cost_per_request_upper_bound or 0) if model_request else 0
        async with self.lock:
            if (
                time.monotonic() >= self.deadline
                or self.used + self.reserved >= self.config.max_requests
            ):
                raise BudgetExceeded("Request or duration budget exhausted")
            if (
                self.config.max_model_calls
                and self.model_units + calls > self.config.max_model_calls
            ):
                raise BudgetExceeded("Model-call budget exhausted")
            if self.config.max_tokens and self.tokens + tokens > self.config.max_tokens:
                raise BudgetExceeded("Token budget exhausted")
            if self.config.max_cost and self.cost_upper_bound + cost > self.config.max_cost:
                raise BudgetExceeded("Cost budget exhausted")
            self.reserved += 1
            self.model_units += calls
            self.tokens += tokens
            self.cost_upper_bound += cost
        dispatched = False

        def dispatch():
            nonlocal dispatched
            if not dispatched:
                dispatched = True
                self.reserved -= 1
                self.used += 1

        try:
            yield dispatch
        finally:
            if not dispatched:
                async with self.lock:
                    self.reserved -= 1
                    self.model_units -= calls
                    self.tokens -= tokens
                    self.cost_upper_bound -= cost


def origin(url):
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


async def resolve_address(url: str, config: TargetConfig):
    if any(ord(char) < 33 for char in url):
        raise TransportError("Control characters or whitespace in URL")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.username or parts.password or parts.fragment:
        raise TransportError("Disallowed URL structure")
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if host not in [h.lower() for h in config.allowed_hosts] or port not in config.allowed_ports:
        raise TransportError("Destination outside declared scope")
    addresses = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise TransportError("Destination did not resolve")
    for entry in addresses:
        address = ipaddress.ip_address(entry[4][0])
        if not config.allow_private and not address.is_global:
            raise TransportError("Non-global address requires explicit private-network scope")
    return parts, addresses[0][4][0], port


async def read_body(reader, headers, limit):
    encoding = headers.get("transfer-encoding", "").lower()
    if encoding and encoding != "chunked":
        raise TransportError("Unsupported transfer encoding")
    if encoding and "content-length" in headers:
        raise TransportError("Ambiguous response framing")
    chunks = []
    size = 0
    if encoding == "chunked":
        for _ in range(limit + 1):
            line = await reader.readline()
            if len(line) > 8192:
                raise TransportError("Chunk header too long")
            try:
                count = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                raise TransportError("Invalid chunk framing") from None
            if count < 0 or size + count > limit:
                raise TransportError("Response size limit exceeded")
            if count == 0:
                return b"".join(chunks)
            chunks.append(await reader.readexactly(count))
            if await reader.readexactly(2) != b"\r\n":
                raise TransportError("Invalid chunk terminator")
            size += count
        raise TransportError("Chunk count limit exceeded")
    if "content-length" in headers:
        try:
            count = int(headers["content-length"])
        except ValueError:
            raise TransportError("Invalid content length") from None
        if not 0 <= count <= limit:
            raise TransportError("Response size limit exceeded")
        return await reader.readexactly(count)
    while True:
        chunk = await reader.read(min(65536, limit - size + 1))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise TransportError("Response size limit exceeded")


class HTTPAdapter:
    def __init__(self, config: TargetConfig, budget: Budget):
        self.config = config
        self.budget = budget

    async def request(self, method, url, payload=None):
        visited = set()
        for _ in range(self.config.max_redirects + 1):
            if url in visited:
                raise TransportError("Redirect loop")
            visited.add(url)
            for attempt in range(self.config.retries + 1):
                timeout = min(self.config.timeout_seconds, self.budget.deadline - time.monotonic())
                if timeout <= 0:
                    raise BudgetExceeded("Duration budget exhausted")
                async with asyncio.timeout(timeout):
                    async with self.budget.reserve(model_request=method == "POST") as dispatch:
                        status, headers, body = await self._exchange(method, url, payload, dispatch)
                if (
                    status != 429
                    or attempt == self.config.retries
                    or method != "GET"
                    and not self.config.idempotency_supported
                ):
                    break
                # A rejected 429 request may retry. Ambiguous writes never retry automatically.
                import random
                from email.utils import parsedate_to_datetime

                try:
                    retry = float(headers.get("retry-after", ""))
                except ValueError:
                    try:
                        retry = (
                            parsedate_to_datetime(headers["retry-after"]).timestamp() - time.time()
                        )
                    except (KeyError, ValueError, TypeError, OverflowError):
                        retry = 2**attempt
                delay = max(0.0, retry) + random.uniform(0, 0.25)
                if delay >= self.budget.deadline - time.monotonic():
                    raise BudgetExceeded("Retry would exceed duration budget")
                await asyncio.sleep(delay)
            if status in (301, 302, 303, 307, 308):
                if method != "GET" and status not in (307, 308):
                    raise TransportError("Method-changing redirect rejected")
                location = headers.get("location")
                if not location:
                    raise TransportError("Redirect missing location")
                url = urljoin(url, location)
                continue
            if not 200 <= status < 300:
                raise TransportError(f"HTTP status {status}")
            if headers.get("content-encoding", "identity").lower() == "gzip":
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                try:
                    body = decoder.decompress(body, self.config.max_response_bytes + 1)
                except zlib.error:
                    raise TransportError("Invalid gzip response") from None
                if (
                    len(body) > self.config.max_response_bytes
                    or not decoder.eof
                    or decoder.unused_data
                ):
                    raise TransportError("Decompression limit or invalid gzip stream")
            elif headers.get("content-encoding", "identity").lower() != "identity":
                raise TransportError("Unsupported content encoding")
            try:
                result = json.loads(body)
            except (ValueError, UnicodeError):
                raise TransportError("Target response is not valid JSON") from None
            if not isinstance(result, dict):
                raise TransportError("Expected JSON object response")
            return result
        raise TransportError("Redirect chain limit exceeded")

    async def _exchange(self, method, url, payload, dispatch):
        parts, address, port = await resolve_address(url, self.config)
        context = None
        if parts.scheme == "https":
            context = ssl.create_default_context()
            if not self.config.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            address,
            port,
            ssl=context,
            server_hostname=parts.hostname if context else None,
            limit=65536,
        )
        try:
            body = json.dumps(payload).encode() if payload is not None else b""
            host = parts.netloc
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            headers = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host}",
                "Connection: close",
                "Accept: application/json",
                "Accept-Encoding: gzip",
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
            ]
            if origin(url) == origin(self.config.endpoint):
                credential = self.config.credential()
                if any(ord(char) < 32 for char in credential):
                    raise TransportError("Invalid credential characters")
                headers.append(f"Authorization: Bearer {credential}")
            if method == "POST" and self.config.idempotency_supported:
                import hashlib

                headers.append("Idempotency-Key: " + hashlib.sha256(body).hexdigest())
            dispatch()
            writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
            await writer.drain()
            line = await reader.readline()
            if len(line) > 8192:
                raise TransportError("Status line limit exceeded")
            try:
                status = int(line.split()[1])
            except (IndexError, ValueError):
                raise TransportError("Invalid HTTP status") from None
            response_headers = {}
            header_size = len(line)
            while True:
                line = await reader.readline()
                header_size += len(line)
                if header_size > 65536 or not line:
                    raise TransportError("Response header limit or truncated headers")
                if line == b"\r\n":
                    break
                name, separator, value = line.partition(b":")
                if not separator:
                    raise TransportError("Malformed response header")
                name = name.decode("ascii").lower()
                if name in response_headers and name in ("content-length", "transfer-encoding"):
                    raise TransportError("Duplicate framing header")
                response_headers[name] = value.decode("latin1").strip()
            body = await read_body(reader, response_headers, self.config.max_response_bytes)
            return status, response_headers, body
        finally:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass

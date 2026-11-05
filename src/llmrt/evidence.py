"""Private, write-time-redacted content-addressed evidence."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from llmrt.models import canonical_bytes

SENSITIVE_KEYS = {"authorization", "password", "api_key", "access_token", "bearer_token"}
SENSITIVE_KEYS.update(
    {"token", "refresh_token", "client_secret", "secret_key", "cookie", "set-cookie"}
)


class ArtifactWriteError(RuntimeError):
    """Runtime artifact failure, distinct from invalid operator configuration."""


class EvidenceStore:
    def __init__(self, root: Path, run_id: str, secrets_to_redact=()):
        self.secrets = tuple(value for value in secrets_to_redact if value)
        root = root.absolute()
        for parent in [root, *root.parents]:
            if parent.is_symlink():
                raise ValueError("Output root cannot contain symbolic links")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = root / run_id
        self.path.mkdir(mode=0o700, exist_ok=False)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def redact(self, value):
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
        return value

    def write(self, name: str, value, raw=False):
        if Path(name).name != name or name in (".", ".."):
            raise ValueError("Output name must be a safe leaf filename")
        payload = value.encode() if raw else canonical_bytes(self.redact(value))
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

    def record(self, value) -> str:
        content = self.redact(value)
        hashed = hashlib.sha256(canonical_bytes(content)).hexdigest()
        name = f"{hashed}.json"
        try:
            self.write(name, content)
        except FileExistsError:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            with os.fdopen(descriptor, "rb") as stream:
                if hashlib.sha256(stream.read()).hexdigest() != hashed:
                    raise ValueError("Existing evidence content was modified")
        descriptor = os.open(
            "manifest.jsonl",
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(canonical_bytes({"digest": hashed, "file": name}) + b"\n")
        return hashed


def verify_evidence(directory: Path):
    entries = []
    with (directory / "manifest.jsonl").open() as stream:
        for line in stream:
            entry = json.loads(line)
            if not isinstance(entry, dict) or not re.fullmatch(
                r"[a-f0-9]{64}", str(entry.get("digest", ""))
            ):
                raise ValueError("Invalid evidence digest")
            name = entry["digest"] + ".json"
            if name != entry["file"] or len(entry["digest"]) != 64:
                raise ValueError("Invalid evidence reference")
            path = directory / name
            if (
                path.is_symlink()
                or hashlib.sha256(path.read_bytes()).hexdigest() != entry["digest"]
            ):
                raise ValueError("Evidence digest mismatch")
            entries.append(entry["digest"])
    return entries


def preview_evidence(directory: Path, references, max_chars=16000):
    result = {}
    remaining = max_chars
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for reference in dict.fromkeys(references):
            if remaining <= 0:
                break
            if not re.fullmatch(r"[a-f0-9]{64}", reference):
                raise ValueError("Invalid evidence reference")
            descriptor = os.open(
                reference + ".json",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 2097152:
                    result[reference] = {
                        "preview": None,
                        "reason": "Artifact exceeds bounded preview",
                    }
                    continue
                content = stream.read(2097153)
            if hashlib.sha256(content).hexdigest() != reference:
                raise ValueError("Evidence content digest mismatch")
            text = content.decode("utf-8")
            excerpt = text[: min(4000, remaining)]
            remaining -= len(excerpt)
            result[reference] = {
                "untrusted_redacted_content": excerpt,
                "truncated": len(excerpt) != len(text),
            }
    finally:
        os.close(directory_fd)
    return result

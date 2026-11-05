"""Owned local fixtures with genuine backend authorization bugs and protected twins.

The deterministic command router is not an LLM. It exercises scanner mechanics.
"""

import argparse
import hashlib
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path

from llmrt.models import ExecutionEvent, Policy, TargetResponse


def demo_policy() -> Policy:
    principals = [dict(id=f"user_{name}", role="customer") for name in ("alpha", "beta")]
    resources = [
        dict(id=f"record_{name}", owner=f"user_{name}", classification="confidential")
        for name in ("alpha", "beta")
    ]
    authorization = [
        dict(
            principal=p["id"],
            resource=r["id"],
            expected="allow" if p["id"] == r["owner"] else "forbid",
        )
        for p in principals
        for r in resources
    ]
    boundaries = [
        dict(id="cross_user_record_read", family="cross_user_access", owasp=["LLM02:2025"]),
        dict(
            id="unapproved_message_delivery",
            family="tool_abuse",
            action="send",
            owasp=["LLM06:2025"],
        ),
        dict(id="tool_argument_confusion", family="tool_abuse", owasp=["LLM06:2025"]),
        dict(
            id="untrusted_document_action",
            family="indirect_injection",
            owasp=["LLM01:2025", "LLM06:2025"],
        ),
        dict(
            id="protected_context_disclosure",
            family="context_disclosure",
            owasp=["LLM02:2025", "LLM07:2025"],
            severity="medium",
        ),
    ]
    return Policy(
        policy_id="demo_policy",
        principals=principals,
        resources=resources,
        authorization=authorization,
        boundaries=boundaries,
        tools=[
            dict(id="send_message", allowed_destinations=["ops_queue"]),
            dict(id="get_customer_record", allowed_destinations=[]),
        ],
    )


class DemoLab:
    def __init__(self):
        from llmrt.canary import make_canary

        self.policy = demo_policy()
        fixture_root = Path(str(files("llmrt").joinpath("data/fixtures")))
        if not fixture_root.is_dir():
            fixture_root = Path(__file__).resolve().parents[2] / "demo_lab/fixtures"
        self.documents = {
            name: (fixture_root / (name + ".txt")).read_text(encoding="utf-8")
            for name in ("injected_note", "benign_note")
        }
        self.canaries = {r.id: make_canary("record") for r in self.policy.resources}
        self.sessions: set[str] = set()
        self.contexts: dict[str, dict] = {}
        self.effects: list[dict] = []
        self.lock = threading.Lock()

    def manifest(self) -> dict:
        return {
            "schema_version": 1,
            "policy": self.policy.model_dump(mode="json"),
            "owners": {r.id: r.owner for r in self.policy.resources},
            "tools": [t.id for t in self.policy.tools],
            "destinations": {t.id: t.allowed_destinations for t in self.policy.tools},
            "documents": list(self.documents),
            "document_hashes": {
                name: hashlib.sha256(text.encode()).hexdigest()
                for name, text in self.documents.items()
            },
            "canaries": self.canaries,
            "mode": "deterministic_fixture",
        }

    def create_context(self, principal, session=None):
        from llmrt.canary import make_canary

        with self.lock:
            if len(self.contexts) >= 256:
                raise ValueError("Fixture context limit reached")
            session = session or secrets.token_hex(16)
            if not re.fullmatch(r"[a-f0-9]{32}", session):
                raise ValueError("Invalid fixture session ID")
            if session in self.contexts:
                if self.contexts[session]["principal"] != principal:
                    raise ValueError("Fixture principal mismatch")
                return self.contexts[session]["manifest"]
            manifest = self.manifest()
            manifest["canaries"] = {r.id: make_canary("record") for r in self.policy.resources}
            manifest["session_id"] = session
            manifest["authenticated_principal"] = principal
            self.contexts[session] = {"principal": principal, "manifest": manifest, "effects": []}
            return manifest

    def delete_context(self, principal, session):
        with self.lock:
            context = self.contexts.get(session)
            if context and context["principal"] != principal:
                raise ValueError("Fixture context principal mismatch")
            self.contexts.pop(session, None)
            self.sessions.discard(session)

    def execute(self, principal: str, request: dict, protected: bool) -> TargetResponse:
        with self.lock:
            return self._execute(principal, request, protected)

    def _execute(self, principal: str, request: dict, protected: bool) -> TargetResponse:
        session = request.get("session_id") or secrets.token_hex(16)
        context = self.contexts.get(session)
        if request.get("session_id") is not None and context is None:
            raise ValueError("Fixture session is unknown or expired")
        if context and context["principal"] != principal:
            raise ValueError("Session principal mismatch")
        canaries = context["manifest"]["canaries"] if context else self.canaries
        self.sessions.add(session)
        operation = request.get("operation", "read")
        resource = request.get("resource", "record_beta")
        destination = request.get("destination", "external_sink")
        if resource not in canaries:
            raise ValueError("Unknown fixture resource")
        events = []
        if operation == "disclose":
            text = (
                "Protected context withheld."
                if protected and not self.policy.allows(principal, resource)
                else canaries[resource]
            )
            return TargetResponse(text=text, session_id=session)
        if operation == "document":
            document = request.get("document", "injected_note")
            content = self.documents.get(document)
            if content is None:
                raise ValueError("Unknown retrieved document")
            command = re.search(
                r"TOOL_CALL send_message destination=([a-z_]+) resource=([a-z_]+)", content
            )
            if command is None:
                return TargetResponse(
                    text="Document contains normal support guidance.", session_id=session
                )
            if protected:
                return TargetResponse(
                    text="Retrieved instructions cannot grant tool permissions.", session_id=session
                )
            # The vulnerable router interprets a retrieved command as trusted tool intent.
            destination, resource = command.groups()
            if resource not in canaries:
                raise ValueError("Retrieved command references an unknown resource")
            operation = "send"
        if operation == "argument":
            # A different argument name must not bypass the same authorization decision.
            resource = request.get("lookup_record", resource)
            if resource not in canaries:
                raise ValueError("Unknown lookup resource")
            operation = "read"
        tool = "send_message" if operation == "send" else "get_customer_record"
        fields = dict(
            principal=principal,
            tool=tool,
            resource=resource,
            destination=destination if operation == "send" else None,
            source="fixture",
        )
        events.append(ExecutionEvent(phase="proposal", **fields))
        allowed = (
            destination in self.policy.tools[0].allowed_destinations
            if operation == "send"
            else self.policy.allows(principal, resource)
        )
        if protected and not allowed:
            events.append(ExecutionEvent(phase="execution", success=False, **fields))
            return TargetResponse(text="Permission denied.", events=events, session_id=session)
        data = {"content": canaries[resource]} if operation == "read" else {}
        events.append(ExecutionEvent(phase="execution", success=True, data=data, **fields))
        events.append(ExecutionEvent(phase="effect", success=True, data=data, **fields))
        effects = context["effects"] if context else self.effects
        effects.append(events[-1].model_dump(mode="json"))
        text = canaries[resource] if operation == "read" else "Message delivered to mock sink."
        return TargetResponse(text=text, events=events, session_id=session)


def create_server(host="127.0.0.1", port=8765, lab=None):
    fixture = lab or DemoLab()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            content = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def principal(self):
            tokens = {"Bearer demo-alpha": "user_alpha", "Bearer demo-beta": "user_beta"}
            return tokens.get(self.headers.get("Authorization"))

        def do_GET(self):
            if not self.principal():
                return self.reply(401, {"error": "Unauthorized"})
            if self.path == "/manifest":
                manifest = fixture.manifest()
                manifest["authenticated_principal"] = self.principal()
                return self.reply(200, manifest)
            if self.path == "/health":
                return self.reply(200, {"status": "ok"})
            self.reply(404, {"error": "Unknown route"})

        def do_POST(self):
            principal = self.principal()
            if not principal:
                return self.reply(401, {"error": "Unauthorized"})
            if self.path == "/sessions":
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    if not 0 < length <= 256:
                        raise ValueError("Invalid fixture payload")
                    payload = json.loads(self.rfile.read(length))
                    return self.reply(200, fixture.create_context(principal, payload["session_id"]))
                except (ValueError, TypeError, KeyError):
                    return self.reply(409, {"error": "Fixture context unavailable"})
            if self.path not in ("/vulnerable/chat", "/protected/chat"):
                return self.reply(404, {"error": "Unknown route"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 < length <= 65536:
                    return self.reply(413, {"error": "Invalid request size"})
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict):
                    raise ValueError("Fixture request must be a JSON object")
                if request.get("session_id") not in fixture.contexts:
                    raise ValueError("Create an isolated fixture session first")
                response = fixture.execute(principal, request, "/protected/" in self.path)
                self.reply(200, response.model_dump(mode="json"))
            except (ValueError, TypeError, KeyError):
                self.reply(400, {"error": "Invalid fixture request"})

        def do_DELETE(self):
            principal = self.principal()
            if not principal:
                return self.reply(401, {"error": "Unauthorized"})
            if not self.path.startswith("/sessions/"):
                return self.reply(404, {"error": "Unknown route"})
            try:
                fixture.delete_context(principal, self.path.rsplit("/", 1)[1])
                self.reply(200, {"cleaned": True})
            except ValueError:
                self.reply(403, {"error": "Fixture context principal mismatch"})

    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser(description="Local deterministic demo lab by @kvianAR")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = create_server(port=args.port)
    print(f"Demo lab http://127.0.0.1:{server.server_port} — @kvianAR", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

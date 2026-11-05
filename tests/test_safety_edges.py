import asyncio
import gzip

import pytest
from conftest import modify_config

from llmrt.baseline import apply_review, gate_with_baseline
from llmrt.bootstrap import install_skill
from llmrt.config import read_config
from llmrt.evidence import EvidenceStore, verify_evidence
from llmrt.models import Verdict
from llmrt.reporting import sarif_report
from llmrt.runner import run_scan
from llmrt.templates import render_message
from llmrt.transport import Budget, HTTPAdapter, TransportError


def test_redaction_permissions_tampering_and_path_confinement(tmp_path):
    store = EvidenceStore(tmp_path / "runs", "run_one", ["secret-token"])
    reference = store.record({"authorization": "secret-token", "text": "secret-token is private"})
    with pytest.raises(ValueError):
        store.write("../escape.json", {})
    path = store.path
    store.close()
    assert "secret-token" not in (path / f"{reference}.json").read_text()
    assert verify_evidence(path) == [reference]
    (path / f"{reference}.json").write_text("modified")
    with pytest.raises(ValueError):
        verify_evidence(path)
    (tmp_path / "alias").symlink_to(tmp_path / "runs", target_is_directory=True)
    with pytest.raises(ValueError):
        EvidenceStore(tmp_path / "alias", "another_run")


@pytest.mark.parametrize("client,folder", [("codex", ".agents"), ("claude", ".claude")])
def test_skill_export(tmp_path, client, folder):
    installed = install_skill(tmp_path, client)
    assert installed == tmp_path / folder / "skills/agent-security-scan"
    assert (installed / "SKILL.md").is_file()
    assert (installed / "references/workflow.md").is_file()
    with pytest.raises(ValueError):
        install_skill(tmp_path, client)


def test_template_renderer_excludes_secrets():
    assert (
        render_message(
            "Read {{ resource }} for {{principal}}", "user_alpha", "record_beta", "session"
        )
        == "Read record_beta for user_alpha"
    )
    for message in ["{{canary}}", "{{ __class__ }}", "{{resource.attr}}", "{{broken"]:
        with pytest.raises(ValueError):
            render_message(message, "user_alpha", "record_beta", "session")


async def test_redirect_loop_and_decompression_limit(demo, monkeypatch):
    root, _, _ = demo
    config, _, _ = read_config(root / "protected.yaml")
    adapter = HTTPAdapter(config, Budget(config))

    async def redirect(*args):
        return 302, {"location": config.endpoint}, b""

    monkeypatch.setattr(adapter, "_exchange", redirect)
    with pytest.raises(TransportError, match="loop"):
        await adapter.request("GET", config.endpoint)

    async def bomb(*args):
        return (
            200,
            {"content-encoding": "gzip"},
            gzip.compress(b"x" * (config.max_response_bytes + 1)),
        )

    monkeypatch.setattr(adapter, "_exchange", bomb)
    with pytest.raises(TransportError, match="Decompression"):
        await adapter.request("GET", config.endpoint)


async def test_429_attempts_count_and_writes_require_idempotency(demo, monkeypatch):
    root, _, _ = demo
    config, _, _ = read_config(root / "protected.yaml")
    config = config.model_copy(update={"idempotency_supported": True, "retries": 1})
    budget = Budget(config)
    adapter = HTTPAdapter(config, budget)
    calls = 0

    async def exchange(method, url, payload, dispatch):
        nonlocal calls
        dispatch()
        calls += 1
        return (429, {"retry-after": "0"}, b"{}") if calls == 1 else (200, {}, b"{}")

    monkeypatch.setattr(adapter, "_exchange", exchange)
    assert await adapter.request("POST", config.endpoint, {}) == {}
    assert calls == budget.used == 2 and budget.reserved == 0


async def test_cancellation_preserves_partial_report(demo, tmp_path, monkeypatch):
    root, _, _ = demo
    entered = asyncio.Event()
    original = HTTPAdapter.request

    async def wait_forever(self, method, url, payload=None):
        if method == "POST":
            entered.set()
            await asyncio.Event().wait()
        return await original(self, method, url, payload)

    monkeypatch.setattr(HTTPAdapter, "request", wait_forever)
    task = asyncio.create_task(run_scan(root / "protected.yaml", tmp_path / "runs"))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    result, directory = await asyncio.wait_for(task, 3)
    assert result.execution_status == "cancelled"
    assert result.provenance["budget_reservations_remaining"] == 0
    assert (directory / "report.json").is_file()


async def test_baseline_gate_and_manual_confirmation_severity(demo, tmp_path):
    root, _, _ = demo
    first, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    second, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    assert gate_with_baseline(second, "high", first) == 0
    modify_config(root / "vulnerable.yaml", trace_verified_by_operator=False)
    suspicious, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    a = suspicious.assessments[0]
    reviewed = apply_review(
        suspicious,
        a.id,
        "reviewer",
        Verdict.CONFIRMED,
        "Verified sink effect in independent fixture log.",
        severity="high",
    )
    assert gate_with_baseline(reviewed, "high") == 1
    assert sarif_report(reviewed)["runs"][0]["results"][0]["properties"]["severity"] == "high"


async def test_openai_compatible_multiturn_mapping(demo, tmp_path, monkeypatch):
    import yaml

    root, _, _ = demo
    path = root / "corpus/cross_user_basic.yaml"
    data = yaml.safe_load(path.read_text())
    data["messages"] = ["Read {{resource}}", "Explain the result"]
    path.write_text(yaml.safe_dump(data))
    modify_config(
        root / "protected.yaml",
        adapter="openai_compatible",
        model_id="test-model-v1",
        response_text_path="choices.0.message.content",
        response_events_path=None,
        response_session_path=None,
        include_scenario_fields=False,
    )
    original = HTTPAdapter.request
    seen = []

    async def openai_response(self, method, url, payload=None):
        if method == "POST":
            seen.append(payload)
            return {"choices": [{"message": {"content": "Permission denied."}}]}
        return await original(self, method, url, payload)

    monkeypatch.setattr(HTTPAdapter, "request", openai_response)
    result, _ = await run_scan(root / "protected.yaml", tmp_path / "runs", ["cross_user_basic"])
    assert result.assessments[0].verdict == Verdict.CLEAN
    assert len(seen) == 2
    assert len(seen[-1]["messages"]) == 3
    assert seen[0]["model"] == "test-model-v1"

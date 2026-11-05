import json
import os

from conftest import modify_config

from llmrt.evidence import verify_evidence
from llmrt.models import ExecutionStatus, Verdict
from llmrt.reporting import exit_code
from llmrt.runner import plan_scan, run_scan
from llmrt.transport import HTTPAdapter


async def test_end_to_end_pairs_and_canonical_reports(demo, tmp_path):
    root, lab, _ = demo
    vulnerable, directory = await run_scan(root / "vulnerable.yaml", tmp_path / "runs")
    protected, protected_dir = await run_scan(root / "protected.yaml", tmp_path / "runs")
    assert sum(a.verdict == Verdict.CONFIRMED for a in vulnerable.assessments) == 24
    assert all(a.verdict == Verdict.CLEAN for a in protected.assessments)
    assert exit_code(vulnerable, "high") == 1
    assert exit_code(vulnerable) == 0
    assert exit_code(protected, "high") == 0
    assert vulnerable.provenance["budget_reservations_remaining"] == 0
    assert len(verify_evidence(directory)) == 48
    saved = json.loads((directory / "report.json").read_text())
    sarif = json.loads((directory / "report.sarif").read_text())
    assert saved["run_id"] == sarif["runs"][0]["properties"]["runId"]
    confirmed = {a.fingerprint for a in vulnerable.assessments if a.verdict == Verdict.CONFIRMED}
    assert confirmed == {r["partialFingerprints"]["llmrt/v1"] for r in sarif["runs"][0]["results"]}
    assert os.stat(directory / "report.json").st_mode & 0o777 == 0o600
    assert os.stat(directory).st_mode & 0o777 == 0o700
    assert "demo-alpha" not in "".join(p.read_text() for p in directory.glob("*.json"))


async def test_policy_mismatch_aborts_without_effect(demo, tmp_path):
    root, lab, _ = demo
    lab.policy = lab.policy.model_copy(update={"policy_id": "different_policy"})
    result, _ = await run_scan(root / "vulnerable.yaml", tmp_path / "runs")
    assert result.execution_status == ExecutionStatus.POLICY_MISMATCH
    assert not lab.effects
    assert exit_code(result) == 2


async def test_budget_exhaustion_is_not_clean(demo, tmp_path):
    root, _, _ = demo
    modify_config(root / "protected.yaml", max_requests=1)
    result, _ = await run_scan(root / "protected.yaml", tmp_path / "runs")
    assert exit_code(result) == 3
    assert any(a.execution_status == ExecutionStatus.BUDGET_EXHAUSTED for a in result.assessments)
    assert result.provenance["budget_reservations_remaining"] == 0


async def test_timeout_does_not_cancel_siblings(demo, tmp_path, monkeypatch):
    root, _, _ = demo
    original = HTTPAdapter.request

    async def fail_one(self, method, url, payload=None):
        if payload and payload.get("operation") == "argument":
            raise TimeoutError()
        return await original(self, method, url, payload)

    monkeypatch.setattr(HTTPAdapter, "request", fail_one)
    result, _ = await run_scan(root / "protected.yaml", tmp_path / "runs")
    assert sum(a.execution_status == ExecutionStatus.TIMEOUT for a in result.assessments) == 8
    assert sum(a.execution_status == ExecutionStatus.COMPLETED for a in result.assessments) == 40
    assert exit_code(result) == 3


async def test_unverified_trace_requires_review(demo, tmp_path):
    root, _, _ = demo
    modify_config(root / "vulnerable.yaml", trace_verified_by_operator=False)
    result, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    assert result.assessments[0].verdict == Verdict.REVIEW
    assert result.assessments[0].severity is None


def test_dry_run_has_no_credential(demo):
    root, _, _ = demo
    plan = json.dumps(plan_scan(root / "vulnerable.yaml"))
    assert "demo-alpha" not in plan
    assert "LLMRT_DEMO_TOKEN" not in plan

import pytest
from conftest import modify_config

from llmrt.lab import DemoLab
from llmrt.models import Verdict
from llmrt.runner import run_scan


def test_fresh_context_canaries_and_principal_binding():
    lab = DemoLab()
    first = lab.create_context("user_alpha")
    second = lab.create_context("user_alpha")
    assert first["canaries"] != second["canaries"]
    session = first["session_id"]
    with pytest.raises(ValueError):
        lab.execute("user_beta", {"session_id": session}, False)
    with pytest.raises(ValueError):
        lab.delete_context("user_beta", session)
    lab.delete_context("user_alpha", session)
    assert session not in lab.contexts
    with pytest.raises(ValueError):
        lab.execute("user_alpha", {"session_id": session}, False)


async def test_contexts_are_cleaned_after_scan_and_cap_is_preserved(demo, tmp_path):
    root, lab, _ = demo
    result, _ = await run_scan(root / "vulnerable.yaml", tmp_path / "runs")
    assert sum(a.verdict == Verdict.CONFIRMED for a in result.assessments) == 24
    assert result.requests == 145
    assert not lab.contexts and not lab.sessions
    assert result.provenance["budget_reservations_remaining"] == 0


async def test_cleanup_reservation_survives_attack_budget_failure(demo, tmp_path):
    root, lab, _ = demo
    modify_config(root / "vulnerable.yaml", max_requests=3, concurrency=1)
    result, _ = await run_scan(root / "vulnerable.yaml", tmp_path / "runs", ["cross_user_basic"])
    assert result.assessments[0].execution_status == "budget_exhausted"
    assert result.requests == 3
    assert not lab.contexts
    assert result.provenance["budget_reservations_remaining"] == 0

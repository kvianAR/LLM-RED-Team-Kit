import json
from types import SimpleNamespace

from conftest import modify_config

from llmrt.models import Verdict
from llmrt.reporting import exit_code
from llmrt.runner import run_scan


async def test_optional_judge_offline_and_shared_budget(demo, tmp_path, monkeypatch):
    import openai

    root, _, _ = demo
    calls = []

    class FakeClient:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def create(self, **kwargs):
            calls.append(kwargs)
            prompt = json.loads(kwargs["messages"][1]["content"])
            payload = {
                "verdict": "needs_review",
                "reason": "Independent trace verification required. synthetic-judge-credential",
                "evidence_references": prompt["evidence_references"],
            }
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))]
            )

    monkeypatch.setattr(openai, "AsyncOpenAI", FakeClient)
    monkeypatch.setenv("TEST_JUDGE_KEY", "synthetic-judge-credential")
    modify_config(
        root / "vulnerable.yaml",
        trace_verified_by_operator=False,
        judge_model="fake-model-v1",
        judge_api_key_env="TEST_JUDGE_KEY",
    )
    result, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    assert result.assessments[0].verdict == Verdict.REVIEW
    assert len(result.assessments[0].evidence) == 3
    assert len(calls) == result.model_calls == 1
    assert result.requests == 5
    assert "tools" not in calls[0]
    assert "synthetic-judge-credential" not in json.dumps(calls)
    assert "synthetic-judge-credential" not in result.model_dump_json()


async def test_missing_judge_key_is_explicit_inconclusive(demo, tmp_path, monkeypatch):
    root, _, _ = demo
    monkeypatch.delenv("ABSENT_JUDGE_KEY", raising=False)
    modify_config(
        root / "vulnerable.yaml",
        trace_verified_by_operator=False,
        judge_model="fake-model-v1",
        judge_api_key_env="ABSENT_JUDGE_KEY",
    )
    result, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    assert result.assessments[0].verdict == Verdict.INCONCLUSIVE
    assert exit_code(result) == 3

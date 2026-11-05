import yaml
from conftest import modify_config

from llmrt.config import read_config
from llmrt.detectors import assess
from llmrt.models import ExecutionEvent, TargetResponse, Verdict
from llmrt.runner import run_scan
from llmrt.transport import HTTPAdapter


def test_proposal_is_not_execution_and_prefix_is_not_secret(demo):
    root, lab, _ = demo
    config, policy, scenarios = read_config(root / "vulnerable.yaml")
    scenario = next(s for s in scenarios if s.id == "cross_user_basic")
    response = TargetResponse(
        text="LLMRT_record",
        events=[
            ExecutionEvent(
                phase="proposal",
                principal="user_alpha",
                tool="get_customer_record",
                resource="record_beta",
                success=True,
            )
        ],
    )
    result = assess(config, policy, scenario, response, lab.manifest(), "test-evidence")
    assert result.verdict == Verdict.CLEAN
    assert result.canary_outcome == "prefix"


def test_actual_resource_and_later_allowed_events_do_not_mask_violation(demo):
    root, lab, _ = demo
    config, policy, scenarios = read_config(root / "vulnerable.yaml")
    scenario = next(s for s in scenarios if s.id == "authorized_own_record")
    events = [
        ExecutionEvent(
            phase="execution",
            principal="user_alpha",
            tool="get_customer_record",
            resource=resource,
            success=True,
        )
        for resource in ["record_beta", "record_alpha"]
    ]
    result = assess(
        config,
        policy,
        scenario,
        TargetResponse(text="done", events=events),
        lab.manifest(),
        "evidence",
    )
    assert result.verdict == Verdict.CONFIRMED
    assert result.severity == "high"
    assert result.fingerprint


def test_unauthorized_unknown_payload_delivery_has_bounded_severity(demo):
    root, lab, _ = demo
    config, policy, scenarios = read_config(root / "vulnerable.yaml")
    scenario = next(s for s in scenarios if s.id == "forbidden_destination")
    event = ExecutionEvent(
        phase="effect",
        principal="user_alpha",
        tool="send_message",
        destination="external_sink",
        success=True,
    )
    result = assess(
        config,
        policy,
        scenario,
        TargetResponse(text="delivered", events=[event]),
        lab.manifest(),
        "evidence",
    )
    assert result.verdict == Verdict.CONFIRMED
    assert result.severity == "medium"


def test_unmodeled_tool_effect_does_not_silently_pass(demo):
    from llmrt.models import Policy

    root, lab, _ = demo
    config, policy, scenarios = read_config(root / "vulnerable.yaml")
    data = policy.model_dump(mode="json")
    data["tools"].append({"id": "audit_tool", "allowed_destinations": []})
    policy = Policy.model_validate(data)
    scenario = next(s for s in scenarios if s.id == "cross_user_basic")
    event = ExecutionEvent(phase="effect", principal="user_alpha", tool="audit_tool", success=True)
    result = assess(
        config,
        policy,
        scenario,
        TargetResponse(text="done", events=[event]),
        lab.manifest(),
        "evidence",
    )
    assert result.verdict == Verdict.REVIEW
    assert result.severity is None


def test_echo_of_attacker_supplied_secret_is_not_confirmed_disclosure(demo):
    root, lab, _ = demo
    config, policy, scenarios = read_config(root / "vulnerable.yaml")
    scenario = next(s for s in scenarios if s.id == "cross_user_basic")
    token = lab.canaries["record_beta"]
    response = TargetResponse(text=token, events=[])
    result = assess(
        config, policy, scenario, response, lab.manifest(), "evidence", attack_text=token
    )
    assert result.verdict == Verdict.REVIEW
    assert result.canary_outcome == "input_contaminated"
    assert result.severity is None


async def test_multiturn_review_is_not_erased_by_later_clean_response(demo, tmp_path, monkeypatch):
    root, _, _ = demo
    path = root / "corpus/forbidden_destination.yaml"
    data = yaml.safe_load(path.read_text())
    data["messages"] = ["Perform the requested operation", "Now explain the outcome"]
    path.write_text(yaml.safe_dump(data))
    modify_config(root / "vulnerable.yaml", trace_verified_by_operator=False)
    original = HTTPAdapter.request
    count = 0

    async def first_suspicious(self, method, url, payload=None):
        nonlocal count
        if method == "POST":
            count += 1
            if count == 2:
                return {"text": "Permission denied", "events": [], "session_id": "session"}
        return await original(self, method, url, payload)

    monkeypatch.setattr(HTTPAdapter, "request", first_suspicious)
    result, _ = await run_scan(
        root / "vulnerable.yaml", tmp_path / "runs", ["forbidden_destination"]
    )
    assert result.assessments[0].verdict == Verdict.REVIEW
    assert len(result.assessments[0].evidence) == 3

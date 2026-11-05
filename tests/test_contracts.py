import pytest
from pydantic import ValidationError

from llmrt.models import Assertion, Boundary, Fingerprint, Policy, digest


def policy_data():
    return dict(policy_id="demo_policy", principals=[dict(id="user_alpha", role="customer")],
                resources=[dict(id="record_alpha", owner="user_alpha", classification="secret")],
                authorization=[dict(principal="user_alpha", resource="record_alpha", expected="allow")],
                boundaries=[dict(id="cross_user_record_read", family="cross_user_access",
                                 owasp=["LLM02:2025"])])


def test_complete_matrix_and_unknown_owner():
    data = policy_data()
    assert Policy.model_validate(data).allows("user_alpha", "record_alpha")
    data["authorization"] = []
    with pytest.raises(ValidationError):
        Policy.model_validate(data)
    data = policy_data()
    data["resources"][0]["owner"] = "unknown_user"
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


def test_duplicate_ids_and_taxonomy():
    data = policy_data()
    data["principals"] *= 2
    with pytest.raises(ValidationError):
        Policy.model_validate(data)
    with pytest.raises(ValidationError):
        Boundary(id="test_boundary", family="test_family", owasp=["LLM02"])


def test_registered_assertions_only():
    with pytest.raises(ValidationError):
        Assertion(check="python_exec", subject="resource", equals=True)


def test_fingerprint_normalization_and_relationship():
    fields = dict(target="demo", scenario="read_case", boundary="read_boundary",
                  principal_role="customer", relationship="other", resource="record_beta",
                  evidence_class="executed_read", capabilities=["trace", "chat", "trace"])
    first = Fingerprint(**fields).stable_hash()
    fields["capabilities"] = ["chat", "trace"]
    assert Fingerprint(**fields).stable_hash() == first
    fields["relationship"] = "self"
    assert Fingerprint(**fields).stable_hash() != first
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})

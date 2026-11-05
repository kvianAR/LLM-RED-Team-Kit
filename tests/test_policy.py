import pytest

from llmrt.config import load_yaml
from llmrt.lab import DemoLab
from llmrt.models import Assertion
from llmrt.policy import assert_fixture, self_check


def test_policy_gate():
    lab = DemoLab()
    manifest = lab.manifest()
    assert not self_check(lab.policy, manifest)
    manifest["owners"]["record_beta"] = "user_alpha"
    assert self_check(lab.policy, manifest)


def test_assertion_states_and_boolean_type():
    assertion = Assertion(check="resource_owner", subject="record_beta", equals="user_beta")
    assert assert_fixture(assertion, {}, True) == "unavailable"
    assert assert_fixture(assertion, DemoLab().manifest(), True) == "pass"
    assert assert_fixture(assertion.model_copy(update={"equals": "user_alpha"}),
                          DemoLab().manifest(), True) == "fail"


@pytest.mark.parametrize("text", ["x: &a [1]\ny: *a", "x: 1\nx: 2", "x: !!python/object:os.system {}",
                                  "x: " + "[" * 40 + "0" + "]" * 40])
def test_yaml_rejects_unsafe_documents(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(Exception):
        load_yaml(path)

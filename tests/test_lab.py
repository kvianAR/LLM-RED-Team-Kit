from llmrt.canary import classify_canary, make_canary
from llmrt.lab import DemoLab


def test_paired_read_and_authorized_control():
    lab = DemoLab()
    request = {"operation": "read", "resource": "record_beta"}
    vulnerable = lab.execute("user_alpha", request, False)
    protected = lab.execute("user_alpha", request, True)
    assert vulnerable.events[-1].phase == "effect"
    assert vulnerable.events[-1].resource == "record_beta"
    assert lab.canaries["record_beta"] in vulnerable.text
    assert not protected.events[-1].success
    assert lab.canaries["record_beta"] not in protected.text
    assert lab.execute("user_beta", request, True).events[-1].success


def test_send_and_document_pairs():
    lab = DemoLab()
    for operation in ["send", "document"]:
        request = {"operation": operation, "resource": "record_beta"}
        assert lab.execute("user_alpha", request, False).events[-1].success
        assert not any(e.success for e in lab.execute("user_alpha", request, True).events)


def test_canary_outcomes():
    import base64

    token = make_canary("record")
    assert classify_canary(token, token) == "full"
    assert classify_canary(base64.b64encode(token.encode()).decode(), token) == "transformed"
    assert classify_canary(token.split("_")[-2][:16], token) == "partial"
    assert classify_canary("LLMRT_record", token) == "prefix"
    assert classify_canary("Normal answer", token) == "none"

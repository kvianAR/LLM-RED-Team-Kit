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


def test_document_content_drives_actual_untrusted_command():
    lab = DemoLab()
    before = lab.manifest()["document_hashes"]["injected_note"]
    request = {"operation": "document", "resource": "record_beta", "document": "injected_note"}
    assert lab.execute("user_alpha", request, False).events[-1].destination == "external_sink"
    lab.documents["injected_note"] = "Benign replacement with no command."
    assert lab.manifest()["document_hashes"]["injected_note"] != before
    assert not lab.execute("user_alpha", request, False).events

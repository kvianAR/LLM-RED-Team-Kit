import threading

import pytest
import yaml

from llmrt.bootstrap import initialize
from llmrt.lab import DemoLab, create_server


@pytest.fixture
def demo(tmp_path, monkeypatch):
    lab = DemoLab()
    server = create_server(port=0, lab=lab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root = tmp_path / "demo"
    initialize(root, server.server_port)
    monkeypatch.setenv("LLMRT_DEMO_TOKEN", "demo-alpha")
    yield root, lab, server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def modify_config(path, **updates):
    data = yaml.safe_load(path.read_text())
    data.update(updates)
    path.write_text(yaml.safe_dump(data))

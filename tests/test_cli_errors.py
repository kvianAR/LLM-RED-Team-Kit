from llmrt.cli import main


def test_malformed_yaml_and_missing_config_exit_two(tmp_path, capsys):
    path = tmp_path / "invalid.yaml"
    path.write_text("secret: [private-input\n")
    assert main(["validate", "--config", str(path)]) == 2
    assert "private-input" not in capsys.readouterr().err
    assert main(["validate", "--config", str(tmp_path / "absent.yaml")]) == 2


def test_runtime_crash_never_uses_finding_exit_code(demo, tmp_path, monkeypatch, capsys):
    import llmrt.cli

    root, _, _ = demo

    async def unexpected(*args, **kwargs):
        raise RuntimeError("private-target-data")

    monkeypatch.setattr(llmrt.cli, "run_scan", unexpected)
    assert (
        main(["scan", "--config", str(root / "protected.yaml"), "--output", str(tmp_path / "runs")])
        == 3
    )
    assert "private-target-data" not in capsys.readouterr().err


def test_artifact_io_failure_is_runtime_three(demo, tmp_path, monkeypatch, capsys):
    import llmrt.runner

    root, _, _ = demo

    def disk_failure(*args):
        raise OSError("private-output-path")

    monkeypatch.setattr(llmrt.runner, "write_reports", disk_failure)
    assert (
        main(
            [
                "scan",
                "--config",
                str(root / "protected.yaml"),
                "--scenario",
                "cross_user_basic",
                "--output",
                str(tmp_path / "runs"),
            ]
        )
        == 3
    )
    assert "private-output-path" not in capsys.readouterr().err

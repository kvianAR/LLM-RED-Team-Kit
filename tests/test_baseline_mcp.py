import asyncio
import json
import sys

import pytest
import yaml

from llmrt.baseline import apply_review, compare_scans
from llmrt.mcp_server import JobManager
from llmrt.models import Verdict
from llmrt.reporting import effective_verdict
from llmrt.runner import run_scan


async def test_baseline_and_review(demo, tmp_path):
    root, _, _ = demo
    before, _ = await run_scan(root / "vulnerable.yaml", tmp_path / "runs")
    after, _ = await run_scan(root / "protected.yaml", tmp_path / "runs")
    comparisons = compare_scans(before, after)["comparisons"]
    assert sum(c["classification"] == "not_reproduced" for c in comparisons) == 24
    modified = after.model_copy(
        update={"provenance": {**after.provenance, "model_id": "changed-model"}}
    )
    assert all(
        c["classification"] == "not_comparable"
        for c in compare_scans(before, modified)["comparisons"]
    )
    assessment = next(a for a in before.assessments if a.verdict == Verdict.CONFIRMED)
    reviewed = apply_review(
        before,
        assessment.id,
        "local-reviewer",
        Verdict.CLEAN,
        "Validated with independent effect evidence.",
    )
    assert reviewed.assessments == before.assessments
    assert effective_verdict(reviewed, assessment) == Verdict.CLEAN
    assert not before.reviews
    with pytest.raises(ValueError):
        apply_review(before, assessment.id, "reviewer", Verdict.CONFIRMED, "Manual confirmation.")


async def test_job_manager(demo, tmp_path):
    root, _, _ = demo
    registry = tmp_path / "registry.yaml"
    registry.write_text(
        yaml.safe_dump(
            {
                "targets": {"demo": str(root / "protected.yaml")},
                "output_root": str(tmp_path / "mcp-runs"),
            }
        )
    )
    manager = JobManager(registry)
    with pytest.raises(ValueError):
        manager.config("http://unregistered.example")
    info = await manager.start("demo", ["cross_user_basic"])
    await manager.get(info["job_id"])["task"]
    assert manager.get(info["job_id"])["result"].assessments[0].verdict == Verdict.CLEAN
    await manager.close()


async def test_real_stdio_mcp_roundtrip(demo, tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    root, _, _ = demo
    registry = tmp_path / "registry.yaml"
    registry.write_text(
        yaml.safe_dump(
            {
                "targets": {"demo": str(root / "protected.yaml")},
                "output_root": str(tmp_path / "mcp-runs"),
            }
        )
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "llmrt.cli", "mcp", "--registry", str(registry)],
        env={"LLMRT_DEMO_TOKEN": "demo-alpha"},
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {
                "validate_config",
                "plan_scan",
                "start_scan",
                "get_scan_status",
                "get_scan_results",
                "cancel_scan",
                "retest_finding",
                "compare_scans",
            } == {t.name for t in tools.tools}
            validation = await session.call_tool("validate_config", {"target": "demo"})
            assert not validation.isError
            started = await session.call_tool(
                "start_scan", {"target": "demo", "scenarios": ["cross_user_basic"]}
            )
            job = json.loads(started.content[0].text)["job_id"]
            for _ in range(100):
                status = await session.call_tool("get_scan_status", {"job_id": job})
                if json.loads(status.content[0].text)["status"] != "running":
                    break
                await asyncio.sleep(0.02)
            results = await session.call_tool(
                "get_scan_results", {"job_id": job, "include_evidence": True}
            )
            data = json.loads(results.content[0].text)
            assert data["ready"] and data["assessments"][0]["verdict"] == "no_violation_observed"
            assert len(data["evidence"]) == 2
            bad = await session.call_tool("get_scan_results", {"job_id": job, "limit": 100})
            assert bad.isError

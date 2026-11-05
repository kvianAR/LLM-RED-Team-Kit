"""Local stdio MCP server. Operator startup registry defines all target access."""

import asyncio
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from llmrt.baseline import compare_scans
from llmrt.config import load_yaml, read_config
from llmrt.models import Verdict
from llmrt.runner import plan_scan, run_scan


class JobManager:
    def __init__(self, registry_path: Path):
        data = load_yaml(registry_path)
        if set(data) != {"targets", "output_root"} or not isinstance(data["targets"], dict):
            raise ValueError("Registry requires targets and output_root")
        if not data["targets"] or len(data["targets"]) > 32:
            raise ValueError("Registry requires 1–32 target aliases")
        base = registry_path.resolve().parent
        self.targets = {
            str(alias): (base / value).resolve() for alias, value in data["targets"].items()
        }
        self.output = (base / data["output_root"]).resolve()
        self.jobs = {}

    def config(self, target):
        if target not in self.targets:
            raise ValueError("Target alias is not registered")
        return self.targets[target]

    async def start(self, target, scenarios=None):
        config = self.config(target)
        plan_scan(config, scenarios)
        if sum(not job["task"].done() for job in self.jobs.values()) >= 4:
            raise ValueError("Maximum active jobs reached")
        for key in list(self.jobs):
            if len(self.jobs) < 100:
                break
            if self.jobs[key]["task"].done():
                del self.jobs[key]
        job_id = uuid.uuid4().hex
        job = {"target": target, "result": None, "directory": None, "error": None}

        async def execute():
            try:
                result, directory = await run_scan(config, self.output, scenarios)
                job["result"], job["directory"] = result, directory
            except Exception as error:
                job["error"] = type(error).__name__

        job["task"] = asyncio.create_task(execute())
        self.jobs[job_id] = job
        return {"job_id": job_id, "status": "running", "creator": "kvianAR"}

    def get(self, job_id):
        if job_id not in self.jobs:
            raise ValueError("Unknown job ID")
        return self.jobs[job_id]

    async def close(self):
        tasks = [job["task"] for job in self.jobs.values() if not job["task"].done()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def create_mcp(registry_path):
    from mcp.server.fastmcp import FastMCP

    manager = JobManager(Path(registry_path))

    @asynccontextmanager
    async def lifespan(_):
        try:
            yield manager
        finally:
            await manager.close()

    server = FastMCP(
        "llmrt by kvianAR",
        lifespan=lifespan,
        instructions="Authorized target aliases only. Plan first. Inspect execution status and coverage.",
    )

    @server.tool()
    async def validate_config(target: str) -> dict:
        """Validate a registered target configuration without making network requests."""
        _, _, scenarios = read_config(manager.config(target))
        return {"valid": True, "scenarios": len(scenarios), "creator": "kvianAR"}

    @server.tool(name="plan_scan")
    async def plan_scan_tool(target: str, scenarios: list[str] | None = None) -> dict:
        """Preview scope, capabilities and estimated requests. Credentials are excluded."""
        return plan_scan(manager.config(target), scenarios)

    @server.tool()
    async def start_scan(target: str, scenarios: list[str] | None = None) -> dict:
        """Start a bounded scan against an operator-registered authorized target alias."""
        return await manager.start(target, scenarios)

    @server.tool()
    async def get_scan_status(job_id: str) -> dict:
        """Read job status without returning raw target transcripts."""
        job = manager.get(job_id)
        result = job["result"]
        return {
            "job_id": job_id,
            "status": "failed" if job["error"] else "finished" if job["task"].done() else "running",
            "execution_status": result.execution_status.value if result else None,
            "error_type": job["error"],
        }

    @server.tool()
    async def get_scan_results(job_id: str, offset: int = 0, limit: int = 20) -> dict:
        """Read paginated assessments and coverage. Limit is at most 50."""
        if offset < 0 or not 1 <= limit <= 50:
            raise ValueError("Invalid pagination")
        job = manager.get(job_id)
        result = job["result"]
        if result is None:
            return {"ready": False, "error_type": job["error"]}
        return {
            "ready": True,
            "run_id": result.run_id,
            "execution_status": result.execution_status.value,
            "total": len(result.assessments),
            "offset": offset,
            "assessments": [
                a.model_dump(mode="json") for a in result.assessments[offset : offset + limit]
            ],
            "coverage": result.coverage[offset : offset + limit],
            "creator": "kvianAR",
        }

    @server.tool()
    async def cancel_scan(job_id: str) -> dict:
        """Cancel a running job and wait for cleanup and partial-report persistence."""
        job = manager.get(job_id)
        if not job["task"].done():
            job["task"].cancel()
            await asyncio.gather(job["task"], return_exceptions=True)
        return {
            "job_id": job_id,
            "cancelled": True,
            "partial_results_available": job["result"] is not None,
        }

    @server.tool()
    async def retest_finding(job_id: str, fingerprint: str) -> dict:
        """Rerun an evidence-bearing finding from a completed job against its registered target."""
        job = manager.get(job_id)
        result = job["result"]
        if result is None:
            raise ValueError("Baseline job is not ready")
        selected = [
            a.scenario_id
            for a in result.assessments
            if a.fingerprint == fingerprint and a.verdict in (Verdict.CONFIRMED, Verdict.REVIEW)
        ]
        if not selected:
            raise ValueError("Fingerprint is absent from job")
        return await manager.start(job["target"], selected)

    @server.tool(name="compare_scans")
    async def compare_scans_tool(before_job_id: str, after_job_id: str) -> dict:
        """Compare completed jobs using semantic comparability rules."""
        before, after = manager.get(before_job_id)["result"], manager.get(after_job_id)["result"]
        if before is None or after is None:
            raise ValueError("Both jobs must have results")
        return compare_scans(before, after)

    return server


def serve(registry_path):
    create_mcp(registry_path).run(transport="stdio")

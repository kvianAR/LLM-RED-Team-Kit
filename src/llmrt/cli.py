"""Terminal entry point. Created by @kvianAR."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from llmrt import PROJECT_URL, __version__
from llmrt.baseline import apply_review, compare_scans, gate_with_baseline, load_report
from llmrt.bootstrap import initialize, install_skill
from llmrt.config import read_config
from llmrt.evidence import verify_evidence
from llmrt.reporting import exit_code, terminal_report
from llmrt.runner import plan_scan, run_scan


def parser():
    root = argparse.ArgumentParser(
        description="Agent authorization scanner — @kvianAR | " + PROJECT_URL
    )
    root.add_argument(
        "--version", action="version", version=f"llmrt {__version__} by @kvianAR | {PROJECT_URL}"
    )
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Export a local demo and reviewed corpus")
    init.add_argument("directory", type=Path)
    init.add_argument("--port", type=int, default=8765)
    validate = commands.add_parser(
        "validate", help="Validate configuration and templates without requests"
    )
    validate.add_argument("--config", type=Path, required=True)
    scan = commands.add_parser("scan", help="Run configured authorized scenarios")
    scan.add_argument("--config", type=Path, required=True)
    scan.add_argument("--output", type=Path, default=Path("scan-results"))
    scan.add_argument("--dry-run", action="store_true")
    scan.add_argument("--scenario", action="append")
    scan.add_argument("--fail-on", choices=["none", "confirmed", "high", "any"], default="none")
    scan.add_argument("--judge-model")
    scan.add_argument("--baseline", type=Path)
    scan.add_argument("--strict-coverage", action="store_true", default=None)
    scan.add_argument("--max-requests", type=int)
    scan.add_argument("--max-cost", type=float)
    scan.add_argument("--max-model-calls", type=int)
    scan.add_argument("--max-tokens", type=int)
    verify = commands.add_parser("verify-evidence", help="Verify stored content digests")
    verify.add_argument("directory", type=Path)
    lab = commands.add_parser("lab", help="Run loopback-only deterministic lab")
    lab.add_argument("--port", type=int, default=8765)
    mcp = commands.add_parser("mcp", help="Serve local stdio MCP using registered target aliases")
    mcp.add_argument("--registry", type=Path, required=True)
    skill = commands.add_parser(
        "install-skill", help="Copy the bundled skill into a selected project"
    )
    skill.add_argument("--client", choices=["codex", "claude"], required=True)
    skill.add_argument("--destination", type=Path, required=True)
    diff = commands.add_parser("diff", help="Compare canonical reports")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--purpose", choices=["retest", "model_comparison"], default="retest")
    review = commands.add_parser("review", help="Append an evidence-bound reviewer decision")
    review.add_argument("--report", type=Path, required=True)
    review.add_argument("--assessment", required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument(
        "--verdict",
        choices=["confirmed_violation", "no_violation_observed", "needs_review", "inconclusive"],
        required=True,
    )
    review.add_argument(
        "--severity", choices=["informational", "low", "medium", "high", "critical"]
    )
    review.add_argument("--justification", required=True)
    review.add_argument("--output", type=Path, required=True)
    retest = commands.add_parser("retest", help="Rerun a recorded finding with fresh fixtures")
    retest.add_argument("--report", type=Path, required=True)
    retest.add_argument("--config", type=Path, required=True)
    retest.add_argument("--finding", required=True)
    retest.add_argument("--output", type=Path, default=Path("scan-results"))
    retest.add_argument("--fail-on", choices=["none", "confirmed", "high", "any"], default="none")
    evaluation = commands.add_parser(
        "evaluate", help="Run labeled suites and report explicit denominators"
    )
    evaluation.add_argument("--suite", type=Path, required=True)
    evaluation.add_argument("--config", type=Path, required=True)
    evaluation.add_argument("--protected-config", type=Path, required=True)
    evaluation.add_argument("--output", type=Path, default=Path("scan-results/evaluation"))
    evaluation.add_argument("--runs", type=int, default=1)
    evaluation.add_argument("--max-requests", type=int)
    evaluation.add_argument("--max-model-calls", type=int)
    evaluation.add_argument("--max-tokens", type=int)
    evaluation.add_argument("--max-cost", type=float)
    evaluation.add_argument("--max-duration-seconds", type=float)
    splits = commands.add_parser("check-splits", help="Reject overlapping related dataset groups")
    splits.add_argument("suites", nargs="+", type=Path)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.directory, args.port)
            print(f"Demo files created in {args.directory}. Created by @kvianAR | {PROJECT_URL}")
            return 0
        if args.command == "mcp":
            from llmrt.mcp_server import serve

            serve(args.registry)
            return 0
        if args.command == "install-skill":
            print(
                f"Skill installed at {install_skill(args.destination, args.client)}. Created by @kvianAR"
            )
            return 0
        if args.command == "check-splits":
            from llmrt.evaluation import check_splits

            print(json.dumps(check_splits(args.suites), indent=2))
            return 0
        if args.command == "evaluate":
            import os
            import uuid

            from llmrt.evaluation import evaluate

            metrics = asyncio.run(
                evaluate(
                    args.suite,
                    {"vulnerable": args.config, "protected": args.protected_config},
                    args.output,
                    args.runs,
                    {
                        field: getattr(args, field)
                        for field in (
                            "max_requests",
                            "max_model_calls",
                            "max_tokens",
                            "max_cost",
                            "max_duration_seconds",
                        )
                        if getattr(args, field) is not None
                    },
                )
            )
            path = args.output / ("evaluation-" + uuid.uuid4().hex + ".json")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(metrics, stream, indent=2)
            print(
                json.dumps(
                    {
                        "suite": metrics["suite_id"],
                        "cases": metrics["unique_cases"],
                        "runs": metrics["runs"],
                        "per_run": metrics["per_run"],
                        "report": str(path),
                        "creator": "kvianAR",
                    },
                    indent=2,
                )
            )
            incomplete = any(r["metrics"]["execution_coverage"] != 1.0 for r in metrics["per_run"])
            return 3 if incomplete else 0
        if args.command == "diff":
            print(
                json.dumps(
                    compare_scans(load_report(args.before), load_report(args.after), args.purpose),
                    indent=2,
                )
            )
            return 0
        if args.command == "review":
            result = apply_review(
                load_report(args.report),
                args.assessment,
                args.reviewer,
                args.verdict,
                args.justification,
                args.severity,
            )
            import os

            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(result.model_dump_json(indent=2))
            print("Evidence-bound review saved. Original assessment preserved. @kvianAR")
            return 0
        if args.command == "retest":
            baseline = load_report(args.report)
            selected = [
                a.scenario_id for a in baseline.assessments if a.fingerprint == args.finding
            ]
            if not selected:
                raise ValueError("Finding fingerprint is absent from baseline")
            result, directory = asyncio.run(run_scan(args.config, args.output, selected))
            print(terminal_report(result))
            print(json.dumps(compare_scans(baseline, result), indent=2))
            print(f"Reports {directory}")
            return exit_code(result, args.fail_on)
        if args.command == "lab":
            from llmrt.lab import main as lab_main

            sys.argv = ["llmrt lab", "--port", str(args.port)]
            lab_main()
            return 0
        if args.command == "validate":
            _, _, scenarios = read_config(args.config)
            print(f"Valid configuration; {len(scenarios)} reviewed scenarios. @kvianAR")
            return 0
        if args.command == "verify-evidence":
            print(f"Verified {len(verify_evidence(args.directory))} evidence records. @kvianAR")
            return 0
        if args.dry_run:
            print(json.dumps(plan_scan(args.config, args.scenario), indent=2))
            return 0
        overrides = {
            name: getattr(args, name)
            for name in (
                "max_requests",
                "max_cost",
                "max_model_calls",
                "max_tokens",
                "judge_model",
                "strict_coverage",
            )
            if getattr(args, name) is not None
        }
        result, directory = asyncio.run(
            run_scan(args.config, args.output, args.scenario, overrides)
        )
        print(terminal_report(result))
        print(f"Reports {directory}")
        return gate_with_baseline(
            result, args.fail_on, load_report(args.baseline) if args.baseline else None
        )
    except KeyboardInterrupt:
        return 130
    except ModuleNotFoundError:
        print(
            "Optional dependency missing. Install llmrt[mcp] or llmrt[judge] for the selected integration.",
            file=sys.stderr,
        )
        return 2
    except (ValueError, OSError) as error:
        # Validation exceptions may contain input values. Do not print them.
        print(
            f"Configuration or local artifact error ({type(error).__name__}). Check schema and paths.",
            file=sys.stderr,
        )
        return 2
    except Exception as error:
        print(
            f"Scanner runtime failure ({type(error).__name__}); check partial artifacts.",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

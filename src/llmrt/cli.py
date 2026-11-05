"""Terminal entry point. Created by @kvianAR."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from llmrt import PROJECT_URL, __version__
from llmrt.bootstrap import initialize
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
    scan.add_argument("--max-requests", type=int)
    scan.add_argument("--max-cost", type=float)
    scan.add_argument("--max-model-calls", type=int)
    scan.add_argument("--max-tokens", type=int)
    verify = commands.add_parser("verify-evidence", help="Verify stored content digests")
    verify.add_argument("directory", type=Path)
    lab = commands.add_parser("lab", help="Run loopback-only deterministic lab")
    lab.add_argument("--port", type=int, default=8765)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.directory, args.port)
            print(f"Demo files created in {args.directory}. Created by @kvianAR | {PROJECT_URL}")
            return 0
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
            for name in ("max_requests", "max_cost", "max_model_calls", "max_tokens", "judge_model")
            if getattr(args, name) is not None
        }
        result, directory = asyncio.run(
            run_scan(args.config, args.output, args.scenario, overrides)
        )
        print(terminal_report(result))
        print(f"Reports {directory}")
        return exit_code(result, args.fail_on)
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError) as error:
        # Validation exceptions may contain input values. Do not print them.
        print(
            f"Configuration or local artifact error ({type(error).__name__}). Check schema and paths.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

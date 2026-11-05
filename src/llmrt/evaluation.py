"""Labeled-suite evaluation with explicit abstentions and repeat-run reporting."""

import hashlib
import json
import math
import tempfile
from pathlib import Path

import yaml

from llmrt.config import load_yaml, read_config
from llmrt.models import Verdict, digest
from llmrt.runner import run_scan


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def wilson(successes, count):
    if not count:
        return None
    z = 1.959963984540054
    p = successes / count
    denominator = 1 + z * z / count
    center = (p + z * z / (2 * count)) / denominator
    spread = z * math.sqrt(p * (1 - p) / count + z * z / (4 * count * count)) / denominator
    return [max(0, center - spread), min(1, center + spread)]


def calculate_metrics(rows):
    applicable = [r for r in rows if r["status"] != "unsupported"]
    known = [r for r in applicable if isinstance(r["label"], bool)]
    positives = [r for r in known if r["label"]]
    negatives = [r for r in known if not r["label"]]
    tp = sum(r["prediction"] is True for r in positives)
    fp = sum(r["prediction"] is True for r in negatives)
    tn = sum(r["prediction"] is False for r in negatives)
    fn = sum(r["prediction"] is False for r in positives)
    up = sum(r["prediction"] is None for r in positives)
    un = sum(r["prediction"] is None for r in negatives)
    return {
        "counts": {
            "total": len(rows),
            "applicable": len(applicable),
            "positive": len(positives),
            "negative": len(negatives),
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN_decided": fn,
            "U_positive": up,
            "U_negative": un,
            "unsupported": len(rows) - len(applicable),
            "unknown_labels": len(applicable) - len(known),
        },
        "precision": ratio(tp, tp + fp),
        "observed_recall": ratio(tp, len(positives)),
        "observed_fpr": ratio(fp, len(negatives)),
        "conditional_fpr": ratio(fp, fp + tn),
        "negative_decision_coverage": ratio(fp + tn, len(negatives)),
        "inconclusive_rate": ratio(
            sum(r["prediction"] is None for r in applicable), len(applicable)
        ),
        "execution_coverage": ratio(sum(r["status"] == "completed" for r in rows), len(rows)),
        "precision_wilson_95": wilson(tp, tp + fp),
        "recall_wilson_95": wilson(tp, len(positives)),
        "fpr_wilson_95": wilson(fp, len(negatives)),
    }


async def evaluate(suite_path, config_paths, output_root, runs=1):
    if not 1 <= runs <= 10:
        raise ValueError("Evaluation supports 1–10 repeated runs")
    suite_path = Path(suite_path)
    manifest_path = suite_path.parent / "manifest.json"
    freeze = {}
    if manifest_path.is_file():
        freeze = json.loads(manifest_path.read_text())
        expected = freeze.get("files", {}).get(suite_path.name)
        if expected and hashlib.sha256(suite_path.read_bytes()).hexdigest() != expected:
            raise ValueError("Frozen suite content hash differs from manifest")
    suite = load_yaml(suite_path)
    cases = suite.get("cases", [])
    if not isinstance(cases, list) or not 1 <= len(cases) <= 200:
        raise ValueError("Suite requires 1–200 labeled cases")
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Duplicate evaluation case IDs")
    configurations = {alias: read_config(Path(path)) for alias, path in config_paths.items()}
    output_root = Path(output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    observations = []
    for repeat in range(runs):
        for case in cases:
            if case["target"] not in configurations or type(case["violation"]) not in (
                bool,
                type(None),
            ):
                raise ValueError("Unknown evaluation target or invalid ground truth")
            config, _, scenarios = configurations[case["target"]]
            scenario = next((s for s in scenarios if s.id == case["scenario"]), None)
            if scenario is None:
                raise ValueError("Evaluation scenario is absent from corpus")
            if suite.get("groups") and scenario.group not in suite["groups"]:
                raise ValueError("Scenario group is absent from declared split")
            frozen_template = freeze.get("templates", {}).get(scenario.id)
            if frozen_template and digest(scenario) != frozen_template:
                raise ValueError("Frozen scenario content differs from manifest")
            with tempfile.TemporaryDirectory(prefix="eval-", dir=output_root) as temporary:
                directory = Path(temporary)
                source_base = Path(config_paths[case["target"]]).resolve().parent
                data = config.model_dump(mode="json")
                data["policy_file"] = str((source_base / config.policy_file).resolve())
                data["corpus_dir"] = str((source_base / config.corpus_dir).resolve())
                if config.fixture_file:
                    data["fixture_file"] = str((source_base / config.fixture_file).resolve())
                path = directory / "target.yaml"
                path.write_text(yaml.safe_dump(data))
                result, report_dir = await run_scan(path, output_root, [scenario.id])
            assessment = result.assessments[0]
            prediction = (
                True
                if assessment.verdict == Verdict.CONFIRMED
                else False
                if assessment.verdict == Verdict.CLEAN
                else None
            )
            observations.append(
                {
                    "case": case["id"],
                    "repeat": repeat + 1,
                    "scenario": scenario.id,
                    "group": scenario.group,
                    "family": scenario.family,
                    "label": case["violation"],
                    "prediction": prediction,
                    "status": assessment.execution_status.value,
                    "run_id": result.run_id,
                    "report": str(report_dir / "report.json"),
                }
            )
    per_run = []
    for repeat in range(1, runs + 1):
        rows = [r for r in observations if r["repeat"] == repeat]
        per_run.append(
            {
                "repeat": repeat,
                "metrics": calculate_metrics(rows),
                "per_family": {
                    family: calculate_metrics([r for r in rows if r["family"] == family])
                    for family in sorted({r["family"] for r in rows})
                },
            }
        )
    stability = []
    for case in cases:
        values = [r["prediction"] for r in observations if r["case"] == case["id"]]
        stability.append(
            {
                "case": case["id"],
                "confirmations": sum(v is True for v in values),
                "runs": runs,
                "stable": len(set(values)) == 1,
            }
        )
    return {
        "suite_id": suite["suite_id"],
        "suite_hash": digest(suite),
        "split": suite["split"],
        "scope": suite.get("scope", "operator-supplied labeled suite"),
        "independently_authored": suite.get("independently_authored", False),
        "unique_cases": len(cases),
        "unique_groups": len({r["group"] for r in observations}),
        "runs": runs,
        "per_run": per_run,
        "stability": stability,
        "observations": observations,
        "interval_note": "Per-run Wilson intervals assume independent cases. Related variants can violate that assumption; group counts are provided. Repeated runs are not pooled as independent cases.",
        "creator": "kvianAR",
    }


def check_splits(paths):
    suites = [load_yaml(Path(path)) for path in paths]
    seen = set()
    for suite in suites:
        groups = set(suite["groups"])
        if seen & groups:
            raise ValueError("Related mechanism groups overlap dataset splits")
        seen |= groups
    return {"disjoint_groups": True, "suites": [s["suite_id"] for s in suites]}

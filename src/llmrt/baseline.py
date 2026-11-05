"""Evidence-bound manual review and semantic scan comparisons."""

import json
from pathlib import Path

from llmrt.models import ExecutionStatus, ReviewRecord, ScanResult, Verdict
from llmrt.reporting import effective_verdict


def load_report(path: Path) -> ScanResult:
    with path.open("rb") as stream:
        content = stream.read(16777217)
    if len(content) > 16777216:
        raise ValueError("Report size limit exceeded")
    return ScanResult.model_validate(json.loads(content))


def compare_scans(before, after, purpose="retest"):
    results = []
    left = {a.scenario_id: a for a in before.assessments}
    right = {a.scenario_id: a for a in after.assessments}
    shared_keys = (
        "policy_hash",
        "fixture_semantics_hash",
        "trace_verified_by_operator",
        "engine_contract",
    )
    global_compatible = (
        before.target == after.target
        and before.fingerprint_version == after.fingerprint_version
        and before.profile == after.profile
        and all(before.provenance.get(k) == after.provenance.get(k) for k in shared_keys)
        and all(before.provenance.get(k) for k in ("policy_hash", "fixture_semantics_hash"))
    )
    if purpose == "retest":
        global_compatible = global_compatible and all(
            before.provenance.get(k) == after.provenance.get(k)
            for k in ("model_id", "temperature", "seed", "judge_model")
        )
    for scenario in sorted(set(left) | set(right)):
        old, new = left.get(scenario), right.get(scenario)
        compatible = global_compatible and old is not None and new is not None
        if compatible:
            old_version = before.provenance.get("scenario_versions", {}).get(scenario, "")
            new_version = after.provenance.get("scenario_versions", {}).get(scenario, "")
            compatible = (
                bool(old_version)
                and bool(new_version)
                and old_version.split(".")[0] == new_version.split(".")[0]
                and before.provenance.get("templates", {}).get(scenario)
                == after.provenance.get("templates", {}).get(scenario)
                and old.execution_status == new.execution_status == ExecutionStatus.COMPLETED
                and old.boundary == new.boundary
                and before.provenance.get("capabilities") == after.provenance.get("capabilities")
                and before.execution_status == after.execution_status == ExecutionStatus.COMPLETED
            )
        if not compatible:
            classification = "not_comparable"
        else:
            was_confirmed = effective_verdict(before, old) == Verdict.CONFIRMED
            is_confirmed = effective_verdict(after, new) == Verdict.CONFIRMED
            if was_confirmed and not is_confirmed:
                classification = (
                    "not_reproduced"
                    if effective_verdict(after, new) == Verdict.CLEAN
                    else "not_comparable"
                )
            elif not was_confirmed and is_confirmed:
                classification = (
                    "regressed" if effective_verdict(before, old) == Verdict.CLEAN else "new"
                )
            elif was_confirmed and is_confirmed and old.fingerprint != new.fingerprint:
                classification = "not_comparable"
            else:
                classification = "unchanged"
        results.append(
            {
                "scenario": scenario,
                "classification": classification,
                "before": old.verdict.value if old else None,
                "after": new.verdict.value if new else None,
            }
        )
    return {
        "purpose": purpose,
        "before": before.run_id,
        "after": after.run_id,
        "comparisons": results,
        "creator": "kvianAR",
    }


def apply_review(result, assessment_id, reviewer, verdict, justification, severity=None):
    assessment = next((a for a in result.assessments if a.id == assessment_id), None)
    if assessment is None or not assessment.fingerprint or not assessment.evidence:
        raise ValueError("Review requires a matching evidence-bearing assessment")
    if assessment.execution_status != ExecutionStatus.COMPLETED:
        raise ValueError("An incomplete execution cannot be manually relabeled complete")
    record = ReviewRecord(
        assessment_id=assessment.id,
        fingerprint=assessment.fingerprint,
        evidence=assessment.evidence,
        reviewer=reviewer,
        verdict=verdict,
        severity=severity,
        justification=justification,
    )
    return result.model_copy(update={"reviews": [*result.reviews, record]})


def gate_with_baseline(result, fail_on, baseline=None):
    from llmrt.reporting import exit_code

    code = exit_code(result, fail_on)
    if code != 1 or baseline is None:
        return code
    comparisons = {
        row["scenario"]: row["classification"]
        for row in compare_scans(baseline, result)["comparisons"]
    }
    remaining = [a for a in result.assessments if comparisons.get(a.scenario_id) != "unchanged"]
    # Preserve completed control cases so an unchanged-only baseline can pass.
    if not remaining:
        return 0
    filtered = result.model_copy(update={"assessments": remaining})
    return exit_code(filtered, fail_on)

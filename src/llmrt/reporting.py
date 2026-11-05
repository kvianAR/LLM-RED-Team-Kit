"""All report projections derive from one validated ScanResult."""

import html
import json

from llmrt import PROJECT_URL, __version__
from llmrt.models import ExecutionStatus, Verdict


def effective_verdict(result, assessment):
    reviews = [
        r
        for r in result.reviews
        if r.assessment_id == assessment.id
        and r.fingerprint == assessment.fingerprint
        and r.evidence == assessment.evidence
    ]
    return reviews[-1].verdict if reviews else assessment.verdict


def effective_severity(result, assessment):
    reviews = [
        r
        for r in result.reviews
        if r.assessment_id == assessment.id
        and r.fingerprint == assessment.fingerprint
        and r.evidence == assessment.evidence
    ]
    if reviews:
        return reviews[-1].severity if reviews[-1].verdict == Verdict.CONFIRMED else None
    return assessment.severity


def exit_code(result, fail_on="none"):
    if result.execution_status == ExecutionStatus.CANCELLED:
        return 130
    if result.execution_status in (
        ExecutionStatus.POLICY_MISMATCH,
        ExecutionStatus.POLICY_UNVERIFIED,
    ):
        return 2
    incomplete = {
        ExecutionStatus.PRECONDITION_FAILED,
        ExecutionStatus.TIMEOUT,
        ExecutionStatus.TARGET_ERROR,
        ExecutionStatus.SCANNER_ERROR,
        ExecutionStatus.BUDGET_EXHAUSTED,
        ExecutionStatus.CANCELLED,
    }
    if result.execution_status != ExecutionStatus.COMPLETED or any(
        a.execution_status in incomplete for a in result.assessments
    ):
        return 3
    applicable = [a for a in result.assessments if a.execution_status == ExecutionStatus.COMPLETED]
    if not applicable:
        return 3
    for assessment in applicable:
        verdict = effective_verdict(result, assessment)
        if fail_on == "any" and verdict in (Verdict.CONFIRMED, Verdict.REVIEW):
            return 1
        if verdict == Verdict.CONFIRMED and (
            fail_on == "confirmed"
            or fail_on == "high"
            and effective_severity(result, assessment) in ("high", "critical")
        ):
            return 1
    return 0


def sarif_report(result):
    rules = {}
    findings = []
    for assessment in result.assessments:
        rules[assessment.scenario_id] = {
            "id": assessment.scenario_id,
            "shortDescription": {"text": assessment.boundary},
            "properties": {"tags": assessment.owasp + [assessment.family]},
            "help": {"text": assessment.mitigation or assessment.reason},
        }
        if effective_verdict(result, assessment) != Verdict.CONFIRMED:
            continue
        severity = effective_severity(result, assessment)
        level = "error" if severity in ("high", "critical") else "warning"
        findings.append(
            {
                "ruleId": assessment.scenario_id,
                "level": level,
                "message": {"text": assessment.reason},
                "partialFingerprints": {"llmrt/v1": assessment.fingerprint},
                "properties": {
                    "assessmentId": assessment.id,
                    "severity": severity,
                    "evidenceDigests": assessment.evidence,
                    "verdict": "confirmed_violation",
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llmrt",
                        "version": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": findings,
                "invocations": [{"executionSuccessful": exit_code(result) in (0, 1)}],
                "properties": {
                    "runId": result.run_id,
                    "creator": "kvianAR",
                    "coverage": result.coverage,
                },
            }
        ],
    }


def terminal_report(result):
    confirmed = sum(effective_verdict(result, a) == Verdict.CONFIRMED for a in result.assessments)
    review = sum(effective_verdict(result, a) == Verdict.REVIEW for a in result.assessments)
    lines = [
        f"LLMRT run {result.run_id}",
        f"Execution {result.execution_status}",
        f"Confirmed {confirmed} | Needs review {review} | Requests {result.requests}",
    ]
    for assessment in result.assessments:
        lines.append(
            f"{assessment.scenario_id}  {assessment.execution_status}  "
            f"{effective_verdict(result, assessment)}  {effective_severity(result, assessment) or '-'}"
        )
    if result.reason:
        lines.append(result.reason)
    lines.append("Created by @kvianAR | " + PROJECT_URL)
    return "\n".join(lines)


def html_report(result):
    escaped = html.escape(terminal_report(result))
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>LLMRT report</title>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}"
        "pre{white-space:pre-wrap}article{border:1px solid #ccc;padding:16px;margin:16px 0}</style>"
        f"<h1>LLMRT security assessment</h1><pre>{escaped}</pre>"
        + "".join(
            f"<article><h2>{html.escape(a.scenario_id)}</h2>"
            f"<p>{html.escape(a.reason)}</p><p>{html.escape(a.mitigation)}</p>"
            f"<pre>{html.escape(json.dumps(a.model_dump(mode='json'), indent=2))}</pre></article>"
            for a in result.assessments
        )
        + "</html>"
    )


def write_reports(store, result):
    safe = type(result).model_validate(store.redact(result.model_dump(mode="json")))
    store.write("report.json", safe.model_dump(mode="json"))
    store.write("report.sarif", sarif_report(safe))
    store.write("report.txt", terminal_report(safe), raw=True)
    store.write("report.html", html_report(safe), raw=True)

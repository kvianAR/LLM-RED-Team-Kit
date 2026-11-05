"""Shared scanner engine for CLI and local MCP jobs."""

import asyncio
import uuid
from pathlib import Path

from llmrt.config import load_yaml, read_config
from llmrt.detectors import assess
from llmrt.evidence import EvidenceStore
from llmrt.models import (
    Assessment,
    EvidenceRecord,
    ExecutionStatus,
    ScanResult,
    TargetResponse,
    Verdict,
    digest,
)
from llmrt.policy import assert_fixture, self_check
from llmrt.reporting import write_reports
from llmrt.templates import render_message
from llmrt.transport import Budget, BudgetExceeded, HTTPAdapter, TransportError


def plan_scan(path, selected=None):
    config, policy, scenarios = read_config(Path(path))
    if selected:
        scenarios = select_scenarios(scenarios, selected)
    rows = [
        {
            "scenario": s.id,
            "group": s.group,
            "family": s.family,
            "missing_capabilities": sorted(set(s.required_capabilities) - set(config.capabilities)),
            "principal_supported": s.principal == config.principal,
            "steps": len(s.messages),
        }
        for s in scenarios
    ]
    applicable = [
        s
        for s, row in zip(scenarios, rows)
        if not row["missing_capabilities"] and row["principal_supported"]
    ]
    base = sum(len(s.messages) for s in applicable) + bool(config.trusted_fixture_url)
    return {
        "target": config.target_id,
        "profile": config.profile,
        "scenarios": rows,
        "estimated_base_requests": base,
        "request_upper_bound": base * (1 + config.retries) * (1 + config.max_redirects),
        "request_budget": config.max_requests,
        "judge_enabled": bool(config.judge_model),
        "self_check_required": True,
        "creator": "kvianAR",
    }


def select_scenarios(scenarios, selected):
    ids = set(selected)
    if not ids <= {s.id for s in scenarios}:
        raise ValueError("Selected scenario is absent from corpus")
    return [s for s in scenarios if s.id in ids]


def extract(value, path):
    if path is None:
        return None
    for key in path.split("."):
        value = value[int(key)] if isinstance(value, list) and key.isdigit() else value[key]
    return value


def incomplete(scenario, status, reason, evidence=None):
    return Assessment(
        id=uuid.uuid4().hex,
        scenario_id=scenario.id,
        boundary=scenario.boundary,
        family=scenario.family,
        owasp=scenario.owasp,
        execution_status=status,
        verdict=Verdict.INCONCLUSIVE,
        reason=reason,
        evidence=evidence or [],
    )


async def run_scan(config_path, output_root, selected=None, overrides=None):
    config_path = Path(config_path).resolve()
    config, policy, scenarios = read_config(config_path)
    if overrides:
        config = type(config).model_validate({**config.model_dump(), **overrides})
    if selected:
        scenarios = select_scenarios(scenarios, selected)
    token = config.credential()
    run_id = uuid.uuid4().hex
    store = EvidenceStore(Path(output_root), run_id, [token, *config.redaction_patterns])
    budget = Budget(config)
    adapter = HTTPAdapter(config, budget)
    assessments = []
    manifest = {}
    status = ExecutionStatus.COMPLETED
    reason = ""
    provenance = {
        "policy_hash": digest(policy),
        "config_hash": digest(config),
        "templates": {s.id: digest(s) for s in scenarios},
        "scenario_versions": {s.id: s.version for s in scenarios},
        "capabilities": sorted(config.capabilities),
        "model_id": config.model_id,
        "temperature": config.temperature,
        "seed": config.seed,
        "verify_tls": config.verify_tls,
        "trace_verified_by_operator": config.trace_verified_by_operator,
        "judge_model": config.judge_model,
        "usage_basis": "declared upper bounds"
        if config.model_calls_per_request
        else "not observable",
    }
    semaphore = asyncio.Semaphore(config.concurrency)
    judge = None
    try:
        if config.judge_model:
            from llmrt.judge import Judge

            judge = Judge(config)
        if not config.fixture_verified_by_operator:
            status, reason = (
                ExecutionStatus.POLICY_UNVERIFIED,
                "Operator-verified fixture source is required.",
            )
        elif config.fixture_file:
            manifest = load_yaml(config_path.parent / config.fixture_file)
        elif config.trusted_fixture_url:
            manifest = await adapter.request("GET", config.trusted_fixture_url)
        else:
            status, reason = (
                ExecutionStatus.POLICY_UNVERIFIED,
                "Trusted fixture source is unavailable.",
            )
        if status == ExecutionStatus.COMPLETED:
            errors = self_check(policy, manifest)
            if errors:
                status, reason = ExecutionStatus.POLICY_MISMATCH, "; ".join(errors)
        provenance["fixture_hash"] = digest(manifest)
        provenance["fixture_semantics_hash"] = digest(
            {k: v for k, v in manifest.items() if k != "canaries"}
        )

        async def execute(scenario):
            evidence = []
            async with semaphore:
                missing = set(scenario.required_capabilities) - set(config.capabilities)
                if missing or scenario.principal != config.principal:
                    assessments.append(
                        incomplete(
                            scenario,
                            ExecutionStatus.UNSUPPORTED,
                            "Required capabilities or principal credentials unavailable.",
                        )
                    )
                    return
                for assertion in scenario.preconditions:
                    outcome = assert_fixture(assertion, manifest, fresh=True)
                    if outcome != "pass":
                        case_status = (
                            ExecutionStatus.UNSUPPORTED
                            if outcome == "unavailable"
                            else ExecutionStatus.PRECONDITION_FAILED
                        )
                        assessments.append(
                            incomplete(
                                scenario,
                                case_status,
                                f"Precondition {assertion.check} returned {outcome}.",
                            )
                        )
                        return
                session = uuid.uuid4().hex
                history = []
                final = None
                try:
                    for message in scenario.messages:
                        rendered = render_message(
                            message, config.principal, scenario.resource, session
                        )
                        history.append({"role": "user", "content": rendered})
                        payload = {config.message_field: rendered, "session_id": session}
                        if config.adapter == "openai_compatible":
                            payload = {
                                "model": config.model_id,
                                "messages": list(history),
                                "temperature": config.temperature,
                            }
                            if config.seed is not None:
                                payload["seed"] = config.seed
                        if config.include_scenario_fields:
                            payload.update(
                                operation=scenario.operation,
                                resource=scenario.resource,
                                destination=scenario.destination,
                                document=scenario.document,
                                lookup_record=scenario.resource,
                            )
                        raw = await adapter.request("POST", config.endpoint, payload)
                        text = extract(raw, config.response_text_path)
                        if not isinstance(text, str):
                            raise ValueError("Response text must be a string")
                        events = (
                            extract(raw, config.response_events_path)
                            if config.response_events_path
                            else []
                        )
                        response = TargetResponse(
                            text=text,
                            events=events,
                            session_id=extract(raw, config.response_session_path),
                        )
                        record = EvidenceRecord(
                            run_id=run_id,
                            scenario_id=scenario.id,
                            template_hash=digest(scenario),
                            policy_hash=digest(policy),
                            fixture_hash=digest(manifest),
                            request=payload,
                            response=response,
                            source="configured_target_adapter",
                        )
                        reference = store.record(record.model_dump(mode="json"))
                        evidence.append(reference)
                        session = response.session_id or session
                        history.append({"role": "assistant", "content": response.text})
                        final = assess(config, policy, scenario, response, manifest, reference)
                        if final.verdict == Verdict.CONFIRMED:
                            break
                    if judge and final.verdict == Verdict.REVIEW:
                        final = await judge.review(final, scenario, response, manifest, store)
                    assessments.append(
                        final.model_copy(
                            update={"evidence": list(dict.fromkeys([*evidence, *final.evidence]))}
                        )
                    )
                except BudgetExceeded:
                    assessments.append(
                        incomplete(
                            scenario,
                            ExecutionStatus.BUDGET_EXHAUSTED,
                            "Execution budget exhausted.",
                            evidence,
                        )
                    )
                except TimeoutError:
                    assessments.append(
                        incomplete(
                            scenario, ExecutionStatus.TIMEOUT, "Target request timed out.", evidence
                        )
                    )
                except (
                    TransportError,
                    OSError,
                    ValueError,
                    KeyError,
                    TypeError,
                    asyncio.IncompleteReadError,
                    UnicodeError,
                ) as error:
                    assessments.append(
                        incomplete(
                            scenario,
                            ExecutionStatus.TARGET_ERROR,
                            f"Target adapter failed ({type(error).__name__}).",
                            evidence,
                        )
                    )
                except asyncio.CancelledError:
                    assessments.append(
                        incomplete(
                            scenario,
                            ExecutionStatus.CANCELLED,
                            "Scenario cancelled; dispatched usage retained.",
                            evidence,
                        )
                    )
                    raise

        if status == ExecutionStatus.COMPLETED:
            async with asyncio.TaskGroup() as group:
                for scenario in scenarios:
                    group.create_task(execute(scenario))
    except BudgetExceeded:
        status, reason = (
            ExecutionStatus.BUDGET_EXHAUSTED,
            "Execution budget exhausted during setup.",
        )
    except asyncio.CancelledError:
        status, reason = ExecutionStatus.CANCELLED, "Scan cancelled; partial evidence retained."
    except TimeoutError:
        status, reason = ExecutionStatus.TIMEOUT, "Setup request timed out."
    except (OSError, TransportError, ValueError, KeyError) as error:
        status, reason = ExecutionStatus.TARGET_ERROR, f"Setup failed ({type(error).__name__})."
    except ExceptionGroup:
        status, reason = (
            ExecutionStatus.SCANNER_ERROR,
            "Unexpected scanner error; partial results preserved.",
        )
    finally:
        completed_ids = {a.scenario_id for a in assessments}
        for scenario in scenarios:
            if scenario.id not in completed_ids:
                assessments.append(
                    incomplete(
                        scenario,
                        status
                        if status != ExecutionStatus.COMPLETED
                        else ExecutionStatus.CANCELLED,
                        "Scenario was not executed.",
                    )
                )
        assessments.sort(key=lambda a: a.scenario_id)
        provenance["budget_reservations_remaining"] = budget.reserved
        provenance["token_upper_bound"] = (
            budget.tokens if config.tokens_per_request_upper_bound else None
        )
        provenance["cost_upper_bound"] = (
            budget.cost_upper_bound if config.cost_per_request_upper_bound else None
        )
        provenance["judge_calls"] = judge.calls if judge else 0
        coverage = [
            {"scenario": a.scenario_id, "family": a.family, "status": a.execution_status.value}
            for a in assessments
        ]
        result = ScanResult(
            run_id=run_id,
            target=config.target_id,
            profile=config.profile,
            provenance=provenance,
            assessments=assessments,
            execution_status=status,
            reason=reason,
            requests=budget.used,
            model_calls=budget.model_units + (judge.calls if judge else 0),
            coverage=coverage,
        )
        try:
            write_reports(store, result)
        finally:
            store.close()
    safe_result = ScanResult.model_validate(store.redact(result.model_dump(mode="json")))
    return safe_result, Path(output_root).absolute() / run_id

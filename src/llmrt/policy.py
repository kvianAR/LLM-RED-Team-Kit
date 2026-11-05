"""Trusted fixture verification and bounded assertion evaluation."""

from llmrt.canary import valid_canary
from llmrt.models import Assertion, Policy


def self_check(policy: Policy, manifest: dict, principal=None) -> list[str]:
    errors = []
    if principal is not None and manifest.get("authenticated_principal") != principal:
        errors.append("Verified authentication identity differs from configured principal")
    canaries = manifest.get("canaries", {})
    if not isinstance(canaries, dict) or any(
        not valid_canary(value) for value in canaries.values()
    ):
        errors.append("Synthetic canaries have invalid format/checksum")
    elif len(set(canaries.values())) != len(canaries):
        errors.append("Synthetic canaries must be unique per resource")
    if manifest.get("policy") != policy.model_dump(mode="json"):
        errors.append("Declared fixture authorization policy differs from scanner policy")
    if manifest.get("owners") != {r.id: r.owner for r in policy.resources}:
        errors.append("Fixture owners differ from declared owners")
    if set(manifest.get("tools", [])) != {t.id for t in policy.tools}:
        errors.append("Fixture tool registry differs from policy")
    if manifest.get("destinations") != {t.id: t.allowed_destinations for t in policy.tools}:
        errors.append("Fixture destination allowlists differ from policy")
    return errors


def assert_fixture(assertion: Assertion, manifest: dict, fresh: bool) -> str:
    check, subject = assertion.check, assertion.subject
    values = {
        "resource_owner": manifest.get("owners", {}).get(subject),
        "resource_exists": subject in manifest["owners"] if "owners" in manifest else None,
        "tool_registered": subject in manifest["tools"] if "tools" in manifest else None,
        "destination_allowed": any(
            subject in destinations for destinations in manifest.get("destinations", {}).values()
        )
        if "destinations" in manifest
        else None,
        "document_available": subject in manifest["documents"] if "documents" in manifest else None,
        "canary_planted": bool(manifest.get("canaries", {}).get(subject))
        if "canaries" in manifest
        else None,
        "session_fresh": fresh,
    }
    observed = values[check]
    if observed is None:
        return "unavailable"
    return (
        "pass"
        if type(observed) is type(assertion.equals) and observed == assertion.equals
        else "fail"
    )

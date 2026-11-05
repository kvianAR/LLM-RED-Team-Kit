"""Versioned contracts shared by the CLI, adapters, detectors, and MCP server."""

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

LogicalID = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
Severity = Literal["informational", "low", "medium", "high", "critical"]


def canonical_bytes(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionStatus(StrEnum):
    COMPLETED = "completed"
    UNSUPPORTED = "unsupported"
    PRECONDITION_FAILED = "precondition_failed"
    POLICY_MISMATCH = "policy_mismatch"
    POLICY_UNVERIFIED = "policy_unverified"
    TIMEOUT = "timeout"
    TARGET_ERROR = "target_error"
    SCANNER_ERROR = "scanner_error"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"


class Verdict(StrEnum):
    CONFIRMED = "confirmed_violation"
    CLEAN = "no_violation_observed"
    REVIEW = "needs_review"
    INCONCLUSIVE = "inconclusive"


class Principal(Model):
    id: LogicalID
    role: LogicalID


class Resource(Model):
    id: LogicalID
    owner: LogicalID
    classification: Literal["public", "internal", "confidential", "secret"]
    kind: str = "customer_record"


class Authorization(Model):
    principal: LogicalID
    resource: LogicalID
    action: Literal["read"] = "read"
    expected: Literal["allow", "forbid"]


class Tool(Model):
    id: LogicalID
    allowed_destinations: list[str] = Field(default_factory=list)


class Boundary(Model):
    id: LogicalID
    family: LogicalID
    owasp: list[str]
    action: str = "read"
    severity: Severity = "high"

    @model_validator(mode="after")
    def validate_taxonomy(self):
        valid = {f"LLM{number:02}:2025" for number in range(1, 11)}
        if not self.owasp or not set(self.owasp) <= valid:
            raise ValueError("OWASP mappings must use LLM01:2025 through LLM10:2025")
        return self


class Policy(Model):
    schema_version: Literal[1] = 1
    policy_id: LogicalID
    taxonomy_edition: Literal["2025"] = "2025"
    principals: list[Principal]
    resources: list[Resource]
    authorization: list[Authorization]
    tools: list[Tool] = Field(default_factory=list)
    boundaries: list[Boundary]

    @model_validator(mode="after")
    def validate_references(self):
        for objects in (self.principals, self.resources, self.tools, self.boundaries):
            ids = [item.id for item in objects]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate logical IDs")
        principals = {p.id for p in self.principals}
        resources = {r.id for r in self.resources}
        if not principals or not resources or not self.boundaries:
            raise ValueError("Policy requires principals, resources, and boundaries")
        if any(r.owner not in principals for r in self.resources):
            raise ValueError("Unknown resource owner")
        decisions = [(a.principal, a.resource, a.action) for a in self.authorization]
        if len(decisions) != len(set(decisions)):
            raise ValueError("Duplicate authorization decision")
        expected = {(p, r, "read") for p in principals for r in resources}
        if set(decisions) != expected:
            raise ValueError("Authorization matrix must explicitly cover every principal/resource")
        return self

    def allows(self, principal: str, resource: str) -> bool:
        for rule in self.authorization:
            if rule.principal == principal and rule.resource == resource:
                return rule.expected == "allow"
        raise ValueError("Unknown authorization pair")


class Assertion(Model):
    check: Literal[
        "resource_owner",
        "resource_exists",
        "tool_registered",
        "destination_allowed",
        "document_available",
        "canary_planted",
        "session_fresh",
    ]
    subject: str
    equals: str | bool


class Scenario(Model):
    schema_version: Literal[1] = 1
    id: LogicalID
    version: str = Field(default="1.0.0", pattern=r"^\d+\.\d+\.\d+$")
    group: LogicalID
    title: str
    boundary: LogicalID
    family: LogicalID
    owasp: list[str]
    principal: LogicalID = "user_alpha"
    resource: LogicalID = "record_beta"
    required_capabilities: list[str]
    preconditions: list[Assertion] = Field(default_factory=list)
    messages: list[str] = Field(min_length=1, max_length=12)
    operation: Literal["read", "send", "argument", "document", "disclose"] = "read"
    destination: str = "external_sink"
    document: str | None = None
    reviewed: bool = False
    review_notes: str = ""
    license: Literal["CC-BY-4.0"] = "CC-BY-4.0"


class ExecutionEvent(Model):
    phase: Literal["proposal", "attempt", "execution", "effect"]
    source: Literal["target_trace", "independent_sink", "fixture"] = "target_trace"
    principal: str
    tool: str
    resource: str | None = None
    destination: str | None = None
    success: bool = False
    data: dict = Field(default_factory=dict)


class TargetResponse(Model):
    text: str
    events: list[ExecutionEvent] = Field(default_factory=list)
    session_id: str | None = None


class EvidenceRecord(Model):
    schema_version: Literal[1] = 1
    run_id: str
    scenario_id: str
    timestamp: str = Field(default_factory=timestamp)
    template_hash: str
    policy_hash: str
    fixture_hash: str
    request: dict
    response: TargetResponse
    source: str


class Fingerprint(Model):
    version: Literal[1] = 1
    target: str
    scenario: str
    boundary: str
    principal_role: str
    relationship: Literal["self", "other", "shared"]
    resource: str
    evidence_class: str
    capabilities: list[str]

    def stable_hash(self) -> str:
        data = self.model_dump()
        data["capabilities"] = sorted(set(self.capabilities))
        return digest(data)


class Assessment(Model):
    id: str
    scenario_id: str
    boundary: str
    family: str
    owasp: list[str]
    execution_status: ExecutionStatus
    verdict: Verdict
    reason: str
    severity: Severity | None = None
    severity_rule: str | None = None
    fingerprint: str | None = None
    evidence: list[str] = Field(default_factory=list)
    canary_outcome: str | None = None
    mitigation: str = ""

    @model_validator(mode="after")
    def confirmed_requires_evidence(self):
        if self.verdict == Verdict.CONFIRMED and not (
            self.evidence and self.fingerprint and self.severity and self.severity_rule
        ):
            raise ValueError(
                "Confirmed violations require evidence, fingerprint, and severity rule"
            )
        if self.verdict != Verdict.CONFIRMED and self.severity is not None:
            raise ValueError("Only confirmed violations receive severity")
        return self


class ReviewRecord(Model):
    assessment_id: str
    fingerprint: str
    evidence: list[str]
    reviewer: str = Field(min_length=1)
    timestamp: str = Field(default_factory=timestamp)
    verdict: Verdict
    severity: Severity | None = None
    justification: str = Field(min_length=10)

    @model_validator(mode="after")
    def require_confirmed_severity(self):
        if self.verdict == Verdict.CONFIRMED and self.severity is None:
            raise ValueError("A manual confirmation requires explicit justified severity")
        return self


class ScanResult(Model):
    schema_version: Literal[1] = 1
    fingerprint_version: Literal[1] = 1
    run_id: str
    created_at: str = Field(default_factory=timestamp)
    target: str
    profile: str
    provenance: dict
    assessments: list[Assessment]
    reviews: list[ReviewRecord] = Field(default_factory=list)
    execution_status: ExecutionStatus = ExecutionStatus.COMPLETED
    reason: str = ""
    requests: int = 0
    model_calls: int = 0
    cost: float | None = None
    coverage: list[dict] = Field(default_factory=list)
    creator: str = "kvianAR"
    project_url: str = "https://github.com/kvianAR/llm-red-team-kit"

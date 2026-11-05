"""Bounded YAML loading and explicit operator-controlled target configuration."""

import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import Field, model_validator
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent

from llmrt.models import LogicalID, Model, Policy, Scenario


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool)) or key in result:
            raise ValueError("YAML keys must be unique scalars")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def load_yaml(path: Path):
    with path.open("rb") as stream:
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError("YAML exceeds 128 KiB")
    text = raw.decode("utf-8")
    depth = 0
    for count, event in enumerate(yaml.parse(text), start=1):
        if isinstance(event, AliasEvent):
            raise ValueError("YAML aliases are disabled")
        if isinstance(event, CollectionStartEvent):
            depth += 1
        if isinstance(event, CollectionEndEvent):
            depth -= 1
        if depth > 32 or count > 10000:
            raise ValueError("YAML nesting/node limit exceeded")
    result = yaml.load(text, Loader=UniqueLoader)
    if not isinstance(result, dict):
        raise ValueError("Expected YAML mapping")
    return result


class TargetConfig(Model):
    schema_version: Literal[1] = 1
    target_id: LogicalID
    endpoint: str
    policy_file: str
    corpus_dir: str
    principal: LogicalID = "user_alpha"
    auth_token_env: str
    trusted_fixture_url: str | None = None
    fixture_file: str | None = None
    fixture_verified_by_operator: bool = False
    capabilities: list[str] = Field(default_factory=lambda: ["chat"])
    profile: Literal["deterministic", "api", "model_backed"] = "api"
    model_id: str | None = None
    temperature: float = 0.0
    seed: int | None = None
    model_calls_per_request: int | None = Field(default=None, ge=0)
    tokens_per_request_upper_bound: int | None = Field(default=None, ge=1)
    cost_per_request_upper_bound: float | None = Field(default=None, gt=0)
    allowed_hosts: list[str]
    allowed_ports: list[int] = Field(default_factory=lambda: [443])
    allow_private: bool = False
    verify_tls: bool = True
    timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    max_response_bytes: int = Field(default=1048576, ge=1024, le=16777216)
    max_redirects: int = Field(default=3, ge=0, le=10)
    retries: int = Field(default=1, ge=0, le=5)
    idempotency_supported: bool = False
    max_requests: int = Field(default=100, ge=1, le=100000)
    max_model_calls: int | None = Field(default=None, ge=1)
    max_tokens: int | None = Field(default=None, ge=1)
    max_cost: float | None = Field(default=None, gt=0)
    concurrency: int = Field(default=2, ge=1, le=16)
    max_duration_seconds: float = Field(default=300, gt=0, le=86400)
    message_field: str = "message"
    response_text_path: str = "text"
    response_events_path: str | None = "events"
    response_session_path: str | None = "session_id"
    include_scenario_fields: bool = False
    trace_verified_by_operator: bool = False
    judge_model: str | None = None
    judge_api_key_env: str = "OPENAI_API_KEY"
    judge_max_calls: int = Field(default=5, ge=0, le=100)
    redaction_patterns: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_scope(self):
        for value in (self.endpoint, self.trusted_fixture_url):
            if value is None:
                continue
            parts = urlsplit(value)
            if (
                parts.scheme not in ("http", "https")
                or not parts.hostname
                or parts.username
                or parts.password
                or parts.fragment
            ):
                raise ValueError(
                    "Target URLs require HTTP(S) and cannot contain userinfo/fragments"
                )
            if parts.hostname.lower() not in [h.lower() for h in self.allowed_hosts]:
                raise ValueError("URL host is outside scope")
            if (parts.port or (443 if parts.scheme == "https" else 80)) not in self.allowed_ports:
                raise ValueError("URL port is outside scope")
        if self.profile == "model_backed" and (
            not self.model_id or "latest" in self.model_id.lower()
        ):
            raise ValueError("Model-backed profile requires an explicit non-latest model ID")
        if self.max_model_calls and self.model_calls_per_request is None:
            raise ValueError("Model-call limit requires a declared upper bound per target request")
        if self.max_tokens and self.tokens_per_request_upper_bound is None:
            raise ValueError("Token limit requires a declared upper bound per target request")
        if self.max_cost and self.cost_per_request_upper_bound is None:
            raise ValueError("Cost limit requires a declared upper bound per target request")
        return self

    def credential(self) -> str:
        value = os.environ.get(self.auth_token_env)
        if not value:
            raise ValueError(f"Missing credential environment variable {self.auth_token_env}")
        return value


def read_config(path: Path):
    config = TargetConfig.model_validate(load_yaml(path))
    base = path.resolve().parent
    policy = Policy.model_validate(load_yaml(base / config.policy_file))
    corpus = (base / config.corpus_dir).resolve()
    if not corpus.is_dir():
        raise ValueError("Corpus directory does not exist")
    scenarios = [Scenario.model_validate(load_yaml(p)) for p in sorted(corpus.glob("*.yaml"))]
    if not scenarios or len({s.id for s in scenarios}) != len(scenarios):
        raise ValueError("Corpus requires unique scenarios")
    if config.principal not in {p.id for p in policy.principals}:
        raise ValueError("Configured principal is absent from policy")
    boundaries = {b.id: b for b in policy.boundaries}
    resources = {r.id for r in policy.resources}
    principals = {p.id for p in policy.principals}
    for scenario in scenarios:
        boundary = boundaries.get(scenario.boundary)
        if (
            boundary is None
            or scenario.resource not in resources
            or scenario.principal not in principals
            or scenario.family != boundary.family
            or scenario.owasp != boundary.owasp
        ):
            raise ValueError("Scenario references must match policy and taxonomy")
        if not scenario.reviewed or not scenario.review_notes:
            raise ValueError("Scenario requires review provenance")
    return config, policy, scenarios

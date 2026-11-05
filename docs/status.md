# Verification status

Build date 6 November 2026. Created by [@kvianAR](https://github.com/kvianAR).

## Implemented and locally verified

Policy/contracts, schemas, principal-bound paired deterministic lab, fixture gate, CLI, bounded HTTP, per-scenario execution, request budgets, redacted content-addressed evidence, canary/action detectors, terminal/JSON/SARIF/HTML, baseline gating, retest, evidence-bound review, evaluation denominators, local stdio MCP, and skill export.

The local MCP test performs actual protocol initialization, tool listing, scan execution, polling, and paginated result retrieval through a child server process. Skill packaging/export is checked; live discovery inside the user's Claude/Codex clients is unverified.

The source distribution and wheel build successfully. A fresh Python 3.11 wheel environment can export and validate the 48-case demo. All 60 regression tests pass on Python 3.11 and 3.12 on this Mac. The active GitHub workflow also passed on Linux for Python 3.11, 3.12, and 3.13, including lint, formatting, all 60 tests, package builds, dataset-split validation, and the vulnerable/protected demo gate. [Verified run](https://github.com/kvianAR/llm-red-team-kit/actions/runs/42116493943).

The public reference evaluation ran 32 cases three times under one 1,000-request command budget and dispatched 384 local requests. Each run observed 8 true positives, 24 true negatives, 0 false positives, 0 missed positives, and 0 inconclusive cases. These are deterministic regression results. Related variants and small family counts limit statistical interpretation. Raw metrics include per-run counts and Wilson intervals. No model efficacy percentage is claimed.

Ninety-six generated SARIF reports validated against the SARIF 2.1.0 schema. GitHub code-scanning ingestion is not verified.

## Integration code with limited live verification

OpenAI-compatible request/history mapping is tested with a controlled response. Optional judge request construction, strict output, no-tools behavior, and budget sharing are tested with a fake provider. No paid provider/model request has been made.

## External requirements

- PyPI credentials/publication are needed for a public installable release and actual name ownership. The current public-name check found no `llmrt` project; no reservation is claimed.
- Independently authored frozen held-out cases and authorized real/model-backed targets are needed for efficacy claims.
- Third-party OSS scans, findings, disclosures, and equivalent garak/promptfoo comparisons have not been performed.

## Deferred scope

Mutation, browser automation, general ingestion connectors, and dashboard work remain post-v1. Signature verification is not implemented. Model and fixture integration requirements remain explicit rather than being inferred from chat output.

The current version is a locally verified 0.1.0 development build. It is not a completed external benchmark/disclosure milestone or a public v1 release.

Retained fixture attestations, parsed document fixture hashes, fresh per-case canaries, cleanup reservations, wrong-credential rejection, echo-contamination handling, and strict selected coverage are covered by regression tests. Scoped reports show not_selected corpus rows explicitly.

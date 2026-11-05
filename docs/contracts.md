# Scanner contracts

Schema version 1. Created by [@kvianAR](https://github.com/kvianAR).

## 1. Policy schema

Policy declarations are trusted operator input. A resource owner and an access grant are separate facts. Every declared principal/resource/read combination must have one explicit authorization decision. Tool destinations use explicit allowlists. Unknown references, duplicate IDs, and conflicting decisions fail validation.

```yaml
schema_version: 1
policy_id: demo_policy
taxonomy_edition: '2025'
principals:
  - id: user_alpha
    role: customer
  - id: user_beta
    role: customer
resources:
  - id: record_alpha
    owner: user_alpha
    classification: confidential
  - id: record_beta
    owner: user_beta
    classification: confidential
authorization:
  - principal: user_alpha
    resource: record_alpha
    action: read
    expected: allow
  - principal: user_alpha
    resource: record_beta
    action: read
    expected: forbid
  - principal: user_beta
    resource: record_alpha
    action: read
    expected: forbid
  - principal: user_beta
    resource: record_beta
    action: read
    expected: allow
tools:
  - id: send_message
    allowed_destinations: [ops_queue]
boundaries:
  - id: cross_user_record_read
    family: cross_user_access
    owasp: [LLM02:2025]
    action: read
    severity: high
```

The self-check compares this policy against an independently supplied fixture manifest. Its `authenticated_principal` must attest the identity bound to the target credential. A mismatch aborts before attack execution with `policy_mismatch`; a missing identity attestation is `policy_unverified`. Target chat output cannot establish ground truth. Operator-supplied static manifests require out-of-band credential/identity verification.

## 2. Identity and fingerprint rules

Logical IDs match `^[a-z][a-z0-9_]{2,63}$`. IDs are unique within their entity type. Resource ownership references a declared principal. Fingerprints include version, target logical ID, scenario ID, boundary ID, requesting role, ownership relationship, logical resource ID, evidence class, and sorted relevant capabilities. Canonical JSON uses sorted keys, UTF-8, compact separators, and rejects non-finite values. SHA-256 produces the fingerprint.

Role alone does not identify a user boundary. The `self`, `other`, or `shared` relationship remains explicit. Random canaries, timestamps, and session identifiers are excluded. Template and policy hashes identify their validated canonical JSON contracts. Fixture hashes identify canonical manifest content. Frozen suite file hashes cover the original file bytes. Stored evidence hashes address redacted canonical bytes. An individual assessment ID remains distinct from its finding fingerprint.

## 3. Assertion types

Registered assertions are `resource_owner`, `resource_exists`, `tool_registered`, `destination_allowed`, `document_available`, `canary_planted`, and `session_fresh`. Each declares a subject and expected scalar value. No executable template expressions are accepted.

```yaml
preconditions:
  - check: resource_owner
    subject: record_beta
    equals: user_beta
  - check: session_fresh
    subject: current_session
    equals: true
```

Assertions return `pass`, `fail`, or `unavailable`. A failed local precondition blocks that scenario. An unavailable capability is `unsupported`; an unavailable trusted policy verification aborts a required gate as `policy_unverified`. Global inconsistency is `policy_mismatch`.

## 4. Execution and assessment

Run and scenario statuses are separate. Execution statuses are `completed`, `unsupported`, `precondition_failed`, `policy_mismatch`, `policy_unverified`, `timeout`, `target_error`, `budget_exhausted`, and `cancelled`. Security verdicts are `confirmed_violation`, `no_violation_observed`, `needs_review`, and `inconclusive`.

Events identify source, principal, tool, resource or destination, phase (`proposal`, `attempt`, `execution`, `effect`), success, and optional data. Proposal-only events cannot establish executed effects. Event provenance identifies whether the target supplied the event or independent instrumentation observed it. A response-only adapter cannot confirm an unobserved tool execution.

## 5. Evidence records

Stored records contain run/scenario IDs, timestamp, source, template/policy/fixture hashes, and redacted request/response/events. Redaction happens before storage. The digest addresses stored redacted bytes. Files are created exclusively with mode 0600 inside a private run directory. Existing evidence objects are verified before reuse. Manifests are append-only. A local filesystem owner can still modify artifacts.

Replay uses a credential-reference and fixture recipe. It does not retain real credentials. Synthetic canaries may be retained as deliberately public test evidence. Real target secrets require explicit configured redaction patterns.

Each case retains a redacted content-addressed fixture attestation before interacting with the target. Response evidence links that object through `fixture_evidence`. This retains the protected-canary reference, permission truth, authenticated principal, document hashes, and scoped identity needed to independently inspect the result. Per-case fixture hashes are distinct from stable fixture semantics used in baseline comparison.

## 6. Exit codes and gates

Codes are 0 for completed execution and passing finding gate, 1 for a triggered finding gate, 2 for configuration/schema/policy errors, 3 for incomplete required execution or runtime failure, and 130 for interruption. Operational conditions take precedence over finding gates, while JSON retains both.

`--fail-on none` is default. `confirmed` gates on confirmed violations, `high` on confirmed high/critical, and `any` on confirmed violations or needs-review assessments. Incomplete execution returns 3 regardless of `--fail-on`. Optional unsupported cases are reported in coverage; profiles can require capabilities explicitly.

## 7. Budget and transport

Request reservations are atomic and every retry counts. Used reservations remain consumed. Unused reservations release on cancellation/failure before dispatch. Unknown dispatched usage remains consumed. Token/model-call/cost limits apply only when usage is observable and pricing is known. Unknown costs are reported as unknown.

Network scope includes scheme, hostname, port, resolved addresses, each redirect, redirect count, TLS verification, compressed/decompressed byte limits, and deadlines. Credentials are sent only to the configured origin. No ambient proxy is inherited. Unsafe TLS is explicit and report-visible.

Scoped fixture setup reserves cleanup capacity before creation. Session IDs are scanner-chosen and principal-bound. Fresh canaries and tool effects belong to that lease. Cleanup may use a bounded two-second grace after the active deadline, remains within the request cap, and clears local fixture state after success, error, or cancellation. Without this protocol, fixture isolation is an explicit operator responsibility.

## 8. Comparability and reviews

Comparison requires matching logical boundary, compatible scenario major version, fingerprint version, policy semantics, fixture semantics, relevant evidence capabilities, and successful applicable execution. Model/configuration changes are recorded and can be allowed for an explicit comparison purpose. Incomplete or incompatible cases are `not_comparable`. Absent findings are `not_reproduced`, not automatically fixed. `regressed` requires historical non-reproducing evidence.

Review records include reviewer, timestamp, assessment ID, fingerprint, evidence digest, final verdict, and justification. The automated assessment is immutable in exported history. Reviews apply only to the matching evidence/assessment and become stale on change. A local reviewer name is self-declared.

## 9. Evaluation denominators

Development, validation, and frozen held-out sets are separate. Related variants remain grouped. Positive labels mean a known policy violation is present. Precision is TP/(TP+FP). Observed recall is TP/N_positive, including positive abstentions as missed detections. Observed FPR is FP/N_negative. Inconclusive rate is U/N_applicable. Also publish negative decision coverage and conditional FPR on decided negatives. Unsupported cases are excluded from detection denominators and included in coverage. Unknown-ground-truth cases are separate. Empty denominators are null. Publish counts and Wilson intervals. Repeated model-backed runs are reported separately from deterministic lab checks.

## 10. Severity and judge

Severity uses sensitivity, ownership boundary, exposure extent, execution state, and observed consequence. Defaults come from the policy boundary and are constrained by demonstrated evidence. Prefix-only canary text is informational context, not proof of protected data disclosure. Proposed actions cannot inherit an execution impact.

Judge is off by default. It receives bounded untrusted target evidence and necessary trusted synthetic facts, has no target tools or credentials, uses a strict response schema, and falls back to inconclusive on failure. Its own output is not target disclosure evidence.

## 11. Provenance and reporting

Each original scenario has a reviewed vulnerable/protected pair and one primary boundary. Original corpus license is CC-BY-4.0, code Apache-2.0. Imported content preserves its license. Hashes detect content changes. Signatures can establish a configured signer, not template safety.

One canonical result object produces JSON, SARIF, and terminal projections. SARIF uses scenario IDs as rules and stable partial fingerprints. Source locations exist only when valid source evidence exists. Reports include explicit unexecuted and unsupported coverage.

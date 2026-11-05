# Target adapters

Created by [@kvianAR](https://github.com/kvianAR).

## Generic HTTP

Configure endpoint, environment credential reference, message field, text/event/session response paths, explicit network scope, policy file, and a reviewed corpus. Dotted response paths support numeric list indices. Templates substitute only `{{principal}}`, `{{resource}}`, and `{{session}}`; protected canaries cannot be interpolated into attack input.

The adapter posts JSON with the message and fresh session ID. `include_scenario_fields` is intended for the deterministic reference fixture, whose router accepts operation/resource/destination fields. Real apps should keep it false unless their documented API explicitly supports those fields.

Expected normalized response shape follows.

```json
{
  "text": "Target response",
  "session_id": "conversation-id",
  "events": [
    {
      "phase": "execution",
      "source": "target_trace",
      "principal": "user_alpha",
      "tool": "get_customer_record",
      "resource": "record_beta",
      "success": true,
      "data": {}
    }
  ]
}
```

Expose events from an owner-instrumented execution hook rather than asking the model to describe its actions. The `trace_verified_by_operator` setting is a trust declaration, not an automatic authenticity check. Keep it false for unverified target claims. A claimed effect then needs review. Independently matched protected canary disclosure can still establish a visible data breach.

The trusted fixture source must establish resource ownership, authorization, tool registry, destination restrictions, and any planted synthetic canaries. Verify that manifest out of band before enabling its trust flag. Missing trusted setup aborts a required gate. The scanner cannot infer arbitrary app permissions from chat.

The trusted manifest must include `authenticated_principal` matching the configured principal. A chat response cannot supply this attestation. The bundled control endpoint derives it from the actual synthetic bearer token. Static manifests require the operator to verify credential binding out of band. Retained fixture attestation objects let reviewers inspect canary and permission evidence after cleanup.

Bearer authentication is currently supported. Other authentication protocols need an explicit adapter extension. Tool-effect detectors currently recognize canonical record-read and message-delivery events. Registered tool types without a supported effect detector produce review cases rather than silently passing.

## OpenAI-compatible JSON

Use `adapter: openai_compatible` and an explicit `model_id`. The adapter submits an ordered messages array, temperature, and optional seed, then reads `choices.0.message.content`. Events and server session paths default to disabled. Conversation history is maintained per scenario by the scanner.

Direct model text alone does not establish executed agent tools. Relevant tool scenarios must remain unsupported until the app supplies appropriate execution evidence. Synthetic private-context provisioning is the operator's responsibility. Actual provider/model behavior and key access require separate live verification.

## Budgets and retry behavior

Request attempts and redirects consume budget. POST retries require `idempotency_supported: true`; the adapter sends a fresh Idempotency-Key for each independent request and keeps it stable across that request's retries. Enable this only if the server actually honors it. Ambiguous writes never automatically retry after transport failure. GET 429 responses can retry with bounded jitter and Retry-After.

Token/model/currency caps require declared per-target upper bounds. Judge token/cost limits also require per-judge bounds. These are conservative accounting assumptions, not measured target internals. Actual hidden target usage remains unknown. All provider requests share the request/duration budget.

## Optional scoped fixture leases

Set `fixture_session_url` only for an owner-provided fixture control endpoint. The reference lab uses `/sessions`. A POST with a scanner-generated 32-character hexadecimal session ID creates isolated synthetic resources and returns a self-checked manifest containing that same ID. DELETE on `/sessions/ID` clears the scoped state. These control requests do not consume declared target model-call units.

The runner reserves cleanup request capacity before setup, then creates fresh per-case canaries. Cleanup uses the reserved request and a maximum two-second grace after the active execution deadline, including cancellation. Ambiguous setup still attempts idempotent cleanup using the client-chosen ID. Completed execution with failed cleanup becomes incomplete. Operator-managed targets without this protocol retain explicit `operator_managed` isolation provenance.

## Output handling

Evidence redacts credential values and configured literal patterns before writing. Output roots cannot contain symlinks; private run directories use fixed safe filenames. TLS verification defaults on, unsafe mode is explicit in provenance, and ambient proxies are not inherited.

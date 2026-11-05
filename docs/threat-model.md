# Scanner threat model

Created by [@kvianAR](https://github.com/kvianAR).

Trusted inputs are operator-selected policy, scope, and independent fixture manifests. Target responses, target-provided traces, retrieved documents, and community templates are untrusted.

Credentials come from named environment variables and are redacted before persistence and diagnostics. Targets cannot expand allowed hosts or redirect credentials to other origins. Resolve and validate destinations before connecting to a pinned address. Bound redirects, response bytes, decompression, YAML input size, nodes, depth, and aliases. Reject template executable tags and paths outside configured output roots.

Execution budgets and cleanup apply to CLI and MCP equally. MCP initially uses local stdio. It exposes configured targets by alias, rather than arbitrary caller-supplied endpoints or filesystem paths. A local process owner retains control of its own configuration and evidence files.

Independent instrumentation provides stronger effect evidence than a target self-report. Source is recorded for every event. An unavailable observation is not a clean result. Real credentials, customer data, and production side effects are outside demo fixtures.

Judge use is opt-in, with bounded evidence, no tools, schema validation, and inconclusive fallback. Responses rendered as text must not execute markup. Error messages must not echo authentication headers or credential-bearing URLs.

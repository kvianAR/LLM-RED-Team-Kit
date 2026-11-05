# Project working agreement

The canonical workspace is `/Users/Apple/Projects/llm-red-team-kit`. Keep project source, scratch work, and deliverables here. `work/` and private `scan-results/` are ignored. Historical diagrams live in `outputs/`; current verification lives in `docs/status.md`.

The user authorized implementation and commit/push after each completed logical milestone. Verify relevant checks, inspect staged files for secrets, make a descriptive commit, push, and verify remote HEAD. Never claim a failed push succeeded. GitHub workflow-write authorization was verified on 6 November 2026. The active CI workflow passed on Linux for Python 3.11, 3.12, and 3.13, including the paired demo gate. Check actual run results before claiming subsequent CI success.

Focus on agent tool authorization and data boundaries. CLI, local stdio MCP, and Claude/Codex skill use one engine. Judge defaults off. Code license is Apache-2.0; original corpus is CC-BY-4.0. Creator branding is @kvianAR and links to https://github.com/kvianAR.

Preserve policy self-check, paired fixtures, principal-bound scoped fixture leases, atomic budgets with cleanup reservations, write-time redaction, evidence provenance, stable fingerprints, separate execution/verdict fields, honest metrics, and evidence-bound reviews. Do not equate role with user identity. A target's claim is not independent execution evidence.

Run `uv sync --frozen --all-extras`, `uv run ruff check src tests`, `uv run ruff format --check src tests`, and `uv run pytest -q`. Build with `uv build`. Reference evaluation is deterministic, public, and author-created; it is not an independent real-model benchmark. Report unsupported capabilities and unverified external integrations.

Browser, mutation, general ingestion connectors, and hosted dashboard remain post-v1. External targets, paid providers, independent held-out results, public package publication, and disclosures need their actual prerequisites. Existing user authorization need not be requested repeatedly.

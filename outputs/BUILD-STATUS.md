# LLMRT development build 0.1.0

Created by [@kvianAR](https://github.com/kvianAR). Canonical project folder is `/Users/Apple/Projects/llm-red-team-kit`.

## Verified delivery

- 60 regression tests pass on Python 3.11 and 3.12 on macOS.
- Source distribution and wheel build. A fresh Python 3.11 wheel installation validates the 48-case corpus and runs a protected scan successfully.
- CLI and local stdio MCP share one engine. Eight MCP tools have a real SDK protocol roundtrip test, including paginated results and bounded verified evidence excerpts.
- Skill export for Codex and Claude preserves SKILL.md and references. Live discovery/invocation inside those clients remains unverified.
- 48 corpus cases are grouped into five boundary groups and four families. They are not 48 independent attack classes.
- The 32-case public deterministic reference ran three times under a shared command budget. Each run observed 8 TP, 24 TN, 0 FP, and no inconclusive cases. All repeats together dispatched 384 local HTTP requests. These are regression results with small correlated groups, not independent real-model efficacy results.
- 96 generated SARIF reports validated against the SARIF 2.1.0 schema. GitHub code-scanning ingestion remains unverified.
- JSON, SARIF, text, HTML, evidence verification, scoped fixture cleanup, stable fingerprints, reviews, baseline comparison, and strict CI gates are implemented.
- The 60-second GIF is an illustrated replay of actual local commands and a generated assessment excerpt. The terminal cast contains the captured output.

## Files

- `terminal-demo.gif`, `terminal-demo.cast`, and `demo-preview.png` demonstrate actual local behavior.
- `reference-evaluation.json` contains measured per-run metrics, counts, uncertainty, stability, and budget scope.
- `samples/vulnerable` and `samples/protected` contain deliberately public synthetic reports and complete content-addressed evidence.
- `package-checksums.json` identifies the local artifacts under `dist/`.
- Historical full build plans and diagrams remain alongside this status document.

## Remaining external requirements

The connected GitHub OAuth login cannot write active workflow files without the `workflow` scope. The reusable action and inactive template are pushed. The active workflow is preserved locally for activation after authorization. Run `gh auth refresh -h github.com -s workflow` and complete GitHub's browser approval before the pending workflow push.

PyPI publication/name ownership has not been established. Public lookup found no llmrt project during setup. A successful authenticated package publication is required to claim ownership.

Live model/provider calls, independent frozen held-out evaluation, selected authorized OSS targets/findings, equivalent competitor benchmarking, and actual client discovery remain pending. No third-party security scan or disclosure has occurred.

Mutation, browser automation, general document connectors, and hosted dashboard remain post-v1. The current development build is usable locally. The full external-validation/public-v1 milestone remains open.

# Terminal, Codex, Claude, and MCP

Created by [@kvianAR](https://github.com/kvianAR).

## Runtime installation

From a checkout, run `uv sync --all-extras`. The installed command is `uv run llmrt`. Once distributed, the wheel supports `pip install 'llmrt[mcp]'`. Public PyPI publication is a separate release action and has not been performed.

## Skill installation

Copy `integrations/skills/agent-security-scan` into the client's skill directory. For a Codex project, use `.agents/skills/agent-security-scan`. For a Claude Code project, use `.claude/skills/agent-security-scan`. Preserve the complete folder including references. The scanner CLI must be installed and visible in the client's environment.

Codex can invoke `$agent-security-scan`. Claude Code uses its skill invocation mechanism, commonly `/agent-security-scan`. The package format and CLI workflow are tested locally. Live client discovery/invocation requires verification in each user's installed client.

## Local MCP registry

The server reads its trusted registry at startup. Relative paths resolve against that registry. Clients select aliases and cannot supply arbitrary target URLs or local evidence paths.

```yaml
targets:
  vulnerable: demo/vulnerable.yaml
  protected: demo/protected.yaml
output_root: scan-results
```

Run `llmrt mcp --registry /absolute/path/registry.yaml`. It uses stdio, keeps protocol messages on stdout, and accepts no remote network listener.

Example registration commands, with a scanner executable on PATH and credentials set in the client's environment, follow.

```bash
codex mcp add llmrt -- llmrt mcp --registry /absolute/path/registry.yaml
claude mcp add --transport stdio llmrt -- llmrt mcp --registry /absolute/path/registry.yaml
```

Use an absolute installed executable path when a desktop client has a different PATH. Do not put real credentials in version-controlled registration files or command examples. The server inherits configured environment credential references.

Tools are `validate_config`, `plan_scan`, `start_scan`, `get_scan_status`, `get_scan_results`, `cancel_scan`, `retest_finding`, and `compare_scans`. Four active jobs and 100 retained jobs bound server memory. Results paginate. Shutdown cancels running jobs and waits for cleanup.

Official Codex sources were fetched during implementation on 6 November 2026. Claude documentation retrieval was unavailable in this environment; verify commands against the installed client's help before registration.

- https://developers.openai.com/codex/skills/
- https://developers.openai.com/codex/mcp/
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/mcp

## Bounded evidence inspection

`get_scan_results` accepts `include_evidence: true`. It verifies content hashes and returns redacted untrusted-content excerpts, capped at 4,000 characters per object and 16,000 characters total per call. Larger artifacts remain referenced rather than being read without a bound. Fixture attestations and target observations remain separate objects. Captured instructions are data and do not authorize client actions.

Pagination reports both assessment total and coverage_total. A scoped scan can have one assessment and many not_selected coverage entries. Page up to the larger count when retrieving the complete matrix.

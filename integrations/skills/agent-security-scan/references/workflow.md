# CLI and MCP workflow

CLI setup uses `llmrt init demo`, `llmrt lab`, and the generated config files. Set `LLMRT_DEMO_TOKEN=demo-alpha` for the public local fixtures. This token is synthetic.

```bash
llmrt validate --config demo/vulnerable.yaml
llmrt scan --config demo/vulnerable.yaml --dry-run
llmrt scan --config demo/vulnerable.yaml --fail-on high
```

For an external target, use an operator-authored policy, trusted fixture source, supported response mapping, and explicit network scope. The default adapter expects normalized JSON `text`, `events`, and `session_id`; configure these paths for the target. Missing traces reduce applicability.

MCP tool sequence is `validate_config`, `plan_scan`, `start_scan`, `get_scan_status`, and `get_scan_results`. Use only registered aliases. Results paginate with offset and limit. `retest_finding` and `compare_scans` support the follow-up workflow.

Exit 1 means the finding gate triggered. Exit 2 means configuration/policy error. Exit 3 means incomplete execution/runtime failure. Exit 130 means interruption. Default `--fail-on none` still surfaces operational failure.

Read `report.json` as the canonical output. SARIF and terminal output are projections. Preserve the distinction between automated assessment and evidence-bound reviewer decisions. Deterministic demo results measure scanner mechanics, not actual model attack success.

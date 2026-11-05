# Security policy

Created by [@kvianAR](https://github.com/kvianAR).

Report security concerns privately through the repository's available private-reporting channel. If private reporting is unavailable, contact the owner through their published GitHub contact route before sharing sensitive details. Do not put credentials or customer data in a public issue.

The scanner handles target credentials and untrusted content. It validates destination scope before connecting to a pinned resolved address, verifies TLS by default, caps redirects and response/decompression sizes, rejects YAML aliases, redacts configured secrets before persistence, and creates private evidence files. Local MCP selects operator-registered aliases and uses stdio.

Real secrets that appear in target responses must be included in operator-defined literal redaction patterns. The scanner cannot identify every unknown secret automatically. Target-supplied event claims do not become independent evidence by labeling themselves independent. Execution trust is an explicit operator configuration and is recorded.

Judge is optional, off by default, and has no target tools. Evidence exports remain sensitive artifacts even after redaction. Local filesystem owners can modify their own artifacts; content hashes detect changes when verified but do not make files tamper-proof.

Use current security updates and follow [the authorized-testing guide](docs/authorized-testing.md). Release limitations and verification status are tracked in documentation.

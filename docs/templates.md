# Scenario authoring

Created by [@kvianAR](https://github.com/kvianAR).

Start from a reviewed corpus YAML. Preserve schema/version fields and CC-BY-4.0 attribution. Assign one primary boundary that exists in the operator policy. OWASP names use the 2025 edition. Declare real capabilities rather than advertising unavailable traces.

Use registered assertions and expected values. Each case needs a vulnerable/protected counterpart, a legitimate or benign control, a specific observable forbidden outcome, and cleanup expectations. Document author review and group related variants using `group`. New wording does not establish a new vulnerability class.

The loader rejects duplicate YAML keys, aliases, executable tags, oversized documents, and excessive nesting. It accepts declarative strings and registered operation metadata. Signature verification is not currently implemented; source review and content hashes are the available provenance controls.

Messages support `{{resource}}`, `{{principal}}`, and `{{session}}`. Unknown expressions fail validation. The scanner never inserts protected canary values into attacker messages. Multi-turn messages are ordered and use the same isolated conversation.

The current reference fixture implements read, alternate-argument lookup, message delivery, retrieved-document influence, and context disclosure. New real-app tool families require explicit adapter/instrumentation and detector support. Browser and general document-ingestion connectors remain post-v1.

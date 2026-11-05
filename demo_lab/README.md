# Paired deterministic lab

Run `uv run python -m llmrt.lab`. It binds loopback only. Both endpoints share synthetic fixtures and a policy manifest.

- `/vulnerable/chat` deliberately omits backend permission enforcement.
- `/protected/chat` checks record access and message destinations.
- `/manifest` supplies trusted local fixture setup for the scanner self-check.

Use synthetic bearer `demo-alpha` or `demo-beta`. These are public test credentials. The command router does not use an LLM. Its outcomes validate scanner plumbing, not model prompt-injection resistance. Message effects stay in a local in-memory mock sink.

Created by [@kvianAR](https://github.com/kvianAR).

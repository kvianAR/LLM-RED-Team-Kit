# Evaluation and honest denominators

Created by [@kvianAR](https://github.com/kvianAR).

Run `llmrt evaluate --suite evaluation/reference.yaml --config examples/demo/vulnerable.yaml --protected-config examples/demo/protected.yaml --output scan-results/evaluation --runs 3 --max-requests 1000` while the lab is running and the synthetic token is set.

The included suites exercise owned deterministic fixtures. Development covers direct record access. Validation covers destination enforcement and argument lookup. The reference split covers retrieved-document actions and protected context disclosure. Related corpus variants remain in the same group/split. Group overlap is checked by `llmrt check-splits`.

The reference suite is public and author-created. Its mechanisms have been exercised during implementation. It is not an independently authored frozen held-out benchmark and cannot support model generalization or real-world security efficacy claims. Use the evaluation harness with a separately authored, version-frozen held-out suite before publishing such claims. Keep any new benchmark suite untouched during tuning and publish its provenance/hash.

Each case has an explicit target alias, scenario ID, and known violation label. Run repeats separately. Do not pool correlated repeats as independent samples. Ground truth comes from declared fixture permissions and actual guarded/unguarded backend behavior.

Precision uses confirmed TP/(TP+FP). Observed recall uses TP/all applicable known-positive cases, so positive abstentions remain missed detections. Observed FPR uses FP/all applicable known-negative cases. Also publish conditional FPR, negative decision coverage, inconclusive rate, execution coverage, per-family counts, Wilson intervals, and case-group counts. Empty denominators produce null.

Unsupported cases remain visible in coverage and outside detection denominators. Unknown ground truth is reported separately. A perfect deterministic result does not establish resistance to real LLM attacks. Comparing other tools requires equivalent scope, evidence access, budgets, and positive/negative fixtures.

## Entire-command budget

Evaluation shares request, declared model/token/cost, and duration limits across every case and repeat. Defaults use the most restrictive configured limits. Explicit evaluation flags can set the overall cap, while each child scan retains its own stricter limits. The 32-case three-run reference uses `--max-requests 1000` and dispatches 384 local requests, including setup and cleanup. Exhausted cases remain inconclusive and the CLI returns an operational failure. Static suite references and frozen hashes validate before requests.

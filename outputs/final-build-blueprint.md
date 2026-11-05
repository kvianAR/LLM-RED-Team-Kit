# Agent Tool-Authorization Scanner — Final Build Blueprint

Prepared on 6 November 2026. Status is planning complete, implementation pending flow review.

## 1. Product aur focus

Working project name LLM Red Team Kit hai. CLI ka provisional naam `llmrt` hai. Public package-name availability release se pehle verify hogi.

Product LLM agents ke tool authorization aur data boundaries test karega. Har finding requesting principal, untrusted input, proposed action, actual execution, affected resource aur observed outcome se explain hogi.

Core question ye hai ki agent ne requesting principal ki permissions ke bahar data access ya action execute kiya ya nahi.

Targets apne local apps aur explicitly authorized staging environments honge. Public source availability hosted service ko test karne ki authorization establish nahi karti.

## 2. Final deliverables

- Python >=3.11 package aur CLI.
- Policy/config schemas aur versioned data contracts.
- Deterministic vulnerable/protected lab aur later model-backed profile.
- Generic HTTP adapter aur documented agent-event integration.
- Reviewed YAML scenarios, har security scenario ke saath protected counterpart.
- Policy self-check, fixture assertions aur capability planning.
- Async runner, session isolation, bounded retries aur atomic budgets.
- Write-time-redacted, content-addressed evidence.
- Canary, policy aur verified tool-event detectors.
- Dev, validation aur frozen held-out evaluation datasets.
- Optional judge, default off.
- Explainable severity, reviewer records aur stable fingerprints.
- Canonical JSON, terminal summary aur SARIF.
- Retest, baseline diff, coverage matrix aur CI gate.
- Authorized OSS applicability/validation, documentation aur packaged release.

HTML reporting v1 ke end par optional polish hai. Mutation, general document connectors, browser automation aur dashboard post-v1 hain. Controlled document/RAG fixtures v1 lab ka part rahengi.

## 3. Build flow — step 1 se step 18

### Step 1 — Policy, taxonomy aur scanner threat model

Pehle assets, principals, resources aur allowed actions define karenge. Ownership aur permission alag fields honge. Har in-scope principal/resource/action combination ka decision explicit hoga. Unknown combination assessment ke liye unverified rahega.

Har boundary ko stable ID, attack family, data sensitivity, allowed actions aur default severity rule milega. OWASP LLM Top 10 edition 2025 pin hogi. Relevant IDs LLM01 prompt injection, LLM02 sensitive information disclosure, LLM05 improper output handling, LLM06 excessive agency, LLM07 system prompt leakage aur LLM08 vector/embedding weaknesses hain. Mapping supported claims tak limited hogi.

Scanner threat model credentials, untrusted target content, templates, network destinations, response processing, judge aur evidence exports cover karega. Allowed hosts, redirects, resolved IPs, response limits, YAML limits aur output-path confinement controls define honge.

Output `docs/contracts.md`, `docs/threat-model.md` aur initial policy example honge.

Completion check mein har initial scenario ka requesting principal, protected resource, intended control aur observable forbidden outcome clear hona chahiye.

### Step 2 — Data contracts aur fingerprint schema

Versioned models `Policy`, `Scenario`, `ExecutionEvent`, `EvidenceRecord`, `Assessment`, `Finding`, `ReviewRecord` aur `ScanResult` define karenge. Event types proposal, execution attempt, execution result aur observed effect ko separate represent karenge.

Execution status aur security verdict independent fields rahenge. Run-level status aur per-scenario status bhi separate honge. Schema extra/unknown fields aur malformed IDs reject karega.

Fingerprint canonical structured fields ka SHA-256 hoga. Fields fingerprint version, target logical ID, scenario ID, policy boundary, principal role/relationship, resource logical ID, evidence class aur relevant capabilities cover karenge. Cross-user relationship preserve hogi, taaki same-role users collapse karke boundary disappear na ho. Tokens, timestamps aur random session IDs fingerprint mein nahi honge.

Template/fixture hashes exact content provenance denge. Stable logical finding ID aur exact evidence digest separate rahenge.

Output `src/llmrt/models.py`, serializer specification aur valid/invalid examples honge.

Completion check mein schemas events ko validate karein aur equivalent normalized inputs same fingerprint produce karein.

### Step 3 — Package, CLI, dry-run aur exit codes

Python >=3.11 aur uv workflow setup karenge. CLI commands progressively `init`, `validate`, `plan`/`--dry-run`, `scan`, `retest`, `diff` aur `evaluate` provide karengi. Unimplemented commands success simulate nahi karengi.

Dry-run selected scenarios, capabilities, missing prerequisites aur estimated calls dikhayega. Credentials echo nahi hongi. Estimate ki assumptions visible hongi.

Exit codes 0 successful execution/gate pass, 1 finding gate triggered, 2 invalid config/schema/policy mismatch, 3 runtime failure/required execution incomplete, aur 130 user interruption honge. Operational errors finding gate se independent rahenge. Multiple conditions ke liye precedence aur structured reasons defined honge.

`--fail-on` default `none` hoga. `confirmed` confirmed violations, `high` confirmed high/critical, aur `any` confirmed violations plus unresolved review cases par gate trigger karega. Inconclusive execution execution-policy contract follow karegi.

Completion check fresh environment install, help, config rejection aur exit-code regression checks pass karna hai.

### Step 4 — Deterministic vulnerable/protected lab

Sabse pehla pair cross-user record lookup hoga. Vulnerable endpoint authenticated principal ka per-user filter miss karega. Protected endpoint backend mein same authorization enforce karega.

Lab token-to-principal mapping use karegi. Request body mein principal badalne se authentication identity change nahi hogi. Synthetic users, resources aur private facts use honge.

Baad mein unvalidated message destination, tool argument confusion aur untrusted retrieved-document influence ke pairs add honge. Mock tools local sink events produce karenge.

Deterministic mode detector/runner plumbing ko repeatably test karega. Ye mode actual model susceptibility ka benchmark claim support nahi karega. Model-backed mode separate profile mein add hoga.

Output demo lab, trusted fixture manifest aur expected event sequences honge. Completion check vulnerable pair mein expected forbidden event aur protected twin mein allowed/rejected behavior observe karna hai.

### Step 5 — Policy self-check gate

Scan se pehle fixture manifest ko policy declarations ke saath validate karenge. Principal/resource existence, expected owner, explicit grants, required tools, destinations aur protected synthetic content check hoga.

Registered assertions `resource_owner`, `resource_exists`, `tool_registered`, `destination_allowed`, `document_available`, `canary_planted` aur `session_fresh` jaise bounded checks honge. Templates arbitrary executable code nahi denge.

Outcomes pass, fail aur unavailable honge. Global inconsistency `policy_mismatch` ke saath scan abort karegi. Scenario-specific failed setup affected scenario block karega. Unavailable independent evidence unsupported/unverified reason dega.

External targets mein scanner target ke conversational claims ko authorization truth nahi maanega. Owner-supplied trusted manifests ya separate control-plane integration ki requirement visible rahegi.

Completion check intentionally mismatched fixtures par zero attack execution aur clear failure reason hai.

### Step 6 — Configuration aur HTTP adapter

Config endpoint, method, message mapping, response extraction, credentials ke environment references, sessions, capabilities, tool-event source aur limits define karegi.

Adapter target response ko normalized events mein convert karega. Proposal aur execution fields documented honge. Missing traces complete execution evidence imply nahi karengi.

TLS verification default enabled hogi. Disable setting explicit aur report-visible hogi. Allowed scheme/host/port, resolved destination IP aur har redirect follow karne se pehle scope validate hoga. Redirect cap/loop detection aur credential-forwarding restrictions apply hongi. Environment proxy behavior explicit hoga.

Compressed aur decompressed response sizes, response duration aur supported formats bounded honge. Unexpected shapes structured target errors banengi.

Completion check happy path, invalid auth, malformed response, timeout, excessive response aur disallowed redirect cases cover karna hai.

### Step 7 — Templates aur reviewed corpus

Template schema ID, schema version, scenario version, primary boundary, family, OWASP mapping, required capabilities, fixtures, preconditions, steps, expected evidence aur cleanup define karega.

Har scenario vulnerable/protected pair mein author hoga. Benign requests aur legitimate authorized tool use bhi evaluation ke liye include honge. Overlapping variants ko separate attack classes jaisa count nahi karenge.

Loader size, nesting, node count aur YAML alias behavior bound karega. Safe loading akeli resource-exhaustion protection nahi hai. Source provenance, content hash aur optional signature verification support defined honge. Template target scope expand nahi kar sakti.

Original code ke liye Apache-2.0 planned hai. Original templates/corpus ke liye CC-BY-4.0 planned hai. Imported content ki original licensing aur attribution retain hogi.

Pehle ek reviewed pair end-to-end chalega. V1 corpus target 40–60 reviewed scenarios hai. Count se pehle quality aur independence verify hogi.

Completion check schema validation, pair review checklist, provenance aur duplicate review complete hona hai.

### Step 8 — Runner, isolation aur budgets

Runner scenarios plan, setup, execute, observe aur cleanup karega. Har case fresh conversation/session aur isolated fixture state use karega. Sequential turns ordered rahengi.

TaskGroup expected target failures ko scenario boundaries par collect karega. Ek normal timeout unrelated scenarios cancel nahi karega. Genuine concurrent subtasks scoped groups use karengi. Cancellation propagate hogi aur cleanup finally paths mein chalega.

Limits requests, model calls, tokens, duration aur knowable cost par apply hongi. Reservations atomic hongi. Usage settle hone ke baad unused reservation release hogi. Failed attempt ka actual incurred usage retained hoga. Unknown usage conservative accounting use karegi.

429 retries bounded backoff, jitter aur Retry-After follow karengi. Har attempt budget consume karega. State-changing ambiguous actions blindly retry nahi hongi.

Completion check timeout isolation, cancellation, budget exhaustion, retry counting aur reservation-leak regressions pass karna hai.

### Step 9 — Evidence aur redaction

Relevant requests, target-produced responses, tool events aur effect observations storage se pehle redact honge. Evidence record source, timestamp, run/scenario IDs, fixture/template hashes aur provenance retain karega.

Content addresses stored redacted bytes ka SHA-256 honge. Append-only manifests observations link karenge. Owner-only permissions supported platforms par enforce hongi. Generated paths output directory ke andar confined honge.

Replay recipe credentials ke references, fixture generators, request structure aur version metadata retain karegi. Fresh synthetic secrets generate honge. Redacted evidence har case mein byte-identical replay enable nahi karegi.

Target-provided traces ka provenance visible hoga. Independently collected sink/tool instrumentation stronger evidence provide kar sakti hai. Trace access independent trust guarantee nahi hai.

Completion check secret-redaction fixtures, digest verification, private permissions, path handling aur partial-run evidence persistence hai.

### Step 10 — Evaluation harness aur dataset splits

Development fixtures debugging, validation set tuning, aur frozen held-out set final evaluation ke liye separate honge. Related variants same split mein grouped honge taaki near-duplicate leakage reduce ho.

Ground truth independent fixture policy aur observed effects se define hogi. Dataset legitimate tool use, protected cases, known violations, ambiguous outputs, missing traces aur execution failures include karega.

Positive metric class confirmed violation hai. Precision TP/(TP+FP), observed recall TP/(TP+FN+U_pos), observed FPR FP/N_neg aur inconclusive rate U/N_applicable publish karenge. U_pos known-positive applicable cases hain jin par confirmed detection nahi ho saki. Unknown-ground-truth cases TP/FP denominators mein nahi jayenge. Unsupported cases coverage mein separately report honge. Negative-case abstentions FPR ko artificially reassuring dikha sakti hain, isliye negative decision coverage aur conditional FPR bhi publish hongi. Empty denominator undefined hoga.

Counts, confidence intervals, per-family results aur repeat-run variation publish karenge. Deterministic lab accuracy aur model-backed attack success separate tables honge.

Completion check handcrafted confusion-matrix examples par metric calculations verify karna aur dataset split manifest freeze karna hai.

### Step 11 — Deterministic detectors aur tuning

Pehla detector cross-user record boundary par hoga. Expected authorization aur actual executed resource read compare karega. Allowed request, refusal, proposal-only event aur actual unauthorized execution separate cases honge.

Canary format `LLMRT_<family_tag>_<random>_<checksum>` hoga. Prefix, partial random-component, full aur verified transformed disclosure separately record honge. Public prefix akela secret leak proof nahi hai. Checksum authenticity guarantee nahi deta.

Semantic disclosure ke liye synthetic facts use karenge. Raw target output aur judge explanation separate sources honge.

Detector tuning validation set par hogi. Frozen held-out set tuning feedback loop nahi banega.

Completion check vulnerable/protected twin aur benign-control regression tests pass karna hai.

### Step 12 — Optional isolated judge

Judge default off rahega. Deterministic-only scan fully supported hoga. Direct provider SDK pehla optional integration ho sakta hai. LiteLLM optional rahega.

Judge bounded relevant evidence aur trusted synthetic reference facts receive karega. Uske paas target credentials ya action tools nahi honge. Strict output schema, bounded retries aur inconclusive fallback apply hongi.

Mutator ko protected canary nahi milegi. Judge ko raw canary tabhi milegi jab required ho. Judge output mein secret repeat hone ko target disclosure nahi count karenge.

Completion check invalid output, timeout, target-to-judge injection attempts aur missing evidence cases correctly handle karna hai.

### Step 13 — Verdict, severity aur reviewer override

Security verdict confirmed_violation, no_violation_observed, needs_review aur inconclusive hoga. Unsupported/budget/timeouts execution fields mein rahenge.

Severity table data sensitivity, principal boundary, disclosure extent, action state aur demonstrated consequence use karegi. Default band aur justified policy context both visible honge. Severity demonstrated impact se constrained hogi.

Reviewer append-only decision fingerprint, assessment ID, evidence digest, identity, timestamp aur justification retain karega. Original assessment preserve rahega. Changed evidence par old override stale ho sakta hai.

Completion check policy rules ki repeatability aur reviewed/automated verdict separation hai.

### Step 14 — Canonical reports

Ek canonical ScanResult se JSON, terminal aur SARIF render honge. JSON complete machine-readable export hoga. Terminal aur SARIF selected projections honge.

SARIF template IDs stable rules banenge. partialFingerprints export honge. Valid source mappings available hon toh uriBaseId use hoga. Endpoint findings ke liye fake file locations invent nahi karenge. Schema validation aur actual supported ingestion test karenge.

Reports finding evidence, preconditions, impact, mitigation, coverage gaps aur execution failures dikhayengi. Source visibility absent ho toh mitigation recommendation contextual hogi, verified source patch claim nahi hoga.

Completion check shared identifiers/verdict/severity/counts agree karna aur untrusted report text safe render hona hai.

### Step 15 — Retest aur baseline diff

Retest stable scenario/policy semantics aur fresh fixtures use karega. Exact model identifiers, available revision, temperature aur supported seed record honge. Hosted-model determinism guarantee nahi hogi.

Comparability per scenario aur comparison purpose ke according evaluate hogi. Hash changes triggers hain, semantic incompatibility ka final proof nahi. Policy, fixtures, boundary, evidence capabilities, scenario semantics aur execution completeness check honge.

Diff new, unchanged, regressed, not_reproduced aur not_comparable distinguish karega. Resolved designation defined repeated-verification criteria se aayegi. Incomplete execution ko fixed nahi kahenge.

Completion check stable fingerprints across fresh canaries aur incomplete-baseline comparison regressions pass karna hai.

### Step 16 — CI gate aur coverage matrix

GitHub Action test target readiness check, scan, report upload aur gate evaluation karegi. Trusted workflows mein credentials securely inject hongi. Untrusted pull-request content ko secrets exposure se protect karenge.

Gate security findings aur operational completeness separately handle karega. Default interactive fail-on none ho sakta hai. Example CI workflow explicit high-severity regression policy choose karega.

Capability × family matrix executed, partial, unsupported, not selected, budget exhausted aur execution failed distinguish karegi. Disabled judge ya missing traces visible honge.

Completion check known vulnerable target fail, protected target pass aur incomplete scan clearly fail/report karna hai.

### Step 17 — Authorized OSS applicability aur validation

Target choose karne se pehle required capabilities, available adapters, policy visibility, trace sources, local setup, license aur authorization scope check karenge. Applicability insufficient ho toh target defer hoga.

Owned isolated instances aur synthetic data preferred validation setup honge. Findings independent local evidence se validate hongi. Unverified candidates confirmed finding nahi banengi.

Actual findings release requirement nahi hain. Authorized validation outcomes, unsupported surfaces aur limitations publish karna requirement hai. External disclosure approved channel aur owner coordination follow karegi.

Completion check documented supported target validation aur honest applicability record hai.

### Step 18 — Frozen evaluation, documentation aur v1

Held-out suite frozen versions, documented budgets aur repeated runs ke saath execute hogi. Counts, metrics, confidence intervals, per-family breakdown, inconclusive coverage aur limitations publish hongi.

Competitor comparison equivalent capabilities/instrumentation/budgets wale subset par hoga. Unsupported cases separate honge. Unverified superiority claims publish nahi karenge.

Fresh-install quickstart, example configs, custom-template guide, report interpretation, security policy, authorized-testing guide, corpus licenses aur 60-second demo prepare karenge. Package-name availability check aur explicit release decision ke baad distribution publish hogi.

Completion check independent quickstart, verified CLI/reports/CI, held-out results aur documented limitations hai. v1 means defined supported scope ready hai.

## 4. Ek actual scan ka runtime flow

1. Command aur configuration parse hoti hai.
2. Schemas, scope aur credential references validate hote hain.
3. Adapter capabilities discover/declare hoti hain.
4. Templates match hote hain aur unsupported cases list hote hain.
5. Dry-run requested ho toh sanitized plan par execution stop hoti hai.
6. Trusted policy self-check gate execute hoti hai.
7. Budget initialize hota hai aur per-scenario reservation hoti hai.
8. Fresh session aur synthetic fixtures provision hote hain.
9. Scenario assertions pass/fail/unavailable return karti hain.
10. Bounded HTTP/tool interaction execute hoti hai.
11. Proposal, execution aur independently observable effects capture hote hain.
12. Evidence redact hokar content-addressed store mein write hoti hai.
13. Deterministic detectors policy aur observations compare karte hain.
14. Enabled aur necessary ho toh isolated judge assess karta hai.
15. Verdict, evidence references aur applicable severity derive hoti hai.
16. Evidence-bound reviewer decision available ho toh effective verdict record hota hai.
17. Fingerprint aur optional baseline comparison calculate hoti hai.
18. Usage settle, unused reservation release aur fixtures clean up hoti hain.
19. Canonical result, coverage matrix aur reports finalize hote hain.
20. Finding gate aur execution status se documented exit code return hota hai.

Cancellation aur errors bhi cleanup/usage settlement trigger karenge. Already-observed evidence preserved rahegi. Policy mismatch findings nahi banayegi.

## 5. Implementation milestones

### M1 — First working vertical slice

Minimum contracts, CLI, one cross-user vulnerable/protected pair, policy gate, bounded HTTP path, evidence aur first deterministic detector. Verification mein unauthorized read detect, protected/authorized controls clean, mismatch abort aur canonical JSON result hoga.

Week-3 checkpoint ka focus M1 hai. Agar M1 complete nahi hai toh judge, SARIF polish aur additional features ka work defer hoga. Ye effort checkpoint hai, guaranteed delivery date nahi.

### M2 — Trustworthy scanner core

Multiple reviewed pairs, safe runner, schema/provenance validation, content-addressed evidence, evaluation harness, verdicts aur coverage.

### M3 — Team/CI workflow

Stable fingerprints, SARIF, retest, baseline comparison, reviewer records aur GitHub Action.

### M4 — Evidence-backed v1

Reviewed corpus target, frozen held-out evaluation, authorized OSS validation, documentation, demonstration aur release checks.

### Post-v1

Mutation, general document ingestion, Playwright/browser adapter, HTML polish if deferred aur hosted dashboard. Nayi features scope mein tab aayengi jab core milestones satisfy hon ya implementation blocker unhe necessary banaye.

## 6. Proposed repository layout

```text
llm-red-team-kit/
├── pyproject.toml
├── uv.lock
├── README.md
├── LICENSE
├── SECURITY.md
├── docs/
│   ├── contracts.md
│   ├── threat-model.md
│   ├── authorized-testing.md
│   ├── evaluation.md
│   └── templates.md
├── src/llmrt/
│   ├── cli.py
│   ├── models.py
│   ├── config.py
│   ├── policy.py
│   ├── templates/
│   ├── adapters/
│   ├── runner/
│   ├── evidence/
│   ├── detectors/
│   └── reporting/
├── demo_lab/
│   ├── app.py
│   ├── fixtures/
│   └── mock_tools.py
├── corpus/
│   ├── LICENSE
│   └── scenarios/
├── evaluation/
│   ├── dev/
│   ├── validation/
│   ├── held_out/
│   └── manifests/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── regression/
├── examples/
└── .github/
    ├── actions/scan/
    └── workflows/
```

Folders applicable phase mein add honge. Empty speculative modules first milestone ka part nahi honge.

## 7. Project complete hone ke baad uses

### Apne agents ki security testing

Customer support, internal document assistants aur workflow agents mein supported authorization/data boundaries verify kar sakte hain. Policy aur instrumentation integration required hogi.

### CI regression prevention

Prompts, models, retrieval logic aur tools change hone par relevant scenarios rerun karke confirmed regressions block kar sakte hain. Missing coverage separately visible rahegi.

### Authorized assessment work

Client-approved staging environments mein reproducible scenarios aur evidence reports generate kar sakte hain. Business context aur unsupported surfaces manual assessment maang sakte hain.

### Research aur comparison

Different models, authorization controls, retrieval pipelines aur tool policies ka controlled comparison kar sakte hain. Deterministic plumbing evaluation aur model attack-success evaluation separately report hongi.

### Resume aur open-source portfolio

Installable tool, vulnerable/protected lab, CI action, measured held-out results aur clear documentation show kar sakte hain. Actual verified numbers ke baad resume metrics add hongi.

### Responsible vulnerability research

Selected authorized OSS instances mein real issues discover/validate ho sakte hain. Findings ki guarantee nahi hai. Disclosure explicit approval aur owner process follow karegi.

### Future services

Managed scans, organization-specific templates, private agent-policy checks aur dashboard explore kar sakte hain. Demand, account isolation, hosting cost aur operational security evaluate karni hogi.

## 8. Costs aur practical limits

Deterministic local lab aur code tests paid model calls ke bina operate kar sakte hain. Model-backed target, optional judge aur later mutation provider usage incur karenge.

Cost scenario count, turn count, token usage, repeated runs aur chosen providers par depend karegi. Hidden target backend usage independently measure karna possible nahi ho sakta.

Scanner defined policies aur supported observed surfaces assess karega. Clean result tested conditions ka result hai. Arbitrary endpoint ko bina integration full tool-action visibility nahi milegi.

## 9. Final start point

Flow review ke baad M1 start hoga. Pehle policy/contracts, phir CLI aur deterministic lab, phir self-check, HTTP path, evidence aur first detector integrate honge.

M1 demonstration mein same logical test vulnerable target par forbidden record read detect karega, protected target par protection observe karega aur fixture mismatch par execution abort karega.

Implementation start karne se pehle ye blueprint reviewable hai. Is deliverable mein plan aur diagrams hain. Scanner code, package installation, scans aur releases is stage par pending hain.

# Roadmap

## v0.2.0

Local-only delivery. No remote operations, tags or publication.

### 01. Conjunctive server policy inheritance

Status: complete. Delivery range: `7162306..f926d1b`.

Problem: Repeated per-tool restrictions drift between servers.

Acceptance: Matching server rules constrain matching tool/resource/prompt grants; deny wins; server rates share a bucket across operations.

Test plan: Unit tests for narrowing, deny, shared rate windows and default denial.

### 02. Offline policy lint command

Status: complete. Delivery range: `f926d1b..4c6bb0d`.

Problem: Configuration errors currently surface only when a proxy starts.

Acceptance: policy check validates YAML without starting upstreams; JSON diagnostics distinguish errors and warnings; strict mode rejects broad grants.

Test plan: CLI tests for valid, malformed, duplicate, broad and contradictory rules.

### 03. Guard text resources and prompts

Status: complete. Delivery ranges: `4c6bb0d..151d7bc`, `020b9c8..126d789`, `b8214d3..2c80dc8`.

Problem: Tools-only guards leave useful MCP read surfaces unavailable.

Acceptance: Namespaced prompt discovery/get and opaque resource URI discovery/read enforce policy, metadata pins and output scanning; binary content is denied.

Test plan: Real subprocess journeys plus hostile metadata/output, invalid shape, pagination and changed metadata tests.

### 04. Freeze an independent synthetic holdout

Status: complete. Delivery range: `151d7bc..8f60b8d` (holdout freeze: `4e34e37`).

Problem: The existing corpus was authored alongside detector rules.

Acceptance: Keep original tuning fixtures separate; freeze new held-out attack fixtures before evaluation and report misses without tuning detectors.

Test plan: Assert disjoint IDs and payloads; replay all held-out cases through real subprocesses.

### 05. Expand benign coverage and report detector false positives

Status: complete. Delivery range: `8f60b8d..c2e6900`.

Problem: Eleven benign fixtures underrepresent ordinary technical text.

Acceptance: Add diverse benign fixtures including quoted security text and public contacts; report each detector hit count and false-positive denominator.

Test plan: Replay benign fixtures; verify per-detector counts and empty split summaries.

### 06. Version audit JSONL and add query CLI

Status: complete. Delivery range: `c2e6900..6e93c0f`.

Problem: Local logs lack a stable export contract and focused filtering.

Acceptance: Publish a JSON Schema; emit versioned payload-free records; query by decision/method/reason/time with bounded output and actionable line errors.

Test plan: Schema, privacy, filtering, malformed-line and CLI tests against real files.

### 07. Measure concurrent guarded call latency

Status: complete. Delivery range: `6e93c0f..020b9c8`.

Problem: Sequential attack replay is not a concurrency benchmark.

Acceptance: Benchmark real benign subprocess calls with configurable sessions and requests; report nearest-rank p50/p95/p99, throughput, errors, and scope.

Test plan: Real subprocess harness tests; run measured concurrency samples with no classifier.

### 08. Build and verify v0.2.0 distributions

Status: release build implemented in `126d789..b8214d3`; fresh-clone verification pending.

Problem: The next release needs installable artifacts and reproducible evidence.

Acceptance: Bump metadata; build wheel/sdist locally; install wheel from fresh local clone; run full checks/demo and document measured limitations.

Test plan: Fresh clone uv sync, pytest, ruff, demo, corpus, benchmark, uv build and installed-wheel smoke tests.

## Future work

Sampling/elicitation forwarding and client-side approval semantics; resource templates/subscriptions; persistent reviewed pins; OS sandbox integration; remote OAuth and distributed state. No stubs are included.

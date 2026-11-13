# v0.2 verification evidence

All commands below ran locally on Apple Silicon, Python 3.12.15. No hosted CI, live classifier, remote publication or real attack side effect was exercised. All corpus data is original and synthetic.

## Acceptance matrix

| Milestone | Observable evidence | Result |
|---|---|---|
| 01: inheritance | `test_inheritance.py` proves server constraints narrow leaf grants, server denies win, unmatched leaves stay denied, and server rate buckets span different tools | Pass |
| 02: policy lint | `test_policy_check.py` invokes the actual CLI for malformed YAML/schema, wildcard warnings/strict exit, duplicate rules and exact deny conflicts; `policy check examples/policy.yaml --json` returned no errors and a broad-grant warning at `tools[0]` | Pass |
| 03: resources/prompts | `test_surfaces.py` runs real subprocess list/read/get journeys, hostile metadata/output, changed pins and prompt-argument rejection; binary/malformed validation and paginated inventory tests pass; mixed capability tests skip unsupported upstream surfaces | Pass |
| 04: heldout | `heldout.json` was committed in `4e34e37` before its first replay; `test_splits.py` checks disjoint IDs/nonempty payloads and real replay reporting; detector implementation was not changed in v0.2 | Pass |
| 05: benign reporting | `test_benign_report.py` replays the new benign set, preserves five false positives, checks per-detector denominators and verifies empty evaluation summaries | Pass |
| 06: audit | `test_audit_query.py` verifies versioned schema, payload omission, mode 0600, query filtering and fail-closed line errors even after the output limit; actual query and HTML viewer commands executed | Pass |
| 07: benchmark | `test_benchmark.py` executes three real subprocess sessions and validates percentiles/bounds; measured four-session CLI run below completed 400 calls | Pass |
| 08: distribution | Fresh clone installed and passed full checks/demo; wheel and sdist built; isolated wheel demo, audit schema query, license/version and both new corpus splits loaded outside the source tree | Pass |

## Fresh local clone

Verified source commit: `e1790bb`. Final follow-up changes are documentation/evidence only.

Clone directory: `/tmp/mcp-guard-v02-asxv_9cs/repo`. It was created with:

```sh
git clone --no-hardlinks /Users/gouthammadineni/Documents/personal/mcp-guard /tmp/mcp-guard-v02-asxv_9cs/repo
```

No network repository was contacted. The clone has only its automatically created local-source origin; it was not fetched or pushed. No git configuration was edited.

Executed from that clone:

```sh
uv sync --frozen
uv run pytest --cov=mcp_guard --cov-report=term-missing -q --tb=short
uv run ruff check .
uv run ruff format --check .
uv run mcp-guard demo --directory .guard/fresh-demo
uv run mcp-guard test --directory .guard/fresh-tuning
uv build
uv run mcp-guard benchmark --sessions 4 --requests 100 --directory .guard/fresh-benchmark
uv run mcp-guard test --split all --directory .guard/fresh-all
```

Observed:

- Dependency installation succeeded from the frozen lockfile.
- **130 tests passed in 61.62s**, **86% statement coverage**.
- Ruff lint passed; **54 files already formatted**.
- Demo blocked all six selected synthetic scenarios.
- Tuning replay: **29/29 attacks blocked, 0/11 benign false positives, 40/40 raw deliveries, zero transport errors**.
- Built `dist/mcp_guard-0.2.0.tar.gz` and `dist/mcp_guard-0.2.0-py3-none-any.whl`.
- All-split replay exited **1**, as expected for known misses/false positives, not a transport failure:

```text
Attacks blocked: 45/49 (91.8%)
Benign false positives: 5/43 (11.6%)
Without guard: 92/92 scenarios delivered; transport errors: 0
```

Of the added 20 held-out attacks, 16 were blocked and four missed (Spanish, indirect instruction, Base64, ROT13). No detector rules were modified to improve that score. The holdout is separated in time from tuning, not independently authored or a representative statistical benchmark.

Benign payload detector hits: injection 1/43, tool_instruction 1/43, secret 0/43, email 2/43, card 1/43, unscannable 0/43. Multiple hits can overlap; the denominator is always the evaluated benign population.

## Concurrent benchmark capture

Fresh-clone output:

```json
{
  "sessions": 4,
  "calls_per_session": 100,
  "attempted": 400,
  "completed": 400,
  "errors": 0,
  "wall_seconds": 0.575318,
  "throughput_calls_per_second": 695.267,
  "latency_ms": {"p50": 5.721, "p95": 5.932, "p99": 6.003}
}
```

Synthetic local stdio calls; process startup, initialization and one warm-up per session excluded. Each timed call includes refreshed discovery, schema/policy checks, scanning and file audit. Each session serializes calls; four independent sessions run concurrently. No classifier or remote tool. This is not incremental overhead, a production throughput promise or a cross-machine comparison. An earlier source run measured p50 5.900ms / p95 6.373ms / p99 6.933ms and 670.100 successful calls/s, demonstrating normal run variation.

## Installed wheel outside source checkout

Working directory: `/tmp/mcp-guard-v02-asxv_9cs`, not the repo. Commands used the wheel built by the fresh clone:

```sh
uv run --isolated --no-project --python 3.12 --with /tmp/mcp-guard-v02-asxv_9cs/repo/dist/mcp_guard-0.2.0-py3-none-any.whl mcp-guard demo --directory /tmp/mcp-guard-v02-asxv_9cs/wheel-demo
uv run --isolated --no-project --python 3.12 --with /tmp/mcp-guard-v02-asxv_9cs/repo/dist/mcp_guard-0.2.0-py3-none-any.whl mcp-guard audit query /tmp/mcp-guard-v02-asxv_9cs/wheel-demo/audit.jsonl --decision blocked --limit 1
uv run --isolated --no-project --python 3.12 --with /tmp/mcp-guard-v02-asxv_9cs/repo/dist/mcp_guard-0.2.0-py3-none-any.whl python -c 'from importlib.metadata import metadata; from mcp_guard import __version__; from mcp_guard.corpus import load_corpus; print(__version__, metadata("mcp-guard")["License-Expression"], len(load_corpus("heldout")), len(load_corpus("benign")))'
```

Observed: runtime-only wheel environment installed; six demo scenarios blocked; query returned a schema-version-1 blocked `tools/call` event; metadata/data command printed **`0.2.0 MIT 20 32`**. No source-tree import or test-only SDK was required.

## Read-surface wire capture

Executed `mcp-guard proxy --config examples/read-surfaces.yaml` over stdio with initialization, resources/list, resources/read and prompts/get. Server metadata reported 0.2.0 and resources/prompts capabilities. Discovery returned `mcp-guard://demo/fixture%3A%2F%2F%2Fsummary`. Resource read returned the same guarded URI and text `Weather: 21 C and sunny.`; prompt get returned that text as a user message. An actual `audit query --method resources/read --limit 1` returned its versioned allowed event. HTML audit rendering succeeded.

## Deferred and not claimed

Sampling/elicitation forwarding, resource templates/subscriptions, persistent reviewed pins, OS sandboxing, remote OAuth, distributed quotas/state and tamper-evident audit remain future work, with no stub implementation. Detection is heuristic and English-centric; metadata pins are not implementation attestation; output blocking cannot undo side effects. Neither wire delivery nor synthetic block rate proves model compromise prevention. Full limitations are in README and the technical design.

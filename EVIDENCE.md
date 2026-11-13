# Verification evidence

All commands below were executed locally. Hosted CI and live LLM endpoints were not run.
All attack fixtures are synthetic. No attack action is performed outside the simulator.

## Acceptance matrix

| ID | Delivered proof | Evidence | Result |
|---|---|---|---|
| EC-1 | Unit + real-process integration | `test_policy.py` tests deny precedence, regex/path/domain boundaries and rate expiry; `test_proxy.py::test_confirmation_and_schema` exercises exact one-use approval and JSON Schema through a real server; `test_hardening.py::test_symlink_escape` resolves a real symlink | Pass |
| EC-2 | Real-process integration | `test_proxy.py::test_real_attacks_quarantined`; all 40 scenarios through `test_evaluation.py::test_full_corpus_uses_real_server`; malformed peer fixtures in `test_adversarial_upstream.py` | Pass |
| EC-3 | Real transport integration + CLI capture | `test_http.py` covers JSON and SSE upstream POSTs and authenticated downstream sessions; `test_interop.py` uses official MCP SDK 2.3.0 over stdio and HTTP; executed `examples/http_client.py` output is in README | Pass |
| EC-4 | Executed CLI output | `uv run mcp-guard demo` and `uv run mcp-guard test`; 29 attacks blocked, 11 benign allowed, raw acceptance 40/40, zero transport errors | Pass |
| EC-5 | Unit + executed viewer command | `test_state.py::test_audit_escapes_and_omits_payload`; `uv run mcp-guard view .guard/audit.jsonl --output .guard/audit.html` produced the local static viewer | Pass |

## Source-checkout run

Commands:

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest --cov=mcp_guard --cov-report=term-missing -q
uv run mcp-guard demo
uv run mcp-guard test
uv run mcp-guard view .guard/audit.jsonl --output .guard/audit.html
uv build
```

Observed: Ruff passed; 89 tests passed in 49.52s; total statement coverage 86%.
Policy coverage 97%, detector coverage 100%, RPC coverage 100%.
Replay: 29/29 attacks blocked, 0/11 benign false positives, no transport errors.
Measured guarded discovery+call: median 3.427ms, nearest-rank p95 3.610ms.
This includes two guarded discovery operations for normal call scenarios; it is not
isolated proxy overhead or a cross-machine performance promise.
Both source distribution and wheel built successfully.
The README includes actual demo/replay/HTTP output from these runs.

## Clean clone, install and wheel check

A local `git clone --no-hardlinks` was made from commit `37498e9` into a fresh
system temporary directory. Its local-source origin was removed immediately;
no network remote was created. From that clone:

```sh
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run mcp-guard demo
uv run mcp-guard test
uv build
uv run --isolated --no-project --python 3.12 --with dist/mcp_guard-0.1.0-py3-none-any.whl mcp-guard demo
```

Observed: dependency installation succeeded; Ruff passed; **89 passed in 51.63s**.
The demo blocked the same six examples. Full replay again blocked 29/29 attacks,
allowed all 11 benign cases, and reported zero transport errors. Clean-clone timing
was median 3.319ms / p95 3.697ms, illustrating expected measurement variation.
The isolated **runtime-only wheel environment** also executed the complete demo,
proving packaged corpus data and console entrypoint work without the source tree's
development dependencies. No key was configured or used. The temporary clone was
removed after verification; the original repository remains local-only.

## HTTP demo capture

Executed two loopback processes: the vulnerable server with
`--case injection-ignore --http 8766 --sse`, and the proxy with
`--config examples/http-upstream.yaml --transport http --port 8765`.
Both used a throwaway synthetic local bearer token for this test.
`uv run python examples/http_client.py` listed four policy-visible tools and received
JSON-RPC error `-32001 / output_injection` for `demo__echo`. Both processes were stopped.

## Scope and evidence limits

This is an authored regression corpus, not an independent red-team study. No human
or model followed the malicious instructions. “Without guard” measures wire-level
acceptance by the simulator, not real exfiltration or agent compromise. No remote
classifier quality, real filesystem sandboxing, distributed throughput, OAuth or
hosted-CI claim is made. See README limitations and DESIGN interview notes.

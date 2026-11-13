# Design: a narrow MCP trust boundary

## Problem and threat model
MCP servers return data and tool metadata that an agent can mistake for authority.
This local security proxy treats client arguments and upstream content as untrusted.
It enforces operator policy before execution and quarantines suspicious responses.
It is not a sandbox, malware detector, DLP guarantee, or authorization server.
Only synthetic fixtures are used; no employer code or data is included.

## Chosen design
Python 3.12, asyncio, aiohttp, httpx, PyYAML and JSON Schema. Small modules own
policy, detection, JSON-RPC, transports, audit and reproducible evaluation.
Implement MCP's tools profile directly instead of adopting the SDK: the trust
boundary and wire validation remain visible and interview-defensible. MCP versions
2024-11-05, 2025-03-26 and 2025-06-18 are negotiated; only tools capabilities are
advertised. Resources/prompts/sampling/elicitation are deliberately unsupported.
Stdio uses newline-delimited JSON, not LSP Content-Length framing. Streamable HTTP
accepts JSON or SSE POST responses; downstream GET supports notification SSE.
Legacy HTTP+SSE endpoint discovery and event replay/resumption are out of scope.

## Interfaces and flow
A Router owns named upstream sessions. Tools are always server__tool names.
Every call refreshes tools/list, verifies pinned canonical metadata fingerprints,
checks inputSchema and YAML policy, consumes any local one-use approval, then
executes the upstream call and scans the entire JSON result. Returned tool
metadata is scanned too. A changed tool is quarantined until proxy restart.
Policy is default-deny; deny rules win; matching allow rules are conjunctive.
Rate windows are monotonic and per proxy session/tool. Invalid policy fails startup.
Unknown RPC methods fail closed. Server-initiated requests are rejected, not relayed.
An asyncio lock serializes each upstream's request/response stream.

## Failure behavior and limits
Malformed/oversized frames, timeout, upstream errors, scanner/classifier failure,
unknown tools and unsafe arguments return JSON-RPC errors without raw content.
Tool output blocks cannot undo upstream side effects: argument policy is the
pre-execution boundary. Text/structured output is scanned; non-text binary content
is rejected. Operator regexes are trusted configuration; cap argument/output size.
Paths use resolved containment and reject encoded traversal/backslashes; filesystem
TOCTOU remains an upstream concern. URL allowlists match exact normalized HTTPS
hostnames, forbid credentials, IP literals and unusual ports. They do not prevent
DNS rebinding or redirects inside upstream tools; upstream must enforce those too.

## Confirmation, privacy and deployment
Approvals are issued out-of-band by CLI into a 0600 SQLite file, bound to exact
canonical namespaced tool+arguments, expire, and are atomically consumed once.
No approval token is exposed to the agent. Local file access is trusted.
Audit JSONL records metadata, finding codes and hashes, never args/output text.
Viewer is static escaped HTML, no scripts or network resources.
HTTP binds loopback only, validates Origin and Host, requires a bearer token from
env, and isolates each MCP session with its own upstream processes and policy state.
Configuration is operator-trusted and can launch commands. Upstream processes
inherit only PATH, HOME, TMPDIR and configured env variable names. HTTPS certs are
verified, redirects are disabled. No built-in OAuth; remote/public hosting excluded.
Optional LLM classification sends content to an operator-selected OpenAI-compatible
endpoint; opt-in only, key from env, deterministic local mock available. Fail closed.

## Alternatives and tradeoffs
SDK: broader protocol coverage but less transparent boundary; prefer explicit narrow
profile. Shared global upstream: cheaper but leaks session state; isolate sessions.
Redaction of output: retains usefulness but can preserve instructions; block whole
message. Regex-only: offline and explainable but evadable; optional classifier adds
latency, cost and disclosure risk. SQLite approvals avoid bearer tokens in model context.

## Verification and rollout
No migration or external deploy. Local branch only; no remotes or publication.
Unit tests cover policy boundaries, detectors, approval expiry/reuse, validation and
privacy. Integration tests launch the real vulnerable stdio server and local HTTP/SSE
servers, exercise multiple upstreams and downstream authentication/session behavior.
Bundled synthetic attacks and benign fixtures are replayed through the real stdio
server; report per-category block rates, false positives and latency, not general
security effectiveness. Demo compares raw upstream with guarded responses.

## Acceptance Criteria & Evidence Contract
| ID | Criterion | Proof | Assertion |
|---|---|---|---|
| EC-1 | Operator YAML constrains calls | Integration + unit | deny, traversal, URL, regex, rate, approval reject before call |
| EC-2 | Untrusted outputs/metadata quarantined | Integration | injection, secrets, PII, tool instructions, rug pull blocked |
| EC-3 | MCP transports work | Integration | real stdio and authenticated HTTP JSON/SSE tools journey |
| EC-4 | Offline demo/evaluation reproducible | CLI capture | >=20 attacks, benign denominator and per-category counts |
| EC-5 | Audit usable without payload disclosure | Unit + demo | JSONL metadata and escaped HTML rendered |

## Limitations / roadmap
Heuristics are English-centric and evadeable; corpus is authored alongside detector,
not an independent benchmark. No binary scanning, persistent metadata pins, distributed
rate limits, OAuth, legacy SSE discovery, batching, progress forwarding or resumable
streams. Future work: independent adversarial corpus, OS sandbox integration and
external operator UI. These are not silently advertised as supported features.

## Interview notes

### 1. Write the tools-profile boundary, then test with an independent SDK
The hard part is not JSON parsing: it is request correlation, notification handling,
bounded SSE events, lifecycle negotiation and handling an upstream that never finishes.
The implementation uses strict frame/result validation and absolute deadlines.
Rejected: a broad transparent pass-through (exposes unsupported trust boundaries),
and building the implementation atop the same SDK used by the tests (less independent
wire verification). The official SDK is a test-only interoperability client.
The protocol lifecycle reference is
https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle.

### 2. Inspect discovery at call time, not just on connection
One initial scan misses a later description/schema rug pull. Canonical fingerprints
and a discovery refresh before each call make that change observable before execution.
Rejected: trusting server-supplied change notifications alone, and silently accepting
changed metadata. The cost is an extra discovery round-trip per call and intentional
denial of service when metadata changes legitimately. Pins are first-use trust after
scanning, not signed attestation. Inventory limits bound aggregate memory.

### 3. Confirmation must be an external authority
A confirmation string in an agent-controlled argument would let the model authorize
itself. Local one-use SQLite grants bind exact arguments and expire; DELETE RETURNING
makes consumption atomic. Rejected: reusable tokens in model context and interactive
prompts on stdio (they corrupt MCP framing and do not work headlessly).
The operator filesystem is the authority; remote multi-user approval needs a separate
authentication model.

### At 100× scale
First measure queue time, discovery round-trips, scan CPU and upstream latency.
Partition by authenticated tenant/session; never share upstream process state across
clients. Move rate limits and approvals to a transactional shared store, retain
argument-bound atomic consumption, and use bounded queues/backpressure rather than
unlimited task creation. Keep reviewed persistent metadata versions and invalidate
caches with explicit policy/version keys. Isolate untrusted servers with OS
permissions/sandboxes. Batch optional classification behind strict deadlines only
after measuring its cost and documenting content disclosure. Do not substitute a
larger model for authorization, request validation or process isolation.

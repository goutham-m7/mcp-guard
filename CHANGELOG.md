# Changelog

All notable changes are documented here. This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic versions.

## [0.2.0] - 2026-11-13

### Added
- Opt-in text resources/list/read and prompts/list/get with namespaced identifiers, metadata pins, policy enforcement and output scanning. Binary results remain blocked.
- Conjunctive server policy inheritance, including shared server rate quotas across tools, resource reads and prompt gets.
- Offline `mcp-guard policy check` with JSON diagnostics and strict warning mode.
- A frozen 20-case synthetic attack holdout, separate from the original tuning fixtures.
- 32 additional benign fixtures and per-detector false-positive reporting. Known misses and conservative false positives remain visible.
- Versioned audit JSONL schema and `audit query` filters for method, decision, reason and time, with bounded output and content-free line diagnostics.
- Concurrent real-subprocess latency benchmark reporting p50/p95/p99, successful throughput and errors.
- Wheel/sdist license metadata, packaged corpus/schema smoke tests and fresh-local-clone verification instructions.

### Changed
- Package and MCP server/client metadata now report 0.2.0 from installed distribution metadata.
- Evaluation CLI can select tuning, heldout, benign or all splits; empty denominators are explicit rather than raising division errors.

### Security
- Read-surface discovery respects upstream capabilities in mixed-server configurations.
- Sampling/elicitation and binary content remain disabled. No detector rules were tuned after holdout inspection. Scanning is heuristic, not a sandbox or universal injection defense.

## [0.1.0]

### Added
- Default-deny MCP tools proxy, stdio and authenticated loopback Streamable HTTP/SSE transports, constrained YAML policy, metadata pinning, output scanning, one-use operator approvals and local audit viewer.
- Original 40-case synthetic regression corpus and optional classifier boundary.

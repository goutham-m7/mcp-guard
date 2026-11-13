# Measure concurrent guarded call latency

Milestone: v0.2.0

## Problem
Sequential attack replay is not a concurrency benchmark.

## Acceptance criteria
Benchmark real benign subprocess calls with configurable sessions and requests; report nearest-rank p50/p95/p99, throughput, errors, and scope.

## Test plan
Real subprocess harness tests; run measured concurrency samples with no classifier.

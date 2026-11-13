"""Real local stdio sessions, warm-up excluded, no network or classifier."""

import asyncio
import math
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path

from .corpus import demo_policy
from .detection import Detector
from .evaluation import INITIALIZE, request
from .guard import Guard
from .policy import Policy
from .state import Approvals, Audit
from .transports import StdioUpstream


def percentiles(samples):
    if not samples:
        raise ValueError("percentiles require samples")
    values = sorted(samples)
    return {
        name: round(values[math.ceil(len(values) * quantile) - 1], 3)
        for name, quantile in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99))
    }


async def benchmark(directory, *, sessions=4, requests=100):
    if (
        not 1 <= sessions <= 32
        or not 1 <= requests <= 10000
        or sessions * requests > 100000
    ):
        raise ValueError("invalid benchmark bounds")
    async with AsyncExitStack() as stack:
        guards = []
        for index in range(sessions):
            path = Path(directory) / f"session-{index}"
            upstream = await StdioUpstream(
                [
                    sys.executable,
                    "-m",
                    "mcp_guard.demo_server",
                    "--case",
                    "benign-weather",
                ]
            ).start()
            stack.push_async_callback(upstream.close)
            guard = Guard(
                {"demo": upstream},
                Policy(demo_policy()),
                Detector(),
                Audit(path / "audit.jsonl"),
                Approvals(path / "approvals.sqlite"),
            )
            initialized = await guard.handle(request("initialize", INITIALIZE))
            await guard.handle(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
            warm = await guard.handle(
                request("tools/call", {"name": "demo__echo", "arguments": {}})
            )
            if "error" in initialized or "error" in warm:
                raise ValueError("benchmark warm-up failed")
            guards.append(guard)

        async def worker(guard):
            durations, errors = [], 0
            for _ in range(requests):
                started = time.perf_counter()
                response = await guard.handle(
                    request("tools/call", {"name": "demo__echo", "arguments": {}})
                )
                durations.append((time.perf_counter() - started) * 1000)
                errors += "error" in response
            return durations, errors

        started = time.perf_counter()
        results = await asyncio.gather(*(worker(guard) for guard in guards))
        elapsed = time.perf_counter() - started
        samples = [ms for durations, _ in results for ms in durations]
        errors = sum(count for _, count in results)
        total = sessions * requests
        return {
            "scope": "Synthetic local stdio; initialization, one warm-up per session and process startup excluded; call-time discovery, scanning and audit included; no classifier. Latencies include errors; calls serialize within each session.",
            "sessions": sessions,
            "calls_per_session": requests,
            "attempted": total,
            "completed": total - errors,
            "errors": errors,
            "wall_seconds": round(elapsed, 6),
            "throughput_calls_per_second": round((total - errors) / elapsed, 3),
            "latency_ms": percentiles(samples),
        }

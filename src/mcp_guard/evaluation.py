"""Replay identical synthetic scenarios against raw and guarded real subprocesses."""

import math
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

from .corpus import demo_policy
from .detection import Detector
from .guard import Guard
from .policy import Policy
from .state import Approvals, Audit
from .transports import StdioUpstream

INITIALIZE = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "replay", "version": "1"},
}


def request(method, params=None):
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


async def replay(case, directory):
    command = [sys.executable, "-m", "mcp_guard.demo_server", "--case", case["id"]]
    raw = StdioUpstream(command)
    raw_delivered = False
    await raw.start()
    try:
        await raw.request("initialize", INITIALIZE)
        await raw.notify("notifications/initialized")
        await raw.request("tools/list")
        if case["kind"] == "rug":
            await raw.request("tools/list")
        await raw.request(
            "tools/call", {"name": case["tool"], "arguments": case["arguments"]}
        )
        raw_delivered = True
    finally:
        await raw.close()
    upstream = await StdioUpstream(command).start()
    guard = Guard(
        {"demo": upstream},
        Policy(demo_policy()),
        Detector(),
        Audit(Path(directory) / "audit.jsonl"),
        Approvals(Path(directory) / "approvals.sqlite"),
    )
    try:
        init = await guard.handle(request("initialize", INITIALIZE))
        if "error" in init:
            raise RuntimeError("replay initialization failed")
        await guard.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        started = time.perf_counter()
        response = await guard.handle(request("tools/list"))
        if "error" not in response:
            response = await guard.handle(
                request(
                    "tools/call",
                    {"name": "demo__" + case["tool"], "arguments": case["arguments"]},
                )
            )
        elapsed = (time.perf_counter() - started) * 1000
        code = response.get("error", {}).get("code")
        return {
            "id": case["id"],
            "category": case["category"],
            "malicious": case["malicious"],
            "raw_delivered": raw_delivered,
            "blocked": code == -32001,
            "error": code is not None and code != -32001,
            "reason": response.get("error", {}).get("message", "allowed"),
            "ms": elapsed,
        }
    finally:
        await guard.close()


async def evaluate(cases, directory):
    rows = [await replay(case, directory) for case in cases]
    attacks = [r for r in rows if r["malicious"]]
    benign = [r for r in rows if not r["malicious"]]
    categories = defaultdict(lambda: {"total": 0, "blocked": 0})
    for row in attacks:
        categories[row["category"]]["total"] += 1
        categories[row["category"]]["blocked"] += row["blocked"]
    times = sorted(r["ms"] for r in rows)
    return {
        "attacks": len(attacks),
        "blocked": sum(r["blocked"] for r in attacks),
        "benign": len(benign),
        "false_positives": sum(r["blocked"] for r in benign),
        "errors": sum(r["error"] for r in rows),
        "raw_delivered": sum(r["raw_delivered"] for r in rows),
        "categories": dict(sorted(categories.items())),
        "latency_ms": {
            "median": round(statistics.median(times), 3),
            "p95": round(times[math.ceil(len(times) * 0.95) - 1], 3),
        },
        "cases": rows,
    }


def summary(report):
    lines = [
        f"Attacks blocked: {report['blocked']}/{report['attacks']} ({100 * report['blocked'] / report['attacks']:.1f}%)",
        f"Benign false positives: {report['false_positives']}/{report['benign']} ({100 * report['false_positives'] / report['benign']:.1f}%)",
        f"Without guard: {report['raw_delivered']}/{report['attacks'] + report['benign']} scenarios delivered; transport errors: {report['errors']}",
    ]
    for category, counts in report["categories"].items():
        lines.append(f"  {category}: {counts['blocked']}/{counts['total']}")
    lines.append(
        f"Guarded list+call latency (excludes process startup): median {report['latency_ms']['median']:.3f} ms; p95 {report['latency_ms']['p95']:.3f} ms"
    )
    return "\n".join(lines)

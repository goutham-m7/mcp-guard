"""Local-only operator CLI. Stdout stays exclusively JSON-RPC in proxy mode."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from aiohttp import web

from .audit_query import AuditQueryError, query_audit
from .benchmark import benchmark
from .config import Config
from .corpus import load_corpus
from .evaluation import evaluate, replay, summary
from .policy_check import check_policy
from .rpc import MAX_BYTES, RpcError, decode, error
from .server import create_app
from .state import Approvals, render_audit


async def stdio(config, audit, approvals):
    guard = await config.build(audit, approvals)
    try:
        while raw := await asyncio.to_thread(sys.stdin.buffer.readline, MAX_BYTES + 2):
            try:
                response = await guard.handle(decode(raw))
            except RpcError as exc:
                response = error(None, exc.code, exc.reason)
            if response is not None:
                print(json.dumps(response), flush=True)
            if len(raw) > MAX_BYTES:
                break
    finally:
        await guard.close()


async def demo(directory):
    print("mcp-guard / offline synthetic attack demo")
    print(
        "The vulnerable server simulates acceptance; it never reads files or sends data.\n"
    )
    selected = {
        "injection-ignore",
        "exfil-external",
        "path-parent",
        "poison-authority",
        "rug-pull",
        "pii-email",
    }
    for case in load_corpus():
        if case["id"] not in selected:
            continue
        row = await replay(case, directory)
        print(case["id"])
        sample = case["payload"] or json.dumps(case["arguments"])
        print(f"  Payload: {sample}")
        print("  Without guard: " + ("DELIVERED" if row["raw_delivered"] else "ERROR"))
        print(
            f"  With guard: {'BLOCKED' if row['blocked'] else 'ALLOWED'} ({row['reason']})"
        )
        if not row["blocked"] or row["error"]:
            return 1
    print(f"\nAudit: {Path(directory) / 'audit.jsonl'}")
    return 0


def parser():
    root = argparse.ArgumentParser(
        prog="mcp-guard", description="Default-deny security proxy for MCP tools"
    )
    commands = root.add_subparsers(dest="command", required=True)
    bench = commands.add_parser(
        "benchmark", help="measure concurrent local stdio calls"
    )
    bench.add_argument("--sessions", type=int, default=4)
    bench.add_argument("--requests", type=int, default=100, help="calls per session")
    bench.add_argument("--directory", default=".guard/benchmark")
    audit = commands.add_parser("audit", help="query versioned JSONL exports")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    query = audit_commands.add_parser("query")
    query.add_argument("path")
    query.add_argument("--decision", choices=["allowed", "blocked", "error"])
    query.add_argument("--method")
    query.add_argument("--reason")
    query.add_argument("--since", type=float, help="inclusive Unix seconds")
    query.add_argument("--until", type=float, help="inclusive Unix seconds")
    query.add_argument("--limit", type=int, default=100)
    policy = commands.add_parser("policy", help="offline policy tools")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    check = policy_commands.add_parser("check", help="validate and lint a YAML policy")
    check.add_argument("path")
    check.add_argument("--json", action="store_true")
    check.add_argument("--strict", action="store_true", help="fail on warnings")
    proxy = commands.add_parser(
        "proxy", help="bridge MCP client and configured upstreams"
    )
    proxy.add_argument("--config", required=True)
    proxy.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    proxy.add_argument("--port", type=int, default=8765)
    proxy.add_argument("--token-env", default="MCP_GUARD_TOKEN")
    proxy.add_argument("--audit", default=".guard/audit.jsonl")
    proxy.add_argument("--approvals", default=".guard/approvals.sqlite")
    for name in ("test", "demo"):
        command = commands.add_parser(
            name, help="replay original offline fixtures through the real demo server"
        )
        command.add_argument("--directory", default=".guard")
        if name == "test":
            command.add_argument(
                "--split",
                choices=["tuning", "heldout", "benign", "all"],
                default="tuning",
            )
            command.add_argument(
                "--json", action="store_true", help="emit machine-readable results"
            )
    approval = commands.add_parser(
        "approve", help="issue a local, exact-argument, one-use approval"
    )
    approval.add_argument("tool")
    approval.add_argument(
        "--arguments", required=True, help="JSON object, must match call exactly"
    )
    approval.add_argument("--ttl", type=int, default=60)
    approval.add_argument("--store", default=".guard/approvals.sqlite")
    view = commands.add_parser(
        "view", help="render payload-free JSONL as static escaped HTML"
    )
    view.add_argument("audit")
    view.add_argument("--output", default=".guard/audit.html")
    return root


def main():
    args = parser().parse_args()
    try:
        if args.command == "benchmark":
            report = asyncio.run(
                benchmark(
                    args.directory, sessions=args.sessions, requests=args.requests
                )
            )
            print(json.dumps(report, indent=2))
            return int(report["errors"] > 0)
        if args.command == "audit":
            rows = query_audit(
                args.path,
                decision=args.decision,
                method=args.method,
                reason=args.reason,
                since=args.since,
                until=args.until,
                limit=args.limit,
            )
            for row in rows:
                print(json.dumps(row, separators=(",", ":")))
            return 0
        if args.command == "policy":
            report = check_policy(args.path)
            if args.json:
                print(json.dumps(report))
            else:
                for level, entries in report.items():
                    for entry in entries:
                        print(f"{level}: {entry['location']}: {entry['code']}")
                if not report["errors"] and not report["warnings"]:
                    print("Policy valid.")
            return (
                2 if report["errors"] else int(args.strict and bool(report["warnings"]))
            )
        if args.command == "proxy":
            config = Config.load(args.config)
            if args.transport == "http":
                token = os.environ[args.token_env]
                web.run_app(
                    create_app(config, token, args.audit, args.approvals),
                    host="127.0.0.1",
                    port=args.port,
                    print=None,
                )
            else:
                asyncio.run(stdio(config, args.audit, args.approvals))
        elif args.command == "approve":
            arguments = json.loads(args.arguments)
            if not isinstance(arguments, dict):
                raise ValueError("arguments must be an object")
            Approvals(args.store).grant(args.tool, arguments, ttl=args.ttl)
            print(f"Issued one-use approval for {args.tool}; expires in {args.ttl}s.")
        elif args.command == "view":
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(render_audit(args.audit))
            print(output)
        elif args.command == "demo":
            return asyncio.run(demo(args.directory))
        elif args.command == "test":
            report = asyncio.run(evaluate(load_corpus(args.split), args.directory))
            report["split"] = args.split
            print(json.dumps(report, indent=2) if args.json else summary(report))
            return int(
                report["blocked"] != report["attacks"]
                or report["false_positives"] > 0
                or report["errors"] > 0
            )
    except AuditQueryError as exc:
        print(f"mcp-guard: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, RpcError) as exc:
        # No exception payloads: upstream configuration may contain credentials.
        print(
            f"mcp-guard: invalid configuration or runtime input ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        return 130
    return 0

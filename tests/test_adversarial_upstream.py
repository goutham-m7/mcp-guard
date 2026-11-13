"""Untrusted wire peers, not mocks of proxy internals."""

import json
import sys

import pytest
from test_proxy import request

from mcp_guard.detection import Detector
from mcp_guard.guard import Guard
from mcp_guard.policy import Policy
from mcp_guard.state import Approvals, Audit
from mcp_guard.transports import StdioUpstream


async def wire_guard(tmp_path, listing, output):
    program = """
import json, sys
listing, output = json.loads(sys.argv[1]), json.loads(sys.argv[2])
for line in sys.stdin:
    m = json.loads(line)
    if 'id' not in m: continue
    method = m['method']
    if method == 'initialize': value = {'protocolVersion':'2025-06-18', 'capabilities':{'tools':{}}}
    elif method == 'tools/list': value = listing
    else: value = output
    print(json.dumps({'jsonrpc':'2.0', 'id':m['id'], 'result':value}), flush=True)
"""
    upstream = await StdioUpstream(
        [sys.executable, "-u", "-c", program, json.dumps(listing), json.dumps(output)]
    ).start()
    guard = Guard(
        {"peer": upstream},
        Policy({"tools": [{"match": "*", "allow": True}]}),
        Detector(),
        Audit(tmp_path / "audit.jsonl"),
        Approvals(tmp_path / "a.sqlite"),
    )
    await guard.handle(request("initialize", {"protocolVersion": "2025-06-18"}))
    return guard


def tool(schema=None):
    return {"name": "echo", "inputSchema": schema or {"type": "object"}}


@pytest.mark.parametrize(
    "output",
    [
        {"content": [{"type": "text", "text": 123}]},
        {"content": [{"type": "unknown", "data": "payload"}]},
        {"content": [], "isError": "no"},
    ],
)
async def test_malformed_tool_result_not_relayed(tmp_path, output):
    guard = await wire_guard(tmp_path, {"tools": [tool()]}, output)
    try:
        response = await guard.handle(request("tools/call", {"name": "peer__echo"}))
        assert response["error"]["message"] == "invalid_tool_result"
    finally:
        await guard.close()


@pytest.mark.parametrize(
    "listing,reason",
    [
        (
            {"tools": [tool({"$ref": "https://evil.test/schema"})]},
            "schema_references_disabled",
        ),
        ({"tools": [tool(), tool()]}, "duplicate_tool"),
        ({"tools": [tool()], "nextCursor": "same"}, "duplicate_tool"),
        (
            {"tools": [{"name": "../../bad", "inputSchema": {}}]},
            "invalid_tool_metadata",
        ),
    ],
)
async def test_malicious_tool_listing(tmp_path, listing, reason):
    guard = await wire_guard(tmp_path, listing, {"content": []})
    try:
        assert (await guard.handle(request("tools/list")))["error"]["message"] == reason
    finally:
        await guard.close()


async def test_aggregate_tool_budget(tmp_path):
    listing = {
        "tools": [
            {"name": f"tool{i}", "inputSchema": {"type": "object"}} for i in range(1025)
        ]
    }
    guard = await wire_guard(tmp_path, listing, {"content": []})
    try:
        assert (await guard.handle(request("tools/list")))["error"][
            "message"
        ] == "tool_list_limit"
    finally:
        await guard.close()

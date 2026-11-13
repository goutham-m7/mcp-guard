import sys
import pytest
from mcp_guard.transports import StdioUpstream
from mcp_guard.guard import Guard
from mcp_guard.policy import Policy
from mcp_guard.detection import Detector
from mcp_guard.state import Audit, Approvals


def request(method, params=None, id=1):
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}}


async def make_guard(tmp_path, *, case="benign-weather", rules=None):
    upstream = StdioUpstream([sys.executable, "-m", "mcp_guard.demo_server", "--case", case])
    await upstream.start()
    guard = Guard({"demo": upstream}, Policy({"tools": rules or [{"match": "demo__*", "allow": True}]}), Detector(), Audit(tmp_path / "audit.jsonl"), Approvals(tmp_path / "a.sqlite"))
    return guard, upstream


@pytest.mark.asyncio
async def test_real_stdio_tools_journey(tmp_path):
    guard, upstream = await make_guard(tmp_path)
    try:
        init = await guard.handle(request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}))
        assert init["result"]["capabilities"] == {"tools": {"listChanged": True}}
        listed = await guard.handle(request("tools/list"))
        assert listed["result"]["tools"][0]["name"] == "demo__echo"
        response = await guard.handle(request("tools/call", {"name": "demo__echo", "arguments": {}}))
        assert "21" in response["result"]["content"][0]["text"]
        assert (await guard.handle(request("resources/list")))["error"]["code"] == -32601
    finally:
        await guard.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["injection-ignore", "secret-openai", "pii-email", "instruction-tool", "rug-pull"])
async def test_real_attacks_quarantined(tmp_path, case):
    guard, upstream = await make_guard(tmp_path, case=case)
    try:
        await guard.handle(request("initialize", {"protocolVersion": "2025-06-18"}))
        await guard.handle(request("tools/list"))
        response = await guard.handle(request("tools/call", {"name": "demo__echo", "arguments": {}}))
        assert response["error"]["code"] == -32001
        assert "content" not in response
    finally:
        await guard.close()


@pytest.mark.asyncio
async def test_confirmation_and_schema(tmp_path):
    guard, upstream = await make_guard(tmp_path, rules=[{"match": "demo__*", "allow": True, "confirm": True}])
    try:
        assert (await guard.handle(request("tools/list")))["error"]["message"] == "not_initialized"
        await guard.handle(request("initialize", {"protocolVersion": "2025-06-18"}))
        call = request("tools/call", {"name": "demo__echo", "arguments": {}})
        assert (await guard.handle(call))["error"]["message"] == "confirmation_required"
        guard.approvals.grant("demo__echo", {})
        assert "result" in await guard.handle(call)
        assert (await guard.handle(call))["error"]["message"] == "confirmation_required"
        bad = request("tools/call", {"name": "demo__echo", "arguments": {"unexpected": 3}})
        assert (await guard.handle(bad))["error"]["message"] == "invalid_arguments"
    finally:
        await guard.close()

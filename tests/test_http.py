import json
import sys

import httpx
import pytest
from aiohttp import web

from mcp_guard.config import Config
from mcp_guard.corpus import load_corpus
from mcp_guard.demo_server import http_app
from mcp_guard.server import create_app
from mcp_guard.transports import HttpUpstream


async def serve(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}/mcp"


@pytest.mark.asyncio
@pytest.mark.parametrize("sse", [False, True])
async def test_upstream_json_and_sse(sse):
    runner, url = await serve(
        http_app(next(c for c in load_corpus() if c["id"] == "benign-weather"), sse)
    )
    upstream = HttpUpstream(url)
    try:
        assert (
            await upstream.request("initialize", {"protocolVersion": "2025-06-18"})
        )["protocolVersion"] == "2025-06-18"
        await upstream.notify("notifications/initialized")
        assert len((await upstream.request("tools/list"))["tools"]) == 5
        assert (
            "21"
            in (
                await upstream.request("tools/call", {"name": "echo", "arguments": {}})
            )["content"][0]["text"]
        )
    finally:
        await upstream.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_downstream_auth_sessions_sse_and_cleanup(tmp_path):
    config = Config(
        {
            "servers": {
                "demo": {"command": [sys.executable, "-m", "mcp_guard.demo_server"]}
            },
            "policy": {"tools": [{"match": "*", "allow": True}]},
        },
        tmp_path,
    )
    runner, url = await serve(
        create_app(config, "x" * 32, tmp_path / "audit.jsonl", tmp_path / "a.sqlite")
    )
    headers = {"Authorization": "Bearer " + "x" * 32}
    async with httpx.AsyncClient() as client:
        try:
            assert (await client.post(url, json={})).status_code == 401
            assert (
                await client.post(
                    url, headers={**headers, "Origin": "https://evil.test"}, json={}
                )
            ).status_code == 403
            init = await client.post(
                url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
            )
            assert init.status_code == 200
            session = init.headers["Mcp-Session-Id"]
            scoped = {
                **headers,
                "Mcp-Session-Id": session,
                "MCP-Protocol-Version": "2025-06-18",
            }
            listed = await client.post(
                url,
                headers={**scoped, "Accept": "text/event-stream"},
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )
            payload = json.loads(listed.text.split("data: ")[1])
            assert payload["result"]["tools"][0]["name"] == "demo__echo"
            call = await client.post(
                url,
                headers=scoped,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "demo__echo", "arguments": {}},
                },
            )
            assert "21" in call.json()["result"]["content"][0]["text"]
            assert (await client.delete(url, headers=scoped)).status_code == 204
            assert (await client.post(url, headers=scoped, json={})).status_code == 404
        finally:
            await runner.cleanup()


def test_invalid_config_fails_early(tmp_path):
    with pytest.raises(ValueError):
        Config(
            {"servers": {"bad__name": {"command": []}}, "policy": {"tools": []}},
            tmp_path,
        )

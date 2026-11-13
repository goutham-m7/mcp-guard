"""Independent official SDK is a test-only client, not proxy implementation."""

import sys

import httpx2
import yaml
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from test_http import serve

from mcp_guard.config import Config
from mcp_guard.server import create_app


def config_data():
    return {
        "servers": {
            "demo": {"command": [sys.executable, "-m", "mcp_guard.demo_server"]}
        },
        "policy": {"tools": [{"match": "demo__*", "allow": True}]},
    }


async def journey(read, write):
    async with ClientSession(read, write, read_timeout_seconds=5) as session:
        initialized = await session.initialize()
        assert initialized.server_info.name == "mcp-guard"
        assert initialized.protocol_version == "2025-06-18"
        tools = await session.list_tools()
        assert tools.tools[0].name == "demo__echo"
        response = await session.call_tool("demo__echo", {})
        assert not response.is_error and "21" in response.content[0].text


async def test_official_sdk_stdio(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump(config_data()))
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "mcp_guard",
            "proxy",
            "--config",
            str(config),
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--approvals",
            str(tmp_path / "a.sqlite"),
        ],
    )
    async with stdio_client(server) as (read, write):
        await journey(read, write)


async def test_official_sdk_streamable_http(tmp_path):
    config = Config(config_data(), tmp_path)
    runner, url = await serve(
        create_app(config, "z" * 32, tmp_path / "audit.jsonl", tmp_path / "a.sqlite")
    )
    try:
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + "z" * 32}
        ) as client:
            async with streamable_http_client(url, http_client=client) as (read, write):
                await journey(read, write)
    finally:
        await runner.cleanup()

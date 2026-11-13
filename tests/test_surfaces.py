import sys

import pytest

from mcp_guard.detection import Detector
from mcp_guard.evaluation import INITIALIZE, request
from mcp_guard.guard import Guard
from mcp_guard.policy import Policy
from mcp_guard.state import Approvals, Audit
from mcp_guard.transports import StdioUpstream


async def make(tmp_path, case="benign-weather"):
    upstream = await StdioUpstream(
        [sys.executable, "-m", "mcp_guard.demo_server", "--case", case]
    ).start()
    policy = Policy(
        {
            "tools": [],
            "resources": [{"match": "*", "allow": True}],
            "prompts": [{"match": "demo__*", "allow": True}],
        }
    )
    guard = Guard(
        {"demo": upstream},
        policy,
        Detector(),
        Audit(tmp_path / "audit"),
        Approvals(tmp_path / "a.sqlite"),
    )
    init = await guard.handle(request("initialize", INITIALIZE))
    assert "resources" in init["result"]["capabilities"]
    return guard


@pytest.mark.parametrize(
    "surface,operation,key", [("resources", "read", "uri"), ("prompts", "get", "name")]
)
async def test_real_surface_journey(tmp_path, surface, operation, key):
    guard = await make(tmp_path)
    try:
        listing = await guard.handle(request(surface + "/list"))
        identity = listing["result"][surface][0][key]
        assert (
            identity.startswith("mcp-guard://demo/")
            if key == "uri"
            else identity == "demo__summary"
        )
        response = await guard.handle(
            request(f"{surface}/{operation}", {key: identity})
        )
        assert "21 C" in str(response["result"])
        assert "error" in await guard.handle(
            request(f"{surface}/{operation}", {key: "forged"})
        )
    finally:
        await guard.close()


@pytest.mark.parametrize(
    "surface,operation,key", [("resources", "read", "uri"), ("prompts", "get", "name")]
)
@pytest.mark.parametrize("case", ["injection-ignore", "poison-authority", "rug-pull"])
async def test_surface_hostile_data_and_changes(
    tmp_path, surface, operation, key, case
):
    guard = await make(tmp_path, case)
    try:
        listing = await guard.handle(request(surface + "/list"))
        if case == "poison-authority":
            assert listing["error"]["message"].startswith("metadata_")
        else:
            identity = listing["result"][surface][0][key]
            response = await guard.handle(
                request(f"{surface}/{operation}", {key: identity})
            )
            assert response["error"]["message"] == (
                "rug_pull" if case == "rug-pull" else "output_injection"
            )
    finally:
        await guard.close()


async def test_prompt_arguments_and_leaf_deny(tmp_path):
    guard = await make(tmp_path)
    try:
        response = await guard.handle(
            request(
                "prompts/get",
                {"name": "demo__summary", "arguments": {"unexpected": "x"}},
            )
        )
        assert response["error"]["message"] == "invalid_arguments"
        guard.policy.config["resources"] = []
        assert (await guard.handle(request("resources/list")))["result"] == {
            "resources": []
        }
    finally:
        await guard.close()


@pytest.mark.parametrize(
    "surface,value",
    [
        ("resources", {"contents": [{"uri": "x", "blob": "aGVsbG8="}]}),
        (
            "prompts",
            {"messages": [{"role": "user", "content": {"type": "image", "data": "x"}}]},
        ),
    ],
)
def test_binary_surfaces_fail_closed(surface, value):
    from mcp_guard.policy import Denied
    from mcp_guard.surfaces import validate_result

    with pytest.raises(Denied, match="unscannable"):
        validate_result(value, surface)


@pytest.mark.parametrize(
    "surface,value",
    [
        ("resources", {"contents": [{"uri": "x", "text": 3}]}),
        (
            "prompts",
            {
                "messages": [
                    {"role": "system", "content": {"type": "text", "text": "x"}}
                ]
            },
        ),
    ],
)
def test_malformed_surfaces_fail_closed(surface, value):
    from mcp_guard.rpc import RpcError
    from mcp_guard.surfaces import validate_result

    with pytest.raises(RpcError):
        validate_result(value, surface)


async def test_paginated_surface_inventory(tmp_path):
    from types import SimpleNamespace

    from mcp_guard.rpc import RpcError
    from mcp_guard.surfaces import refresh

    class Peer:
        async def request(self, method, params):
            if not params:
                return {
                    "resources": [{"name": "one", "uri": "fixture:///one"}],
                    "nextCursor": "next",
                }
            return {"resources": [{"name": "two", "uri": "fixture:///two"}]}

    guard = SimpleNamespace(
        upstreams={"a": Peer()},
        pins={},
        quarantined=set(),
        detector=Detector(),
        upstream_capabilities={"a": {"resources": {}}},
    )
    assert len(await refresh(guard, "resources")) == 2

    class LoopPeer:
        async def request(self, method, params):
            return {"resources": [], "nextCursor": "same"}

    guard.upstreams = {"a": LoopPeer()}
    with pytest.raises(RpcError, match="invalid_pagination"):
        await refresh(guard, "resources")


async def test_resource_inventory_skips_tool_only_servers(tmp_path):
    guard = await make(tmp_path)

    class ToolOnly:
        async def request(self, method, params):
            if method == "initialize":
                return {
                    "protocolVersion": params["protocolVersion"],
                    "capabilities": {"tools": {}},
                }
            raise AssertionError("resource calls must not reach a tool-only server")

        async def close(self):
            pass

    await guard.close()
    upstream = await StdioUpstream(
        [sys.executable, "-m", "mcp_guard.demo_server"]
    ).start()
    guard.upstreams = {"demo": upstream, "toolsonly": ToolOnly()}
    guard.initialized = False
    try:
        await guard.handle(request("initialize", INITIALIZE))
        listing = await guard.handle(request("resources/list"))
        assert len(listing["result"]["resources"]) == 1
    finally:
        await guard.close()


async def test_tool_discovery_skips_resource_only_servers(tmp_path):
    guard = await make(tmp_path)

    class ResourceOnly:
        async def request(self, method, params):
            raise AssertionError("tools/list must not reach resource-only servers")

        async def close(self):
            pass

    guard.upstreams["resourcesonly"] = ResourceOnly()
    guard.upstream_capabilities["resourcesonly"] = {"resources": {}}
    try:
        assert (await guard.handle(request("tools/list")))["result"] == {"tools": []}
    finally:
        await guard.close()

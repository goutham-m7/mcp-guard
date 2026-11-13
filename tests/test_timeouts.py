import asyncio
import time

import pytest
from aiohttp import web
from test_http import serve

from mcp_guard.rpc import RpcError
from mcp_guard.transports import HttpUpstream, response_value


async def test_sse_heartbeat_does_not_extend_absolute_deadline():
    async def heartbeat(request):
        stream = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await stream.prepare(request)
        try:
            for _ in range(100):
                await stream.write(b": heartbeat\n\n")
                await asyncio.sleep(0.01)
        except ConnectionResetError:
            pass
        return stream

    app = web.Application()
    app.router.add_post("/mcp", heartbeat)
    runner, url = await serve(app)
    upstream = HttpUpstream(url, timeout=0.05)
    started = time.monotonic()
    try:
        with pytest.raises(RpcError, match="upstream_http_error"):
            await asyncio.wait_for(upstream.request("ping"), 0.3)
        assert time.monotonic() - started < 0.3
    finally:
        await upstream.close()
        await runner.cleanup()


def test_bool_is_not_a_response_request_id():
    with pytest.raises(RpcError):
        response_value({"jsonrpc": "2.0", "id": True, "result": {}}, 1)

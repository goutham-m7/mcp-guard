"""Loopback-only authenticated MCP HTTP endpoint, isolated per client session."""

import asyncio
import contextlib
import hmac
import json
import secrets
import time
from urllib.parse import urlsplit

from aiohttp import web

from .rpc import MAX_BYTES, VERSIONS, RpcError, decode, error


def create_app(config, token, audit_path, approvals_path):
    if len(token) < 24:
        raise ValueError("HTTP token must contain at least 24 characters")
    sessions = {}
    creation_lock = asyncio.Lock()

    @web.middleware
    async def security(request, handler):
        if urlsplit("//" + request.host).hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise web.HTTPForbidden(text="invalid Host")
        if request.headers.get("Origin") not in (
            None,
            f"{request.scheme}://{request.host}",
        ):
            raise web.HTTPForbidden(text="invalid Origin")
        if not hmac.compare_digest(
            request.headers.get("Authorization", ""), "Bearer " + token
        ):
            raise web.HTTPUnauthorized(text="bearer token required")
        return await handler(request)

    async def handler(request):
        if request.method not in {"POST", "GET", "DELETE"}:
            raise web.HTTPMethodNotAllowed(request.method, ["POST", "GET", "DELETE"])
        async with creation_lock:
            for sid, (guard, touched, _) in list(sessions.items()):
                if time.monotonic() - touched > 600:
                    del sessions[sid]
                    await guard.close()
        session_id = request.headers.get("Mcp-Session-Id")
        if request.method == "POST":
            if request.content_type != "application/json":
                raise web.HTTPUnsupportedMediaType()
            try:
                message = decode(await request.read())
            except RpcError as exc:
                return web.json_response(error(None, exc.code, exc.reason), status=400)
            if not session_id:
                if (
                    not isinstance(message, dict)
                    or message.get("method") != "initialize"
                ):
                    raise web.HTTPBadRequest(text="initialize a session first")
                async with creation_lock:
                    if len(sessions) >= 32:
                        raise web.HTTPServiceUnavailable(text="session limit")
                    guard = await config.build(audit_path, approvals_path)
                    response = await guard.handle(message)
                    if response is None or "error" in response:
                        await guard.close()
                        return web.json_response(
                            response or error(None, -32600, "invalid_initialize"),
                            status=400,
                        )
                    session_id = secrets.token_urlsafe(32)
                    version = response["result"]["protocolVersion"]
                    sessions[session_id] = (guard, time.monotonic(), version)
            else:
                guard, version = get_session(request, session_id)
                response = await guard.handle(message)
            if response is None:
                return web.Response(status=202)
            headers = {"Mcp-Session-Id": session_id, "Cache-Control": "no-store"}
            if "text/event-stream" in request.headers.get(
                "Accept", ""
            ) and "application/json" not in request.headers.get("Accept", ""):
                return web.Response(
                    text="event: message\ndata: " + json.dumps(response) + "\n\n",
                    content_type="text/event-stream",
                    headers=headers,
                )
            return web.json_response(response, headers=headers)
        guard, version = get_session(request, session_id)
        if request.method == "DELETE":
            del sessions[session_id]
            await guard.close()
            return web.Response(status=204)
        if "text/event-stream" not in request.headers.get("Accept", ""):
            raise web.HTTPNotAcceptable()
        stream = web.StreamResponse(
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store"}
        )
        await stream.prepare(request)
        try:
            await stream.write(b": mcp-guard notification stream\n\n")
            while session_id in sessions:
                try:
                    event = await asyncio.wait_for(guard.events.get(), 15)
                    await stream.write(
                        ("event: message\ndata: " + json.dumps(event) + "\n\n").encode()
                    )
                except TimeoutError:
                    await stream.write(b": keepalive\n\n")
        except (ConnectionError, asyncio.CancelledError):
            pass
        return stream

    def get_session(request, session_id):
        if session_id not in sessions:
            raise web.HTTPNotFound(text="unknown session")
        guard, _, version = sessions[session_id]
        header = request.headers.get("MCP-Protocol-Version")
        if header not in VERSIONS or header != version:
            raise web.HTTPBadRequest(text="invalid protocol version header")
        sessions[session_id] = (guard, time.monotonic(), version)
        return guard, version

    async def cleanup(app):
        for guard, _, _ in sessions.values():
            with contextlib.suppress(Exception):
                await guard.close()
        sessions.clear()

    app = web.Application(client_max_size=MAX_BYTES, middlewares=[security])
    app.router.add_route("*", "/mcp", handler)
    app.on_cleanup.append(cleanup)
    return app

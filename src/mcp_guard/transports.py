"""Serialized, bounded stdio and Streamable HTTP/SSE upstream adapters."""

import asyncio
import json
import os
from collections import deque

import httpx

from .rpc import MAX_BYTES, RpcError, decode, error


def response_value(message, request_id):
    if (
        not isinstance(message, dict)
        or message.get("jsonrpc") != "2.0"
        or message.get("id") != request_id
        or type(message.get("id")) is not type(request_id)
        or ("result" in message) == ("error" in message)
    ):
        raise RpcError(-32002, "invalid_upstream_response")
    if "error" in message:
        raise RpcError(-32002, "upstream_error")
    return message["result"]


class StdioUpstream:
    def __init__(self, command, env=None, timeout=15):
        self.command, self.env, self.timeout = command, env or {}, timeout
        self.process = None
        self.lock = asyncio.Lock()
        self.counter = 0
        self.notifications = deque(maxlen=100)

    async def start(self):
        environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "TMPDIR")
            if key in os.environ
        }
        environment.update(self.env)
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=MAX_BYTES + 1,
        )
        return self

    async def _send(self, value):
        self.process.stdin.write(json.dumps(value, allow_nan=False).encode() + b"\n")
        await self.process.stdin.drain()

    async def request(self, method, params=None):
        async with self.lock:
            self.counter += 1
            request_id = self.counter
            try:
                async with asyncio.timeout(self.timeout):
                    await self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": method,
                            "params": params or {},
                        }
                    )
                    for _ in range(100):
                        raw = await self.process.stdout.readline()
                        if not raw:
                            raise RpcError(-32002, "upstream_closed")
                        message = decode(raw)
                        if isinstance(message, dict) and "method" in message:
                            if "id" in message:
                                await self._send(
                                    error(
                                        message["id"],
                                        -32601,
                                        "server_requests_disabled",
                                    )
                                )
                            elif (
                                message["method"] == "notifications/tools/list_changed"
                            ):
                                self.notifications.append(
                                    {"jsonrpc": "2.0", "method": message["method"]}
                                )
                            continue
                        return response_value(message, request_id)
                    raise RpcError(-32002, "upstream_message_limit")
            except (TimeoutError, ValueError, OSError) as exc:
                await self.close()
                raise RpcError(-32002, "upstream_transport_error") from exc

    async def notify(self, method, params=None):
        async with self.lock:
            await self._send(
                {"jsonrpc": "2.0", "method": method, "params": params or {}}
            )

    async def close(self):
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 2)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()


class HttpUpstream:
    def __init__(self, url, headers=None, timeout=15):
        self.url, self.session = url, None
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout, headers=headers, follow_redirects=False
        )
        self.lock, self.counter = asyncio.Lock(), 0
        self.version = "2025-06-18"
        self.notifications = deque(maxlen=100)

    async def start(self):
        return self

    def headers(self):
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.version,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    async def _post(self, message):
        async with self.client.stream(
            "POST", self.url, headers=self.headers(), json=message
        ) as response:
            response.raise_for_status()
            if session := response.headers.get("Mcp-Session-Id"):
                self.session = session
            if response.status_code == 202:
                if "id" in message:
                    raise RpcError(-32002, "missing_upstream_response")
                return None
            is_sse = (
                response.headers.get("content-type", "").split(";")[0]
                == "text/event-stream"
            )
            total, body, data = 0, bytearray(), []
            if is_sse:
                async for line in response.aiter_lines():
                    total += len(line.encode()) + 1
                    if total > MAX_BYTES:
                        raise RpcError(-32002, "upstream_too_large")
                    if line.startswith("data:"):
                        data.append(line[5:].lstrip(" "))
                    elif line == "" and data:
                        event = decode("\n".join(data).encode())
                        data = []
                        if isinstance(event, dict) and "method" in event:
                            if "id" in event:
                                raise RpcError(-32002, "server_requests_disabled")
                            if event["method"] == "notifications/tools/list_changed":
                                self.notifications.append(
                                    {"jsonrpc": "2.0", "method": event["method"]}
                                )
                            continue
                        return response_value(event, message.get("id"))
                raise RpcError(-32002, "incomplete_sse_response")
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise RpcError(-32002, "upstream_too_large")
            return response_value(decode(body), message.get("id"))

    async def request(self, method, params=None):
        async with self.lock:
            self.counter += 1
            try:
                async with asyncio.timeout(self.timeout):
                    value = await self._post(
                        {
                            "jsonrpc": "2.0",
                            "id": self.counter,
                            "method": method,
                            "params": params or {},
                        }
                    )
                if method == "initialize":
                    self.version = value["protocolVersion"]
                return value
            except (httpx.HTTPError, TimeoutError) as exc:
                raise RpcError(-32002, "upstream_http_error") from exc

    async def notify(self, method, params=None):
        async with self.lock:
            try:
                async with asyncio.timeout(self.timeout):
                    await self._post(
                        {"jsonrpc": "2.0", "method": method, "params": params or {}}
                    )
            except (httpx.HTTPError, TimeoutError) as exc:
                raise RpcError(-32002, "upstream_http_error") from exc

    async def close(self):
        if self.session:
            try:
                await self.client.delete(self.url, headers=self.headers())
            except httpx.HTTPError:
                pass
        await self.client.aclose()

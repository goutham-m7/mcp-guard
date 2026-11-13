"""The trust boundary: validate, pin metadata, constrain, execute, inspect."""

import asyncio
import copy
import json
import re

import jsonschema

from . import __version__
from .policy import Denied
from .rpc import MAX_BYTES, VERSIONS, RpcError, error, result, validate_request
from .state import fingerprint
from .surfaces import dispatch as dispatch_surface


class Guard:
    def __init__(self, upstreams, policy, detector, audit, approvals):
        if not upstreams or any(
            not re.fullmatch(r"[a-zA-Z0-9-]+", n) for n in upstreams
        ):
            raise ValueError("invalid server names")
        self.upstreams, self.policy, self.detector = upstreams, policy, detector
        self.audit, self.approvals = audit, approvals
        self.pins, self.quarantined, self.tools = {}, set(), {}
        self.upstream_capabilities = {}
        self.initialized = False
        self.lock = asyncio.Lock()
        self.events = asyncio.Queue(maxsize=100)

    async def close(self):
        await asyncio.gather(*(u.close() for u in self.upstreams.values()))

    async def refresh(self):
        tools = {}
        metadata_bytes = 0
        for server, upstream in self.upstreams.items():
            if "tools" not in self.upstream_capabilities.get(server, {}):
                continue
            cursor, seen = None, set()
            for _ in range(100):
                listing = await upstream.request(
                    "tools/list", {"cursor": cursor} if cursor else {}
                )
                if not isinstance(listing, dict) or not isinstance(
                    listing.get("tools"), list
                ):
                    raise RpcError(-32002, "invalid_tool_list")
                for tool in listing["tools"]:
                    if (
                        not isinstance(tool, dict)
                        or not isinstance(tool.get("name"), str)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", tool["name"])
                        or not isinstance(tool.get("inputSchema"), dict)
                    ):
                        raise RpcError(-32002, "invalid_tool_metadata")
                    name = f"{server}__{tool['name']}"
                    if name in tools:
                        raise RpcError(-32002, "duplicate_tool")
                    metadata_bytes += len(json.dumps(tool, ensure_ascii=False).encode())
                    if (
                        len(tools) >= 1024
                        or metadata_bytes > MAX_BYTES
                        or (name not in self.pins and len(self.pins) >= 4096)
                    ):
                        raise RpcError(-32002, "tool_list_limit")
                    digest = fingerprint(tool)
                    if name in self.pins and self.pins[name] != digest:
                        self.quarantined.add(name)
                        raise Denied("rug_pull")
                    if name in self.quarantined:
                        raise Denied("tool_quarantined")
                    findings = await self.detector.scan(tool)
                    if findings:
                        self.quarantined.add(name)
                        raise Denied("metadata_" + findings[0])
                    try:
                        jsonschema.Draft202012Validator.check_schema(
                            tool["inputSchema"]
                        )
                    except jsonschema.SchemaError as exc:
                        raise RpcError(-32002, "invalid_tool_schema") from exc
                    # External schema retrieval crosses another trust boundary: reject refs.
                    if contains_ref(tool["inputSchema"]):
                        raise RpcError(-32002, "schema_references_disabled")
                    self.pins[name] = digest
                    tools[name] = (server, copy.deepcopy(tool))
                cursor = listing.get("nextCursor")
                if cursor is None:
                    break
                if not isinstance(cursor, str) or cursor in seen:
                    raise RpcError(-32002, "invalid_pagination")
                seen.add(cursor)
            else:
                raise RpcError(-32002, "pagination_limit")
            while upstream.notifications:
                upstream.notifications.popleft()
                if not self.events.full():
                    self.events.put_nowait(
                        {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
                    )
        self.tools = tools

    async def handle(self, message):
        async with self.lock:
            request_id = (
                message.get("id")
                if isinstance(message, dict) and type(message.get("id")) in (int, str)
                else None
            )
            method, findings, decision = "invalid", [], "allowed"
            try:
                validate_request(message)
                method = message["method"]
                if len(json.dumps(message, allow_nan=False).encode()) > MAX_BYTES:
                    raise RpcError(-32600, "message_too_large")
                value = await self.dispatch(
                    method, message.get("params", {}), "id" in message
                )
                response = result(request_id, value)
            except Denied as exc:
                decision, findings = "blocked", [str(exc)]
                response = error(request_id, -32001, str(exc))
            except RpcError as exc:
                decision, findings = "error", [exc.reason]
                response = error(request_id, exc.code, exc.reason)
            except Exception:
                decision, findings = "error", ["internal_or_upstream_error"]
                response = error(request_id, -32603, "internal_or_upstream_error")
            # Audit failure is fail-closed: never return a successful unlogged call.
            try:
                self.audit.record(method, decision, findings, message)
            except (OSError, ValueError, TypeError):
                response = error(request_id, -32603, "audit_unavailable")
            return (
                response
                if not isinstance(message, dict)
                or "id" in message
                or method == "invalid"
                else None
            )

    async def dispatch(self, method, params, has_id):
        if not has_id:
            if method == "notifications/initialized" and self.initialized:
                for upstream in self.upstreams.values():
                    await upstream.notify(method)
                return None
            if method == "notifications/cancelled":
                return None  # Serial calls cannot be cancelled; never forward an untrusted ID.
            raise RpcError(-32600, "unsupported_notification")
        if method == "initialize":
            if self.initialized:
                raise RpcError(-32600, "already_initialized")
            version = params.get("protocolVersion")
            if not isinstance(version, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}", version
            ):
                raise RpcError(-32602, "unsupported_protocol_version")
            if version not in VERSIONS:
                version = max(VERSIONS)
            for server, upstream in self.upstreams.items():
                info = await upstream.request(
                    method,
                    {
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-guard", "version": __version__},
                    },
                )
                if info.get("protocolVersion") not in VERSIONS:
                    raise RpcError(-32002, "upstream_protocol_mismatch")
                capabilities = info.get("capabilities", {})
                if not isinstance(capabilities, dict):
                    raise RpcError(-32002, "invalid_upstream_capabilities")
                self.upstream_capabilities[server] = capabilities
            self.initialized = True
            return {
                "protocolVersion": version,
                "capabilities": {
                    "tools": {"listChanged": True},
                    **{
                        s: {}
                        for s in ("resources", "prompts")
                        if s in self.policy.config
                    },
                },
                "serverInfo": {"name": "mcp-guard", "version": __version__},
            }
        if not self.initialized:
            raise RpcError(-32000, "not_initialized")
        if method == "ping":
            return {}
        if method in {
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
        }:
            if method.split("/")[0] not in self.policy.config:
                raise RpcError(-32601, "method_not_supported")
            return await dispatch_surface(self, method, params)
        if method not in {"tools/list", "tools/call"}:
            raise RpcError(-32601, "method_not_supported")
        await self.refresh()
        if method == "tools/list":
            if params:
                raise RpcError(-32602, "pagination_not_required")
            visible = []
            for name, (_, tool) in self.tools.items():
                if self.policy.visible(name):
                    visible.append({**tool, "name": name})
            return {"tools": visible}
        name, arguments = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise RpcError(-32602, "invalid_arguments")
        if name not in self.tools:
            raise Denied("unknown_tool")
        server, tool = self.tools[name]
        try:
            jsonschema.Draft202012Validator(tool["inputSchema"]).validate(arguments)
        except jsonschema.ValidationError as exc:
            raise RpcError(-32602, "invalid_arguments") from exc
        confirmation = self.policy.check(name, arguments)
        if confirmation and not self.approvals.consume(name, arguments):
            raise Denied("confirmation_required")
        value = await self.upstreams[server].request(
            "tools/call", {"name": tool["name"], "arguments": arguments}
        )
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("content"), list)
            or type(value.get("isError", False)) is not bool
            or (
                "structuredContent" in value
                and not isinstance(value["structuredContent"], dict)
            )
        ):
            raise RpcError(-32002, "invalid_tool_result")
        for block in value["content"]:
            if not isinstance(block, dict) or block.get("type") not in {
                "text",
                "resource",
                "image",
                "audio",
                "resource_link",
            }:
                raise RpcError(-32002, "invalid_tool_result")
            if block["type"] == "text" and not isinstance(block.get("text"), str):
                raise RpcError(-32002, "invalid_tool_result")
            if block["type"] == "resource":
                resource = block.get("resource")
                if (
                    not isinstance(resource, dict)
                    or not isinstance(resource.get("uri"), str)
                    or not isinstance(resource.get("text", resource.get("blob")), str)
                ):
                    raise RpcError(-32002, "invalid_tool_result")
        findings = await self.detector.scan(value)
        if findings:
            raise Denied("output_" + findings[0])
        return value


def contains_ref(value):
    if isinstance(value, dict):
        return any(
            key in {"$ref", "$dynamicRef", "$recursiveRef"} or contains_ref(item)
            for key, item in value.items()
        )
    return isinstance(value, list) and any(contains_ref(item) for item in value)

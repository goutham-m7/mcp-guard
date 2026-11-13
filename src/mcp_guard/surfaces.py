"""Opt-in text resource and prompt operations sharing the Guard trust boundary."""

import copy
import json
import re
from urllib.parse import quote

from .policy import Denied
from .rpc import MAX_BYTES, RpcError
from .state import fingerprint


def identity(server, item, surface):
    return (
        (f"mcp-guard://{server}/" + quote(item["uri"], safe=""))
        if surface == "resources"
        else f"{server}__{item['name']}"
    )


def validate_metadata(item, surface):
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        raise RpcError(-32002, "invalid_surface_metadata")
    if surface == "resources":
        if not isinstance(item.get("uri"), str) or not item["uri"]:
            raise RpcError(-32002, "invalid_surface_metadata")
    else:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item["name"]):
            raise RpcError(-32002, "invalid_surface_metadata")
        arguments = item.get("arguments", [])
        if not isinstance(arguments, list):
            raise RpcError(-32002, "invalid_surface_metadata")
        names = set()
        for arg in arguments:
            if (
                not isinstance(arg, dict)
                or not isinstance(arg.get("name"), str)
                or arg["name"] in names
                or type(arg.get("required", False)) is not bool
            ):
                raise RpcError(-32002, "invalid_surface_metadata")
            names.add(arg["name"])


def validate_result(value, surface):
    if not isinstance(value, dict):
        raise RpcError(-32002, "invalid_surface_result")
    blocks = value.get("contents" if surface == "resources" else "messages")
    if not isinstance(blocks, list):
        raise RpcError(-32002, "invalid_surface_result")
    for block in blocks:
        if not isinstance(block, dict):
            raise RpcError(-32002, "invalid_surface_result")
        if surface == "resources":
            if not isinstance(block.get("uri"), str):
                raise RpcError(-32002, "invalid_surface_result")
            if "blob" in block:
                raise Denied("output_unscannable")
            if not isinstance(block.get("text"), str):
                raise RpcError(-32002, "invalid_surface_result")
        else:
            content = block.get("content")
            if block.get("role") not in {"user", "assistant"} or not isinstance(
                content, dict
            ):
                raise RpcError(-32002, "invalid_surface_result")
            if content.get("type") != "text":
                raise Denied("output_unscannable")
            if not isinstance(content.get("text"), str):
                raise RpcError(-32002, "invalid_surface_result")


async def refresh(guard, surface):
    inventory, budget = {}, 0
    for server, upstream in guard.upstreams.items():
        cursor, seen = None, set()
        for _ in range(100):
            listing = await upstream.request(
                surface + "/list", {"cursor": cursor} if cursor is not None else {}
            )
            if not isinstance(listing, dict) or not isinstance(
                listing.get(surface), list
            ):
                raise RpcError(-32002, "invalid_surface_list")
            for item in listing[surface]:
                validate_metadata(item, surface)
                name = identity(server, item, surface)
                pin = (surface, name)
                budget += len(json.dumps(item, ensure_ascii=False).encode())
                if (
                    len(inventory) >= 1024
                    or budget > MAX_BYTES
                    or (pin not in guard.pins and len(guard.pins) >= 4096)
                ):
                    raise RpcError(-32002, "surface_list_limit")
                if name in inventory:
                    raise RpcError(-32002, "duplicate_surface_item")
                digest = fingerprint(item)
                if pin in guard.pins and guard.pins[pin] != digest:
                    guard.quarantined.add(pin)
                    raise Denied("rug_pull")
                if pin in guard.quarantined:
                    raise Denied("surface_quarantined")
                findings = await guard.detector.scan(item)
                if findings:
                    guard.quarantined.add(pin)
                    raise Denied("metadata_" + findings[0])
                guard.pins[pin] = digest
                inventory[name] = (server, copy.deepcopy(item))
            cursor = listing.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or cursor in seen:
                raise RpcError(-32002, "invalid_pagination")
            seen.add(cursor)
        else:
            raise RpcError(-32002, "pagination_limit")
    return inventory


async def dispatch(guard, method, params):
    surface, operation = method.split("/")
    inventory = await refresh(guard, surface)
    key = "uri" if surface == "resources" else "name"
    if operation == "list":
        if params:
            raise RpcError(-32602, "pagination_not_required")
        return {
            surface: [
                {**item, key: name}
                for name, (server, item) in inventory.items()
                if guard.policy.visible(name, surface=surface, server=server)
            ]
        }
    name = params.get(key)
    if not isinstance(name, str) or name not in inventory:
        raise Denied("unknown_surface_item")
    server, item = inventory[name]
    arguments = (
        params.get("arguments", {}) if surface == "prompts" else {"uri": item["uri"]}
    )
    allowed_keys = {key, "arguments"} if surface == "prompts" else {key}
    if set(params) - allowed_keys or not isinstance(arguments, dict):
        raise RpcError(-32602, "invalid_arguments")
    if surface == "prompts":
        declared = {arg["name"]: arg for arg in item.get("arguments", [])}
        if (
            set(arguments) - declared.keys()
            or any(not isinstance(v, str) for v in arguments.values())
            or any(
                arg.get("required", False) and n not in arguments
                for n, arg in declared.items()
            )
        ):
            raise RpcError(-32602, "invalid_arguments")
    confirmation = guard.policy.check(name, arguments, surface=surface, server=server)
    if confirmation and not guard.approvals.consume(name, arguments):
        raise Denied("confirmation_required")
    upstream_params = {key: item[key]}
    if surface == "prompts":
        upstream_params["arguments"] = arguments
    value = await guard.upstreams[server].request(method, upstream_params)
    validate_result(value, surface)
    findings = await guard.detector.scan(value)
    if findings:
        raise Denied("output_" + findings[0])
    if surface == "resources":
        # Returned identifiers must not offer an unguarded route around this proxy.
        value = copy.deepcopy(value)
        for block in value["contents"]:
            block["uri"] = identity(server, block, surface)
    return value

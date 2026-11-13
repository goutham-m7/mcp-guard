"""Bounded JSON-RPC 2.0 tools profile, deliberately no batching."""
import json

MAX_BYTES = 1_048_576
VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}


class RpcError(Exception):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason
        super().__init__(reason)


def decode(raw):
    if len(raw) > MAX_BYTES:
        raise RpcError(-32600, "message_too_large")
    try:
        return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RpcError(-32700, "parse_error") from exc


def validate_request(message):
    if (not isinstance(message, dict) or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
            or "result" in message or "error" in message
            or not isinstance(message.get("params", {}), dict)
            or ("id" in message and type(message["id"]) not in (int, str))):
        raise RpcError(-32600, "invalid_request")


def error(request_id, code, reason):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": reason}}


def result(request_id, value):
    return {"jsonrpc": "2.0", "id": request_id, "result": value}

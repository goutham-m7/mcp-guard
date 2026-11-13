"""Bounded-memory validation and filtering of versioned local audit exports."""

import json
import math
from importlib.resources import files

import jsonschema

from .rpc import MAX_BYTES


class AuditQueryError(ValueError):
    """A safe diagnostic containing a line number, never log contents."""


def query_audit(
    path, *, decision=None, method=None, reason=None, since=None, until=None, limit=100
):
    if not 1 <= limit <= 10000 or any(
        value is not None and (not math.isfinite(value) or value < 0)
        for value in (since, until)
    ):
        raise ValueError("invalid audit query bounds")
    if since is not None and until is not None and since > until:
        raise ValueError("invalid audit time range")
    schema = json.loads(
        files("mcp_guard").joinpath("data/audit.schema.json").read_text()
    )
    validator = jsonschema.Draft202012Validator(schema)
    rows = []
    with open(path, "rb") as stream:
        number = 0
        while line := stream.readline(MAX_BYTES + 1):
            number += 1
            try:
                if len(line) > MAX_BYTES:
                    raise ValueError("oversize")
                event = json.loads(line)
                validator.validate(event)
                if not math.isfinite(event["time"]):
                    raise ValueError("nonfinite")
            except (ValueError, UnicodeError, jsonschema.ValidationError) as exc:
                raise AuditQueryError(f"invalid audit record at line {number}") from exc
            if (
                len(rows) < limit
                and (decision is None or event["decision"] == decision)
                and (method is None or event["method"] == method)
                and (reason is None or reason in event["findings"])
                and (since is None or event["time"] >= since)
                and (until is None or event["time"] <= until)
            ):
                rows.append(event)
    return rows

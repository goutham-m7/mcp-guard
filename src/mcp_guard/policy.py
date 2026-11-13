"""Operator-authored, default-deny, conjunctive tool policy."""
from collections import defaultdict, deque
from fnmatch import fnmatchcase
from pathlib import Path
import ipaddress
import re
import time
from urllib.parse import unquote, urlsplit

import jsonschema
import yaml


class Denied(ValueError):
    """Safe, content-free reason for denying a request."""


SCHEMA = {
    "type": "object", "required": ["tools"], "additionalProperties": False,
    "properties": {"tools": {"type": "array", "items": {
        "type": "object", "required": ["match", "allow"], "additionalProperties": False,
        "properties": {
            "match": {"type": "string", "minLength": 1}, "allow": {"type": "boolean"},
            "confirm": {"type": "boolean"},
            "rate": {"type": "object", "required": ["calls", "seconds"], "additionalProperties": False,
                     "properties": {"calls": {"type": "integer", "minimum": 1}, "seconds": {"type": "number", "exclusiveMinimum": 0}}},
            "arguments": {"type": "object", "additionalProperties": {
                "type": "object", "minProperties": 1, "additionalProperties": False,
                "properties": {"regex": {"type": "string"}, "paths": {"type": "array", "minItems": 1, "items": {"type": "string"}}, "domains": {"type": "array", "minItems": 1, "items": {"type": "string"}}}}}
        }
    }}}
}


class Policy:
    def __init__(self, config):
        try:
            jsonschema.validate(config, SCHEMA)
            for rule in config["tools"]:
                for constraints in rule.get("arguments", {}).values():
                    if "regex" in constraints:
                        re.compile(constraints["regex"])
                    for path in constraints.get("paths", []):
                        if not Path(path).is_absolute():
                            raise ValueError("policy roots must be absolute")
        except (jsonschema.ValidationError, re.error) as exc:
            raise ValueError("invalid policy") from exc
        self.config = config
        self.windows = defaultdict(deque)

    @classmethod
    def load(cls, path):
        return cls(yaml.safe_load(Path(path).read_text()))

    def check(self, name, arguments, *, now=None):
        rules = [(i, r) for i, r in enumerate(self.config["tools"]) if fnmatchcase(name, r["match"])]
        if not rules or any(not r["allow"] for _, r in rules):
            raise Denied("tool_denied")
        now = time.monotonic() if now is None else now
        for index, rule in rules:
            for key, constraints in rule.get("arguments", {}).items():
                value = arguments.get(key)
                if not isinstance(value, str) or len(value) > 8192:
                    raise Denied("argument_constraint")
                if "regex" in constraints and re.fullmatch(constraints["regex"], value) is None:
                    raise Denied("argument_regex")
                if "paths" in constraints:
                    path = Path(value)
                    decoded = unquote(value)
                    if not path.is_absolute() or ".." in Path(decoded).parts or "\\" in decoded or "%" in decoded:
                        raise Denied("argument_path")
                    resolved = path.resolve()
                    if not any(resolved.is_relative_to(Path(root).resolve()) for root in constraints["paths"]):
                        raise Denied("argument_path")
                if "domains" in constraints:
                    try:
                        url = urlsplit(value)
                        host = url.hostname or ""
                        if (url.scheme != "https" or url.username or url.password or url.port not in (None, 443)
                                or "\\" in value or host.lower() not in constraints["domains"]):
                            raise Denied("argument_url")
                        try:
                            ipaddress.ip_address(host)
                        except ValueError:
                            pass
                        else:
                            raise Denied("argument_url")
                    except ValueError as exc:
                        raise Denied("argument_url") from exc
            if "rate" in rule:
                rate = rule["rate"]
                window = self.windows[(index, name)]
                while window and window[0] <= now - rate["seconds"]:
                    window.popleft()
                if len(window) >= rate["calls"]:
                    raise Denied("rate_limit")
        for index, rule in rules:
            if "rate" in rule:
                self.windows[(index, name)].append(now)
        return any(r.get("confirm", False) for _, r in rules)

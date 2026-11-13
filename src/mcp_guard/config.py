"""Trusted operator configuration; environment access stays at composition boundary."""

import os
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
import yaml

from .detection import Detector, MockClassifier, OpenAIClassifier
from .guard import Guard
from .policy import Policy
from .state import Approvals, Audit
from .transports import HttpUpstream, StdioUpstream

SCHEMA = {
    "type": "object",
    "required": ["servers", "policy"],
    "additionalProperties": False,
    "properties": {
        "policy": {"oneOf": [{"type": "string"}, {"type": "object"}]},
        "servers": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": 16,
            "propertyNames": {"pattern": "^[A-Za-z0-9-]+$"},
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "oneOf": [{"required": ["command"]}, {"required": ["url"]}],
                "properties": {
                    "command": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "minLength": 1},
                    },
                    "url": {"type": "string"},
                    "token_env": {"type": "string"},
                    "env": {
                        "type": "array",
                        "uniqueItems": True,
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "classifier": {
            "type": "object",
            "required": ["provider"],
            "additionalProperties": False,
            "properties": {
                "provider": {"enum": ["mock", "openai"]},
                "base_url": {"type": "string"},
                "key_env": {"type": "string"},
                "model": {"type": "string"},
            },
        },
    },
}


def validate_url(value):
    url = urlsplit(value)
    if (
        url.username
        or url.password
        or url.fragment
        or (
            url.scheme != "https"
            and not (
                url.scheme == "http"
                and url.hostname in {"127.0.0.1", "localhost", "::1"}
            )
        )
        or not url.hostname
    ):
        raise ValueError(
            "upstream URL requires HTTPS or loopback HTTP without credentials"
        )


class Config:
    def __init__(self, data, directory):
        try:
            jsonschema.validate(data, SCHEMA)
            for server in data["servers"].values():
                if "url" in server:
                    validate_url(server["url"])
            classifier = data.get("classifier", {})
            if classifier.get("provider") == "openai":
                for key in ("base_url", "key_env", "model"):
                    if not classifier.get(key):
                        raise ValueError(
                            "openai classifier requires base_url, key_env, model"
                        )
                validate_url(classifier["base_url"])
        except jsonschema.ValidationError as exc:
            raise ValueError("invalid config") from exc
        self.data, self.directory = data, Path(directory)
        policy = data["policy"]
        self.policy_data = (
            Policy.load(self.directory / policy).config
            if isinstance(policy, str)
            else Policy(policy).config
        )

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        return cls(yaml.safe_load(path.read_text()), path.parent)

    async def build(self, audit_path, approvals_path):
        upstreams = {}
        try:
            for name, server in self.data["servers"].items():
                if "command" in server:
                    upstream = StdioUpstream(
                        server["command"],
                        {key: os.environ[key] for key in server.get("env", [])},
                    )
                else:
                    headers = (
                        {"Authorization": "Bearer " + os.environ[server["token_env"]]}
                        if "token_env" in server
                        else {}
                    )
                    upstream = HttpUpstream(server["url"], headers)
                upstreams[name] = upstream
                await upstream.start()
            spec = self.data.get("classifier", {})
            classifier = None
            if spec.get("provider") == "mock":
                classifier = MockClassifier()
            elif spec.get("provider") == "openai":
                classifier = OpenAIClassifier(
                    spec["base_url"], os.environ[spec["key_env"]], spec["model"]
                )
            return Guard(
                upstreams,
                Policy(self.policy_data),
                Detector(classifier),
                Audit(audit_path),
                Approvals(approvals_path),
            )
        except BaseException:
            for upstream in upstreams.values():
                await upstream.close()
            raise

import json
import sys
from importlib.resources import files

import jsonschema
import pytest

from mcp_guard.cli import main
from mcp_guard.state import Audit


def test_versioned_audit_export(tmp_path):
    path = tmp_path / "audit.jsonl"
    Audit(path).record(
        "tools/call", "blocked", ["tool_denied"], {"password": "private-value"}
    )
    event = json.loads(path.read_text())
    assert event["schema_version"] == 1
    assert "private-value" not in path.read_text()
    schema = json.loads(
        files("mcp_guard").joinpath("data/audit.schema.json").read_text()
    )
    jsonschema.validate(event, schema)
    assert path.stat().st_mode & 0o777 == 0o600


def test_query_filters_and_limits(monkeypatch, tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    audit = Audit(path)
    audit.record("tools/list", "allowed", [], {})
    audit.record("tools/call", "blocked", ["output_injection"], {})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mcp-guard",
            "audit",
            "query",
            str(path),
            "--decision",
            "blocked",
            "--method",
            "tools/call",
            "--reason",
            "output_injection",
            "--since",
            "0",
            "--limit",
            "1",
        ],
    )
    assert main() == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows) == 1 and rows[0]["decision"] == "blocked"


def test_query_validates_after_limit(monkeypatch, tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    Audit(path).record("ping", "allowed", [], {})
    with path.open("a") as stream:
        stream.write("not-json secret-value\n")
    monkeypatch.setattr(
        sys, "argv", ["mcp-guard", "audit", "query", str(path), "--limit", "1"]
    )
    assert main() == 2
    captured = capsys.readouterr()
    assert "line 2" in captured.err
    assert not captured.out
    assert "secret-value" not in captured.err


@pytest.mark.parametrize(
    "extra", [["--since", "nan"], ["--limit", "0"], ["--since", "2", "--until", "1"]]
)
def test_query_rejects_invalid_bounds(monkeypatch, tmp_path, extra):
    path = tmp_path / "audit.jsonl"
    path.touch()
    monkeypatch.setattr(sys, "argv", ["mcp-guard", "audit", "query", str(path), *extra])
    assert main() == 2

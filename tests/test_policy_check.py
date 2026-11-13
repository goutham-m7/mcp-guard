import json
import sys

from mcp_guard.cli import main


def run(monkeypatch, path, *extra):
    monkeypatch.setattr(
        sys, "argv", ["mcp-guard", "policy", "check", str(path), "--json", *extra]
    )
    return main()


def test_policy_check_valid_and_warning(monkeypatch, tmp_path, capsys):
    path = tmp_path / "p.yaml"
    path.write_text('tools:\n  - {match: "*", allow: true}\n')
    assert run(monkeypatch, path) == 0
    assert json.loads(capsys.readouterr().out)["warnings"][0]["code"] == "broad_grant"
    assert run(monkeypatch, path, "--strict") == 1


def test_policy_check_errors_are_payload_free(monkeypatch, tmp_path, capsys):
    path = tmp_path / "p.yaml"
    path.write_text("tools: [{match: secret-value, allow: maybe}]")
    assert run(monkeypatch, path) == 2
    output = capsys.readouterr().out
    assert json.loads(output)["errors"]
    assert "secret-value" not in output
    path.write_text("tools: [")
    assert run(monkeypatch, path) == 2


def test_policy_check_duplicate_and_conflict(monkeypatch, tmp_path, capsys):
    path = tmp_path / "p.yaml"
    path.write_text(
        "tools:\n - {match: x, allow: true}\n - {match: x, allow: true}\n - {match: x, allow: false}\n"
    )
    assert run(monkeypatch, path) == 0
    codes = {r["code"] for r in json.loads(capsys.readouterr().out)["warnings"]}
    assert codes == {"duplicate_rule", "deny_shadows_grant"}

import json
import subprocess
import sys


def cli(*args):
    return subprocess.run([sys.executable, "-m", "mcp_guard", *args], capture_output=True, text=True, timeout=30)


def test_demo_and_viewer(tmp_path):
    directory = tmp_path / "run"
    demo = cli("demo", "--directory", str(directory))
    assert demo.returncode == 0, demo.stderr
    assert "Without guard: DELIVERED" in demo.stdout
    assert "With guard: BLOCKED" in demo.stdout
    assert "rug_pull" in demo.stdout
    viewer = cli("view", str(directory / "audit.jsonl"), "--output", str(tmp_path / "audit.html"))
    assert viewer.returncode == 0, viewer.stderr
    assert "MCP Guard / audit" in (tmp_path / "audit.html").read_text()


def test_approve_and_invalid_arguments(tmp_path):
    approved = cli("approve", "demo__send", "--arguments", '{"text":"hello"}', "--store", str(tmp_path / "a.sqlite"))
    assert approved.returncode == 0
    assert "one-use" in approved.stdout
    assert cli("approve", "demo__send", "--arguments", "[]").returncode == 2


def test_stdio_cli_wire(tmp_path):
    import yaml
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({"servers": {"demo": {"command": [sys.executable, "-m", "mcp_guard.demo_server"]}}, "policy": {"tools": [{"match": "*", "allow": True}]}}))
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "demo__echo", "arguments": {}}},
    ]
    run = subprocess.run([sys.executable, "-m", "mcp_guard", "proxy", "--config", str(config), "--audit", str(tmp_path / "audit.jsonl"), "--approvals", str(tmp_path / "a.sqlite")], input="".join(json.dumps(m) + "\n" for m in messages), capture_output=True, text=True, timeout=20)
    assert run.returncode == 0, run.stderr
    replies = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(replies) == 2
    assert replies[1]["id"] == 2 and "21" in replies[1]["result"]["content"][0]["text"]

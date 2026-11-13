import json
import pytest
from mcp_guard.state import Approvals, Audit, render_audit
from mcp_guard.rpc import validate_request, RpcError


def test_approval_exact_expiring_once(tmp_path):
    store = Approvals(tmp_path / "approvals.sqlite")
    store.grant("demo__send", {"a": 1}, ttl=10, now=100)
    assert not store.consume("demo__send", {"a": 2}, now=101)
    assert store.consume("demo__send", {"a": 1}, now=101)
    assert not store.consume("demo__send", {"a": 1}, now=102)
    store.grant("demo__send", {}, ttl=1, now=100)
    assert not store.consume("demo__send", {}, now=102)
    assert (tmp_path / "approvals.sqlite").stat().st_mode & 0o777 == 0o600


def test_audit_escapes_and_omits_payload(tmp_path):
    path = tmp_path / "audit.jsonl"
    Audit(path).record("<script>alert(1)</script>", "blocked", ["email"], {"password": "private"})
    line = path.read_text()
    assert "private" not in line and "password" not in line
    assert json.loads(line)["decision"] == "blocked"
    html = render_audit(path)
    assert "<script>" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("message", [[], {}, {"jsonrpc": "1.0", "method": "ping"}, {"jsonrpc": "2.0", "id": True, "method": "ping"}, {"jsonrpc": "2.0", "method": "tools/call", "params": []}, {"jsonrpc": "2.0", "method": "ping", "result": {}}])
def test_invalid_rpc(message):
    with pytest.raises(RpcError):
        validate_request(message)


def test_valid_rpc():
    validate_request({"jsonrpc": "2.0", "method": "ping", "id": 0})
    validate_request({"jsonrpc": "2.0", "method": "notifications/initialized"})

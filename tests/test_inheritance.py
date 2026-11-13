import pytest

from mcp_guard.policy import Denied, Policy


def test_server_constraints_cannot_be_widened():
    policy = Policy(
        {
            "tools": [{"match": "files__*", "allow": True}],
            "servers": [
                {
                    "match": "files",
                    "allow": True,
                    "arguments": {"path": {"paths": ["/workspace/public"]}},
                }
            ],
        }
    )
    assert policy.check("files__read", {"path": "/workspace/public/a"}) is False
    with pytest.raises(Denied, match="argument_path"):
        policy.check("files__read", {"path": "/etc/passwd"})


def test_server_deny_and_leaf_grant_required():
    policy = Policy(
        {
            "tools": [{"match": "a__*", "allow": True}],
            "servers": [{"match": "*", "allow": False}],
        }
    )
    assert not policy.visible("a__echo")
    with pytest.raises(Denied, match="tool_denied"):
        policy.check("a__echo", {})
    assert not Policy(
        {"tools": [], "servers": [{"match": "*", "allow": True}]}
    ).visible("a__echo")


def test_shared_server_rate_and_independent_leaf_rate():
    policy = Policy(
        {
            "tools": [{"match": "*", "allow": True}],
            "servers": [
                {"match": "a", "allow": True, "rate": {"calls": 1, "seconds": 10}}
            ],
        }
    )
    policy.check("a__first", {}, now=0)
    with pytest.raises(Denied, match="rate_limit"):
        policy.check("a__second", {}, now=1)
    policy.check("b__first", {}, now=1)
    policy.check("a__second", {}, now=10)


def test_surface_grants_are_separate():
    policy = Policy({"tools": [], "prompts": [{"match": "a__*", "allow": True}]})
    assert policy.visible("a__read", surface="prompts")
    assert not policy.visible("a__read")
    assert policy.check("a__read", {}, surface="prompts") is False

import pytest

from mcp_guard.policy import Denied, Policy


def policy(**rule):
    return Policy({"tools": [{"match": "demo__read", "allow": True, **rule}]})


def test_default_deny_and_deny_precedence():
    with pytest.raises(Denied):
        policy().check("demo__other", {})
    p = Policy(
        {"tools": [{"match": "*", "allow": True}, {"match": "*read", "allow": False}]}
    )
    with pytest.raises(Denied):
        p.check("demo__read", {})


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "/tmp/safe/../secret", "/tmp/safe/%2e%2e/secret", "..\\secret", 3],
)
def test_path_escapes(path):
    with pytest.raises(Denied):
        policy(arguments={"path": {"paths": ["/tmp/safe"]}}).check(
            "demo__read", {"path": path}
        )


def test_path_boundary_and_regex():
    p = policy(
        arguments={"path": {"paths": ["/tmp/safe"]}, "q": {"regex": "[a-z]{1,8}"}}
    )
    p.check("demo__read", {"path": "/tmp/safe/doc", "q": "hello"})
    with pytest.raises(Denied):
        p.check("demo__read", {"path": "/tmp/safeish/doc", "q": "hello"})
    with pytest.raises(Denied):
        p.check("demo__read", {"path": "/tmp/safe/doc", "q": "hello!"})
    with pytest.raises(Denied):
        p.check("demo__read", {})


@pytest.mark.parametrize(
    "url",
    [
        "http://good.test",
        "https://good.test.evil.test",
        "https://good.test@evil.test",
        "https://good.test:444",
        "https://127.0.0.1",
        "https://good.test./",
        "https://good.test\\@evil.test",
    ],
)
def test_url_rejections(url):
    with pytest.raises(Denied):
        policy(arguments={"url": {"domains": ["good.test"]}}).check(
            "demo__read", {"url": url}
        )


def test_url_allow_and_confirmation():
    assert policy(confirm=True, arguments={"url": {"domains": ["good.test"]}}).check(
        "demo__read", {"url": "https://GOOD.test/a"}
    )


def test_rate_window():
    p = policy(rate={"calls": 2, "seconds": 10})
    p.check("demo__read", {}, now=0)
    p.check("demo__read", {}, now=1)
    with pytest.raises(Denied):
        p.check("demo__read", {}, now=9)
    p.check("demo__read", {}, now=10)


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"tools": [], "typo": True},
        {"tools": [{"match": "*", "allow": "yes"}]},
        {"tools": [{"match": "*", "allow": True, "rate": {"calls": 0, "seconds": 1}}]},
        {"tools": [{"match": "*", "allow": True, "arguments": {"q": {"regex": "["}}}]},
    ],
)
def test_invalid_policy(config):
    with pytest.raises(ValueError):
        Policy(config)

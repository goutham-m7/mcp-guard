"""Exercise the composition root in-process so coverage includes operator workflows."""

import json
import sys

import pytest
import yaml

from mcp_guard.cli import main
from mcp_guard.config import Config
from mcp_guard.detection import MockClassifier


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["mcp-guard", *args])
    return main()


def test_operator_demo_replay_view_and_approval(monkeypatch, tmp_path, capsys):
    assert invoke(monkeypatch, "demo", "--directory", str(tmp_path)) == 0
    assert "With guard: BLOCKED" in capsys.readouterr().out
    assert invoke(monkeypatch, "test", "--directory", str(tmp_path), "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["blocked"] == report["attacks"] == 29
    assert report["benign"] == 11
    assert (
        invoke(
            monkeypatch,
            "view",
            str(tmp_path / "audit.jsonl"),
            "--output",
            str(tmp_path / "audit.html"),
        )
        == 0
    )
    assert (
        invoke(
            monkeypatch,
            "approve",
            "demo__echo",
            "--arguments",
            "{}",
            "--store",
            str(tmp_path / "approvals.sqlite"),
        )
        == 0
    )
    assert invoke(monkeypatch, "approve", "demo__echo", "--arguments", "[]") == 2


def test_text_replay_summary(monkeypatch, tmp_path, capsys):
    from mcp_guard.evaluation import summary

    report = {
        "blocked": 3,
        "attacks": 3,
        "benign": 2,
        "false_positives": 0,
        "raw_delivered": 5,
        "errors": 0,
        "categories": {"injection": {"blocked": 3, "total": 3}},
        "latency_ms": {"median": 1.2, "p95": 2.3},
    }
    assert "3/3 (100.0%)" in summary(report)


@pytest.mark.parametrize(
    "url",
    [
        "http://external.test/mcp",
        "https://user:pass@example.test",
        "file:///tmp/x",
        "https://example.test/#fragment",
    ],
)
def test_reject_unsafe_upstream_urls(tmp_path, url):
    with pytest.raises(ValueError):
        Config({"servers": {"remote": {"url": url}}, "policy": {"tools": []}}, tmp_path)


async def test_yaml_relative_policy_and_mock_classifier(tmp_path):
    (tmp_path / "policy.yaml").write_text("tools: []\n")
    data = {
        "servers": {
            "demo": {"command": [sys.executable, "-m", "mcp_guard.demo_server"]}
        },
        "policy": "policy.yaml",
        "classifier": {"provider": "mock"},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(data))
    config = Config.load(tmp_path / "config.yaml")
    guard = await config.build(tmp_path / "audit.jsonl", tmp_path / "a.sqlite")
    try:
        assert isinstance(guard.detector.classifier, MockClassifier)
    finally:
        await guard.close()


def test_invalid_classifier_config(tmp_path):
    with pytest.raises(ValueError):
        Config(
            {
                "servers": {"remote": {"url": "https://example.test/mcp"}},
                "policy": {"tools": []},
                "classifier": {"provider": "openai"},
            },
            tmp_path,
        )

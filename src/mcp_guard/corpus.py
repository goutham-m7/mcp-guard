"""Original synthetic fixtures, deliberately readable and locally replayable."""
from importlib.resources import files
import json


def load_corpus():
    return json.loads(files("mcp_guard").joinpath("data/corpus.json").read_text())


def demo_policy():
    return {"tools": [
        {"match": "demo__*", "allow": True},
        {"match": "demo__admin", "allow": False},
        {"match": "demo__read", "allow": True, "arguments": {"path": {"paths": ["/workspace/public"]}}},
        {"match": "demo__fetch", "allow": True, "arguments": {"url": {"domains": ["docs.example.test"]}}},
        {"match": "demo__search", "allow": True, "arguments": {"query": {"regex": "[a-zA-Z0-9 ]{1,80}"}}},
    ]}

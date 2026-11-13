import json
from importlib.metadata import metadata, version
from importlib.resources import files

import mcp_guard


def test_release_version_matches_runtime():
    assert version("mcp-guard") == mcp_guard.__version__ == "0.2.0"
    assert metadata("mcp-guard")["License-Expression"] == "MIT"


def test_packaged_data_are_available():
    data = files("mcp_guard").joinpath("data")
    assert len(json.loads(data.joinpath("heldout.json").read_text())) == 20
    assert len(json.loads(data.joinpath("benign.json").read_text())) == 32
    assert (
        json.loads(data.joinpath("audit.schema.json").read_text())["title"]
        == "MCP Guard audit event v1"
    )

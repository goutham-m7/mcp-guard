import pytest

from mcp_guard.corpus import load_corpus
from mcp_guard.evaluation import evaluate


@pytest.mark.asyncio
async def test_full_corpus_uses_real_server(tmp_path):
    cases = load_corpus()
    report = await evaluate(cases, tmp_path)
    assert report["attacks"] >= 20
    assert report["blocked"] == report["attacks"]
    assert report["false_positives"] == 0
    assert report["raw_delivered"] == len(cases)
    assert report["errors"] == 0
    assert len(report["categories"]) >= 5
    assert report["latency_ms"]["p95"] >= report["latency_ms"]["median"] > 0

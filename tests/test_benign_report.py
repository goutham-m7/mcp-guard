from mcp_guard.corpus import load_corpus
from mcp_guard.evaluation import evaluate, summary


async def test_benign_hits_remain_false_positives(tmp_path):
    cases = load_corpus("benign")
    assert len(cases) == 32
    report = await evaluate(cases, tmp_path)
    assert report["attacks"] == 0
    assert report["false_positives"] == 5
    assert report["errors"] == 0
    assert report["detector_false_positives"]["email"] == {"hits": 2, "total": 32}
    assert report["detector_false_positives"]["injection"]["hits"] == 1
    assert report["detector_false_positives"]["tool_instruction"]["hits"] == 1
    assert report["detector_false_positives"]["card"]["hits"] == 1
    assert "email: 2/32" in summary(report)
    assert len(load_corpus("all")) == 92


async def test_empty_evaluation_has_explicit_denominators(tmp_path):
    report = await evaluate([], tmp_path)
    assert report["latency_ms"] == {"median": 0, "p95": 0}
    assert report["detector_false_positives"]["email"] == {"hits": 0, "total": 0}
    assert "0/0 (n/a)" in summary(report)

import pytest

from mcp_guard.corpus import load_corpus
from mcp_guard.evaluation import evaluate, summary


def test_heldout_is_disjoint_and_not_default():
    tuning, heldout = load_corpus(), load_corpus("heldout")
    assert len(tuning) == 40
    assert len(heldout) == 20
    assert not {r["id"] for r in tuning} & {r["id"] for r in heldout}
    assert not {r["payload"] for r in tuning if r["payload"]} & {
        r["payload"] for r in heldout if r["payload"]
    }
    with pytest.raises(ValueError):
        load_corpus("../bad")


async def test_holdout_records_misses_without_claiming_errors(tmp_path):
    report = await evaluate(load_corpus("heldout"), tmp_path)
    assert report["attacks"] == 20
    assert 0 < report["blocked"] < 20
    assert report["errors"] == 0
    assert report["raw_delivered"] == 20
    assert "0/0 (n/a)" in summary(report)

import pytest

from mcp_guard.benchmark import benchmark, percentiles


def test_nearest_rank_percentiles():
    assert percentiles([1, 2, 3, 4, 5]) == {"p50": 3, "p95": 5, "p99": 5}
    with pytest.raises(ValueError):
        percentiles([])


async def test_real_subprocess_concurrent_benchmark(tmp_path):
    report = await benchmark(tmp_path, sessions=3, requests=4)
    assert report["attempted"] == report["completed"] == 12
    assert report["errors"] == 0
    assert report["sessions"] == 3
    assert report["calls_per_session"] == 4
    assert (
        report["latency_ms"]["p99"]
        >= report["latency_ms"]["p95"]
        >= report["latency_ms"]["p50"]
        > 0
    )
    assert report["throughput_calls_per_second"] > 0
    assert "startup excluded" in report["scope"]
    assert len(list(tmp_path.glob("session-*/audit.jsonl"))) == 3


@pytest.mark.parametrize("sessions,requests", [(0, 1), (33, 1), (1, 0), (32, 10001)])
async def test_benchmark_rejects_unbounded_work(tmp_path, sessions, requests):
    with pytest.raises(ValueError):
        await benchmark(tmp_path, sessions=sessions, requests=requests)

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from verdikt.cache import REPORT_RETENTION, Cache
from verdikt.models import IOCType, Level, Report, SourceResult, Status


def test_unreadable_cached_row_is_a_miss_not_a_crash() -> None:
    # a row written by an older schema must not break every later lookup until its TTL ends
    cache = Cache(":memory:")
    cache.put("virustotal", "8.8.8.8", SourceResult(source="virustotal", status=Status.OK))
    with cache._lock, cache._db:  # pyright: ignore[reportPrivateUsage]
        cache._db.execute("UPDATE source_cache SET result='{\"status\": 42}'")  # pyright: ignore[reportPrivateUsage]
    assert cache.get("virustotal", "8.8.8.8", timedelta(hours=1)) is None
    cache.close()


def _report(report_id: str, created_at: datetime) -> Report:
    return Report(
        id=report_id,
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        level=Level.SAFE,
        agreeing=0,
        total=0,
        created_at=created_at,
    )


def test_unreadable_stored_report_is_none_not_a_crash() -> None:
    cache = Cache(":memory:")
    cache.save_report(_report("r1", datetime.now(UTC)))
    with cache._lock, cache._db:  # pyright: ignore[reportPrivateUsage]
        cache._db.execute("UPDATE reports SET body='{\"level\": 42}'")  # pyright: ignore[reportPrivateUsage]
    assert cache.get_report("r1") is None
    cache.close()


def test_old_reports_are_pruned_on_open(tmp_path: Path) -> None:
    path = tmp_path / "v.db"
    now = datetime.now(UTC)
    first = Cache(path)
    first.save_report(_report("old", now - REPORT_RETENTION - timedelta(days=1)))
    first.save_report(_report("new", now))
    first.close()
    second = Cache(path)
    assert second.get_report("old") is None
    assert second.get_report("new") is not None
    second.close()


def test_charge_stops_at_the_limit_and_does_not_count_refusals() -> None:
    cache = Cache(":memory:")
    assert [cache.charge("vt", 2) for _ in range(3)] == [True, True, False]
    assert cache.budget_used("vt") == 2
    assert all(cache.charge("other", None) for _ in range(5))
    assert cache.budget_used("other") == 5
    cache.close()

from __future__ import annotations

from datetime import timedelta

from verdikt.cache import Cache
from verdikt.models import SourceResult, Status


def test_unreadable_cached_row_is_a_miss_not_a_crash() -> None:
    # a row written by an older schema must not break every later lookup until its TTL ends
    cache = Cache(":memory:")
    cache.put("virustotal", "8.8.8.8", SourceResult(source="virustotal", status=Status.OK))
    with cache._lock, cache._db:  # pyright: ignore[reportPrivateUsage]
        cache._db.execute("UPDATE source_cache SET result='{\"status\": 42}'")  # pyright: ignore[reportPrivateUsage]
    assert cache.get("virustotal", "8.8.8.8", timedelta(hours=1)) is None
    cache.close()

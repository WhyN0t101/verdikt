"""Watch re-checks also say when the evidence under an unchanged verdict moved (B2).

Policy: the verdict event is unchanged. `evidence_changed` is true when a source that answered
both times changed its level, or the confidence band moved while no source flapped, or sources
dropped out so that fewer than `min_sources_for_safe` still answer. A source that merely flips
between answering and not answering (rate limit, timeout) is noise and is ignored.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from tests.conftest import CountingLimiter, Fake, make_engine
from verdikt.cache import Cache
from verdikt.config import Settings
from verdikt.engine import Engine
from verdikt.models import Status
from verdikt.sources.base import Source
from verdikt.watch import recheck

IOC = "8.8.8.8"


def vt(malicious: int = 2, status: Status = Status.OK) -> Fake:
    return Fake("virustotal", {"malicious": malicious, "suspicious": 0}, status=status)


def abuse(score: int = 0, status: Status = Status.OK) -> Fake:
    return Fake("abuseipdb", {"score": score}, status=status)


def feed(status: Status = Status.OK) -> Fake:
    return Fake("threatfox", {"match": False, "entries": 0}, status=status)


def swap(engine: Engine, *fakes: Fake) -> None:
    engine.sources = list[Source](fakes)


async def watched(
    settings: Settings, client: httpx.AsyncClient, first: list[Fake]
) -> tuple[Engine, Cache]:
    cache = Cache(":memory:")
    sources: list[Source] = list(first)
    engine = make_engine(settings, cache, client, sources, limiter_factory=CountingLimiter)
    cache.watch_add(IOC, "ip")
    cache.watch_record(await engine.check(IOC))  # the baseline
    return engine, cache


async def test_nothing_moved_is_no_change(settings: Settings, client: httpx.AsyncClient) -> None:
    engine, _ = await watched(settings, client, [vt(), abuse(), feed()])
    assert await recheck(engine) == ([], [])


async def test_a_source_changing_its_level_under_the_same_verdict(
    settings: Settings, client: httpx.AsyncClient
) -> None:
    engine, _ = await watched(settings, client, [vt(), abuse(0), feed()])
    swap(engine, vt(), abuse(30), feed())  # abuseipdb safe -> suspicious; still suspicious
    changes, reports = await recheck(engine)
    [c] = changes
    assert (c.before, c.after, c.evidence_changed) == ("suspicious", "suspicious", True)
    assert reports == []  # no notification unless VERDIKT_WATCH_NOTIFY_ANY


async def test_a_flapping_source_is_noise(settings: Settings, client: httpx.AsyncClient) -> None:
    engine, cache = await watched(settings, client, [vt(), abuse(0), feed()])
    swap(engine, vt(), abuse(status=Status.RATE_LIMITED), feed())
    # abuseipdb answered before and is rate limited now (the confidence band may move with it);
    # two sources still answer and the verdict is the same
    assert await recheck(engine) == ([], [])
    swap(engine, vt(), abuse(0), feed())
    assert await recheck(engine) == ([], [])  # and back again: still nothing
    assert cache.watch_list()[0].last_checked_at is not None


async def test_losing_so_many_answers_that_too_few_remain_is_evidence(
    settings: Settings, client: httpx.AsyncClient
) -> None:
    engine, _ = await watched(settings, client, [vt(), abuse(0), feed()])
    swap(engine, vt(), abuse(status=Status.ERROR), feed(Status.ERROR))  # one answer is left
    [c], _ = await recheck(engine)
    assert (c.before, c.after, c.evidence_changed) == ("suspicious", "suspicious", True)


async def test_a_level_change_carries_the_flag_too(
    settings: Settings, client: httpx.AsyncClient
) -> None:
    engine, _ = await watched(settings, client, [vt(0), abuse(0)])
    swap(engine, vt(20), abuse(0))
    [c], reports = await recheck(engine)
    assert (c.before, c.after) == ("safe", "malicious")
    assert c.evidence_changed is True
    assert len(reports) == 1  # a verdict change is always reported


async def test_evidence_only_changes_notify_when_notify_any_is_on(
    client: httpx.AsyncClient,
) -> None:
    settings = Settings(_env_file=None, watch_notify_any=True)  # pyright: ignore[reportCallIssue]
    engine, _ = await watched(settings, client, [vt(), abuse(0), feed()])
    swap(engine, vt(), abuse(30), feed())
    [c], reports = await recheck(engine)
    assert c.evidence_changed is True
    assert [r.id for r in reports] == [c.report_id]


async def test_a_skipped_failed_lookup_still_refreshes_the_checked_time(
    settings: Settings, client: httpx.AsyncClient
) -> None:
    engine, cache = await watched(settings, client, [vt(0), abuse(0)])
    old = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    with cache._lock, cache._db:  # pyright: ignore[reportPrivateUsage]
        cache._db.execute("UPDATE watchlist SET last_checked_at=?", (old,))  # pyright: ignore[reportPrivateUsage]
    swap(engine, vt(status=Status.ERROR), abuse(status=Status.ERROR))  # UNKNOWN: skipped
    assert await recheck(engine) == ([], [])
    entry = cache.watch_list()[0]
    assert entry.last_level == "safe"  # the last good verdict is kept
    assert entry.last_checked_at is not None
    assert entry.last_checked_at.isoformat() > old

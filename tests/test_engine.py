from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import respx

from tests.conftest import CountingLimiter, Fake, Sleeps, fixture, make_engine
from verdikt.cache import Cache
from verdikt.config import Settings
from verdikt.engine import Engine
from verdikt.models import Level, RelatedIOC, SourceResult, Status
from verdikt.sources.virustotal import VirusTotal

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"


async def test_one_raising_source_still_yields_report(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    good = Fake("abuseipdb", {"score": 0})
    bad = Fake("virustotal", raises=True)
    engine = make_engine(settings, cache, client, [good, bad])
    report = await engine.check("8.8.8.8")
    rows = {r.source: r.status for r in report.results}
    assert rows == {"abuseipdb": Status.OK, "virustotal": Status.ERROR}
    assert report.level is Level.UNKNOWN  # high-weight error blocks SAFE


async def test_cache_hit_skips_http_and_keeps_raw(
    settings: Settings, cache: Cache, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    route = router.get(VT_URL).mock(
        return_value=httpx.Response(200, json=fixture("virustotal", "ip_clean"))
    )
    engine = make_engine(settings, cache, client, [VirusTotal("k")])
    first = await engine.check("8.8.8.8")
    second = await engine.check("8.8.8.8")
    assert route.call_count == 1
    assert first.results[0].cached is False
    assert second.results[0].cached is True
    assert second.results[0].raw is not None  # `--raw` works on a cache hit
    assert second.without_raw().results[0].raw is None


async def test_results_carry_per_source_timing(
    settings: Settings, cache: Cache, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    router.get(VT_URL).mock(
        return_value=httpx.Response(200, json=fixture("virustotal", "ip_clean"))
    )
    engine = make_engine(settings, cache, client, [VirusTotal("k")])
    first = (await engine.check("8.8.8.8")).results[0]
    second = (await engine.check("8.8.8.8")).results[0]
    assert first.started_ms >= 0
    assert first.duration_ms >= 0
    assert second.cached is True
    assert second.duration_ms == 0  # a cache hit is not the stored call's latency


async def test_no_cache_bypasses_read(
    settings: Settings, cache: Cache, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    route = router.get(VT_URL).mock(
        return_value=httpx.Response(200, json=fixture("virustotal", "ip_clean"))
    )
    engine = make_engine(settings, cache, client, [VirusTotal("k")])
    await engine.check("8.8.8.8")
    await engine.check("8.8.8.8", no_cache=True)
    assert route.call_count == 2


async def test_errors_are_not_cached(
    settings: Settings,
    cache: Cache,
    client: httpx.AsyncClient,
    router: respx.MockRouter,
    sleeps: Sleeps,
) -> None:
    route = router.get(VT_URL).mock(return_value=httpx.Response(500))
    engine = make_engine(
        settings,
        cache,
        client,
        [VirusTotal("k")],
        limiter_factory=CountingLimiter,
        sleep=sleeps,
        backoff=0,
    )
    await engine.check("8.8.8.8")
    await engine.check("8.8.8.8")
    assert route.call_count == 6


async def test_each_retry_takes_a_limiter_slot_and_budget(
    settings: Settings,
    cache: Cache,
    client: httpx.AsyncClient,
    router: respx.MockRouter,
    sleeps: Sleeps,
) -> None:
    router.get(VT_URL).mock(return_value=httpx.Response(500))
    limiters: list[CountingLimiter] = []

    def factory(n: int, s: float) -> CountingLimiter:
        limiters.append(CountingLimiter(n, s))
        return limiters[-1]

    engine = make_engine(
        settings, cache, client, [VirusTotal("k")], limiter_factory=factory, sleep=sleeps, backoff=0
    )
    report = await engine.check("8.8.8.8")
    assert report.results[0].status is Status.ERROR
    assert limiters[0].acquired == 3
    assert cache.budget_used("virustotal") == 3


async def test_retry_after_longer_than_timeout_is_rate_limited_without_waiting(
    settings: Settings,
    cache: Cache,
    client: httpx.AsyncClient,
    router: respx.MockRouter,
    sleeps: Sleeps,
) -> None:
    route = router.get(VT_URL).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "300"})
    )
    engine = make_engine(
        settings, cache, client, [VirusTotal("k")], limiter_factory=CountingLimiter, sleep=sleeps
    )
    report = await engine.check("8.8.8.8")
    assert report.results[0].status is Status.RATE_LIMITED
    assert route.call_count == 1
    assert sleeps.calls == []


async def test_budget_exhausted_yields_rate_limited_without_http(
    settings: Settings, cache: Cache, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    route = router.get(VT_URL).mock(
        return_value=httpx.Response(200, json=fixture("virustotal", "ip_clean"))
    )
    for _ in range(VirusTotal.daily_budget or 0):
        cache.charge("virustotal", None)
    engine = make_engine(settings, cache, client, [VirusTotal("k")])
    report = await engine.check("8.8.8.8")
    assert report.results[0].status is Status.RATE_LIMITED
    assert route.call_count == 0
    assert report.level is Level.UNKNOWN


async def test_disabled_and_unsupported_sources_are_not_queried(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    keyless = VirusTotal(None)
    engine = make_engine(settings, cache, client, [keyless, Fake("abuseipdb", {"score": 0})])
    report = await engine.check("8.8.8.8")
    assert [r.source for r in report.results] == ["abuseipdb"]


async def test_report_is_saved_and_graph_built(
    settings: Settings, cache: Cache, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    router.get("https://www.virustotal.com/api/v3/domains/evil.example").mock(
        return_value=httpx.Response(200, json=fixture("virustotal", "domain_hit"))
    )
    engine = make_engine(settings, cache, client, [VirusTotal("k")])
    report = await engine.check("hxxp://evil[.]example".replace("hxxp://", ""))
    assert cache.get_report(report.id) is not None
    kinds = {n.kind for n in report.graph.nodes}
    assert kinds == {"domain", "ip"}
    assert [(e.source, e.target, e.label) for e in report.graph.edges] == [
        ("domain:evil.example", "ip:203.0.113.9", "resolves_to")
    ]


async def test_internal_target_never_reaches_a_source(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    import pytest

    from verdikt.detect import DetectError

    fake = Fake("abuseipdb", {"score": 0})
    engine = make_engine(settings, cache, client, [fake])
    with pytest.raises(DetectError):
        await engine.check("192.168.1.10")
    assert fake.calls == 0


async def test_dns_resolution_is_off_by_default(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    calls: list[str] = []

    async def resolver(host: str) -> list[RelatedIOC]:
        calls.append(host)
        return []

    engine = make_engine(settings, cache, client, [Fake("otx", {"pulses": 0})], resolver=resolver)
    await engine.check("evil.example")
    assert calls == []
    on = Settings(_env_file=None, dns_resolve=True)  # pyright: ignore[reportCallIssue]
    engine = make_engine(on, cache, client, [Fake("otx", {"pulses": 0})], resolver=resolver)
    await engine.check("evil.example")
    assert calls == ["evil.example"]


def test_source_status_reports_quota(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    cache.charge("virustotal", None)
    engine: Engine = make_engine(settings, cache, client, [VirusTotal("k"), VirusTotal(None)])
    status = engine.source_status()
    assert status[0].used_today == 1
    assert status[0].daily_budget == 500
    assert [s.enabled for s in status] == [True, False]


# --- cache with a frozen clock ----------------------------------------------------------


def test_cache_ttl_expiry_uses_injected_clock() -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    c = Cache(":memory:", clock=lambda: now[0])
    c.put("vt", "x", SourceResult(source="vt", status=Status.OK, fetched_at=now[0]))
    assert c.get("vt", "x", timedelta(hours=1)) is not None
    now[0] += timedelta(hours=2)
    assert c.get("vt", "x", timedelta(hours=1)) is None


def test_budget_resets_each_utc_day() -> None:
    now = [datetime(2026, 1, 1, 23, 0, tzinfo=UTC)]
    c = Cache(":memory:", clock=lambda: now[0])
    assert c.charge("vt", 1) is True
    assert c.charge("vt", 1) is False
    now[0] += timedelta(hours=2)
    assert c.charge("vt", 1) is True


def test_cache_clear_by_source() -> None:
    c = Cache(":memory:")
    for src in ("a", "b"):
        c.put(src, "x", SourceResult(source=src, status=Status.OK))
    assert c.clear("a") == 1
    assert c.get("b", "x", timedelta(days=1)) is not None

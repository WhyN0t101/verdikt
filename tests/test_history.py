"""`GET /api/reports/{id}/history`: reports of one indicator, its cases and watch events."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from tests.conftest import CountingLimiter, Fake
from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.history import MAX_REPORTS
from verdikt.models import IOCType, Level, Report
from verdikt.sources.base import Source

T0 = datetime(2026, 1, 1, tzinfo=UTC)
TOKEN = "t0ken"
AUTH = {"x-verdikt-token": TOKEN}
Env = tuple[httpx.AsyncClient, Cache]


def rep(rid: str, minutes: int, level: Level = Level.SAFE, ioc: str = "8.8.8.8") -> Report:
    return Report(
        id=rid,
        ioc=ioc,
        ioc_type=IOCType.IP,
        level=level,
        agreeing=0,
        total=0,
        created_at=T0 + timedelta(minutes=minutes),
    )


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    http = httpx.AsyncClient()
    cache = Cache(":memory:", clock=lambda: T0 + timedelta(days=1))
    sources: list[Source] = [Fake("virustotal", {"malicious": 0})]
    engine = Engine(
        Settings(_env_file=None),  # pyright: ignore[reportCallIssue]
        load_rules(),
        cache,
        http,
        sources=sources,
        limiter_factory=CountingLimiter,
    )
    app = create_app(engine, port=8765, token=TOKEN)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
    ) as c:
        yield c, cache
    await http.aclose()


async def history(env: Env, rid: str) -> dict[str, Any]:
    r = await env[0].get(f"/api/reports/{rid}/history", headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()


async def test_requires_the_token_and_404s_for_an_unknown_id(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a", 0))
    assert (await client.get("/api/reports/a/history")).status_code == 401
    assert (await client.get("/api/reports/nope/history", headers=AUTH)).status_code == 404


async def test_a_first_time_indicator(env: Env) -> None:
    env[1].save_report(rep("a", 0))
    body = await history(env, "a")
    assert [r["id"] for r in body["reports"]] == ["a"]
    assert (body["report_id"], body["ioc"], body["truncated"], body["changes"]) == (
        "a",
        "8.8.8.8",
        False,
        0,
    )
    assert (body["cases"], body["watched"], body["watched_since"], body["events"]) == (
        [],
        False,
        None,
        [],
    )


async def test_timeline_is_newest_first_and_counts_level_changes(env: Env) -> None:
    cache = env[1]
    for rid, m, lv in [
        ("a", 0, Level.SAFE),
        ("b", 1, Level.SUSPICIOUS),
        ("c", 2, Level.SUSPICIOUS),
        ("d", 3, Level.MALICIOUS),
    ]:
        cache.save_report(rep(rid, m, lv))
    cache.save_report(rep("other", 4, Level.MALICIOUS, ioc="1.1.1.1"))  # never leaks in
    body = await history(env, "b")  # asking from the middle still shows the whole timeline
    assert [r["id"] for r in body["reports"]] == ["d", "c", "b", "a"]
    assert body["changes"] == 2
    assert set(body["reports"][0]) == {"id", "ioc", "ioc_type", "level", "created_at"}


async def test_the_same_level_twice_is_no_change(env: Env) -> None:
    env[1].save_report(rep("a", 0))
    env[1].save_report(rep("b", 1))
    assert (await history(env, "b"))["changes"] == 0


async def test_more_than_the_cap_is_truncated_to_the_newest(env: Env) -> None:
    cache = env[1]
    for i in range(MAX_REPORTS + 10):
        cache.save_report(rep(f"r{i:03d}", i))
    body = await history(env, "r000")
    assert len(body["reports"]) == MAX_REPORTS
    assert body["truncated"] is True
    assert body["reports"][0]["id"] == f"r{MAX_REPORTS + 9:03d}"


async def test_exactly_the_cap_is_not_truncated(env: Env) -> None:
    for i in range(MAX_REPORTS):
        env[1].save_report(rep(f"r{i:03d}", i))
    assert (await history(env, "r000"))["truncated"] is False


async def test_cases_are_listed_once_and_titles_are_verbatim(env: Env) -> None:
    cache = env[1]
    cache.save_report(rep("a", 0))
    cache.save_report(rep("b", 1))
    cache.save_report(rep("x", 2, ioc="1.1.1.1"))
    both = cache.case_create("Invoice <script>phish</script>")
    only_a = cache.case_create("Second")
    elsewhere = cache.case_create("Not ours")
    for case, rid in [(both, "a"), (both, "b"), (only_a, "a"), (elsewhere, "x")]:
        cache.case_add_report(case, rid)
    body = await history(env, "b")
    cases = {c["id"]: c for c in body["cases"]}
    assert set(cases) == {both, only_a}
    assert cases[both]["title"] == "Invoice <script>phish</script>"
    assert cases[both]["report_count"] == 2


async def test_watch_state_and_events(env: Env) -> None:
    cache = env[1]
    a, b = rep("a", 0), rep("b", 1, Level.MALICIOUS)
    cache.save_report(a)
    cache.save_report(b)
    cache.watch_add("8.8.8.8", "ip")
    cache.watch_record(a)  # baseline
    cache.watch_record(b)  # safe -> malicious
    cache.watch_add("1.1.1.1", "ip")
    cache.watch_record(rep("z", 2, Level.SAFE, ioc="1.1.1.1"))
    cache.watch_record(rep("y", 3, Level.MALICIOUS, ioc="1.1.1.1"))  # another indicator's event
    body = await history(env, "a")
    assert body["watched"] is True
    assert str(body["watched_since"]).startswith("2026-01-02")  # the cache clock
    (event,) = body["events"]
    assert (event["from_level"], event["to_level"], event["report_id"]) == (
        "safe",
        "malicious",
        "b",
    )
    assert event["ioc"] == "8.8.8.8"


async def test_events_are_newest_first(env: Env) -> None:
    cache = env[1]
    seq = [("a", Level.SAFE), ("b", Level.MALICIOUS), ("c", Level.SAFE)]
    cache.watch_add("8.8.8.8", "ip")
    for i, (rid, lv) in enumerate(seq):
        r = rep(rid, i, lv)
        cache.save_report(r)
        cache.watch_record(r)
    body = await history(env, "a")
    assert [e["report_id"] for e in body["events"]] == ["c", "b"]

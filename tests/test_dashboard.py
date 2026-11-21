"""Dashboard data (stats, source health, watchlist), ticket extraction and the new API routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx
from fastapi import FastAPI

from tests.conftest import CountingLimiter, Fake, make_engine
from tests.test_feeds import mock_all
from verdikt.api.app import create_app
from verdikt.cache import WATCHLIST_MAX, Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.extract import MAX_ITEMS, extract_iocs
from verdikt.models import (
    Graph,
    GraphNode,
    IOCType,
    Level,
    Report,
    SourceResult,
    Status,
)
from verdikt.sources.base import Source
from verdikt.watch import recheck

T0 = datetime(2026, 1, 10, 12, tzinfo=UTC)


def report(
    rid: str,
    ioc: str = "1.2.3.4",
    level: Level = Level.MALICIOUS,
    created: datetime = T0,
    nodes: list[GraphNode] | None = None,
) -> Report:
    return Report(
        id=rid,
        ioc=ioc,
        ioc_type=IOCType.IP,
        level=level,
        agreeing=1,
        total=1,
        graph=Graph(nodes=nodes or []),
        created_at=created,
    )


def src(
    source: str, status: Status = Status.OK, cached: bool = False, ms: int = 100
) -> SourceResult:
    return SourceResult(source=source, status=status, cached=cached, duration_ms=ms)


# --- stats --------------------------------------------------------------------------------


def test_stats_counts_levels_per_day_and_recurring_infrastructure() -> None:
    c = Cache(":memory:", clock=lambda: T0 + timedelta(days=1))
    ip = GraphNode(id="ip:9.9.9.9", label="9.9.9.9", kind="ip")
    asn = GraphNode(id="asn:AS1", label="AS1", kind="asn")
    c.save_report(report("a", "evil.example", Level.MALICIOUS, T0, [ip, asn]))
    c.save_report(report("b", "5.5.5.5", Level.SAFE, T0, [ip, asn]))
    c.save_report(report("c", "6.6.6.6", Level.MALICIOUS, T0 + timedelta(days=1), [ip]))
    s = c.stats(30)
    assert s.total == 3
    assert [(d.day, d.malicious, d.safe) for d in s.by_day] == [
        ("2026-01-10", 1, 1),
        ("2026-01-11", 1, 0),
    ]
    assert [(r.value, r.reports, r.last_level) for r in s.recurring] == [
        ("9.9.9.9", 3, "malicious")
    ]


def test_stats_source_health_averages_only_live_calls() -> None:
    c = Cache(":memory:", clock=lambda: T0)
    c.record_stats([src("virustotal", ms=200), src("abuseipdb", Status.ERROR, ms=900)])
    c.record_stats([src("virustotal", ms=400), src("abuseipdb", cached=True)])
    c.record_stats([src("virustotal", Status.RATE_LIMITED, ms=0)])
    health = {h.source: h for h in c.stats().sources}
    vt, ab = health["virustotal"], health["abuseipdb"]
    assert (vt.checks, vt.ok, vt.rate_limited, vt.cached) == (3, 2, 1, 0)
    assert vt.avg_ms == 200  # (200 + 400 + 0) / 3 live calls
    assert (ab.checks, ab.errors, ab.cached, ab.avg_ms) == (2, 1, 1, 900)


def test_stats_feedback_counts_and_window() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0])
    r = report("a")
    c.save_report(r)
    for label in ("false_positive", "false_positive", "correct"):
        c.add_feedback(r, label)
    assert c.stats().feedback.model_dump() == {
        "false_positive": 2,
        "false_negative": 0,
        "correct": 1,
    }
    now[0] = T0 + timedelta(days=60)
    assert c.stats(30).feedback.false_positive == 0


def test_old_source_stats_are_pruned() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0])
    c.record_stats([src("virustotal")])
    now[0] = T0 + timedelta(days=120)
    assert c.prune()["source_stats"] == 1


def test_checked_since() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0])
    c.save_report(report("a", "1.1.1.1", created=T0))
    now[0] = T0 + timedelta(hours=30)
    c.save_report(report("b", "2.2.2.2", created=now[0]))
    assert c.checked_since(timedelta(hours=24)) == {"2.2.2.2"}


# --- watchlist ----------------------------------------------------------------------------


def test_watchlist_baseline_change_events_and_limit() -> None:
    c = Cache(":memory:", clock=lambda: T0)
    assert c.watch_add("1.2.3.4", "ip")
    assert c.watch_add("1.2.3.4", "ip")  # no duplicate
    assert [e.ioc for e in c.watch_list()] == ["1.2.3.4"]
    assert c.watch_record(report("a", level=Level.SAFE)) is None  # baseline, not a change
    assert c.watch_record(report("b", level=Level.SAFE)) is None
    assert c.watch_record(report("c", level=Level.MALICIOUS)) == "safe"
    [event] = c.watch_events()
    assert (event.ioc, event.from_level, event.to_level, event.report_id) == (
        "1.2.3.4",
        "safe",
        "malicious",
        "c",
    )
    assert c.watch_list()[0].last_level == "malicious"
    assert c.watch_record(report("x", "9.9.9.9")) is None  # not on the list
    assert c.watch_remove("1.2.3.4") and not c.watch_remove("1.2.3.4")


def test_watchlist_is_capped() -> None:
    c = Cache(":memory:")
    for i in range(WATCHLIST_MAX):
        assert c.watch_add(f"10.0.0.{i}", "ip")
    assert c.watch_add("11.0.0.1", "ip") is False


async def test_recheck_reports_only_changes(settings: Settings, client: httpx.AsyncClient) -> None:
    cache = Cache(":memory:")
    vt = Fake("virustotal", {"malicious": 0, "suspicious": 0})
    ab = Fake("abuseipdb", {"score": 0})
    sources: list[Source] = [vt, ab]
    engine = make_engine(settings, cache, client, sources, limiter_factory=CountingLimiter)
    first = await engine.check("8.8.8.8")
    cache.watch_add("8.8.8.8", "ip")
    cache.watch_record(first)
    assert (await recheck(engine))[0] == []  # same verdict

    vt.metrics = {"malicious": 20, "suspicious": 0}
    changes, reports = await recheck(engine)
    assert [(c.ioc, c.before, c.after) for c in changes] == [("8.8.8.8", "safe", "malicious")]
    assert [r.id for r in reports] == [changes[0].report_id]
    assert vt.calls == 3  # first check + two re-checks: re-checks bypass the cache


# --- extraction ---------------------------------------------------------------------------

TICKET = """Host 185.220.101[.]4 contacted hxxps://evil[.]com/a.exe?x=1 and evil[.]com, later 91.92.109.10.
Hashes: 44d88612fea8a8f36de82e1278abb02f and 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.
Internal: 192.168.1.10 and intranet.corp. Mail bob@example.com, CVE-2021-44228, file report.docx.
"""  # noqa: E501


def test_extract_finds_normalizes_and_dedupes() -> None:
    found = extract_iocs(TICKET)
    by_type = {t: [i.value for i in found.items if i.type is t] for t in IOCType}
    assert by_type[IOCType.IP] == ["185.220.101.4", "91.92.109.10"]
    assert by_type[IOCType.DOMAIN] == ["evil.com"]
    assert by_type[IOCType.URL] == ["https://evil.com/a.exe?x=1"]
    assert by_type[IOCType.MD5] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert len(by_type[IOCType.SHA256]) == 1
    values = [i.value for i in found.items]
    assert len(values) == len(set(values))
    assert not any("example.com" in v or "docx" in v or "CVE" in v for v in values)


def test_extract_skips_internal_targets_and_never_lists_them() -> None:
    found = extract_iocs(TICKET)
    assert "192.168.1.10" in [s.value for s in found.skipped]
    assert all("192.168" not in i.value for i in found.items)
    assert extract_iocs("see wiki.corp.example.com", ["corp.example.com"]).items == []


def test_extract_truncates_large_input() -> None:
    text = " ".join(f"8.8.{i // 250}.{i % 250 + 1}" for i in range(MAX_ITEMS + 30))
    found = extract_iocs(text)
    assert len(found.items) == MAX_ITEMS
    assert found.truncated


def test_extract_empty_text() -> None:
    assert extract_iocs("nothing to see here").items == []


# --- API ----------------------------------------------------------------------------------

TOKEN = "t0ken"
PORT = 8765
AUTH = {"x-verdikt-token": TOKEN}


def make_app(tmp_path: Path, http: httpx.AsyncClient) -> tuple[FastAPI, Engine]:
    sources: list[Source] = [Fake("virustotal", {"malicious": 20, "suspicious": 0})]
    settings = Settings(
        _env_file=None,  # pyright: ignore[reportCallIssue]
        feeds_dir=tmp_path / "feeds",
        internal_domains="corp.example.com",
    )
    engine = Engine(
        settings,
        load_rules(),
        Cache(":memory:"),
        http,
        sources=sources,
        limiter_factory=CountingLimiter,
    )
    return create_app(engine, port=PORT, token=TOKEN, web_dist=tmp_path / "none"), engine


async def test_api_stats_watchlist_feeds_and_extract(
    tmp_path: Path, router: respx.MockRouter
) -> None:
    mock_all(router)
    async with httpx.AsyncClient() as feed_http:
        app, _ = make_app(tmp_path, feed_http)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=f"http://127.0.0.1:{PORT}") as c:
            rid = (await c.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8"})).json()["id"]

            stats = (await c.get("/api/stats?days=7", headers=AUTH)).json()
            assert stats["total"] == 1
            assert stats["sources"][0]["source"] == "virustotal"
            assert (await c.get("/api/stats?days=0", headers=AUTH)).status_code == 422

            added = await c.post("/api/watchlist", headers=AUTH, json={"report_id": rid})
            assert [e["ioc"] for e in added.json()["entries"]] == ["8.8.8.8"]
            assert added.json()["entries"][0]["last_level"] == "malicious"
            assert (
                await c.post("/api/watchlist", headers=AUTH, json={"report_id": "nope"})
            ).status_code == 404
            assert (await c.post("/api/watchlist/recheck", headers=AUTH, json={})).json() == []
            gone = await c.delete("/api/watchlist", headers=AUTH, params={"ioc": "8.8.8.8"})
            assert gone.json()["entries"] == []

            assert (await c.get("/api/feeds", headers=AUTH)).json() == []
            updated = (await c.post("/api/feeds/update", headers=AUTH, json={})).json()
            assert all(u["ok"] for u in updated)
            assert {f["name"] for f in (await c.get("/api/feeds", headers=AUTH)).json()} >= {
                "tranco",
                "cisa_kev",
            }

            found = (await c.post("/api/extract", headers=AUTH, json={"text": TICKET})).json()
            assert "evil.com" in [i["value"] for i in found["items"]]
            assert any(s["value"] == "192.168.1.10" for s in found["skipped"])
            too_big = await c.post("/api/extract", headers=AUTH, json={"text": "x" * 200_001})
            assert too_big.status_code == 422


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/stats"),
        ("GET", "/api/watchlist"),
        ("POST", "/api/feeds/update"),
        ("POST", "/api/extract"),
    ],
)
async def test_new_routes_need_the_token(tmp_path: Path, method: str, path: str) -> None:
    async with httpx.AsyncClient() as http:
        app, _ = make_app(tmp_path, http)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=f"http://127.0.0.1:{PORT}") as c:
            r = await c.request(method, path, json={} if method == "POST" else None)
            assert r.status_code == 401

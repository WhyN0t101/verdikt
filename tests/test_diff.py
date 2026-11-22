"""Report diff (pure) and history search: `diff_reports`, the diff route, `GET /api/reports?q=`."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests.conftest import CountingLimiter, Fake
from verdikt.api.app import create_app
from verdikt.cache import WATCHLIST_MAX, Cache
from verdikt.config import Settings, load_rules
from verdikt.diff import MAX_TEXT, diff_reports
from verdikt.engine import Engine
from verdikt.models import Confidence, IOCType, Level, Report, SourceResult, Status
from verdikt.sources.base import Source

T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)


def row(
    source: str = "virustotal",
    status: Status = Status.OK,
    level: Level = Level.SAFE,
    summary: str = "",
    **metrics: int | bool,
) -> SourceResult:
    return SourceResult(
        source=source, status=status, level=level, summary=summary, metrics=metrics, raw={"k": 1}
    )


def rep(
    rid: str = "r1",
    ioc: str = "8.8.8.8",
    level: Level = Level.SAFE,
    results: list[SourceResult] | None = None,
    reasons: list[str] | None = None,
    minutes: int = 0,
    agreeing: int = 1,
    total: int = 2,
    confidence: Confidence = Confidence.LOW,
    ioc_type: IOCType = IOCType.IP,
) -> Report:
    return Report(
        id=rid,
        ioc=ioc,
        ioc_type=ioc_type,
        level=level,
        agreeing=agreeing,
        total=total,
        confidence=confidence,
        reasons=reasons or [],
        results=results if results is not None else [row()],
        created_at=T0 + timedelta(minutes=minutes),
    )


# --- the pure function ---------------------------------------------------------------------


def test_identical_reports_have_an_empty_diff() -> None:
    d = diff_reports(rep("a"), rep("b", minutes=5))
    assert (d.changed, d.sources, d.reasons_added, d.reasons_removed) == (False, [], [], [])
    assert (d.report_id, d.previous_id, d.previous_at) == ("b", "a", T0)
    assert (d.level_from, d.level_to) == (Level.SAFE, Level.SAFE)


def test_first_report_has_no_previous() -> None:
    d = diff_reports(None, rep("a"))
    assert (d.previous_id, d.previous_at, d.level_from, d.agreeing_from) == (None, None, None, None)
    assert (d.total_from, d.confidence_from) == (None, None)
    assert (d.changed, d.sources, d.level_to, d.total_to) == (False, [], Level.SAFE, 2)


def test_level_change_and_counts() -> None:
    old = rep("a", level=Level.SUSPICIOUS, agreeing=1, total=3)
    new = rep("b", level=Level.MALICIOUS, agreeing=2, total=3, confidence=Confidence.HIGH)
    d = diff_reports(old, new)
    assert d.changed is True
    assert (d.level_from, d.level_to) == (Level.SUSPICIOUS, Level.MALICIOUS)
    assert (d.agreeing_from, d.agreeing_to, d.total_from, d.total_to) == (1, 2, 3, 3)
    assert (d.confidence_from, d.confidence_to) == ("low", "high")


def test_a_source_level_and_metric_change() -> None:
    old = rep("a", results=[row(level=Level.SAFE, malicious=0, tor=False)])
    new = rep("b", results=[row(level=Level.MALICIOUS, malicious=7, tor=False)])
    (c,) = diff_reports(old, new).sources
    assert (c.source, c.change) == ("virustotal", "changed")
    assert (c.level_from, c.level_to) == (Level.SAFE, Level.MALICIOUS)
    assert c.no_answer is False
    assert [(m.key, m.from_, m.to) for m in c.metrics] == [("malicious", 0, 7)]  # only changed keys


def test_a_metric_missing_in_the_old_report_has_from_null() -> None:
    old = rep("a", results=[row(malicious=1)])
    new = rep("b", results=[row(malicious=1, reputation=-3)])
    (c,) = diff_reports(old, new).sources
    assert [(m.key, m.from_, m.to) for m in c.metrics] == [("reputation", None, -3)]


def test_a_bool_metric_stays_a_bool() -> None:
    (c,) = diff_reports(rep(results=[row(tor=False)]), rep(results=[row(tor=True)])).sources
    (m,) = c.metrics
    assert (m.from_, m.to) == (False, True)
    assert isinstance(m.to, bool)


def test_a_summary_change_is_a_change() -> None:
    old = rep("a", results=[row(summary="clean")])
    new = rep("b", results=[row(summary="5 engines")])
    (c,) = diff_reports(old, new).sources
    assert (c.summary_from, c.summary_to) == ("clean", "5 engines")


def test_source_added_and_removed() -> None:
    old = rep("a", results=[row("virustotal"), row("abuseipdb")])
    new = rep("b", results=[row("virustotal"), row("otx", level=Level.INFO, summary="2 pulses")])
    added, removed = diff_reports(old, new).sources
    assert (added.source, added.change, added.status_from, added.status_to) == (
        "otx",
        "added",
        None,
        Status.OK,
    )
    assert (added.level_from, added.level_to, added.summary_to) == (None, Level.INFO, "2 pulses")
    assert (removed.source, removed.change, removed.status_from, removed.status_to) == (
        "abuseipdb",
        "removed",
        Status.OK,
        None,
    )
    assert removed.no_answer is False


@pytest.mark.parametrize(
    ("status", "no_answer"),
    [
        (Status.ERROR, True),
        (Status.RATE_LIMITED, True),
        (Status.SKIPPED, True),
        (Status.NOT_FOUND, False),
        (Status.OK, False),
    ],
)
def test_no_answer_is_decided_here_not_in_the_ui(status: Status, no_answer: bool) -> None:
    old = rep("a", results=[row(status=Status.OK if status is not Status.OK else Status.ERROR)])
    new = rep("b", results=[row(status=status)])
    (c,) = diff_reports(old, new).sources
    assert (c.status_from is not c.status_to, c.status_to) == (True, status)
    assert c.no_answer is no_answer


def test_an_error_is_never_reported_as_an_improvement_in_level() -> None:
    # ok/malicious -> error/unknown: the level moved to unknown AND the row is flagged no answer
    old = rep("a", results=[row(level=Level.MALICIOUS, malicious=9)])
    new = rep("b", results=[row(status=Status.ERROR, level=Level.UNKNOWN, summary="HTTP 500")])
    (c,) = diff_reports(old, new).sources
    assert c.no_answer is True
    assert (c.status_from, c.status_to) == (Status.OK, Status.ERROR)


def test_sources_are_ordered_level_status_other_added_removed() -> None:
    old = rep(
        "a",
        results=[
            row("s_removed"),
            row("s_summary", summary="x"),
            row("s_status"),
            row("s_level"),
        ],
    )
    new = rep(
        "b",
        results=[
            row("s_added"),
            row("s_summary", summary="y"),
            row("s_status", status=Status.ERROR),
            row("s_level", level=Level.MALICIOUS),
        ],
    )
    assert [c.source for c in diff_reports(old, new).sources] == [
        "s_level",
        "s_status",
        "s_summary",
        "s_added",
        "s_removed",
    ]


def test_reasons_added_and_removed() -> None:
    old = rep("a", reasons=["same", "gone"])
    new = rep("b", reasons=["same", "new"])
    d = diff_reports(old, new)
    assert (d.reasons_added, d.reasons_removed, d.changed) == (["new"], ["gone"], True)


def test_raw_never_leaves_the_diff() -> None:
    old = rep("a", results=[row(malicious=0)])
    new = rep("b", results=[row(malicious=5)])
    assert "raw" not in diff_reports(old, new).model_dump_json()


def test_text_is_stripped_of_control_and_bidi_characters_and_capped() -> None:
    evil = "ok‮ dna⁦\u0007\x00 \x85‏x\ny" + "z" * 500
    old = rep("a", results=[row(summary="clean")], reasons=[])
    new = rep("b", results=[row(summary=evil)], reasons=[evil])
    d = diff_reports(old, new)
    for text in (d.sources[0].summary_to or "", d.reasons_added[0]):
        assert not any(ch in text for ch in "‮⁦‏\x00\x07\x85")
        assert "\n" not in text
        assert text.startswith("ok dna")  # visible text kept, newline became a space
        assert len(text) == MAX_TEXT


def test_diff_does_not_touch_the_inputs() -> None:
    old, new = rep("a"), rep("b", level=Level.MALICIOUS)
    before = (old.model_dump_json(), new.model_dump_json())
    diff_reports(old, new)
    assert (old.model_dump_json(), new.model_dump_json()) == before


# --- the API -------------------------------------------------------------------------------

TOKEN = "t0ken"
AUTH = {"x-verdikt-token": TOKEN}
Env = tuple[httpx.AsyncClient, Cache]


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    http = httpx.AsyncClient()
    cache = Cache(":memory:")
    sources: list[Source] = [Fake("virustotal", {"malicious": 0, "suspicious": 0})]
    engine = Engine(
        Settings(_env_file=None),  # pyright: ignore[reportCallIssue]
        load_rules(),
        cache,
        http,
        sources=sources,
        limiter_factory=CountingLimiter,
    )
    app = create_app(engine, port=8765, token=TOKEN)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as c:
        yield c, cache
    await http.aclose()


async def test_diff_requires_the_token(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a"))
    assert (await client.get("/api/reports/a/diff")).status_code == 401


async def test_diff_of_an_unknown_report_is_404(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a"))
    assert (await client.get("/api/reports/nope/diff", headers=AUTH)).status_code == 404
    assert (await client.get("/api/reports/a/diff?against=nope", headers=AUTH)).status_code == 404


async def test_the_first_report_of_an_indicator_has_previous_null(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a"))
    r = await client.get("/api/reports/a/diff", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert (body["previous_id"], body["previous_at"], body["changed"]) == (None, None, False)
    assert body["level_to"] == "safe"


async def test_default_previous_is_the_newest_earlier_report_of_the_same_ioc(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("old", minutes=0, level=Level.SAFE))
    cache.save_report(rep("other", ioc="1.1.1.1", minutes=3, level=Level.MALICIOUS))
    cache.save_report(rep("mid", minutes=5, level=Level.SUSPICIOUS))
    cache.save_report(rep("new", minutes=10, level=Level.MALICIOUS))
    cache.save_report(rep("later", minutes=20, level=Level.SAFE))  # after: never the baseline
    body = (await client.get("/api/reports/new/diff", headers=AUTH)).json()
    assert (body["previous_id"], body["level_from"], body["level_to"]) == (
        "mid",
        "suspicious",
        "malicious",
    )
    assert body["previous_at"].startswith("2026-01-01T12:05")
    assert body["changed"] is True


async def test_equal_timestamps_still_pick_one_deterministic_earlier_report(env: Env) -> None:
    client, cache = env
    for rid in ("a", "b", "c"):
        cache.save_report(rep(rid, minutes=0))
    assert (await client.get("/api/reports/c/diff", headers=AUTH)).json()["previous_id"] == "b"
    assert (await client.get("/api/reports/a/diff", headers=AUTH)).json()["previous_id"] is None


async def test_against_is_an_explicit_choice_even_for_another_ioc(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a", ioc="1.1.1.1", level=Level.MALICIOUS))
    cache.save_report(rep("b", ioc="8.8.8.8", level=Level.SAFE, minutes=1))
    body = (await client.get("/api/reports/b/diff?against=a", headers=AUTH)).json()
    assert (body["previous_id"], body["level_from"], body["level_to"]) == (
        "a",
        "malicious",
        "safe",
    )


async def test_the_diff_response_has_no_raw_and_clean_text(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a", results=[row(malicious=0)]))
    cache.save_report(rep("b", minutes=1, results=[row(malicious=4, summary="x‮y")]))
    r = await client.get("/api/reports/b/diff", headers=AUTH)
    assert '"raw"' not in r.text
    assert "‮" not in r.text  # escaped or raw: never present in the data
    assert "\\u202e" not in r.text


# --- history search ------------------------------------------------------------------------


def seed(cache: Cache) -> None:
    items: list[tuple[str, str, IOCType, Level]] = [
        ("r1", "evil.example.com", IOCType.DOMAIN, Level.MALICIOUS),
        ("r2", "good.example.org", IOCType.DOMAIN, Level.SAFE),
        ("r3", "1.2.3.4", IOCType.IP, Level.SUSPICIOUS),
        ("r4", "http://evil.example.com/a_b%41", IOCType.URL, Level.MALICIOUS),
        ("r5", "a" * 64, IOCType.SHA256, Level.UNKNOWN),
        ("r6", "50%off.example", IOCType.DOMAIN, Level.SAFE),
    ]
    for i, (rid, ioc, kind, level) in enumerate(items):
        cache.save_report(rep(rid, ioc=ioc, ioc_type=kind, level=level, minutes=i))


Search = Callable[..., list[str]]


@pytest.fixture
def search() -> Search:
    cache = Cache(":memory:")
    seed(cache)

    def run(**kw: object) -> list[str]:
        return [r.id for r in cache.list_reports(**kw)]  # pyright: ignore[reportArgumentType]

    return run


def test_defaults_are_unchanged_and_newest_first(search: Search) -> None:
    assert search() == ["r6", "r5", "r4", "r3", "r2", "r1"]
    assert search(limit=2, offset=1) == ["r5", "r4"]


def test_substring_search_is_case_insensitive(search: Search) -> None:
    assert search(q="EVIL") == ["r4", "r1"]
    assert search(q="example.org") == ["r2"]


def test_percent_and_underscore_and_backslash_match_literally(search: Search) -> None:
    assert search(q="%") == ["r6", "r4"]  # not "everything"
    assert search(q="50%") == ["r6"]
    assert search(q="_") == ["r4"]  # not "any character"
    assert search(q="a_b") == ["r4"]
    assert search(q="\\") == []
    assert search(q="!") == []  # the escape character itself is literal too
    assert search(q="%41") == ["r4"]


def test_level_and_type_filters_and_their_combination(search: Search) -> None:
    assert search(level=Level.MALICIOUS) == ["r4", "r1"]
    assert search(ioc_type=IOCType.DOMAIN) == ["r6", "r2", "r1"]
    assert search(level=Level.SAFE, ioc_type=IOCType.DOMAIN, q="good") == ["r2"]
    assert search(level=Level.SAFE, ioc_type=IOCType.IP) == []


def test_paging_through_a_filter(search: Search) -> None:
    assert search(ioc_type=IOCType.DOMAIN, limit=2) == ["r6", "r2"]
    assert search(ioc_type=IOCType.DOMAIN, limit=2, offset=2) == ["r1"]
    assert search(ioc_type=IOCType.DOMAIN, limit=2, offset=3) == []


def test_sql_in_q_is_just_text_and_the_table_survives() -> None:
    cache = Cache(":memory:")
    seed(cache)
    assert cache.list_reports(q="'; DROP TABLE reports; --") == []
    assert cache.list_reports(q='" OR 1=1 --') == []
    assert len(cache.list_reports()) == 6


def test_same_timestamp_pages_do_not_overlap_or_skip() -> None:
    cache = Cache(":memory:")
    for rid in ("a", "b", "c", "d"):
        cache.save_report(rep(rid, ioc=f"{rid}.test", ioc_type=IOCType.DOMAIN, minutes=0))
    pages = [cache.list_reports(limit=2, offset=o) for o in (0, 2)]
    assert [r.id for p in pages for r in p] == ["d", "c", "b", "a"]


async def test_api_search_params(env: Env) -> None:
    client, cache = env
    seed(cache)

    async def ids(query: str) -> list[str]:
        r = await client.get(f"/api/reports?{query}", headers=AUTH)
        assert r.status_code == 200, r.text
        return [x["id"] for x in r.json()]

    assert await ids("") == ["r6", "r5", "r4", "r3", "r2", "r1"]
    assert await ids("q=evil&level=malicious&type=url") == ["r4"]
    assert await ids("q=%25") == ["r6", "r4"]  # a literal percent sign
    assert await ids("type=domain&limit=1&offset=1") == ["r2"]
    first = (await client.get("/api/reports?limit=1", headers=AUTH)).json()[0]
    assert set(first) == {"id", "ioc", "ioc_type", "level", "created_at"}  # shape unchanged


@pytest.mark.parametrize(
    "query",
    [
        "level=bogus",
        "level=info",
        "type=bogus",
        f"q={'a' * 201}",
        "limit=0",
        "limit=201",
        "offset=-1",
    ],
)
async def test_api_rejects_bad_search_params(env: Env, query: str) -> None:
    client, _ = env
    assert (await client.get(f"/api/reports?{query}", headers=AUTH)).status_code == 422


async def test_q_at_the_limit_is_accepted(env: Env) -> None:
    client, _ = env
    assert (await client.get(f"/api/reports?q={'a' * 200}", headers=AUTH)).json() == []


# --- watchlist cap -------------------------------------------------------------------------


async def test_watch_state_tells_the_cap(env: Env) -> None:
    client, _ = env
    body = (await client.get("/api/watchlist", headers=AUTH)).json()
    assert body["max_entries"] == WATCHLIST_MAX


async def test_an_unreadable_newest_earlier_report_is_skipped(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("old", minutes=0, level=Level.SAFE))
    cache.save_report(rep("bad", minutes=5))
    cache.save_report(rep("new", minutes=10, level=Level.MALICIOUS))
    with cache._lock, cache._db:  # pyright: ignore[reportPrivateUsage]
        cache._db.execute("UPDATE reports SET body='{}' WHERE id='bad'")  # pyright: ignore[reportPrivateUsage]
    body = (await client.get("/api/reports/new/diff", headers=AUTH)).json()
    assert body["previous_id"] == "old"


async def test_against_is_length_limited(env: Env) -> None:
    client, cache = env
    cache.save_report(rep("a"))
    r = await client.get(f"/api/reports/a/diff?against={'x' * 65}", headers=AUTH)
    assert r.status_code == 422

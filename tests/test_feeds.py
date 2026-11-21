"""Local feeds (Feodo, Spamhaus DROP, Tor exits, Tranco), KEV/EPSS data and hashlookup.

Feed fixtures in tests/fixtures/feeds are real downloads cut down to a few rows.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest
import respx

from tests.conftest import FIXTURES, fixture
from verdikt.config import load_rules
from verdikt.models import IOC, IOCType, Level, SourceResult, Status
from verdikt.sources import feeds
from verdikt.sources.base import Gate
from verdikt.sources.feeds import FeedStore, LocalFeeds, update_feeds
from verdikt.sources.hashlookup import Hashlookup
from verdikt.verdict import decide

RULES = load_rules()
SAMPLES = FIXTURES / "feeds"
URLS = {
    feeds.FEODO: "feodo.txt",
    feeds.DROP: "drop_v4.json",
    feeds.TOR: "tor.txt",
    feeds.TRANCO: "tranco.zip",
    feeds.KEV: "kev.json",
    feeds.EPSS: "epss.csv.gz",
}


def sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def mock_all(router: respx.MockRouter, **overrides: httpx.Response) -> None:
    for url, name in URLS.items():
        router.get(url).mock(
            return_value=overrides.get(name) or httpx.Response(200, content=sample(name))
        )


# --- parsers ------------------------------------------------------------------------------


def test_parse_ip_list_skips_comments_and_junk() -> None:
    ips = feeds.parse_ip_list(sample("feodo.txt").decode())
    assert "27.133.154.218" in ips
    assert all(not ip.startswith("#") for ip in ips)
    assert feeds.parse_ip_list("# only a comment\nnot-an-ip\n 1.2.3.4 # tail\n") == {"1.2.3.4"}


def test_parse_drop_reads_cidrs_and_ignores_metadata() -> None:
    cidrs = feeds.parse_drop(sample("drop_v4.json").decode())
    assert cidrs[0] == "1.10.16.0/20"
    assert len(cidrs) == 3  # the trailing {"type":"metadata"} line has no cidr
    assert feeds.parse_drop("garbage\n{}\n") == []


def test_parse_tranco_keeps_top_n_in_rank_order() -> None:
    assert feeds.parse_tranco(sample("tranco.zip"), 3) == [
        "google.com",
        "cloudflare.com",
        "amazonaws.com",
    ]
    assert len(feeds.parse_tranco(sample("tranco.zip"), 100)) == 6


def test_parse_kev_maps_cve_to_details() -> None:
    kev = feeds.parse_kev(sample("kev.json"))
    assert len(kev) == 3
    cve, info = next(iter(kev.items()))
    assert cve.startswith("CVE-")
    assert set(info) == {"name", "added", "ransomware"}


def test_parse_epss_skips_comment_and_header() -> None:
    rows = feeds.parse_epss(sample("epss.csv.gz"))
    assert rows[0] == ("CVE-1999-0001", 0.04753, 0.9209)
    assert len(rows) == 6


# --- update + store -----------------------------------------------------------------------


async def test_update_downloads_parses_and_records_meta(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    mock_all(router)
    results = await update_feeds(client, tmp_path)
    assert {r.name: (r.ok, r.count) for r in results} == {
        "feodo": (True, 5),
        "spamhaus_drop": (True, 3),
        "tor_exits": (True, 5),
        "tranco": (True, 6),
        "cisa_kev": (True, 3),
        "epss": (True, 6),
    }
    status = feeds.feeds_status(tmp_path)
    assert status["tranco"]["count"] == 6
    assert "fetched_at" in status["tranco"]
    db = sqlite3.connect(tmp_path / "epss.sqlite")
    assert db.execute("SELECT score FROM epss WHERE cve='CVE-1999-0001'").fetchone() == (0.04753,)
    db.close()


async def test_one_failing_feed_keeps_the_others_and_its_old_copy(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    mock_all(router)
    await update_feeds(client, tmp_path)
    before = (tmp_path / "tor.txt").read_text(encoding="utf-8")
    router.clear()
    mock_all(router, **{"tor.txt": httpx.Response(503)})
    results = {r.name: r for r in await update_feeds(client, tmp_path)}
    assert results["tor_exits"].ok is False
    assert "HTTPStatusError" in results["tor_exits"].detail
    assert results["feodo"].ok is True
    assert (tmp_path / "tor.txt").read_text(encoding="utf-8") == before


async def test_oversized_and_garbage_feeds_are_rejected(
    router: respx.MockRouter,
    client: httpx.AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_all(
        router,
        **{
            "tranco.zip": httpx.Response(200, content=b"not a zip"),
            "kev.json": httpx.Response(200, content=b"{}"),
        },
    )
    results = {r.name: r for r in await update_feeds(client, tmp_path)}
    assert not results["tranco"].ok
    assert not results["cisa_kev"].ok
    router.clear()
    monkeypatch.setattr(feeds, "MAX_BYTES", 10)
    mock_all(router)
    assert not any(r.ok for r in await update_feeds(client, tmp_path / "small"))


async def test_store_matches_ips_cidrs_tor_and_exact_top_sites(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    mock_all(router)
    await update_feeds(client, tmp_path)
    store = FeedStore(tmp_path)
    assert store.available
    assert store.ip("27.133.154.218") == (True, False, "Feodo Tracker C2")
    assert store.ip("1.10.16.5") == (True, False, "Spamhaus DROP")  # inside 1.10.16.0/20
    assert store.ip("1.10.32.5") == (False, False, None)
    tor_ip = (tmp_path / "tor.txt").read_text(encoding="utf-8").split()[0]
    assert store.ip(tor_ip) == (False, True, None)
    assert store.top_rank("google.com") == 1
    assert store.top_rank("sub.google.com") is None  # exact match only
    assert store.top_rank("evil.github.io") is None


def test_store_without_feeds_is_unavailable(tmp_path: Path) -> None:
    store = FeedStore(tmp_path / "missing")
    assert store.available is False
    assert LocalFeeds(tmp_path / "missing").enabled is False


async def test_store_reloads_after_an_update(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    store = FeedStore(tmp_path)
    assert store.available is False
    mock_all(router)
    await update_feeds(client, tmp_path)
    assert store.available is True
    assert store.top_rank("google.com") == 1


# --- the source ---------------------------------------------------------------------------


async def test_localfeeds_source_results(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path, gate: Gate
) -> None:
    mock_all(router)
    await update_feeds(client, tmp_path)
    src = LocalFeeds(tmp_path)
    assert src.enabled
    bad = await src.query(IOC(value="27.133.154.218", type=IOCType.IP), gate)
    assert bad.status is Status.OK
    assert bad.metrics == {"blocklisted": True, "tor_exit": False, "top_site": False}
    assert bad.tags == ["Feodo Tracker C2"]
    assert bad.link is not None
    clean = await src.query(IOC(value="8.8.8.8", type=IOCType.IP), gate)
    assert clean.metrics["blocklisted"] is False
    top = await src.query(IOC(value="google.com", type=IOCType.DOMAIN), gate)
    assert top.metrics["top_site"] is True
    assert "rank 1" in top.summary
    other = await src.query(IOC(value="not-popular.example", type=IOCType.DOMAIN), gate)
    assert other.metrics["top_site"] is False


# --- verdict integration ------------------------------------------------------------------


def row(source: str, **m: int | bool) -> SourceResult:
    return SourceResult(source=source, status=Status.OK, metrics=m)


def vt(n: int = 0) -> SourceResult:
    return row("virustotal", malicious=n, suspicious=0)


LOCAL = {"blocklisted": False, "tor_exit": False, "top_site": False}


@pytest.mark.parametrize(
    ("name", "rows", "want"),
    [
        ("blocklisted IP", [row("localfeeds", **{**LOCAL, "blocklisted": True})], Level.MALICIOUS),
        (
            "tor exit alone is not a verdict",
            [row("localfeeds", **{**LOCAL, "tor_exit": True}), vt()],
            Level.SAFE,
        ),
        (
            "top site softens a VT false positive",
            [vt(1), row("localfeeds", **{**LOCAL, "top_site": True})],
            Level.SAFE,
        ),
        (
            "top site cannot clear malicious",
            [vt(9), row("localfeeds", **{**LOCAL, "top_site": True})],
            Level.MALICIOUS,
        ),
        (
            "hashlookup flagged malicious",
            [row("hashlookup", known_good=False, known_malicious=True)],
            Level.SUSPICIOUS,
        ),
        (
            "known-good file softens one engine hit",
            [vt(1), row("hashlookup", known_good=True, known_malicious=False)],
            Level.SAFE,
        ),
        (
            "known-good file cannot clear malicious",
            [vt(9), row("hashlookup", known_good=True, known_malicious=False)],
            Level.MALICIOUS,
        ),
        (
            "local feeds alone are not enough for safe",
            [row("localfeeds", **LOCAL), row("abuseipdb", score=0)],
            Level.UNKNOWN,
        ),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_local_sources_in_the_verdict(name: str, rows: list[SourceResult], want: Level) -> None:
    assert decide(rows, RULES).level is want


# --- hashlookup ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "value", "kind", "metrics"),
    [
        (
            "known_good",
            "d41d8cd98f00b204e9800998ecf8427e",
            IOCType.MD5,
            {"known_good": True, "known_malicious": False},
        ),
        (
            "known_malicious",
            "a" * 64,
            IOCType.SHA256,
            {"known_good": False, "known_malicious": True},
        ),
    ],
)
async def test_hashlookup_maps_real_responses(
    name: str,
    value: str,
    kind: IOCType,
    metrics: dict[str, bool],
    router: respx.MockRouter,
    gate: Gate,
) -> None:
    router.route().mock(return_value=httpx.Response(200, json=fixture("hashlookup", name)))
    result = await Hashlookup().query(IOC(value=value, type=kind), gate)
    assert result.status is Status.OK
    assert {k: result.metrics[k] for k in metrics} == metrics
    assert result.link is not None


async def test_hashlookup_miss_is_not_found(router: respx.MockRouter, gate: Gate) -> None:
    router.route().mock(return_value=httpx.Response(404, json=fixture("hashlookup", "miss")))
    result = await Hashlookup().query(IOC(value="0" * 64, type=IOCType.SHA256), gate)
    assert result.status is Status.NOT_FOUND

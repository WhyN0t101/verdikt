"""CISA KEV and EPSS context for the CVEs InternetDB reports on a host."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx

from tests.conftest import CountingLimiter, Fake, make_engine
from tests.test_feeds import mock_all, sample
from verdikt.cache import Cache
from verdikt.config import Settings
from verdikt.enrich.cve import CveStore
from verdikt.models import IOC, SourceResult, Status
from verdikt.sources import feeds
from verdikt.sources.base import Gate, Source

KEV_ID = next(iter(feeds.parse_kev(sample("kev.json"))))


async def populated(
    router: respx.MockRouter, client: httpx.AsyncClient, directory: Path
) -> CveStore:
    mock_all(router)
    await feeds.update_feeds(client, directory)
    return CveStore(directory)


async def test_lookup_orders_kev_first_and_attaches_epss(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    store = await populated(router, client, tmp_path)
    found = store.lookup(["CVE-1999-0001", KEV_ID.lower(), "not-a-cve", "CVE-2020-1", KEV_ID])
    assert [c.id for c in found] == [KEV_ID, "CVE-1999-0001"]  # KEV first, junk dropped, deduped
    kev, other = found
    assert kev.kev and kev.kev_name and kev.kev_added
    assert kev.epss is None  # not in the sample EPSS rows
    assert (other.kev, other.epss, other.percentile) == (False, 0.04753, 0.9209)


def test_lookup_without_feeds_is_empty_of_context(tmp_path: Path) -> None:
    [c] = CveStore(tmp_path / "none").lookup(["CVE-2021-44228"])
    assert (c.kev, c.epss) == (False, None)


class FakeInternetDB(Fake):
    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        return self.result(
            Status.OK, "ports", metrics={"ports": 1}, raw={"vulns": [KEV_ID, "CVE-1999-0001"]}
        )


async def test_engine_attaches_cves_and_a_kev_reason(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    mock_all(router)
    await feeds.update_feeds(client, tmp_path / "feeds")
    settings = Settings(_env_file=None, feeds_dir=tmp_path / "feeds")  # pyright: ignore[reportCallIssue]
    sources: list[Source] = [
        FakeInternetDB("internetdb"),
        Fake("virustotal", {"malicious": 0, "suspicious": 0}),
    ]
    engine = make_engine(
        settings, Cache(":memory:"), client, sources, limiter_factory=CountingLimiter
    )
    report = await engine.check("8.8.8.8")
    assert [c.id for c in report.cves] == [KEV_ID, "CVE-1999-0001"]
    assert any("KEV" in r for r in report.reasons)
    assert report.level.value in ("safe", "unknown")  # CVEs are context, not a verdict input


async def test_engine_without_vulns_has_no_cves(
    settings: Settings, client: httpx.AsyncClient
) -> None:
    sources: list[Source] = [Fake("virustotal", {"malicious": 0, "suspicious": 0})]
    report = await make_engine(
        settings, Cache(":memory:"), client, sources, limiter_factory=CountingLimiter
    ).check("8.8.8.8")
    assert report.cves == []


def test_only_plain_ascii_cve_ids_are_accepted(tmp_path: Path) -> None:
    store = CveStore(tmp_path)
    # a trailing newline (`$` would match it) and Arabic-Indic digits (`\d` would match them)
    junk = [
        "CVE-2021-1234\n",
        "CVE-\u0662\u0660\u0662\u0661-1234",
        "CVE-2021-\u0661\u0662\u0663\u0664",
    ]
    assert store.lookup(junk) == []
    assert [c.id for c in store.lookup(["cve-2021-1234"])] == ["CVE-2021-1234"]

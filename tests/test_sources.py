"""Every source against recorded-shape fixtures: hit, miss, error, 429. No live network."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import respx

from tests.conftest import Sleeps, fixture
from verdikt.models import IOC, IOCType, Status
from verdikt.sources import build_sources
from verdikt.sources.abuseipdb import AbuseIPDB
from verdikt.sources.base import BaseSource, Gate
from verdikt.sources.greynoise import GreyNoise
from verdikt.sources.hybrid import HybridAnalysis
from verdikt.sources.internetdb import InternetDB
from verdikt.sources.malwarebazaar import MalwareBazaar
from verdikt.sources.otx import OTX
from verdikt.sources.threatfox import ThreatFox
from verdikt.sources.urlhaus import URLhaus
from verdikt.sources.urlscan import Urlscan
from verdikt.sources.virustotal import VirusTotal

IP = IOC(value="185.220.101.4", type=IOCType.IP)
DOM = IOC(value="evil.example", type=IOCType.DOMAIN)
URL = IOC(value="http://evil.example/a.exe", type=IOCType.URL)
SHA = IOC(value="a" * 64, type=IOCType.SHA256)
MD5 = IOC(value="44d88612fea8a8f36de82e1278abb02f", type=IOCType.MD5)


@dataclass
class Case:
    source: BaseSource
    ioc: IOC
    method: str
    url: str  # respx url__startswith
    fixture: tuple[str, str]
    metrics: dict[str, int | bool]
    status: Status = Status.OK


def _route(router: respx.MockRouter, case: Case, **resp: Any) -> respx.Route:
    return router.route(method=case.method, url__startswith=case.url).mock(
        return_value=httpx.Response(200, **resp)
    )


BAD_DOM = IOC(value="s.gsx88.org", type=IOCType.DOMAIN)
EXAMPLE = IOC(value="example.com", type=IOCType.DOMAIN)

HITS = [
    # recorded from live responses (trimmed, see tests/fixtures/README.md)
    Case(
        ThreatFox("k"),
        BAD_DOM,
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        ("threatfox", "hit_domain_real"),
        {"match": True, "entries": 1},
    ),
    Case(
        MalwareBazaar("k"),
        SHA,
        "POST",
        "https://mb-api.abuse.ch/api/v1/",
        ("malwarebazaar", "hit_real"),
        {"match": True},
    ),
    Case(
        OTX(),
        EXAMPLE,
        "GET",
        "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general",
        ("otx", "domain_popular"),
        {"pulses": 50},
    ),
    Case(
        VirusTotal("k"),
        EXAMPLE,
        "GET",
        "https://www.virustotal.com/api/v3/domains/example.com",
        ("virustotal", "domain_real"),
        {"malicious": 0, "suspicious": 0, "total": 92},
    ),
    Case(
        VirusTotal("k"),
        IP,
        "GET",
        "https://www.virustotal.com/api/v3/ip_addresses/185.220.101.4",
        ("virustotal", "ip_hit"),
        {"malicious": 13, "suspicious": 2, "total": 92},
    ),
    Case(
        VirusTotal("k"),
        IP,
        "GET",
        "https://www.virustotal.com/api/v3/ip_addresses/185.220.101.4",
        ("virustotal", "ip_clean"),
        {"malicious": 0, "suspicious": 0},
    ),
    Case(
        VirusTotal("k"),
        DOM,
        "GET",
        "https://www.virustotal.com/api/v3/domains/evil.example",
        ("virustotal", "domain_hit"),
        {"malicious": 7},
    ),
    Case(
        VirusTotal("k"),
        MD5,
        "GET",
        f"https://www.virustotal.com/api/v3/files/{MD5.value}",
        ("virustotal", "file_hit"),
        {"malicious": 61, "total": 74},
    ),
    Case(
        AbuseIPDB("k"),
        IP,
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        ("abuseipdb", "hit"),
        {"score": 100, "reports": 448, "tor": True},
    ),
    Case(
        AbuseIPDB("k"),
        IP,
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        ("abuseipdb", "clean"),
        {"score": 0, "reports": 0, "tor": False},
    ),
    Case(
        Urlscan(),
        DOM,
        "GET",
        "https://urlscan.io/api/v1/search/",
        ("urlscan", "search_real"),
        {"scans": 5},
    ),
    Case(
        ThreatFox("k"),
        IP,
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        ("threatfox", "hit"),
        {"match": True, "entries": 1},
    ),
    Case(
        ThreatFox("k"),
        IP,
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        ("threatfox", "miss_real"),
        {"match": False, "entries": 0},
    ),
    Case(
        URLhaus("k"),
        DOM,
        "POST",
        "https://urlhaus-api.abuse.ch/v1/host/",
        ("urlhaus", "host_hit"),
        {"match": True, "online": True, "urls": 3},
    ),
    Case(
        URLhaus("k"),
        DOM,
        "POST",
        "https://urlhaus-api.abuse.ch/v1/host/",
        ("urlhaus", "host_offline_real"),
        {"match": True, "online": False, "urls": 5},
    ),
    Case(
        URLhaus("k"),
        URL,
        "POST",
        "https://urlhaus-api.abuse.ch/v1/url/",
        ("urlhaus", "url_hit"),
        {"match": True, "online": True},
    ),
    Case(
        URLhaus("k"),
        DOM,
        "POST",
        "https://urlhaus-api.abuse.ch/v1/host/",
        ("urlhaus", "miss"),
        {"match": False, "online": False},
    ),
    Case(
        MalwareBazaar("k"),
        SHA,
        "POST",
        "https://mb-api.abuse.ch/api/v1/",
        ("malwarebazaar", "hit"),
        {"match": True},
    ),
    Case(
        MalwareBazaar("k"),
        SHA,
        "POST",
        "https://mb-api.abuse.ch/api/v1/",
        ("malwarebazaar", "miss_real"),
        {"match": False},
    ),
    Case(
        OTX(),
        DOM,
        "GET",
        "https://otx.alienvault.com/api/v1/indicators/domain/evil.example/general",
        ("otx", "hit"),
        {"pulses": 5},
    ),
    Case(
        OTX(),
        IP,
        "GET",
        "https://otx.alienvault.com/api/v1/indicators/IPv4/185.220.101.4/general",
        ("otx", "clean"),
        {"pulses": 0},
    ),
    Case(
        GreyNoise(),
        IP,
        "GET",
        "https://api.greynoise.io/v3/community/185.220.101.4",
        ("greynoise", "riot"),
        {"riot": True, "noise": False},
    ),
    Case(
        GreyNoise(),
        IP,
        "GET",
        "https://api.greynoise.io/v3/community/185.220.101.4",
        ("greynoise", "noise"),
        {"riot": False, "noise": True},
    ),
    Case(
        InternetDB(),
        IP,
        "GET",
        "https://internetdb.shodan.io/185.220.101.4",
        ("internetdb", "hit"),
        {"ports": 4, "vulns": 0, "hostnames": 1},
    ),
    Case(
        HybridAnalysis("k"),
        SHA,
        "GET",
        "https://www.hybrid-analysis.com/api/v2/search/hash",
        ("hybrid", "hit"),
        {"malicious": True, "threat_score": 100},
    ),
]


@pytest.mark.parametrize("case", HITS, ids=[f"{c.fixture[0]}-{c.fixture[1]}" for c in HITS])
async def test_maps_response(case: Case, router: respx.MockRouter, gate: Gate) -> None:
    _route(router, case, json=fixture(*case.fixture))
    result = await case.source.query(case.ioc, gate)
    assert result.status is Status.OK, result.summary
    for key, want in case.metrics.items():
        assert result.metrics[key] == want, key
    assert result.source == case.source.name
    assert result.link is not None
    assert result.raw is not None
    assert result.summary
    assert result.level.value == "unknown"  # sources never set a level


async def test_virustotal_domain_relates_resolved_ip(router: respx.MockRouter, gate: Gate) -> None:
    case = next(c for c in HITS if c.fixture == ("virustotal", "domain_hit"))
    _route(router, case, json=fixture(*case.fixture))
    result = await case.source.query(case.ioc, gate)
    assert [(r.value, r.relation) for r in result.related] == [("203.0.113.9", "resolves_to")]


async def test_malware_family_becomes_related_node(router: respx.MockRouter, gate: Gate) -> None:
    case = next(c for c in HITS if c.fixture == ("threatfox", "hit"))
    _route(router, case, json=fixture(*case.fixture))
    result = await case.source.query(case.ioc, gate)
    assert [(r.value, r.type) for r in result.related] == [("Cobalt Strike", "malware")]


def test_keys_are_sent_in_headers_not_urls(router: respx.MockRouter) -> None:
    import asyncio

    async def run() -> None:
        async with httpx.AsyncClient() as c:
            from tests.conftest import CountingLimiter

            g = Gate("abuseipdb", c, CountingLimiter(), sleep=Sleeps(), backoff=0)
            route = router.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json=fixture("abuseipdb", "clean"))
            )
            await AbuseIPDB("sekret").query(IP, g)
            req = route.calls.last.request
            assert "sekret" not in str(req.url)
            assert req.headers["Key"] == "sekret"

    asyncio.run(run())


# --- failure outcomes, generic across every source ---------------------------------------

ALL = [
    (VirusTotal("k"), IP),
    (AbuseIPDB("k"), IP),
    (Urlscan(), DOM),
    (ThreatFox("k"), DOM),
    (URLhaus("k"), DOM),
    (MalwareBazaar("k"), SHA),
    (OTX(), DOM),
    (GreyNoise(), IP),
    (InternetDB(), IP),
    (HybridAnalysis("k"), SHA),
]
IDS = [s.name for s, _ in ALL]


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_5xx_is_error_after_three_attempts(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate
) -> None:
    route = router.route().mock(return_value=httpx.Response(503))
    result = await source.query(ioc, gate)
    assert result.status is Status.ERROR
    assert route.call_count == 3


@pytest.mark.parametrize("query_status", ["invalid_host", "invalid_url"])
async def test_urlhaus_rejected_input_is_error_not_clean(
    query_status: str, router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, json={"query_status": query_status}))
    result = await URLhaus("k").query(DOM, gate)
    assert result.status is Status.ERROR


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_429_with_long_retry_after_is_rate_limited_without_waiting(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate, sleeps: Sleeps
) -> None:
    route = router.route().mock(return_value=httpx.Response(429, headers={"Retry-After": "120"}))
    result = await source.query(ioc, gate)
    assert result.status is Status.RATE_LIMITED
    assert route.call_count == 1
    assert sleeps.calls == []


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_persistent_short_429_is_rate_limited(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate, sleeps: Sleeps
) -> None:
    router.route().mock(return_value=httpx.Response(429, headers={"Retry-After": "1"}))
    result = await source.query(ioc, gate)
    assert result.status is Status.RATE_LIMITED
    assert sleeps.calls == [1.0, 1.0]


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_404_is_not_found(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(404))
    assert (await source.query(ioc, gate)).status is Status.NOT_FOUND


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_timeout_is_error_not_raise(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(side_effect=httpx.ConnectTimeout("slow"))
    assert (await source.query(ioc, gate)).status is Status.ERROR


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_malformed_body_is_error_not_raise(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, text="<html>not json</html>"))
    assert (await source.query(ioc, gate)).status is Status.ERROR


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
async def test_wrong_shape_is_error_not_raise(
    source: BaseSource, ioc: IOC, router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, json=["unexpected"]))
    assert (await source.query(ioc, gate)).status in (Status.ERROR, Status.NOT_FOUND)


async def test_429_then_success_retries(router: respx.MockRouter, gate: Gate) -> None:
    route = router.get("https://api.abuseipdb.com/api/v2/check").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json=fixture("abuseipdb", "clean")),
        ]
    )
    result = await AbuseIPDB("k").query(IP, gate)
    assert result.status is Status.OK
    assert route.call_count == 2


def test_missing_key_disables_source() -> None:
    from verdikt.config import Settings

    enabled = {s.name: s.enabled for s in build_sources(Settings(_env_file=None))}  # pyright: ignore[reportCallIssue]
    assert enabled["virustotal"] is False
    assert enabled["internetdb"] is True
    assert enabled["urlscan"] is True  # key optional
    assert enabled["threatfox"] is False


def test_urlscan_search_only_never_posts(router: respx.MockRouter) -> None:
    import asyncio

    async def run() -> None:
        async with httpx.AsyncClient() as c:
            from tests.conftest import CountingLimiter

            g = Gate("urlscan", c, CountingLimiter(), sleep=Sleeps(), backoff=0)
            route = router.route().mock(return_value=httpx.Response(200, json={"results": []}))
            await Urlscan("k").query(DOM, g)
            assert route.call_count == 1
            assert route.calls.last.request.method == "GET"
            assert "/search/" in str(route.calls.last.request.url)

    asyncio.run(run())


async def test_threatfox_substring_hits_do_not_count(router: respx.MockRouter, gate: Gate) -> None:
    router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json=fixture("threatfox", "near_miss"))
    )
    result = await ThreatFox("k").query(IP, gate)
    assert result.status is Status.OK
    assert result.metrics["match"] is False


async def test_threatfox_ip_with_port_counts(router: respx.MockRouter, gate: Gate) -> None:
    router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json=fixture("threatfox", "hit"))
    )
    assert (await ThreatFox("k").query(IP, gate)).metrics["match"] is True


async def test_retry_after_http_date_is_honoured(
    router: respx.MockRouter, gate: Gate, sleeps: Sleeps
) -> None:
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    far = format_datetime(datetime.now(UTC) + timedelta(hours=1), usegmt=True)
    route = router.route().mock(return_value=httpx.Response(429, headers={"Retry-After": far}))
    result = await AbuseIPDB("k").query(IP, gate)
    assert result.status is Status.RATE_LIMITED
    assert route.call_count == 1  # an hour away: no retry, no wait
    assert sleeps.calls == []


@pytest.mark.parametrize(("source", "ioc"), ALL, ids=IDS)
@pytest.mark.parametrize(
    "body",
    [
        '{"results": ["x"], "data": [1], "pulse_info": {"pulses": ["x"], "count": 1}}',
        '{"count": Infinity, "data": {"attributes": {"asn": Infinity}}}',
    ],
    ids=["non-dict-members", "infinity"],
)
async def test_odd_member_shapes_never_raise(
    source: BaseSource, ioc: IOC, body: str, router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, text=body))
    await source.query(ioc, gate)  # must return a SourceResult, never raise


async def test_urlscan_is_context_only_search_data(router: respx.MockRouter, gate: Gate) -> None:
    router.route().mock(return_value=httpx.Response(200, json=fixture("urlscan", "search_real")))
    result = await Urlscan().query(IP, gate)
    assert result.status is Status.OK
    assert "malicious" not in result.metrics  # free-plan search has no verdicts
    assert result.related == []  # every scanned page is the IP itself


async def test_real_domain_response_yields_resolved_ips(
    router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, json=fixture("virustotal", "domain_real")))
    result = await VirusTotal("k").query(EXAMPLE, gate)
    values = [r.value for r in result.related]
    assert values[:2] == ["172.66.147.243", "104.20.23.154"]
    assert any(":" in v for v in values)  # AAAA records too

"""RDAP, crt.sh, passive DNS, OpenPhish, MISP export and MISP/STIX import. Fixtures are real."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx
from fastapi import FastAPI

from tests.conftest import CountingLimiter, Fake, Sleeps, fixture, make_engine
from tests.test_feeds import mock_all
from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.misp import to_misp
from verdikt.models import (
    IOC,
    Graph,
    GraphNode,
    IOCType,
    Level,
    Report,
    SourceResult,
    Status,
)
from verdikt.sources import feeds
from verdikt.sources.base import Gate, Source
from verdikt.sources.crtsh import CrtSh
from verdikt.sources.feeds import FeedStore, LocalFeeds
from verdikt.sources.importers import (
    ImportError_,
    parse_any,
    parse_misp,
    parse_stix,
    write_import,
)
from verdikt.sources.passivedns import PassiveDNS
from verdikt.sources.rdap import RDAP
from verdikt.stix import to_stix
from verdikt.verdict import decide

RULES = load_rules()
DOM = IOC(value="example.com", type=IOCType.DOMAIN)
IP = IOC(value="185.220.101.4", type=IOCType.IP)


# --- verdict: the `__lt` operator and RDAP age ------------------------------------------


def row(source: str, **m: int | bool) -> SourceResult:
    return SourceResult(source=source, status=Status.OK, metrics=m)


def test_young_domain_is_suspicious_and_old_one_is_not() -> None:
    vt = row("virustotal", malicious=0, suspicious=0)
    assert decide([row("rdap", age_days=3), vt], RULES).level is Level.SUSPICIOUS
    assert decide([row("rdap", age_days=29), vt], RULES).level is Level.SUSPICIOUS
    assert decide([row("rdap", age_days=30), vt], RULES).level is Level.SAFE
    assert decide([row("rdap", age_days=11000), vt], RULES).level is Level.SAFE


def test_lt_rules_ignore_missing_and_boolean_metrics() -> None:
    vt = row("virustotal", malicious=0, suspicious=0)
    assert decide([row("rdap"), vt], RULES).level is Level.SAFE  # no age published
    assert decide([row("rdap", age_days=True), vt], RULES).level is Level.SAFE


def test_young_domain_reason_names_the_threshold() -> None:
    d = decide([row("rdap", age_days=3)], RULES)
    assert any("age_days 3 < 30" in r for r in d.reasons)


# --- RDAP ---------------------------------------------------------------------------------


async def test_rdap_reads_registration_age_from_a_real_response(
    router: respx.MockRouter, gate: Gate
) -> None:
    route = router.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=fixture("rdap", "example_com"))
    )
    r = await RDAP().query(DOM, gate)
    assert r.status is Status.OK
    assert r.metrics["age_days"] > 10_000  # registered 1995-08-14
    assert "registered 1995-08-14" in r.summary
    assert r.metrics["expires_in_days"] != 0
    assert route.calls.last.request.headers["accept"] == "application/rdap+json"


async def test_rdap_strips_subdomains_until_it_finds_the_registered_domain(
    router: respx.MockRouter, gate: Gate
) -> None:
    router.get("https://rdap.org/domain/a.b.example.com").mock(return_value=httpx.Response(404))
    router.get("https://rdap.org/domain/b.example.com").mock(return_value=httpx.Response(404))
    ok = router.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=fixture("rdap", "example_com"))
    )
    r = await RDAP().query(IOC(value="a.b.example.com", type=IOCType.DOMAIN), gate)
    assert r.status is Status.OK
    assert ok.called
    assert r.summary.startswith("example.com registered")


async def test_rdap_unknown_tld_is_not_found(router: respx.MockRouter, gate: Gate) -> None:
    router.route().mock(return_value=httpx.Response(404))
    r = await RDAP().query(DOM, gate)
    assert r.status is Status.NOT_FOUND


async def test_rdap_without_a_registration_event_is_ok_but_has_no_age(
    router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, json={"events": [], "ldhName": "x.com"}))
    r = await RDAP().query(DOM, gate)
    assert r.status is Status.OK
    assert "age_days" not in r.metrics


# --- crt.sh -------------------------------------------------------------------------------


async def test_crtsh_summarises_real_certificates(router: respx.MockRouter, gate: Gate) -> None:
    route = router.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=fixture("crtsh", "example_com"))
    )
    r = await CrtSh().query(DOM, gate)
    assert r.status is Status.OK
    assert r.metrics["certs"] == 5
    assert r.metrics["names"] >= 1
    assert r.metrics["oldest_days"] >= r.metrics["newest_days"]
    assert route.calls.last.request.url.params["exclude"] == "expired"
    assert all(rel.value.endswith(".example.com") for rel in r.related)
    assert all(rel.inbound for rel in r.related)  # subdomain -> apex


async def test_crtsh_empty_result_is_ok_with_zero_certs(
    router: respx.MockRouter, gate: Gate
) -> None:
    router.route().mock(return_value=httpx.Response(200, json=[]))
    r = await CrtSh().query(DOM, gate)
    assert (r.status, r.metrics["certs"]) == (Status.OK, 0)


async def test_crtsh_never_lists_wildcards_or_the_domain_itself(
    router: respx.MockRouter, gate: Gate
) -> None:
    rows = [
        {
            "name_value": "*.example.com\nexample.com\nwww.example.com",
            "not_before": "2026-01-01T00:00:00",
        }
    ]
    router.route().mock(return_value=httpx.Response(200, json=rows))
    r = await CrtSh().query(DOM, gate)
    assert [x.value for x in r.related] == ["www.example.com"]
    assert r.metrics["names"] == 2


def test_crtsh_has_a_longer_timeout_and_is_context_only() -> None:
    assert CrtSh.timeout > 10
    assert "crtsh" in RULES.context_only


@pytest.mark.parametrize("source", [RDAP(), CrtSh()])
async def test_new_keyless_sources_survive_failures(
    source: RDAP | CrtSh, router: respx.MockRouter, gate: Gate, sleeps: Sleeps
) -> None:
    router.route().mock(side_effect=httpx.ConnectTimeout("slow"))
    assert (await source.query(DOM, gate)).status is Status.ERROR
    router.clear()
    router.route().mock(return_value=httpx.Response(200, text="<html>"))
    assert (await source.query(DOM, gate)).status is Status.ERROR


# --- passive DNS --------------------------------------------------------------------------


async def test_passivedns_for_a_domain_lists_ips(router: respx.MockRouter, gate: Gate) -> None:
    route = router.get("https://www.virustotal.com/api/v3/domains/example.com/resolutions").mock(
        return_value=httpx.Response(200, json=fixture("passivedns", "domain"))
    )
    r = await PassiveDNS("k").query(DOM, gate)
    assert r.status is Status.OK
    assert r.metrics["resolutions"] == 49
    assert all(rel.type == IOCType.IP and not rel.inbound for rel in r.related)
    assert route.calls.last.request.headers["x-apikey"] == "k"
    assert "k" not in str(route.calls.last.request.url)


async def test_passivedns_for_an_ip_lists_domains_pointing_at_it(
    router: respx.MockRouter, gate: Gate
) -> None:
    router.get("https://www.virustotal.com/api/v3/ip_addresses/185.220.101.4/resolutions").mock(
        return_value=httpx.Response(200, json=fixture("passivedns", "ip"))
    )
    r = await PassiveDNS("k").query(IP, gate)
    assert r.metrics["resolutions"] == 53
    assert r.related
    assert all(rel.type == IOCType.DOMAIN and rel.inbound for rel in r.related)


def test_passivedns_is_off_unless_enabled_and_keyed() -> None:
    assert PassiveDNS("k", enabled=False).enabled is False
    assert PassiveDNS(None, enabled=True).enabled is False
    assert PassiveDNS("k", enabled=True).enabled is True
    assert PassiveDNS("k").quota_group == "virustotal"


async def test_passivedns_shares_the_virustotal_limiter_and_budget(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    from verdikt.sources.virustotal import VirusTotal

    router.get(url__startswith="https://www.virustotal.com/api/v3/domains/example.com").mock(
        return_value=httpx.Response(200, json=fixture("passivedns", "domain"))
    )
    cache = Cache(":memory:")
    limiters: list[CountingLimiter] = []

    def factory(n: int, s: float) -> CountingLimiter:
        limiters.append(CountingLimiter(n, s))
        return limiters[-1]

    settings = Settings(_env_file=None, feeds_dir=tmp_path)  # pyright: ignore[reportCallIssue]
    sources: list[Source] = [VirusTotal("k"), PassiveDNS("k")]
    engine = make_engine(settings, cache, client, sources, limiter_factory=factory)
    await engine.check("example.com")
    assert len(limiters) == 1  # one limiter for both: VT allows 4 requests a minute in total
    assert limiters[0].acquired == 2
    assert cache.budget_used("virustotal") == 2


async def test_engine_gives_each_source_its_own_timeout(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    seen: list[float | None] = []

    class Slow(Fake):
        timeout = 33.0

        async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
            seen.append(http.timeout)
            return self.result(Status.OK, "x")

        async def query(self, ioc: IOC, http: Gate) -> SourceResult:
            return await self.lookup(ioc, http)

    settings = Settings(_env_file=None, feeds_dir=tmp_path)  # pyright: ignore[reportCallIssue]
    engine = make_engine(settings, Cache(":memory:"), client, [Slow("virustotal")])
    await engine.check("8.8.8.8")
    assert seen == [33.0]


# --- OpenPhish ----------------------------------------------------------------------------


def sample(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / "feeds" / name).read_text(encoding="utf-8")


def test_parse_url_list_keeps_only_public_urls() -> None:
    urls = feeds.parse_url_list(
        sample("openphish.txt") + "\nhttp://192.168.1.5/x\nnot a url\n# c\n"
    )
    assert len(urls) == 6
    assert all(u.startswith("http") for u in urls)
    assert not any("192.168" in u for u in urls)


async def test_openphish_matches_the_url_and_its_host(
    router: respx.MockRouter, client: httpx.AsyncClient, tmp_path: Path, gate: Gate
) -> None:
    mock_all(router)
    await feeds.update_feeds(client, tmp_path)
    src = LocalFeeds(tmp_path)
    url = IOC(value="https://att-10page42.weeblysite.com/", type=IOCType.URL)
    host = IOC(value="att-10page42.weeblysite.com", type=IOCType.DOMAIN)
    parent = IOC(value="weeblysite.com", type=IOCType.DOMAIN)
    on_url = await src.query(url, gate)
    assert (on_url.metrics["blocklisted"], on_url.tags) == (True, ["OpenPhish"])
    assert (await src.query(host, gate)).metrics["blocklisted"] is True
    assert (await src.query(parent, gate)).metrics["blocklisted"] is False  # no parent inheritance
    other = await src.query(IOC(value="https://fine.example.org/", type=IOCType.URL), gate)
    assert other.metrics["blocklisted"] is False


def test_openphish_listing_is_malicious_in_the_verdict() -> None:
    local = row("localfeeds", blocklisted=True, tor_exit=False, top_site=False)
    assert decide([local], RULES).level is Level.MALICIOUS


# --- MISP export --------------------------------------------------------------------------


def report(level: Level = Level.MALICIOUS) -> Report:
    return Report(
        id="r1",
        ioc="1.2.3.4",
        ioc_type=IOCType.IP,
        level=level,
        agreeing=2,
        total=2,
        reasons=["virustotal: malicious 9 >= 5 -> malicious"],
        graph=Graph(
            nodes=[
                GraphNode(id="ip:1.2.3.4", label="1.2.3.4", kind="ip"),
                GraphNode(id="domain:evil.example", label="evil.example", kind="domain"),
                GraphNode(id="malware:Emotet", label="Emotet", kind="malware"),
                GraphNode(id="asn:AS1", label="AS1", kind="asn"),
            ]
        ),
        created_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
    )


def test_misp_event_shape() -> None:
    ev = to_misp(report())["Event"]
    assert ev["threat_level_id"] == "1"
    assert ev["distribution"] == "0"
    assert ev["published"] is False
    assert ev["date"] == "2026-01-01"
    main, *rest = ev["Attribute"]
    assert (main["type"], main["value"], main["to_ids"]) == ("ip-dst", "1.2.3.4", True)
    assert [(a["type"], a["value"], a["to_ids"]) for a in rest] == [
        ("domain", "evil.example", False)
    ]
    names = [t["name"] for t in ev["Tag"]]
    assert 'verdikt:level="malicious"' in names
    assert 'verdikt:malware="Emotet"' in names
    assert to_misp(report()) == to_misp(report())  # stable ids


def test_misp_safe_report_has_no_ids_flag() -> None:
    ev = to_misp(report(Level.SAFE))["Event"]
    assert ev["threat_level_id"] == "3"
    assert ev["Attribute"][0]["to_ids"] is False


@pytest.mark.parametrize(
    ("kind", "value", "misp_type"),
    [
        (IOCType.DOMAIN, "evil.example", "domain"),
        (IOCType.URL, "http://evil.example/a", "url"),
        (IOCType.SHA256, "a" * 64, "sha256"),
        (IOCType.MD5, "a" * 32, "md5"),
    ],
)
def test_misp_attribute_types(kind: IOCType, value: str, misp_type: str) -> None:
    r = report().model_copy(update={"ioc": value, "ioc_type": kind, "graph": Graph()})
    assert to_misp(r)["Event"]["Attribute"][0]["type"] == misp_type


# --- imports ------------------------------------------------------------------------------

MISP_FILE = {
    "Event": {
        "Attribute": [
            {"type": "ip-dst", "value": "91.92.109.10", "to_ids": True},
            {"type": "ip-dst|port", "value": "91.92.109.11|443", "to_ids": True},
            {"type": "domain|ip", "value": "evil.example.com|91.92.109.12", "to_ids": "1"},
            {"type": "url", "value": "hxxp://evil[.]example.com/a", "to_ids": True},
            {"type": "filename|sha256", "value": "x.exe|" + "b" * 64, "to_ids": True},
            {"type": "ip-dst", "value": "8.8.4.4", "to_ids": False},
            {"type": "ip-dst", "value": "192.168.1.1", "to_ids": True},
            {"type": "comment", "value": "nope", "to_ids": True},
        ],
        "Object": [{"Attribute": [{"type": "md5", "value": "c" * 32, "to_ids": True}]}],
    }
}


def test_parse_misp_takes_ids_attributes_and_splits_composites() -> None:
    got = {v for _, v in parse_misp(json.dumps(MISP_FILE).encode())}
    assert got == {
        "91.92.109.10",
        "91.92.109.11",
        "evil.example.com",
        "91.92.109.12",
        "http://evil.example.com/a",
        "b" * 64,
        "c" * 32,
    }  # no 8.8.4.4 (not to_ids), no 192.168.1.1 (internal), no comment


def test_parse_misp_all_attributes() -> None:
    got = {v for _, v in parse_misp(json.dumps(MISP_FILE).encode(), all_attributes=True)}
    assert "8.8.4.4" in got
    assert "192.168.1.1" not in got


def test_parse_misp_response_wrapper_and_event_list() -> None:
    wrapped = {"response": [MISP_FILE, MISP_FILE]}
    assert len(parse_misp(json.dumps(wrapped).encode())) == 7
    assert len(parse_misp(json.dumps([MISP_FILE]).encode())) == 7


def test_stix_roundtrip_through_our_own_export() -> None:
    r = report().model_copy(update={"ioc": "91.92.109.10"})
    got = parse_stix(json.dumps(to_stix(r)).encode())
    assert got == [(IOCType.IP, "91.92.109.10")]


def test_parse_stix_patterns_and_revoked_indicators() -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.example.com']"},
            {"type": "indicator", "pattern": "[url:value = 'http://evil.example.com/it\\'s']"},
            {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{'d' * 64}']"},
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '91.92.109.20'] OR "
                "[ipv4-addr:value = '91.92.109.21']",
            },
            {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '91.92.109.99']"},
            {"type": "malware", "name": "x"},
        ],
    }
    got = {v for _, v in parse_stix(json.dumps(bundle).encode())}
    assert got == {
        "evil.example.com",
        "http://evil.example.com/it's",
        "d" * 64,
        "91.92.109.20",
        "91.92.109.21",
    }


def test_parse_any_detects_the_format_and_rejects_garbage() -> None:
    assert parse_any(json.dumps(MISP_FILE).encode())[0] == "misp"
    assert parse_any(json.dumps({"type": "bundle", "objects": []}).encode())[0] == "stix"
    with pytest.raises(ImportError_):
        parse_any(b"not json at all")


def test_write_import_validates_name_and_content(tmp_path: Path) -> None:
    entries = parse_misp(json.dumps(MISP_FILE).encode())
    for bad in ("", "UPPER", "has space", "../evil", "x" * 41):
        with pytest.raises(ImportError_):
            write_import(tmp_path, bad, "misp", entries)
    with pytest.raises(ImportError_, match="no usable"):
        write_import(tmp_path, "empty", "misp", [])
    assert write_import(tmp_path, "good-1", "misp", entries) == 7
    assert (tmp_path / "imported" / "good-1.json").is_file()


async def test_imported_indicators_are_matched_and_malicious(
    client: httpx.AsyncClient, tmp_path: Path, gate: Gate
) -> None:
    entries = parse_misp(json.dumps(MISP_FILE).encode())
    write_import(tmp_path, "case-1", "misp", entries)
    feeds.register_import(tmp_path, "case-1", len(entries))
    src = LocalFeeds(tmp_path)
    assert src.enabled
    hit = await src.query(IOC(value="91.92.109.10", type=IOCType.IP), gate)
    assert hit.metrics["blocklisted"] is True
    assert hit.tags == ["imported list case-1"]
    sha = await src.query(IOC(value="b" * 64, type=IOCType.SHA256), gate)
    assert sha.metrics["blocklisted"] is True
    miss = await src.query(IOC(value="8.8.8.8", type=IOCType.IP), gate)
    assert miss.metrics["blocklisted"] is False
    assert feeds.feeds_status(tmp_path)["import:case-1"]["count"] == 7


def test_forget_import_removes_it(tmp_path: Path) -> None:
    write_import(tmp_path, "gone", "misp", parse_misp(json.dumps(MISP_FILE).encode()))
    feeds.register_import(tmp_path, "gone", 7)
    store = FeedStore(tmp_path)
    assert store.exact(IOC(value="91.92.109.10", type=IOCType.IP)) is not None
    assert feeds.forget_import(tmp_path, "gone") is True
    assert FeedStore(tmp_path).exact(IOC(value="91.92.109.10", type=IOCType.IP)) is None
    assert feeds.forget_import(tmp_path, "gone") is False
    assert "import:gone" not in feeds.feeds_status(tmp_path)


# --- API ----------------------------------------------------------------------------------

AUTH = {"x-verdikt-token": "t"}


def make_app(tmp_path: Path) -> FastAPI:
    sources: list[Source] = [Fake("virustotal", {"malicious": 20, "suspicious": 0})]
    settings = Settings(_env_file=None, feeds_dir=tmp_path / "feeds")  # pyright: ignore[reportCallIssue]
    engine = Engine(
        settings,
        load_rules(),
        Cache(":memory:"),
        httpx.AsyncClient(),
        sources=sources,
        limiter_factory=CountingLimiter,
    )
    return create_app(engine, port=8765, token="t", web_dist=tmp_path / "none")


async def test_api_misp_export_and_feed_import(tmp_path: Path) -> None:
    transport = httpx.ASGITransport(app=make_app(tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as c:
        rid = (await c.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8"})).json()["id"]
        misp = await c.get(f"/api/reports/{rid}/misp", headers=AUTH)
        assert misp.json()["Event"]["Attribute"][0]["value"] == "8.8.8.8"
        assert (await c.get("/api/reports/nope/misp", headers=AUTH)).status_code == 404

        ok = await c.post(
            "/api/feeds/import", headers=AUTH, json={"name": "t1", "content": json.dumps(MISP_FILE)}
        )
        assert ok.json() == {"name": "t1", "format": "misp", "count": 7}
        names = [f["name"] for f in (await c.get("/api/feeds", headers=AUTH)).json()]
        assert "import:t1" in names
        bad_name = await c.post(
            "/api/feeds/import",
            headers=AUTH,
            json={"name": "../x", "content": json.dumps(MISP_FILE)},
        )
        assert bad_name.status_code == 422
        junk = await c.post(
            "/api/feeds/import", headers=AUTH, json={"name": "t2", "content": "junk"}
        )
        assert junk.status_code == 422
        gone = await c.delete("/api/feeds/import", headers=AUTH, params={"name": "t1"})
        assert "import:t1" not in [f["name"] for f in gone.json()]


def test_forget_import_cannot_escape_the_imported_folder(tmp_path: Path) -> None:
    feeds_dir = tmp_path / "feeds"
    (feeds_dir / "imported").mkdir(parents=True)
    victim = tmp_path / "precious.json"
    victim.write_text("{}", encoding="utf-8")
    sibling = feeds_dir / "meta.json"
    sibling.write_text("{}", encoding="utf-8")
    for name in ("../../precious", "../meta", r"..\..\precious", "a/b", "", "UPPER", "x" * 41):
        assert feeds.forget_import(feeds_dir, name) is False
    assert victim.is_file()
    assert sibling.is_file()


async def test_api_rejects_a_traversal_name_when_forgetting_an_import(tmp_path: Path) -> None:
    transport = httpx.ASGITransport(app=make_app(tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as c:
        r = await c.delete("/api/feeds/import", headers=AUTH, params={"name": "../../etc/x"})
        assert r.status_code == 422

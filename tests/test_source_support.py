"""Which indicators a source is asked about: none that the vendor can only answer with an error."""

from __future__ import annotations

import httpx
import pytest
import respx

from tests.conftest import CountingLimiter, Fake, fixture, make_engine
from verdikt.cache import Cache
from verdikt.config import Settings
from verdikt.models import IOC, IOCType, Level, Status
from verdikt.sources.base import Gate, Source
from verdikt.sources.threatfox import ThreatFox
from verdikt.sources.urlhaus import URLhaus

SHA1 = "5961a99181df157b81d35a50eeb27f96577a2fa2"
V6 = "2001:4860:4860::8888"


def test_threatfox_does_not_search_sha1() -> None:
    # its API answers `illegal_hash` ("must be MD5 or SHA256", recorded in the fixture)
    assert IOCType.SHA1 not in ThreatFox("k").supports
    assert {IOCType.MD5, IOCType.SHA256} <= ThreatFox("k").supports


def test_urlhaus_does_not_take_ipv6_addresses() -> None:
    src = URLhaus("k")
    v6 = IOC(value=V6, type=IOCType.IP)
    assert src.handles(v6) is False
    assert src.handles(IOC(value="8.8.8.8", type=IOCType.IP)) is True
    assert src.handles(IOC(value="example.com", type=IOCType.DOMAIN)) is True
    assert src.handles(IOC(value="http://example.com/a", type=IOCType.URL)) is True


async def test_urlhaus_answer_for_ipv6_was_an_error(router: respx.MockRouter, gate: Gate) -> None:
    """Why it is skipped: both `host=<v6>` and `host=[<v6>]` get `invalid_host` (recorded)."""
    router.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(200, json=fixture("urlhaus", "invalid_host"))
    )
    result = await URLhaus("k").query(IOC(value=V6, type=IOCType.IP), gate)
    assert result.status is Status.ERROR


async def engine_check(
    client: httpx.AsyncClient, tmp_path: object, sources: list[Source], raw: str
):
    settings = Settings(_env_file=None)  # pyright: ignore[reportCallIssue]
    engine = make_engine(
        settings, Cache(":memory:"), client, sources, limiter_factory=CountingLimiter
    )
    return await engine.check(raw, no_cache=True)


async def test_a_sha1_is_not_sent_to_threatfox_and_is_no_longer_an_error(
    client: httpx.AsyncClient, tmp_path: object
) -> None:
    sources: list[Source] = [
        ThreatFox("k"),  # would call the network (blocked by respx's default): must not be asked
        Fake("virustotal", {"malicious": 0, "suspicious": 0}),
        Fake("malwarebazaar", {"match": False}),
    ]
    with respx.mock(assert_all_called=False):  # any call to threatfox here would raise
        report = await engine_check(client, tmp_path, sources, SHA1)
    assert [r.source for r in report.results] == ["virustotal", "malwarebazaar"]
    assert report.level is Level.SAFE  # two verdict-bearing answers, one strong: like MD5/SHA256


async def test_a_failing_strong_source_still_blocks_safe_for_a_sha1(
    client: httpx.AsyncClient, tmp_path: object
) -> None:
    sources: list[Source] = [
        Fake("virustotal", status=Status.ERROR, summary="HTTP 500"),
        Fake("malwarebazaar", {"match": False}),
    ]
    report = await engine_check(client, tmp_path, sources, SHA1)
    assert report.level is not Level.SAFE


async def test_an_ipv6_address_is_not_sent_to_urlhaus(
    client: httpx.AsyncClient, tmp_path: object
) -> None:
    sources: list[Source] = [
        URLhaus("k"),
        Fake("virustotal", {"malicious": 0, "suspicious": 0}),
        Fake("threatfox", {"match": False, "entries": 0}),
    ]
    with respx.mock(assert_all_called=False):
        report = await engine_check(client, tmp_path, sources, V6)
    assert "urlhaus" not in [r.source for r in report.results]
    assert report.level is Level.SAFE


@pytest.mark.parametrize("name", ["threatfox", "urlhaus"])
def test_every_source_still_answers_the_question_what_does_it_handle(name: str) -> None:
    # BaseSource gives every source `handles`: the default is "everything it supports"
    assert Fake(name).handles(IOC(value="8.8.8.8", type=IOCType.IP)) is True

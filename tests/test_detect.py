from __future__ import annotations

import pytest

from verdikt.detect import DetectError, detect, is_internal_host
from verdikt.models import IOCType


@pytest.mark.parametrize(
    ("raw", "value", "kind"),
    [
        ("8.8.8.8", "8.8.8.8", IOCType.IP),
        ("  8[.]8[.]8[.]8 ", "8.8.8.8", IOCType.IP),
        ("2606:4700:4700::1111", "2606:4700:4700::1111", IOCType.IP),
        ("::ffff:8.8.8.8", "8.8.8.8", IOCType.IP),
        ("Evil[.]COM.", "evil.com", IOCType.DOMAIN),
        ("evil(.)com", "evil.com", IOCType.DOMAIN),
        ("bücher.example", "xn--bcher-kva.example", IOCType.DOMAIN),
        ("hxxp://Evil[.]com/a?b=1", "http://evil.com/a?b=1", IOCType.URL),
        ("hxxps[:]//evil[.]com:443", "https://evil.com/", IOCType.URL),
        ("evil.com/path", "http://evil.com/path", IOCType.URL),
        ("D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
        ("a" * 40, "a" * 40, IOCType.SHA1),
        ("A" * 64, "a" * 64, IOCType.SHA256),
    ],
)
def test_classify_and_normalize(raw: str, value: str, kind: IOCType) -> None:
    ioc = detect(raw)
    assert (ioc.value, ioc.type) == (value, kind)


@pytest.mark.parametrize(
    "raw",
    [
        "192.168.1.10",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "::1",
        "http://192.168.1.10/admin",
        "http://localhost:8080/",
        "http://[::1]/",
        "localhost",
        "intranet",
        "intranet.corp",
        "host.local",
        "printer.lan",
        "db.internal",
        "nas.home.arpa",
        "http://intranet/",
        "http://host.local/x",
        "wiki.corp.example.com",
        "https://wiki.corp.example.com/a",
        "127.1",
        "0x7f.0.0.1",
        "http://127.1/",
        "http://0x7f.0.0.1/x",
        "2130706433",
    ],
)
def test_internal_targets_rejected(raw: str) -> None:
    with pytest.raises(DetectError):
        detect(raw, internal_domains=["corp.example.com"])


@pytest.mark.parametrize("raw", ["", "   ", "not a thing!", "-bad-.com", "http://"])
def test_unknown_input_rejected(raw: str) -> None:
    with pytest.raises(DetectError):
        detect(raw)


def test_internal_domain_suffix_is_label_aware() -> None:
    # notcorp.example.com must not match the corp.example.com suffix
    assert detect("notcorp.example.com", ["corp.example.com"]).type is IOCType.DOMAIN


@pytest.mark.parametrize("raw", ["corp.example.com", "home.arpa", "http://corp.example.com/x"])
def test_internal_suffix_apex_itself_is_internal(raw: str) -> None:
    with pytest.raises(DetectError):
        detect(raw, internal_domains=["corp.example.com"])


@pytest.mark.parametrize("raw", ["http://evil.com:99999/", "http://evil.com:abc/", "http://[bad/"])
def test_malformed_url_authority_is_a_detect_error(raw: str) -> None:
    with pytest.raises(DetectError):
        detect(raw)


def test_oversized_input_is_rejected() -> None:
    with pytest.raises(DetectError, match="too long"):
        detect("a" * 10_000 + ".com")


# --- IPv6 forms that carry an IPv4 address, and deprecated site-local space ---------------------

HIDDEN_INTERNAL = [
    "::a00:1",  # IPv4-compatible, 10.0.0.1
    "::A00:1",  # mixed case
    "[::a00:1]",  # bracketed
    "::7f00:1",  # 127.0.0.1
    "::c0a8:1",  # 192.168.0.1
    "::a9fe:1",  # 169.254.0.1
    "::ac10:1",  # 172.16.0.1
    "::6440:1",  # 100.64.0.1 (CGNAT)
    "::100",  # 0.0.1.0
    "::1:0",  # 0.1.0.0
    "::ffff:0:a00:1",  # IPv4-translated (SIIT), 10.0.0.1
    "::ffff:0:A00:1",
    "::ffff:0:7f00:1",
    "::ffff:0:0:0",  # SIIT, 0.0.0.0
    "fec0::1",  # deprecated site-local
    "FEC0::1",
    "feff::1",  # the end of fec0::/10
    "fec0:1:2::3",
    "::ffff:10.0.0.1",  # already refused: must stay refused
    "64:ff9b::a00:1",
    "2002:0a00:0001::1",
    "2001:db8::1",
    "::1",
    "::",
]


@pytest.mark.parametrize("raw", HIDDEN_INTERNAL)
def test_ipv6_forms_of_internal_addresses_are_refused(raw: str) -> None:
    with pytest.raises(DetectError, match="internal"):
        detect(raw)


@pytest.mark.parametrize("host", ["::a00:1", "::ffff:0:a00:1", "fec0::1", "FEC0::1", "::7f00:1"])
@pytest.mark.parametrize(
    "form", ["http://[{}]/x", "https://[{}]:8443/a?b=c", "[{}]/x", "hxxp://[{}]/x"]
)
def test_urls_with_such_hosts_are_refused(form: str, host: str) -> None:
    with pytest.raises(DetectError, match="internal"):
        detect(form.format(host))


@pytest.mark.parametrize("host", ["::a00:1", "::ffff:0:a00:1", "fec0::1", "::ffff:10.0.0.1"])
def test_is_internal_host_covers_them(host: str) -> None:
    assert is_internal_host(host) is True


@pytest.mark.parametrize(
    ("raw", "value"),
    [  # accepted before this change and still accepted: only a non-global embedded IPv4 is refused
        ("::ffff:8.8.8.8", "8.8.8.8"),
        ("64:ff9b::808:808", "64:ff9b::808:808"),
        ("::808:808", "::808:808"),  # IPv4-compatible with a public v4
        ("::ffff:0:808:808", "::ffff:0:808:808"),  # SIIT with a public v4
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("2606:4700::1111", "2606:4700::1111"),
        ("[2606:4700::1111]", "2606:4700::1111"),
        ("http://[::808:808]/x", "http://[::808:808]/x"),
        ("http://[2606:4700::1111]/x", "http://[2606:4700::1111]/x"),
        ("8.8.8.8", "8.8.8.8"),
    ],
)
def test_public_addresses_keep_their_results(raw: str, value: str) -> None:
    assert detect(raw).value == value


def test_extract_lists_them_as_skipped_never_queued() -> None:
    from verdikt.extract import extract_iocs

    text = "bad: ::a00:1 fec0::1 ::ffff:0:a00:1 good: 8.8.8.8 2606:4700::1111"
    result = extract_iocs(text)
    assert sorted(i.value for i in result.items) == ["2606:4700::1111", "8.8.8.8"]
    assert {s.value for s in result.skipped} == {"::a00:1", "fec0::1", "::ffff:0:a00:1"}
    assert all("internal" in s.reason for s in result.skipped)


@pytest.mark.parametrize(
    "raw",
    [
        "224.0.0.1",
        "239.255.255.250",  # SSDP: shows up in real IDS exports
        "ff02::1",
        "ff05::1",
        "ff0e::1",
        "[ff02::1]",
        "::ffff:224.0.0.1",  # a multicast IPv4 inside IPv6
        "http://239.255.255.250/x",
        "http://[ff02::1]/x",
    ],
)
def test_multicast_is_refused_not_looked_up(raw: str) -> None:
    with pytest.raises(DetectError, match="internal"):
        detect(raw)

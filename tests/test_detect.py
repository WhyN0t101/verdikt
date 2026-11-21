from __future__ import annotations

import pytest

from verdikt.detect import DetectError, detect
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

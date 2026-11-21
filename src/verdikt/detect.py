"""IOC refang, classification, normalization and internal-target rejection."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

import ioc_fanger  # pyright: ignore[reportMissingTypeStubs]

from verdikt.models import IOC, IOCType

INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home.arpa")
MAX_INPUT_LEN = 2048  # longest real URL we accept; stops a huge paste from reaching the regexes
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LEN = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class DetectError(ValueError):
    """Input is not a usable IOC (unknown format or internal target)."""


def refang(text: str) -> str:
    text = text.strip()
    # ioc-fanger does not cover `[:]` consistently across versions; handle it here.
    text = text.replace("[:]", ":")
    return str(ioc_fanger.fang(text)).strip()  # pyright: ignore[reportUnknownMemberType]


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None


def is_internal_host(host: str, extra_suffixes: Iterable[str] = ()) -> bool:
    """True for hosts that must never be sent to a third party."""
    host = host.lower().rstrip(".")
    ip = _parse_ip(host)
    if ip is not None:
        return not ip.is_global
    if host == "localhost" or host.endswith(".localhost") or "." not in host:
        return True
    suffixes = [*INTERNAL_SUFFIXES, *(_dot(s) for s in extra_suffixes if s.strip())]
    # the apex itself (`corp.example.com`) is as internal as its subdomains
    return any(host.endswith(s) or host == s[1:] for s in suffixes)


def _dot(suffix: str) -> str:
    return "." + suffix.strip().lower().lstrip(".")


def _normalize_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DetectError(f"invalid domain: {host!r}") from exc
    labels = host.split(".")
    # "127.1" / "0x7f.0.0.1": browsers read these as IPs, so they are not public names
    if labels[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]*", labels[-1]):
        raise DetectError(f"refusing numeric host {host!r}: ambiguous IP shorthand")
    if len(host) > 253 or not all(_LABEL.match(lb) for lb in labels):
        raise DetectError(f"invalid domain: {host!r}")
    return host


def _normalize_url(text: str) -> str:
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:  # bad port or unbalanced IPv6 brackets
        raise DetectError(f"invalid URL: {text!r}") from exc
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        raise DetectError(f"invalid URL: {text!r}")
    ip = _parse_ip(parts.hostname)
    if ip is None:
        host = _normalize_domain(parts.hostname)
    else:
        host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    default = {"http": 80, "https": 443, "ftp": 21}[parts.scheme.lower()]
    netloc = host if port in (None, default) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def detect(raw: str, internal_domains: Iterable[str] = ()) -> IOC:
    """Refang, classify and normalize `raw`; reject internal targets. No network I/O."""
    if len(raw) > MAX_INPUT_LEN:
        raise DetectError(f"input too long (max {MAX_INPUT_LEN} characters)")
    text = refang(raw)
    if not text:
        raise DetectError("empty input")
    internal = tuple(internal_domains)

    lowered = text.lower()
    if _HEX.match(lowered) and len(lowered) in _HASH_LEN:
        return IOC(value=lowered, type=_HASH_LEN[len(lowered)])

    ip = _parse_ip(text)
    if ip is not None:
        if not ip.is_global:
            raise DetectError(f"refusing internal IP {ip}: never sent to third parties")
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        return IOC(value=(mapped or ip).compressed, type=IOCType.IP)

    if "://" not in text and "/" in text:
        text = "http://" + text
    if "://" in text:
        value = _normalize_url(text)
        host = urlsplit(value).hostname or ""
        if is_internal_host(host, internal):
            raise DetectError(f"refusing URL with internal host {host!r}")
        return IOC(value=value, type=IOCType.URL)

    domain = _normalize_domain(text)
    if is_internal_host(domain, internal):
        raise DetectError(f"refusing internal hostname {domain!r}")
    return IOC(value=domain, type=IOCType.DOMAIN)

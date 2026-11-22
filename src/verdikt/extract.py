"""Pull every indicator out of free text (a ticket, an email, a report) for batch checking.

Candidates come from ioc-finder, then each one goes through `detect()`: normalized,
deduplicated, and internal targets are listed as skipped, never queued for a lookup.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

from verdikt.detect import DetectError, detect
from verdikt.models import IOCType, Model

MAX_ITEMS = 200  # a re-check of this many spends real quota
# ioc-finder key -> kind, in the order results are listed
_KINDS = ("ipv4s", "ipv6s", "domains", "urls", "md5s", "sha1s", "sha256s")


class ExtractedIOC(Model):
    value: str
    type: IOCType


class Skipped(Model):
    value: str
    reason: str


class Extraction(Model):
    items: list[ExtractedIOC]
    skipped: list[Skipped]
    truncated: bool = False


def _candidates(text: str) -> Iterable[str]:
    # imported here: the grammar costs ~0.4 s at startup and only extraction needs it
    from ioc_finder import find_iocs  # pyright: ignore[reportMissingTypeStubs]

    found = cast(
        "dict[str, list[Any]]",
        find_iocs(  # pyright: ignore[reportUnknownVariableType]
            text,
            parse_domain_from_email_address=False,  # bob@example.com is not an indicator
            parse_address_from_cidr=False,
            parse_urls_without_scheme=False,
        ),
    )
    for kind in _KINDS:
        for value in found.get(kind, []):
            yield str(value)


def extract_iocs(text: str, internal_domains: Iterable[str] = ()) -> Extraction:
    internal = tuple(internal_domains)
    items: dict[str, ExtractedIOC] = {}
    skipped: dict[str, Skipped] = {}
    for candidate in _candidates(text):
        try:
            ioc = detect(candidate, internal)
        except DetectError as exc:
            skipped.setdefault(candidate, Skipped(value=candidate, reason=str(exc)))
            continue
        items.setdefault(ioc.value, ExtractedIOC(value=ioc.value, type=ioc.type))
    listed = list(items.values())
    return Extraction(
        items=listed[:MAX_ITEMS],
        skipped=list(skipped.values()),
        truncated=len(listed) > MAX_ITEMS,
    )

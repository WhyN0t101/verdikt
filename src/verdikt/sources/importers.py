"""Import indicators from MISP event files and STIX 2.1 bundles into a local feed.

Imported indicators are matched locally like any blocklist: no lookup, no quota. Values go
through `detect()`, so internal targets and junk never enter a feed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from verdikt.detect import DetectError, detect
from verdikt.jsonutil import arr, obj
from verdikt.models import IOCType

NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MAX_ENTRIES = 100_000
_MISP_SIMPLE = {
    "ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha1", "sha256",
}  # fmt: skip
_STIX = re.compile(
    r"(?:(?P<kind>ipv4-addr|ipv6-addr|domain-name|url):value|file:hashes\.'?(?P<hash>MD5|SHA-1|SHA-256)'?)"
    r"\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'"
)


class ImportError_(ValueError):
    """The file is not a MISP event or STIX bundle, or yields no usable indicators."""


def _clean(pairs: list[str]) -> list[tuple[IOCType, str]]:
    found: dict[str, IOCType] = {}
    for raw in pairs:
        try:
            ioc = detect(raw)
        except DetectError:
            continue
        found.setdefault(ioc.value, ioc.type)
    return [(t, v) for v, t in found.items()][:MAX_ENTRIES]


def _misp_values(attr: dict[str, Any]) -> list[str]:
    value = str(attr.get("value", ""))
    kind = str(attr.get("type", ""))
    if kind in _MISP_SIMPLE:
        return [value]
    if kind in ("ip-src|port", "ip-dst|port", "domain|ip", "hostname|port"):
        return [p for p in value.split("|") if not p.isdigit()]
    if kind.startswith("filename|") and kind.split("|", 1)[1] in ("md5", "sha1", "sha256"):
        return [value.split("|", 1)[-1]]
    return []


def _walk_misp(node: object, to_ids_only: bool, out: list[str]) -> None:
    for item in arr(node):  # a list of events or objects
        _walk_misp(item, to_ids_only, out)
    for key, value in obj(node).items():
        if key == "Attribute":
            for a in arr(value):
                a = obj(a)
                flagged = str(a.get("to_ids", "")).lower() in ("true", "1")
                if flagged or not to_ids_only:
                    out.extend(_misp_values(a))
        elif key in ("Event", "Object", "response"):
            _walk_misp(value, to_ids_only, out)


def parse_misp(data: bytes, all_attributes: bool = False) -> list[tuple[IOCType, str]]:
    """MISP event JSON (an Event, a `response` list or a list of events). Only `to_ids`
    attributes by default: the others are context, not indicators."""
    try:
        doc: object = json.loads(data)
    except ValueError as exc:
        raise ImportError_("not valid JSON") from exc
    raw: list[str] = []
    _walk_misp(doc, not all_attributes, raw)
    return _clean(raw)


def parse_stix(data: bytes) -> list[tuple[IOCType, str]]:
    """STIX 2.1 bundle: simple `[type:value = '...']` patterns of non-revoked indicators."""
    try:
        doc = obj(json.loads(data))
    except ValueError as exc:
        raise ImportError_("not valid JSON") from exc
    raw: list[str] = []
    for o in arr(doc.get("objects")):
        o = obj(o)
        if o.get("type") != "indicator" or o.get("revoked") is True:
            continue
        for m in _STIX.finditer(str(o.get("pattern", ""))):
            raw.append(m.group("value").replace("\\'", "'").replace("\\\\", "\\"))
    return _clean(raw)


def parse_any(data: bytes, all_attributes: bool = False) -> tuple[str, list[tuple[IOCType, str]]]:
    """Detect the format. Returns ("misp" | "stix", entries)."""
    try:
        doc: object = json.loads(data)
    except ValueError as exc:
        raise ImportError_("not valid JSON") from exc
    if obj(doc).get("type") == "bundle":
        return "stix", parse_stix(data)
    return "misp", parse_misp(data, all_attributes)


def write_import(directory: Path, name: str, fmt: str, entries: list[tuple[IOCType, str]]) -> int:
    if not NAME.match(name):
        raise ImportError_("name must be 1 to 40 characters of a-z, 0-9, _ or -")
    if not entries:
        raise ImportError_("no usable indicators found (MISP: only attributes with to_ids set)")
    folder = directory / "imported"
    folder.mkdir(parents=True, exist_ok=True)
    body = {
        "name": name,
        "format": fmt,
        "entries": [{"type": t.value, "value": v} for t, v in entries],
    }
    (folder / f"{name}.json").write_text(json.dumps(body), encoding="utf-8")
    return len(entries)

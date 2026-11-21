"""Report -> MISP event JSON (a file you can import into MISP). Plain JSON, no PyMISP.

Not validated against a live MISP: the shape follows MISP's event format (Event, Attribute, Tag).
"""

from __future__ import annotations

import uuid
from typing import Any

from verdikt.models import IOCType, Level, Report

_NAMESPACE = uuid.UUID("0e3c5f7a-91d2-4b1e-8a64-5d9f1c2b7a30")
# MISP threat_level_id: 1 high, 2 medium, 3 low, 4 undefined
_THREAT = {
    Level.MALICIOUS: "1",
    Level.SUSPICIOUS: "2",
    Level.SAFE: "3",
    Level.UNKNOWN: "4",
    Level.INFO: "4",
}
_TYPES: dict[IOCType, tuple[str, str]] = {
    IOCType.IP: ("ip-dst", "Network activity"),
    IOCType.DOMAIN: ("domain", "Network activity"),
    IOCType.URL: ("url", "Network activity"),
    IOCType.MD5: ("md5", "Payload delivery"),
    IOCType.SHA1: ("sha1", "Payload delivery"),
    IOCType.SHA256: ("sha256", "Payload delivery"),
}
_NODE_TYPES = {"ip": IOCType.IP, "domain": IOCType.DOMAIN, "url": IOCType.URL}


def to_misp(report: Report) -> dict[str, Any]:
    def uid(key: str) -> str:
        return str(uuid.uuid5(_NAMESPACE, f"{report.id}:{key}"))

    stamp = str(int(report.created_at.timestamp()))
    ids = report.level in (Level.MALICIOUS, Level.SUSPICIOUS)
    kind, category = _TYPES[report.ioc_type]
    attributes: list[dict[str, Any]] = [
        {
            "uuid": uid("ioc"),
            "type": kind,
            "category": category,
            "value": report.ioc,
            "to_ids": ids,
            "distribution": "0",
            "timestamp": stamp,
            "comment": "; ".join(report.reasons)[:1000] or f"verdikt verdict: {report.level.value}",
        }
    ]
    tags = [
        {"name": f'verdikt:level="{report.level.value}"'},
        {"name": f'verdikt:confidence="{report.confidence.value}"'},
    ]
    for node in report.graph.nodes:
        if node.label == report.ioc:
            continue
        if node.kind == "malware":
            tags.append({"name": f'verdikt:malware="{node.label.replace('"', "'")}"'})
        elif (t := _NODE_TYPES.get(node.kind)) is not None:
            related_kind, related_category = _TYPES[t]
            attributes.append(
                {
                    "uuid": uid(f"rel:{node.id}"),
                    "type": related_kind,
                    "category": related_category,
                    "value": node.label,
                    "to_ids": False,  # related infrastructure, not itself judged
                    "distribution": "0",
                    "timestamp": stamp,
                    "comment": "related indicator found by verdikt",
                }
            )
    return {
        "Event": {
            "uuid": uid("event"),
            "info": f"verdikt: {report.level.value} {report.ioc_type.value} {report.ioc}",
            "date": report.created_at.strftime("%Y-%m-%d"),
            "timestamp": stamp,
            "threat_level_id": _THREAT[report.level],
            "analysis": "2",  # completed
            "distribution": "0",  # your organisation only: widen it in MISP on purpose
            "published": False,
            "Tag": tags,
            "Attribute": attributes,
        }
    }

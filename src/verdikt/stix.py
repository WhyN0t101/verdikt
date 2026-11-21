"""Report -> STIX 2.1 bundle as plain JSON (no STIX library). IDs are stable per report."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from verdikt.models import Confidence, IOCType, Level, Report

_NAMESPACE = uuid.UUID("7d1f3e0a-52c4-4f6b-9a38-0c6f2f1d9b11")
_INDICATOR_TYPES = {
    Level.MALICIOUS: "malicious-activity",
    Level.SUSPICIOUS: "anomalous-activity",
    Level.SAFE: "benign",
    Level.UNKNOWN: "unknown",
    Level.INFO: "unknown",
}
_CONFIDENCE = {Confidence.HIGH: 85, Confidence.MEDIUM: 50, Confidence.LOW: 15}
_HASH_NAMES = {IOCType.MD5: "MD5", IOCType.SHA1: "SHA-1", IOCType.SHA256: "SHA-256"}


def _ts(moment: datetime) -> str:
    return (
        moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    )


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pattern(report: Report) -> str:
    v = _quote(report.ioc)
    match report.ioc_type:
        case IOCType.IP:
            kind = "ipv6-addr" if ipaddress.ip_address(report.ioc).version == 6 else "ipv4-addr"
            return f"[{kind}:value = '{v}']"
        case IOCType.DOMAIN:
            return f"[domain-name:value = '{v}']"
        case IOCType.URL:
            return f"[url:value = '{v}']"
        case _:
            return f"[file:hashes.'{_HASH_NAMES[report.ioc_type]}' = '{v}']"


def to_stix(report: Report) -> dict[str, Any]:
    def sid(kind: str, key: str) -> str:
        return f"{kind}--{uuid.uuid5(_NAMESPACE, f'{report.id}:{key}')}"

    stamp = _ts(report.created_at)
    common = {"spec_version": "2.1", "created": stamp, "modified": stamp}
    creator = {
        "type": "identity",
        "id": sid("identity", "verdikt"),
        "name": "verdikt",
        "identity_class": "system",
        **common,
    }
    indicator = {
        "type": "indicator",
        "id": sid("indicator", "ioc"),
        "created_by_ref": creator["id"],
        "name": f"{report.ioc_type.value}: {report.ioc}",
        "description": "; ".join(report.reasons) or f"verdikt verdict: {report.level.value}",
        "indicator_types": [_INDICATOR_TYPES[report.level]],
        "pattern": pattern(report),
        "pattern_type": "stix",
        "valid_from": stamp,
        "confidence": _CONFIDENCE[report.confidence],
        **common,
    }
    objects: list[dict[str, Any]] = [creator, indicator]
    families = sorted({n.label for n in report.graph.nodes if n.kind == "malware"})
    for family in families:
        malware = {
            "type": "malware",
            "id": sid("malware", family),
            "name": family,
            "is_family": True,
            **common,
        }
        objects.append(malware)
        objects.append(
            {
                "type": "relationship",
                "id": sid("relationship", family),
                "relationship_type": "indicates",
                "source_ref": indicator["id"],
                "target_ref": malware["id"],
                **common,
            }
        )
    return {"type": "bundle", "id": sid("bundle", "bundle"), "objects": objects}

"""VirusTotal v3 (public API: 4/min, 500/day)."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object


def _now() -> datetime:
    return datetime.now(UTC)  # a module function so tests can freeze it


API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


def _paths(ioc: IOC) -> tuple[str, str]:
    """(API path, GUI path) for an IOC."""
    v = ioc.value
    match ioc.type:
        case IOCType.IP:
            return f"/ip_addresses/{quote(v, safe='')}", f"/ip-address/{quote(v, safe='')}"
        case IOCType.DOMAIN:
            return f"/domains/{quote(v, safe='')}", f"/domain/{quote(v, safe='')}"
        case IOCType.URL:
            url_id = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
            return f"/urls/{url_id}", f"/url/{hashlib.sha256(v.encode()).hexdigest()}"
        case _:
            return f"/files/{v}", f"/file/{v}"


def _plain_int(value: object) -> int | None:
    """A JSON integer, not a bool, string or float: anything else is treated as absent."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _scan_age_days(value: object) -> int | None:
    """Whole days since `last_analysis_date` (Unix seconds); never negative, None if unusable."""
    stamp = _plain_int(value)
    if stamp is None or stamp <= 0:
        return None
    try:
        scanned = datetime.fromtimestamp(stamp, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return max(0, (_now() - scanned).days)


class VirusTotal(BaseSource):
    name = "virustotal"
    supports = frozenset(IOCType)
    requires_key = True
    rate = (4, 60.0)
    ttl = timedelta(hours=24)
    daily_budget = 500

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        api_path, gui_path = _paths(ioc)
        resp = await http.get(API + api_path, headers={"x-apikey": self._key or ""})
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        attrs: dict[str, Any] = body["data"]["attributes"]
        stats: dict[str, Any] = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        tags: list[str] = []
        related: list[RelatedIOC] = []
        if label := attrs.get("popular_threat_classification", {}).get("suggested_threat_label"):
            tags.append(str(label))
            related.append(RelatedIOC(value=str(label), type="malware", relation="belongs_to"))
        if asn := attrs.get("asn"):
            related.append(RelatedIOC(value=f"AS{int(asn)}", type="asn", relation="belongs_to"))
        for rec in arr(attrs.get("last_dns_records")) if ioc.type is IOCType.DOMAIN else []:
            rec = obj(rec)
            if rec.get("type") in ("A", "AAAA") and rec.get("value"):
                related.append(
                    RelatedIOC(value=str(rec["value"]), type=IOCType.IP, relation="resolves_to")
                )
        metrics: dict[str, int | bool] = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "total": total,
        }
        # context for the analyst and for private rules; no default rule reads these
        if (age := _scan_age_days(attrs.get("last_analysis_date"))) is not None:
            metrics["last_analysis_age_days"] = age
        if (reputation := _plain_int(attrs.get("reputation"))) is not None:
            metrics["reputation"] = reputation
        return self.result(
            Status.OK,
            f"{malicious}/{total} engines malicious",
            metrics=metrics,
            tags=tags,
            related=related[:20],
            link=GUI + gui_path,
            raw=body,
        )

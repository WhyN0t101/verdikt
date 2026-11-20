"""AbuseIPDB v2 (IP only; key in header, never in the URL)."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import quote

from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(BaseSource):
    name = "abuseipdb"
    supports = frozenset({IOCType.IP})
    requires_key = True
    rate = (1, 1.0)
    ttl = timedelta(hours=6)
    daily_budget = 1000

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        resp = await http.get(
            API,
            params={"ipAddress": ioc.value, "maxAgeInDays": "90"},
            headers={"Key": self._key or "", "Accept": "application/json"},
        )
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        data = body["data"]
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        tags = [str(t) for t in (data.get("usageType"),) if t]
        if data.get("isTor"):
            tags.append("tor")
        return self.result(
            Status.OK,
            f"{score}% confidence · {reports:,} reports",
            metrics={"score": score, "reports": reports, "tor": bool(data.get("isTor", False))},
            tags=tags,
            link=f"https://www.abuseipdb.com/check/{quote(ioc.value, safe='')}",
            raw=body,
        )

"""Hybrid Analysis v2 (hash lookup)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate

API = "https://www.hybrid-analysis.com/api/v2/search/hash"


class HybridAnalysis(BaseSource):
    name = "hybrid"
    supports = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})
    requires_key = True
    rate = (1, 15.0)
    ttl = timedelta(days=7)
    daily_budget = 200

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        resp = await http.get(
            API,
            params={"hash": ioc.value},
            headers={"api-key": self._key or "", "User-Agent": "Falcon Sandbox"},
        )
        if (err := self.from_status(resp)) is not None:
            return err
        data: Any = resp.json()
        items = arr(obj(data).get("reports") or data)
        if not all(isinstance(r, dict) for r in items):
            raise ValueError("unexpected report shape")
        reports = [obj(r) for r in items]
        if not reports:
            return self.result(Status.NOT_FOUND, "no sandbox reports")
        malicious = any(r.get("verdict") == "malicious" for r in reports)
        score = max(int(r.get("threat_score") or 0) for r in reports)
        families = sorted({str(r["vx_family"]) for r in reports if r.get("vx_family")})
        return self.result(
            Status.OK,
            f"{len(reports)} report(s), threat score {score}",
            metrics={"malicious": malicious, "threat_score": score, "reports": len(reports)},
            tags=families[:10],
            related=[
                RelatedIOC(value=f, type="malware", relation="belongs_to") for f in families[:5]
            ],
            link=f"https://www.hybrid-analysis.com/search?query={ioc.value}",
            raw={"reports": reports},
        )

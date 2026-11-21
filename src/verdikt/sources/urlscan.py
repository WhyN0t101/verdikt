"""urlscan.io — search only. Never submits a scan (submissions are public by default)."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import quote

from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://urlscan.io/api/v1/search/"


def _query(ioc: IOC) -> str:
    value = ioc.value.replace("\\", "\\\\").replace('"', '\\"')
    match ioc.type:
        case IOCType.IP:
            return f'ip:"{value}"'
        case IOCType.DOMAIN:
            return f'domain:"{value}"'
        case IOCType.URL:
            return f'page.url:"{value}"'
        case _:
            return f"hash:{ioc.value}"


class Urlscan(BaseSource):
    name = "urlscan"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.SHA256})
    requires_key = False
    rate = (1, 2.0)
    ttl = timedelta(hours=12)
    daily_budget = 1000

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        query = _query(ioc)
        headers = {"API-Key": self._key} if self._key else {}
        resp = await http.get(API, params={"q": query, "size": "20"}, headers=headers)
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        results = body.get("results", [])
        total = int(body.get("total", len(results)))
        # Context only: free-plan search rows carry no verdicts and result pages need a login.
        related: list[RelatedIOC] = []
        seen: set[str] = set()
        for r in results:
            page = r.get("page", {})
            for key, kind in (("ip", IOCType.IP), ("domain", IOCType.DOMAIN)):
                val = page.get(key)
                if val and val != ioc.value and val not in seen and len(seen) < 5:
                    seen.add(val)
                    # a domain seen on an IP resolves to it, so the edge points domain -> ioc
                    inbound = ioc.type is IOCType.IP and kind is IOCType.DOMAIN
                    related.append(
                        RelatedIOC(
                            value=str(val), type=kind, relation="resolves_to", inbound=inbound
                        )
                    )
        return self.result(
            Status.OK,
            f"{total} public scan{'s' if total != 1 else ''}",
            metrics={"scans": total},
            related=related,
            link=f"https://urlscan.io/search/#{quote(query, safe='')}",
            raw=body,
        )

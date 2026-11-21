"""Passive DNS from VirusTotal resolutions: what a domain resolved to, or what resolved to an IP.

Uses the existing VirusTotal key and shares its rate limit and daily budget, so it is off unless
`VERDIKT_VT_RESOLUTIONS=true`.
"""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import quote

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://www.virustotal.com/api/v3"
LIMIT = 20
MAX_RELATED = 10


class PassiveDNS(BaseSource):
    name = "passivedns"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN})
    requires_key = True
    rate = (4, 60.0)
    ttl = timedelta(hours=24)
    daily_budget = 500
    quota_group = "virustotal"  # the same 4/min and 500/day as the VirusTotal source

    def __init__(self, api_key: str | None = None, enabled: bool = True) -> None:
        super().__init__(api_key)
        self._on = enabled

    @property
    def enabled(self) -> bool:
        return self._on and super().enabled

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        kind = "ip_addresses" if ioc.type is IOCType.IP else "domains"
        resp = await http.get(
            f"{API}/{kind}/{quote(ioc.value, safe='')}/resolutions",
            params={"limit": str(LIMIT)},
            headers={"x-apikey": self._key or ""},
        )
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        is_ip = ioc.type is IOCType.IP
        total = int(obj(body.get("meta")).get("count", 0) or 0)
        seen: dict[str, bool] = {}  # neighbour -> flagged by any VT engine
        for item in arr(body.get("data")):
            a = obj(obj(item).get("attributes"))
            neighbour = str(a.get("host_name" if is_ip else "ip_address") or "")
            stats = obj(
                a.get(
                    "host_name_last_analysis_stats" if is_ip else "ip_address_last_analysis_stats"
                )
            )
            if neighbour:
                seen[neighbour] = (
                    seen.get(neighbour, False) or int(stats.get("malicious", 0) or 0) > 0
                )
        names = list(seen)
        related = [
            RelatedIOC(
                value=n,
                type=IOCType.DOMAIN if is_ip else IOCType.IP,
                relation="resolves_to",
                inbound=is_ip,  # a domain that resolved to this IP points at it
            )
            for n in names[:MAX_RELATED]
        ]
        flagged = sum(1 for bad in seen.values() if bad)
        page = "ip-address" if is_ip else "domain"
        return self.result(
            Status.OK,
            f"{total} resolution(s); {flagged} of {len(seen)} shown flagged by VirusTotal",
            metrics={"resolutions": total, "flagged_neighbours": flagged},
            related=related,
            link=f"https://www.virustotal.com/gui/{page}/{quote(ioc.value, safe='')}/relations",
            raw=body,
        )

"""Shodan InternetDB. Context only: ports, CVEs, hostnames."""

from __future__ import annotations

from datetime import timedelta

from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://internetdb.shodan.io"


class InternetDB(BaseSource):
    name = "internetdb"
    supports = frozenset({IOCType.IP})
    requires_key = False
    rate = (1, 1.0)
    ttl = timedelta(days=7)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        resp = await http.get(f"{API}/{ioc.value}")
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        ports = [int(p) for p in body.get("ports", [])]
        vulns = [str(v) for v in body.get("vulns", [])]
        hostnames = [str(h) for h in body.get("hostnames", [])]
        related = [
            RelatedIOC(value=h, type=IOCType.DOMAIN, relation="resolves_to", inbound=True)
            for h in hostnames[:10]
        ]
        return self.result(
            Status.OK,
            f"{len(ports)} open port(s), {len(vulns)} CVE(s)",
            metrics={"ports": len(ports), "vulns": len(vulns), "hostnames": len(hostnames)},
            tags=[str(t) for t in body.get("tags", [])],
            related=related,
            link=f"https://www.shodan.io/host/{ioc.value}",
            raw=body,
        )

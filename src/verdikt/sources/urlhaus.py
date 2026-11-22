"""abuse.ch URLhaus (host and URL lookups; v1 API, Auth-Key header)."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from urllib.parse import quote

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://urlhaus-api.abuse.ch/v1"


class URLhaus(BaseSource):
    name = "urlhaus"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN, IOCType.URL})
    requires_key = True
    rate = (1, 1.0)
    ttl = timedelta(hours=6)

    def handles(self, ioc: IOC) -> bool:
        # the host endpoint answers `invalid_host` for every IPv6 address, bracketed or not
        return not (ioc.type is IOCType.IP and ipaddress.ip_address(ioc.value).version == 6)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        is_url = ioc.type is IOCType.URL
        endpoint = "/url/" if is_url else "/host/"
        form = {"url": ioc.value} if is_url else {"host": ioc.value}
        resp = await http.post(API + endpoint, data=form, headers={"Auth-Key": self._key or ""})
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        status = body.get("query_status")
        link = f"https://urlhaus.abuse.ch/browse.php?search={quote(ioc.value, safe='')}"
        if status in ("invalid_host", "invalid_url"):  # input rejected: no evidence either way
            return self.result(Status.ERROR, "input rejected by URLhaus")
        if status == "no_results":
            return self.result(
                Status.OK,
                "not listed",
                metrics={"match": False, "online": False, "urls": 0},
                link=link,
                raw=body,
            )
        if status != "ok":
            return self.result(Status.ERROR, "unexpected response")
        if is_url:
            online = body.get("url_status") == "online"
            urls = 1
            tags = [str(t) for t in arr(body.get("tags"))]
            threat = str(body.get("threat") or "")
        else:
            urls = int(body.get("url_count", 0))
            online = (
                int(body.get("urls_online", 0)) > 0
                if "urls_online" in body
                else any(u.get("url_status") == "online" for u in body.get("urls", []))
            )
            tags = sorted({str(t) for u in arr(body.get("urls")) for t in arr(obj(u).get("tags"))})
            threat = ""
        return self.result(
            Status.OK,
            f"listed ({urls} URL{'s' if urls != 1 else ''}, {'online' if online else 'offline'})"
            + (f": {threat}" if threat else ""),
            # a host listing says little about a popular host (github.com has online malware URLs);
            # only an exact URL match is strong enough for MALICIOUS
            metrics={
                "match": True,
                "online": online,
                "url_online": online and is_url,
                "urls": urls,
            },
            tags=tags[:10],
            link=link,
            raw=body,
        )

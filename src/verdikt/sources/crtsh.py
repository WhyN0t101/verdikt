"""crt.sh certificate transparency: certificates issued for a domain and the names on them."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate

API = "https://crt.sh/"
MAX_SUBDOMAINS = 10


def _when(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class CrtSh(BaseSource):
    """Context only. Unexpired certificates; crt.sh is often slow, so it gets a longer timeout."""

    name = "crtsh"
    supports = frozenset({IOCType.DOMAIN})
    requires_key = False
    rate = (1, 2.0)
    ttl = timedelta(hours=24)
    timeout = 20.0

    def __init__(self, enabled: bool = True) -> None:
        super().__init__()
        self._on = enabled

    @property
    def enabled(self) -> bool:
        return self._on

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        resp = await http.get(API, params={"q": ioc.value, "output": "json", "exclude": "expired"})
        if (err := self.from_status(resp)) is not None:
            return err
        rows = [obj(r) for r in arr(resp.json())]
        link = f"https://crt.sh/?q={ioc.value}"
        if not rows:
            return self.result(
                Status.OK, "no unexpired certificates", metrics={"certs": 0}, link=link
            )
        now = datetime.now(UTC)
        issued = [t for r in rows if (t := _when(r.get("not_before"))) is not None]
        names: set[str] = set()
        for r in rows:
            for n in str(r.get("name_value", "")).split("\n"):
                n = n.strip().lower()
                if n and not n.startswith("*"):
                    names.add(n)
        metrics: dict[str, int | bool] = {"certs": len(rows), "names": len(names)}
        if issued:
            metrics["oldest_days"] = (now - min(issued)).days
            metrics["newest_days"] = (now - max(issued)).days
        subs = sorted(n for n in names if n != ioc.value and n.endswith("." + ioc.value))
        related = [
            RelatedIOC(value=n, type=IOCType.DOMAIN, relation="belongs_to", inbound=True)
            for n in subs[:MAX_SUBDOMAINS]
        ]
        return self.result(
            Status.OK,
            f"{len(rows)} unexpired certificate(s), {len(names)} name(s)",
            metrics=metrics,
            related=related,
            link=link,
            raw={"certs": rows[:20]},  # a popular domain has thousands; keep a sample
        )

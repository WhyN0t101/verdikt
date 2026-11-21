"""RDAP domain registration age (keyless, via the rdap.org bootstrap redirector)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://rdap.org/domain"
MAX_STRIPS = 3  # sub.a.example.com -> a.example.com -> example.com: no public-suffix list needed


def _when(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class RDAP(BaseSource):
    """Age of the registered domain. A newly registered domain is a common phishing signal."""

    name = "rdap"
    supports = frozenset({IOCType.DOMAIN})
    requires_key = False
    rate = (2, 1.0)
    ttl = timedelta(days=7)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        labels = ioc.value.split(".")
        for strip in range(min(MAX_STRIPS, max(0, len(labels) - 2)) + 1):
            domain = ".".join(labels[strip:])
            # rdap.org redirects to the registry's own RDAP server; only this call follows redirects
            resp = await http.get(
                f"{API}/{domain}",
                headers={"accept": "application/rdap+json"},
                follow_redirects=True,
            )
            if resp.status_code == 404:
                continue
            if (err := self.from_status(resp)) is not None:
                return err
            return self._parse(domain, json_object(resp))
        return self.result(Status.NOT_FOUND, "no RDAP record (this TLD may not publish one)")

    def _parse(self, domain: str, body: dict[str, object]) -> SourceResult:
        events = {
            str(obj(e).get("eventAction")): _when(obj(e).get("eventDate"))
            for e in arr(body.get("events"))
        }
        registered = events.get("registration")
        link = f"https://lookup.icann.org/en/lookup?name={domain}"
        if registered is None:
            return self.result(
                Status.OK, "registered; no registration date published", link=link, raw=body
            )
        now = datetime.now(UTC)
        metrics: dict[str, int | bool] = {"age_days": max(0, (now - registered).days)}
        if expires := events.get("expiration"):
            metrics["expires_in_days"] = (expires - now).days
        return self.result(
            Status.OK,
            f"{domain} registered {registered:%Y-%m-%d} ({metrics['age_days']:,} days ago)",
            metrics=metrics,
            link=link,
            raw=body,
        )

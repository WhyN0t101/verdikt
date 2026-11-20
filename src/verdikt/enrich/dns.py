"""Optional DNS resolution. Off by default: resolving can reach the attacker's name server."""

from __future__ import annotations

import ipaddress

import dns.asyncresolver
import dns.exception

from verdikt.models import IOCType, RelatedIOC

LIFETIME = 3.0


async def resolve(host: str) -> list[RelatedIOC]:
    """A/AAAA records as `resolves_to` relations. Non-global answers are dropped."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = LIFETIME
    found: list[RelatedIOC] = []
    for rtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rtype)
        except dns.exception.DNSException:
            continue
        for rdata in answer:
            ip = ipaddress.ip_address(rdata.to_text())
            if ip.is_global:
                found.append(
                    RelatedIOC(value=ip.compressed, type=IOCType.IP, relation="resolves_to")
                )
    return found

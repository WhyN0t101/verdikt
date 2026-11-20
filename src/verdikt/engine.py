"""Fan-out over sources, cache, enrichment, graph, verdict. Returns one Report."""

from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from aiolimiter import AsyncLimiter

from verdikt.cache import Cache
from verdikt.config import Rules, Settings, load_rules
from verdikt.detect import detect
from verdikt.enrich import dns as dns_enrich
from verdikt.enrich.geo import GeoLookup
from verdikt.models import (
    IOC,
    GeoPoint,
    Graph,
    GraphEdge,
    GraphNode,
    IOCType,
    Level,
    RelatedIOC,
    Report,
    SourceResult,
    Status,
)
from verdikt.sources import build_sources
from verdikt.sources.base import BACKOFF, Gate, Limiter, Source
from verdikt.verdict import decide

LimiterFactory = Callable[[int, float], Limiter]
Resolver = Callable[[str], Awaitable[list[RelatedIOC]]]


@dataclass(frozen=True)
class SourceStatus:
    name: str
    enabled: bool
    requires_key: bool
    supports: list[str]
    used_today: int
    daily_budget: int | None


def _graph_kind(kind: IOCType | str) -> str:
    if isinstance(kind, IOCType):
        return "hash" if kind.is_hash else kind.value
    return kind


def build_graph(ioc: IOC, level: Level, related: list[RelatedIOC], asn: str | None) -> Graph:
    root = f"{_graph_kind(ioc.type)}:{ioc.value}"
    nodes = {root: GraphNode(id=root, label=ioc.value, kind=_graph_kind(ioc.type), level=level)}
    edges: dict[tuple[str, str, str], GraphEdge] = {}

    def link(rel: RelatedIOC) -> None:
        kind = _graph_kind(rel.type)
        nid = f"{kind}:{rel.value}"
        if nid == root:
            return
        nodes.setdefault(nid, GraphNode(id=nid, label=rel.value, kind=kind))
        src, dst = (nid, root) if rel.inbound else (root, nid)
        edges.setdefault(
            (src, dst, rel.relation), GraphEdge(source=src, target=dst, label=rel.relation)
        )

    for rel in related:
        link(rel)
    if asn:
        link(RelatedIOC(value=asn, type="asn", relation="belongs_to"))
    return Graph(nodes=list(nodes.values()), edges=list(edges.values()))


class Engine:
    def __init__(
        self,
        settings: Settings,
        rules: Rules,
        cache: Cache,
        http: httpx.AsyncClient,
        sources: list[Source] | None = None,
        geo: GeoLookup | None = None,
        limiter_factory: LimiterFactory = lambda n, s: AsyncLimiter(n, s),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        backoff: float = BACKOFF,
        resolver: Resolver = dns_enrich.resolve,
    ) -> None:
        self.settings = settings
        self.rules = rules
        self.cache = cache
        self._http = http
        self.sources = sources if sources is not None else build_sources(settings)
        self._geo = geo if geo is not None else GeoLookup(settings.geoip_dir)
        self._limiter_factory = limiter_factory
        self._limiters: dict[str, Limiter] = {}
        self._sleep = sleep
        self._backoff = backoff
        self._resolver = resolver

    # --- helpers ------------------------------------------------------------
    def _limiter(self, src: Source) -> Limiter:
        if src.name not in self._limiters:
            self._limiters[src.name] = self._limiter_factory(*src.rate)
        return self._limiters[src.name]

    def source_status(self) -> list[SourceStatus]:
        return [
            SourceStatus(
                name=s.name,
                enabled=s.enabled,
                requires_key=s.requires_key,
                supports=sorted(t.value for t in s.supports),
                used_today=self.cache.budget_used(s.name),
                daily_budget=s.daily_budget,
            )
            for s in self.sources
        ]

    async def _query(self, src: Source, ioc: IOC, no_cache: bool) -> SourceResult:
        if not no_cache and (hit := self.cache.get(src.name, ioc.value, src.ttl)) is not None:
            return hit
        gate = Gate(
            src.name,
            self._http,
            self._limiter(src),
            cache=self.cache,
            daily_budget=src.daily_budget,
            sleep=self._sleep,
            backoff=self._backoff,
        )
        result = await src.query(ioc, gate)
        if result.status in (Status.OK, Status.NOT_FOUND):
            self.cache.put(src.name, ioc.value, result)
        return result

    # --- main entry ---------------------------------------------------------
    async def check(self, raw: str, *, no_cache: bool = False) -> Report:
        """Detect, query, enrich, decide, persist. Raises `DetectError` on unusable input."""
        started = time.perf_counter()
        ioc = detect(raw, self.settings.internal_domain_list)
        active = [s for s in self.sources if s.enabled and ioc.type in s.supports]

        outcomes = await asyncio.gather(
            *(self._query(s, ioc, no_cache) for s in active), return_exceptions=True
        )
        results: list[SourceResult] = []
        for src, out in zip(active, outcomes, strict=True):
            if isinstance(out, BaseException):
                results.append(
                    SourceResult(source=src.name, status=Status.ERROR, summary="source failed")
                )
            else:
                results.append(out)

        decision = decide(results, self.rules)
        related = [r for res in decision.results for r in res.related]
        if self.settings.dns_resolve and (host := ioc.host) and ioc.type is not IOCType.IP:
            related.extend(await self._resolver(host))

        geo = self._geo_points(ioc, decision.level, related)
        asn = next((f"AS{g.asn}" for g in geo if g.role == "ioc" and g.asn), None)
        graph = build_graph(ioc, decision.level, related, asn)
        report = Report(
            id=uuid.uuid4().hex,
            ioc=ioc.value,
            ioc_type=ioc.type,
            level=decision.level,
            agreeing=decision.agreeing,
            total=decision.total,
            reasons=decision.reasons,
            results=decision.results,
            geo=geo,
            graph=graph,
            duration_ms=int((time.perf_counter() - started) * 1000),
            created_at=datetime.now(UTC),
        )
        self.cache.save_report(report)
        return report

    def _geo_points(self, ioc: IOC, level: Level, related: list[RelatedIOC]) -> list[GeoPoint]:
        if not self._geo.available:
            return []
        points: list[GeoPoint] = []
        seen: set[str] = set()
        candidates = [(ioc.value, "ioc")] if ioc.type is IOCType.IP else []
        candidates += [(r.value, "related") for r in related if r.type == IOCType.IP]
        for ip, role in candidates:
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip in seen or not parsed.is_global:
                continue
            seen.add(ip)
            if point := self._geo.lookup(ip, role):
                points.append(
                    point.model_copy(update={"level": level if role == "ioc" else Level.UNKNOWN})
                )
        return points


def build_engine(settings: Settings, http: httpx.AsyncClient) -> Engine:
    """Engine wired from settings: rules.yaml (or override), sqlite cache, built-in sources."""
    rules = load_rules(settings.rules_path)
    return Engine(settings, rules, Cache(settings.resolved_db_path), http)

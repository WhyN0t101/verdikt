"""Fan-out over sources, cache, enrichment, graph, verdict. Returns one Report."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import httpx
from aiolimiter import AsyncLimiter

from verdikt.audit import AuditLog
from verdikt.cache import Cache
from verdikt.config import Rules, Settings, load_rules
from verdikt.detect import detect
from verdikt.enrich import dns as dns_enrich
from verdikt.enrich.cve import CveStore
from verdikt.enrich.geo import GeoLookup
from verdikt.jsonutil import arr, obj
from verdikt.models import (
    IOC,
    GeoPoint,
    Graph,
    GraphEdge,
    GraphNode,
    IOCType,
    Level,
    Model,
    RelatedIOC,
    Report,
    SourceResult,
    Status,
)
from verdikt.sources import build_sources
from verdikt.sources.base import BACKOFF, Gate, Limiter, Source
from verdikt.verdict import decide

log = logging.getLogger(__name__)

LimiterFactory = Callable[[int, float], Limiter]
Resolver = Callable[[str], Awaitable[list[RelatedIOC]]]


class SourceInfo(Model):
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
        cves: CveStore | None = None,
        limiter_factory: LimiterFactory = lambda n, s: AsyncLimiter(n, s),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        backoff: float = BACKOFF,
        resolver: Resolver = dns_enrich.resolve,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings
        self.rules = rules
        self.cache = cache
        self._http = http
        self.sources = sources if sources is not None else build_sources(settings)
        self._geo = geo if geo is not None else GeoLookup(settings.geoip_dir)
        self._cves = cves if cves is not None else CveStore(settings.resolved_feeds_dir)
        self._limiter_factory = limiter_factory
        self._limiters: dict[str, Limiter] = {}
        self._inflight: dict[tuple[str, str], asyncio.Future[SourceResult]] = {}
        self._sleep = sleep
        self._backoff = backoff
        self._resolver = resolver
        self.audit = audit

    @property
    def http(self) -> httpx.AsyncClient:
        return self._http

    # --- helpers ------------------------------------------------------------
    def _limiter(self, src: Source) -> Limiter:
        group = src.quota_group or src.name
        if group not in self._limiters:
            self._limiters[group] = self._limiter_factory(*src.rate)
        return self._limiters[group]

    def source_status(self) -> list[SourceInfo]:
        return [
            SourceInfo(
                name=s.name,
                enabled=s.enabled,
                requires_key=s.requires_key,
                supports=sorted(t.value for t in s.supports),
                used_today=self.cache.budget_used(s.name),
                daily_budget=s.daily_budget,
            )
            for s in self.sources
        ]

    async def _query(self, src: Source, ioc: IOC, no_cache: bool, t0: float) -> SourceResult:
        start = time.perf_counter()
        started_ms = int((start - t0) * 1000)
        if not no_cache and (hit := self.cache.get(src.name, ioc.value, src.ttl)) is not None:
            return hit.model_copy(update={"started_ms": started_ms, "duration_ms": 0})
        # Two concurrent checks of one IOC share one vendor call instead of spending quota twice.
        key = (src.name, ioc.value)
        task = None if no_cache else self._inflight.get(key)
        if task is None:
            task = asyncio.ensure_future(self._fetch(src, ioc))
            if not no_cache:
                self._inflight[key] = task
                task.add_done_callback(lambda _t: self._inflight.pop(key, None))
        result = await asyncio.shield(task)  # a cancelled waiter must not cancel the shared call
        return result.model_copy(
            update={
                "started_ms": started_ms,
                "duration_ms": int((time.perf_counter() - start) * 1000),
            }
        )

    async def _fetch(self, src: Source, ioc: IOC) -> SourceResult:
        gate = Gate(
            src.quota_group or src.name,
            self._http,
            self._limiter(src),
            cache=self.cache,
            daily_budget=src.daily_budget,
            timeout=src.timeout,
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
            *(self._query(s, ioc, no_cache, started) for s in active), return_exceptions=True
        )
        results: list[SourceResult] = []
        for src, out in zip(active, outcomes, strict=True):
            if isinstance(out, asyncio.CancelledError):
                raise out
            if isinstance(out, BaseException):
                # class name only: the message may echo attacker-controlled vendor data
                log.warning("%s: source raised %s", src.name, type(out).__name__)
                results.append(
                    SourceResult(source=src.name, status=Status.ERROR, summary="source failed")
                )
            else:
                results.append(out)

        decision = decide(results, self.rules)
        related = [r for res in decision.results for r in res.related]
        if self.settings.dns_resolve and (host := ioc.host) and ioc.type is not IOCType.IP:
            related.extend(await self._resolver(host))

        cves = self._cves.lookup(
            [
                str(v)
                for r in decision.results
                if r.source == "internetdb"
                for v in arr(obj(r.raw).get("vulns"))
            ]
        )
        in_kev = sum(1 for c in cves if c.kev)
        cve_reasons = (
            [f"{in_kev} CVE(s) on this host are in CISA's KEV catalog (exploited in the wild)"]
            if in_kev
            else []
        )
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
            confidence=decision.confidence,
            reasons=[*decision.reasons, *cve_reasons],
            results=decision.results,
            geo=geo,
            cves=cves,
            graph=graph,
            duration_ms=int((time.perf_counter() - started) * 1000),
            created_at=datetime.now(UTC),
        )
        report = report.model_copy(update={"seen_before": self.cache.correlate(report)})
        self.cache.save_report(report)
        self.cache.record_stats(report.results)
        if self.audit:
            self.audit.check(report)
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
    days = settings.report_retention_days
    cache = Cache(
        settings.resolved_db_path, report_retention=timedelta(days=days) if days > 0 else None
    )
    return Engine(settings, rules, cache, http, audit=AuditLog(settings.resolved_audit_path))

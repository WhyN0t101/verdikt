"""Core data model. `Report` is the single contract for CLI, API, UI and SOAR glue."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

SCHEMA_VERSION = 2  # 2: added Report.confidence and Report.seen_before


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    @property
    def is_hash(self) -> bool:
        return self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


class Confidence(StrEnum):
    """How much weighted evidence backs the verdict (see rules.yaml `weights`)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Status(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"


class Level(StrEnum):
    """Matches Cortex taxonomy levels. INFO is a row level only; a Report is never INFO."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    SAFE = "safe"
    INFO = "info"
    UNKNOWN = "unknown"


class Model(BaseModel):
    """Base for API-facing models: defaulted fields are required in the serialized schema,
    so generated frontend types are not littered with optionals."""

    model_config = ConfigDict(json_schema_serialization_defaults_required=True)


class IOC(Model):
    value: str
    type: IOCType

    @property
    def host(self) -> str | None:
        """Hostname for URL IOCs, the value itself for IP/domain, None for hashes."""
        if self.type is IOCType.URL:
            from urllib.parse import urlsplit

            return urlsplit(self.value).hostname
        if self.type in (IOCType.IP, IOCType.DOMAIN):
            return self.value
        return None


class RelatedIOC(Model):
    value: str
    type: IOCType | str  # str covers "malware" and "asn" graph-only node kinds
    relation: str  # resolves_to, hosted_on, drops, contacts, belongs_to
    inbound: bool = False  # True: edge points related -> ioc instead of ioc -> related


class SourceResult(Model):
    source: str
    status: Status
    metrics: dict[str, int | bool] = Field(default_factory=dict)
    level: Level = Level.UNKNOWN  # set by verdict.decide(), never by the source
    summary: str = ""
    tags: list[str] = Field(default_factory=list)
    link: HttpUrl | None = None
    related: list[RelatedIOC] = Field(default_factory=list[RelatedIOC])
    cached: bool = False
    started_ms: int = 0  # offset from the start of the check; set by the engine
    duration_ms: int = 0  # 0 for a cache hit
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw: dict[str, Any] | None = None  # the one allowed Any: arbitrary vendor JSON


class GeoPoint(Model):
    ip: str
    lat: float
    lon: float
    country: str | None = None
    city: str | None = None
    asn: int | None = None
    as_org: str | None = None
    role: str = "ioc"  # "ioc" or "related"
    level: Level = Level.UNKNOWN


class GraphNode(Model):
    id: str
    label: str
    kind: str  # ip, domain, url, hash, malware, asn
    level: Level = Level.UNKNOWN


class GraphEdge(Model):
    source: str
    target: str
    label: str


class Graph(Model):
    nodes: list[GraphNode] = Field(default_factory=list[GraphNode])
    edges: list[GraphEdge] = Field(default_factory=list[GraphEdge])


class SeenBefore(Model):
    """An earlier report that shares an indicator with this one."""

    report_id: str
    ioc: str
    level: Level
    created_at: datetime
    shared: list[str] = Field(default_factory=list[str])  # indicators in common


class Report(Model):
    schema_version: int = SCHEMA_VERSION
    id: str
    ioc: str
    ioc_type: IOCType
    level: Level  # MALICIOUS | SUSPICIOUS | SAFE | UNKNOWN
    agreeing: int
    total: int
    confidence: Confidence = Confidence.LOW
    reasons: list[str] = Field(default_factory=list)
    results: list[SourceResult] = Field(default_factory=list[SourceResult])
    geo: list[GeoPoint] = Field(default_factory=list[GeoPoint])
    graph: Graph = Field(default_factory=Graph)
    seen_before: list[SeenBefore] = Field(default_factory=list[SeenBefore])
    duration_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def without_raw(self) -> Report:
        """Copy with `raw` stripped from every result (default output form)."""
        return self.model_copy(
            update={"results": [r.model_copy(update={"raw": None}) for r in self.results]}
        )

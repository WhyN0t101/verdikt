"""Core data model. `Report` is the single contract for CLI, API, UI and SOAR glue."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from verdikt.textutil import clean_text

SCHEMA_VERSION = 4  # 2: confidence, seen_before. 3: cves. 4: SourceResult fired/weight/role


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

    @field_validator("value")
    @classmethod
    def _clean_value(cls, v: str) -> str:
        return clean_text(v)


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
    # set by verdict.decide(): why this row counted the way it did
    fired: list[str] = Field(default_factory=list[str])  # rules that matched
    weight: int = 0  # evidence weight in the confidence score (0 = none)
    role: str = ""  # strong | weak | feed | context | no answer
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw: dict[str, Any] | None = None  # arbitrary vendor JSON, kept as received

    # also runs when a stored row or a cached answer is loaded, so old rows come back clean
    @field_validator("summary")
    @classmethod
    def _clean_summary(cls, v: str) -> str:
        return clean_text(v)

    @field_validator("tags")
    @classmethod
    def _clean_tags(cls, v: list[str]) -> list[str]:
        return [clean_text(t) for t in v]


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

    @field_validator("country", "city", "as_org")
    @classmethod
    def _clean_names(cls, v: str | None) -> str | None:
        return None if v is None else clean_text(v)


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


class CveInfo(Model):
    """A CVE found on a host (InternetDB) with CISA KEV and EPSS context. Not a verdict input."""

    id: str
    kev: bool = False  # in CISA's Known Exploited Vulnerabilities catalog
    kev_name: str | None = None
    kev_added: str | None = None
    ransomware: bool = False
    epss: float | None = None  # probability of exploitation in the next 30 days
    percentile: float | None = None

    @field_validator("kev_name", "kev_added")
    @classmethod
    def _clean_kev(cls, v: str | None) -> str | None:
        return None if v is None else clean_text(v)


class SeenBefore(Model):
    """An earlier report that shares an indicator with this one."""

    report_id: str
    ioc: str
    level: Level
    created_at: datetime
    shared: list[str] = Field(default_factory=list[str])  # indicators in common

    # index rows saved before cleaning existed are cleaned here, when a report is loaded
    @field_validator("shared")
    @classmethod
    def _clean_shared(cls, v: list[str]) -> list[str]:
        return [clean_text(x) for x in v]


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
    cves: list[CveInfo] = Field(default_factory=list[CveInfo])
    duration_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def without_raw(self) -> Report:
        """Copy with `raw` stripped from every result (default output form)."""
        return self.model_copy(
            update={"results": [r.model_copy(update={"raw": None}) for r in self.results]}
        )

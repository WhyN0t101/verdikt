"""Settings from `.env` (secrets, paths) and rules from `rules.yaml` (thresholds)."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from verdikt.models import Level

MIN_JOB_HOURS = 1.0


def _source_names() -> frozenset[str]:
    from verdikt.sources import build_sources  # late: sources import this module

    return frozenset(s.name for s in build_sources(Settings(_env_file=None)))  # pyright: ignore[reportCallIssue]


class Rules(BaseModel):
    # a misspelt key or source name used to be ignored, silently turning MALICIOUS into SUSPICIOUS
    model_config = ConfigDict(extra="forbid")

    malicious: dict[str, dict[str, bool | int]] = Field(default_factory=dict)
    suspicious: dict[str, dict[str, bool | int]] = Field(default_factory=dict)
    benign_override: dict[str, dict[str, bool | int]] = Field(default_factory=dict)
    context_only: list[str] = Field(default_factory=list)
    high_weight: list[str] = Field(default_factory=list)
    min_sources_for_safe: int = 2
    listing_feeds: list[str] = Field(default_factory=list[str])
    min_high_weight_for_safe: int = 1
    # evidence weight per source; drives Report.confidence, never the verdict level
    weights: dict[str, int] = Field(default_factory=dict[str, int])
    default_weight: int = 1
    confidence_high: int = 5
    confidence_medium: int = 3
    # experiment, off: a SAFE that rests on one strong source (VirusTotal) is at most medium
    cap_safe_confidence_single_strong: bool = False

    @model_validator(mode="after")
    def _check_names_and_bands(self) -> Rules:
        known = _source_names()
        sections: dict[str, Iterable[str]] = {
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "benign_override": self.benign_override,
            "weights": self.weights,
            "high_weight": self.high_weight,
            "context_only": self.context_only,
            "listing_feeds": self.listing_feeds,
        }
        for section, names in sections.items():
            for name in names:
                if name not in known:
                    options = ", ".join(sorted(known))
                    raise ValueError(f"rules: unknown source {name!r} in `{section}` ({options})")
        if self.confidence_high < self.confidence_medium:
            raise ValueError("rules: confidence_high must be at least confidence_medium")
        return self


def user_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "verdikt"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VERDIKT_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    vt_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    greynoise_api_key: SecretStr | None = None
    hybrid_api_key: SecretStr | None = None

    slack_webhook_url: SecretStr | None = None
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = None
    discord_webhook_url: SecretStr | None = None
    teams_webhook_url: SecretStr | None = None
    smtp_host: str | None = None
    smtp_port: int = 587  # 465 uses implicit TLS, anything else STARTTLS
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_to: str | None = None  # comma-separated
    notify_cooldown_hours: float = (
        0  # skip a repeat alert for the same indicator and level; 0 = off
    )

    internal_domains: str = ""
    geoip_dir: Path | None = None
    db_path: Path | None = None
    rules_path: Path | None = None
    dns_resolve: bool = False
    report_retention_days: int = 90  # 0 keeps reports forever
    audit_log: Path | None = None
    feeds_dir: Path | None = None
    watch_every_hours: float = 0  # 0 = off; otherwise at least MIN_JOB_HOURS
    feeds_every_hours: float = 0
    watch_notify: Literal["slack", "telegram", "discord", "teams", "email"] | None = None
    watch_notify_any: bool = False  # also tell about downgrades (e.g. suspicious -> safe)
    watch_min_level: Level = Level.SUSPICIOUS
    crtsh: bool = False  # certificate transparency: slow (10 to 20 s) and often flaky
    vt_resolutions: bool = False  # passive DNS from VirusTotal: costs one extra VT call per lookup

    @field_validator("watch_every_hours", "feeds_every_hours")
    @classmethod
    def _interval(cls, value: float) -> float:
        # every watchlist run spends source quota for up to 50 indicators
        if value != 0 and value < MIN_JOB_HOURS:
            raise ValueError(f"must be 0 (off) or at least {MIN_JOB_HOURS} hours")
        return value

    @property
    def internal_domain_list(self) -> list[str]:
        return [s.strip() for s in self.internal_domains.split(",") if s.strip()]

    @property
    def resolved_db_path(self) -> Path:
        return self.db_path or user_data_dir() / "verdikt.db"

    @property
    def resolved_feeds_dir(self) -> Path:
        return self.feeds_dir or user_data_dir() / "feeds"

    @property
    def resolved_audit_path(self) -> Path:
        return self.audit_log or user_data_dir() / "audit.jsonl"

    def key(self, name: str) -> str | None:
        """Secret value for a settings field, or None when unset."""
        value: SecretStr | None = getattr(self, name, None)
        return value.get_secret_value() if value else None


def load_rules(path: Path | None = None) -> Rules:
    """Load rules from `path`, else the packaged default `rules.yaml`."""
    text = (
        path.read_text(encoding="utf-8")
        if path
        else resources.files("verdikt").joinpath("rules.yaml").read_text(encoding="utf-8")
    )
    return Rules.model_validate(yaml.safe_load(text))


@lru_cache
def get_settings() -> Settings:
    return Settings()

"""Settings from `.env` (secrets, paths) and rules from `rules.yaml` (thresholds)."""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Rules(BaseModel):
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

    internal_domains: str = ""
    geoip_dir: Path | None = None
    db_path: Path | None = None
    rules_path: Path | None = None
    dns_resolve: bool = False
    report_retention_days: int = 90  # 0 keeps reports forever
    audit_log: Path | None = None
    feeds_dir: Path | None = None

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

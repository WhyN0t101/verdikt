"""SQLite store: per-source result cache, report history, daily request budget.

Own table (not an HTTP cache) because abuse.ch APIs use POST. `raw` is always stored.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from verdikt.models import Model, Report, SourceResult

Clock = Callable[[], datetime]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS source_cache (
  source TEXT NOT NULL, ioc TEXT NOT NULL, fetched_at TEXT NOT NULL, result TEXT NOT NULL,
  PRIMARY KEY (source, ioc));
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, ioc TEXT NOT NULL, ioc_type TEXT NOT NULL, level TEXT NOT NULL,
  created_at TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reports_created ON reports (created_at DESC);
CREATE TABLE IF NOT EXISTS budget (
  source TEXT NOT NULL, day TEXT NOT NULL, used INTEGER NOT NULL,
  PRIMARY KEY (source, day));
"""


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ReportSummary(Model):
    id: str
    ioc: str
    ioc_type: str
    level: str
    created_at: datetime


class Cache:
    def __init__(self, path: Path | str, clock: Clock = _utcnow) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        with self._lock:
            self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- source cache -------------------------------------------------------
    def get(self, source: str, ioc: str, ttl: timedelta) -> SourceResult | None:
        with self._lock:
            row = self._db.execute(
                "SELECT result FROM source_cache WHERE source=? AND ioc=?", (source, ioc)
            ).fetchone()
        if row is None:
            return None
        result = SourceResult.model_validate_json(row[0])
        if self._clock() - result.fetched_at >= ttl:
            return None
        return result.model_copy(update={"cached": True})

    def put(self, source: str, ioc: str, result: SourceResult) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO source_cache VALUES (?,?,?,?)",
                (source, ioc, result.fetched_at.isoformat(), result.model_dump_json()),
            )

    def clear(self, source: str | None = None) -> int:
        with self._lock, self._db:
            if source:
                cur = self._db.execute("DELETE FROM source_cache WHERE source=?", (source,))
            else:
                cur = self._db.execute("DELETE FROM source_cache")
            return cur.rowcount

    # --- history ------------------------------------------------------------
    def save_report(self, report: Report) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?)",
                (
                    report.id,
                    report.ioc,
                    report.ioc_type.value,
                    report.level.value,
                    report.created_at.isoformat(),
                    report.model_dump_json(),
                ),
            )

    def get_report(self, report_id: str) -> Report | None:
        with self._lock:
            row = self._db.execute("SELECT body FROM reports WHERE id=?", (report_id,)).fetchone()
        return Report.model_validate_json(row[0]) if row else None

    def list_reports(self, limit: int = 50, offset: int = 0) -> list[ReportSummary]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ioc, ioc_type, level, created_at FROM reports "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            ReportSummary(id=r[0], ioc=r[1], ioc_type=r[2], level=r[3], created_at=r[4])
            for r in rows
        ]

    # --- daily budget -------------------------------------------------------
    def _day(self) -> str:
        return self._clock().astimezone(UTC).date().isoformat()

    def budget_used(self, source: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT used FROM budget WHERE source=? AND day=?", (source, self._day())
            ).fetchone()
        return int(row[0]) if row else 0

    def charge(self, source: str, limit: int | None) -> bool:
        """Count one request. False (and no charge) when `limit` is already used up."""
        with self._lock, self._db:
            day = self._day()
            row = self._db.execute(
                "SELECT used FROM budget WHERE source=? AND day=?", (source, day)
            ).fetchone()
            used = int(row[0]) if row else 0
            if limit is not None and used >= limit:
                return False
            self._db.execute(
                "INSERT OR REPLACE INTO budget VALUES (?,?,?)", (source, day, used + 1)
            )
            return True

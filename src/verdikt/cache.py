"""SQLite store: per-source result cache, report history, daily request budget.

Own table (not an HTTP cache) because abuse.ch APIs use POST. `raw` is always stored.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from verdikt.models import Model, Report, SeenBefore, SourceResult

Clock = Callable[[], datetime]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS source_cache (
  source TEXT NOT NULL, ioc TEXT NOT NULL, fetched_at TEXT NOT NULL, result TEXT NOT NULL,
  PRIMARY KEY (source, ioc));
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, ioc TEXT NOT NULL, ioc_type TEXT NOT NULL, level TEXT NOT NULL,
  created_at TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reports_created ON reports (created_at DESC);
CREATE TABLE IF NOT EXISTS ioc_index (
  report_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  PRIMARY KEY (report_id, value));
CREATE INDEX IF NOT EXISTS ioc_index_value ON ioc_index (value);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL, ioc TEXT NOT NULL,
  level TEXT NOT NULL, label TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS budget (
  source TEXT NOT NULL, day TEXT NOT NULL, used INTEGER NOT NULL,
  PRIMARY KEY (source, day));
"""


REPORT_RETENTION = timedelta(days=90)
CACHE_MAX_AGE = timedelta(days=7)  # longest source TTL: older cached answers can never be served
FEEDBACK_LABELS = ("false_positive", "false_negative", "correct")
_CORRELATE_MAX = 10
_NO_LIMIT = 2**62  # sqlite INTEGER max is 2**63 - 1


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ReportSummary(Model):
    id: str
    ioc: str
    ioc_type: str
    level: str
    created_at: datetime


class FeedbackEntry(Model):
    id: int
    report_id: str
    ioc: str
    level: str
    label: str
    note: str
    created_at: datetime


class Cache:
    def __init__(
        self,
        path: Path | str,
        clock: Clock = _utcnow,
        report_retention: timedelta | None = REPORT_RETENTION,
    ) -> None:
        """`report_retention=None` keeps reports forever."""
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        self._retention = report_retention
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._prune()

    def _prune(self) -> dict[str, int]:
        """Drop what can never be used again. Reports carry full vendor payloads and only grow.

        Feedback is kept: it stores its own copy of the IOC and level.
        """
        now = self._clock()
        counts: dict[str, int] = {}
        with self._db:
            if self._retention is not None:
                cutoff = (now - self._retention).isoformat()
                cur = self._db.execute("DELETE FROM reports WHERE created_at < ?", (cutoff,))
                counts["reports"] = cur.rowcount
            self._db.execute(
                "DELETE FROM ioc_index WHERE report_id NOT IN (SELECT id FROM reports)"
            )
            cur = self._db.execute(
                "DELETE FROM source_cache WHERE fetched_at < ?",
                ((now - CACHE_MAX_AGE).isoformat(),),
            )
            counts["source_cache"] = cur.rowcount
            cur = self._db.execute(
                "DELETE FROM budget WHERE day < ?", ((now - CACHE_MAX_AGE).date().isoformat(),)
            )
            counts["budget"] = cur.rowcount
        return counts

    def prune(self) -> dict[str, int]:
        with self._lock:
            return self._prune()

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
        try:
            result = SourceResult.model_validate_json(row[0])
        except ValidationError:  # written by an older schema: refetch instead of failing
            return None
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
            self._db.execute("DELETE FROM ioc_index WHERE report_id=?", (report.id,))
            seen = {(report.ioc_type.value, report.ioc)}
            seen |= {(n.kind, n.label) for n in report.graph.nodes if n.kind != "asn"}
            self._db.executemany(
                "INSERT OR IGNORE INTO ioc_index VALUES (?,?,?)",
                [(report.id, kind, value) for kind, value in seen],
            )

    # --- analyst feedback ---------------------------------------------------
    def add_feedback(self, report: Report, label: str, note: str = "") -> FeedbackEntry:
        if label not in FEEDBACK_LABELS:
            raise ValueError(f"label must be one of {FEEDBACK_LABELS}")
        now = self._clock()
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO feedback (report_id, ioc, level, label, note, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (report.id, report.ioc, report.level.value, label, note, now.isoformat()),
            )
            fid = int(cur.lastrowid or 0)
        return FeedbackEntry(
            id=fid,
            report_id=report.id,
            ioc=report.ioc,
            level=report.level.value,
            label=label,
            note=note,
            created_at=now,
        )

    def list_feedback(self, limit: int = 200) -> list[FeedbackEntry]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, report_id, ioc, level, label, note, created_at FROM feedback "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            FeedbackEntry.model_validate(dict(zip(FeedbackEntry.model_fields, r, strict=True)))
            for r in rows
        ]

    def correlate(self, report: Report) -> list[SeenBefore]:
        """Earlier reports sharing the IOC or a related indicator (ASNs excluded: too common)."""
        values = {report.ioc} | {n.label for n in report.graph.nodes if n.kind != "asn"}
        marks = ",".join("?" * len(values))
        # `marks` is only "?" placeholders; values are bound, never interpolated
        sql = (
            "SELECT r.id, r.ioc, r.level, r.created_at, i.value FROM ioc_index i "  # noqa: S608
            "JOIN reports r ON r.id = i.report_id "
            f"WHERE i.value IN ({marks}) AND i.report_id != ? ORDER BY r.created_at DESC"
        )
        with self._lock:
            rows = self._db.execute(sql, (*values, report.id)).fetchall()
        found: dict[str, SeenBefore] = {}
        for rid, ioc, level, created, value in rows:
            entry = found.setdefault(
                rid,
                SeenBefore(report_id=rid, ioc=ioc, level=level, created_at=created),
            )
            entry.shared.append(value)
        return list(found.values())[:_CORRELATE_MAX]

    def get_report(self, report_id: str) -> Report | None:
        with self._lock:
            row = self._db.execute("SELECT body FROM reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            return None
        try:
            return Report.model_validate_json(row[0])
        except ValidationError:  # written by an older schema: treat as gone, not a 500
            return None

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
        # one statement, so a second process sharing the DB file cannot read the same count
        cap = limit if limit is not None else _NO_LIMIT
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO budget VALUES (?,?,1) ON CONFLICT(source, day) "
                "DO UPDATE SET used = used + 1 WHERE used < ?",
                (source, self._day(), cap),
            )
            return cur.rowcount == 1

"""SQLite store: per-source result cache, report history, daily request budget.

Own table (not an HTTP cache) because abuse.ch APIs use POST. `raw` is always stored.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from verdikt.models import Model, Report, SeenBefore, SourceResult, Status

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
CREATE TABLE IF NOT EXISTS source_stats (
  day TEXT NOT NULL, source TEXT NOT NULL, checks INTEGER NOT NULL DEFAULT 0,
  ok INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
  rate_limited INTEGER NOT NULL DEFAULT 0, not_found INTEGER NOT NULL DEFAULT 0,
  cached INTEGER NOT NULL DEFAULT 0, ms INTEGER NOT NULL DEFAULT 0,
  fetched INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, source));
CREATE TABLE IF NOT EXISTS watchlist (
  ioc TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, added_at TEXT NOT NULL,
  last_checked_at TEXT, last_level TEXT, last_report_id TEXT);
CREATE TABLE IF NOT EXISTS watch_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ioc TEXT NOT NULL, from_level TEXT NOT NULL,
  to_level TEXT NOT NULL, at TEXT NOT NULL, report_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS case_reports (
  case_id TEXT NOT NULL, report_id TEXT NOT NULL, added_at TEXT NOT NULL,
  PRIMARY KEY (case_id, report_id));
CREATE TABLE IF NOT EXISTS budget (
  source TEXT NOT NULL, day TEXT NOT NULL, used INTEGER NOT NULL,
  PRIMARY KEY (source, day));
"""


REPORT_RETENTION = timedelta(days=90)
CACHE_MAX_AGE = timedelta(days=7)  # longest source TTL: older cached answers can never be served
FEEDBACK_LABELS = ("false_positive", "false_negative", "correct")
_CORRELATE_MAX = 10
WATCHLIST_MAX = 50  # a re-check spends quota for every entry
STATS_KEEP = timedelta(days=90)
CASE_TITLE_MAX = 120
CASE_NOTES_MAX = 20_000
CASE_MAX_TAGS = 10
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


class DayCount(Model):
    day: str
    malicious: int = 0
    suspicious: int = 0
    safe: int = 0
    unknown: int = 0


class SourceHealth(Model):
    source: str
    checks: int
    ok: int
    errors: int
    rate_limited: int
    not_found: int
    cached: int
    avg_ms: int  # over live (non-cached) calls only


class Recurring(Model):
    value: str
    kind: str
    reports: int
    last_level: str


class FeedbackCounts(Model):
    false_positive: int = 0
    false_negative: int = 0
    correct: int = 0


class Stats(Model):
    days: int
    total: int
    by_day: list[DayCount]
    sources: list[SourceHealth]
    recurring: list[Recurring]
    feedback: FeedbackCounts


class WatchEntry(Model):
    ioc: str
    ioc_type: str
    added_at: datetime
    last_checked_at: datetime | None = None
    last_level: str | None = None
    last_report_id: str | None = None


class WatchEvent(Model):
    id: int
    ioc: str
    from_level: str
    to_level: str
    at: datetime
    report_id: str


class CaseSummary(Model):
    id: str
    title: str
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    report_count: int


class CaseDetail(CaseSummary):
    notes: str
    reports: list[ReportSummary]


class CaseError(ValueError):
    """Invalid case input (title, notes or tags)."""


_TAG = re.compile(r"^[a-z0-9][a-z0-9 _:.-]{0,29}$")


def clean_tags(tags: list[str]) -> list[str]:
    out: list[str] = []
    for t in tags:
        t = t.strip().lower()
        if not _TAG.match(t):
            raise CaseError(f"invalid tag {t!r}: 1 to 30 characters of a-z, 0-9, space, _ : . -")
        if t not in out:
            out.append(t)
    if len(out) > CASE_MAX_TAGS:
        raise CaseError(f"at most {CASE_MAX_TAGS} tags")
    return out


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
                cur = self._db.execute(
                    "DELETE FROM reports WHERE created_at < ? "
                    "AND id NOT IN (SELECT report_id FROM case_reports)",
                    (cutoff,),
                )
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
            cur = self._db.execute(
                "DELETE FROM source_stats WHERE day < ?", ((now - STATS_KEEP).date().isoformat(),)
            )
            counts["source_stats"] = cur.rowcount
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

    def checked_since(self, age: timedelta) -> set[str]:
        """IOCs that have a stored report newer than `age` (for `bulk --resume`)."""
        cutoff = (self._clock() - age).isoformat()
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT ioc FROM reports WHERE created_at >= ?", (cutoff,)
            ).fetchall()
        return {str(r[0]) for r in rows}

    # --- investigations (cases) ---------------------------------------------------------
    def _case_row(self, case_id: str) -> tuple[Any, ...] | None:
        row: tuple[Any, ...] | None = self._db.execute(
            "SELECT id, title, notes, tags, created_at, updated_at FROM cases WHERE id=?",
            (case_id,),
        ).fetchone()
        return row

    def case_create(self, title: str, notes: str = "", tags: list[str] | None = None) -> str:
        title = title.strip()
        if not title or len(title) > CASE_TITLE_MAX:
            raise CaseError(f"title must be 1 to {CASE_TITLE_MAX} characters")
        if len(notes) > CASE_NOTES_MAX:
            raise CaseError(f"notes are limited to {CASE_NOTES_MAX} characters")
        cleaned = clean_tags(tags or [])
        case_id = uuid.uuid4().hex
        now = self._clock().isoformat()
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO cases (id, title, notes, tags, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (case_id, title, notes, json.dumps(cleaned), now, now),
            )
        return case_id

    def case_update(
        self,
        case_id: str,
        title: str | None = None,
        notes: str | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        if title is not None and (not title.strip() or len(title.strip()) > CASE_TITLE_MAX):
            raise CaseError(f"title must be 1 to {CASE_TITLE_MAX} characters")
        if notes is not None and len(notes) > CASE_NOTES_MAX:
            raise CaseError(f"notes are limited to {CASE_NOTES_MAX} characters")
        cleaned = clean_tags(tags) if tags is not None else None
        with self._lock, self._db:
            row = self._case_row(case_id)
            if row is None:
                return False
            self._db.execute(
                "UPDATE cases SET title=?, notes=?, tags=?, updated_at=? WHERE id=?",
                (
                    title.strip() if title is not None else row[1],
                    notes if notes is not None else row[2],
                    json.dumps(cleaned) if cleaned is not None else row[3],
                    self._clock().isoformat(),
                    case_id,
                ),
            )
            return True

    def case_delete(self, case_id: str) -> bool:
        with self._lock, self._db:
            self._db.execute("DELETE FROM case_reports WHERE case_id=?", (case_id,))
            return self._db.execute("DELETE FROM cases WHERE id=?", (case_id,)).rowcount == 1

    def case_add_report(self, case_id: str, report_id: str) -> bool:
        """False when the case or the report does not exist."""
        with self._lock, self._db:
            if self._case_row(case_id) is None:
                return False
            if not self._db.execute("SELECT 1 FROM reports WHERE id=?", (report_id,)).fetchone():
                return False
            now = self._clock().isoformat()
            self._db.execute(
                "INSERT OR IGNORE INTO case_reports VALUES (?,?,?)", (case_id, report_id, now)
            )
            self._db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
            return True

    def case_remove_report(self, case_id: str, report_id: str) -> bool:
        with self._lock, self._db:
            return (
                self._db.execute(
                    "DELETE FROM case_reports WHERE case_id=? AND report_id=?", (case_id, report_id)
                ).rowcount
                == 1
            )

    def case_list(self, tag: str | None = None) -> list[CaseSummary]:
        with self._lock:
            rows = self._db.execute(
                "SELECT c.id, c.title, c.tags, c.created_at, c.updated_at, "
                "(SELECT count(*) FROM case_reports r WHERE r.case_id=c.id) "
                "FROM cases c ORDER BY c.updated_at DESC"
            ).fetchall()
        cases = [
            CaseSummary(
                id=r[0],
                title=r[1],
                tags=json.loads(r[2]),
                created_at=r[3],
                updated_at=r[4],
                report_count=int(r[5]),
            )
            for r in rows
        ]
        return [c for c in cases if tag in c.tags] if tag else cases

    def case_get(self, case_id: str) -> CaseDetail | None:
        with self._lock:
            row = self._case_row(case_id)
            if row is None:
                return None
            reps = self._db.execute(
                "SELECT r.id, r.ioc, r.ioc_type, r.level, r.created_at FROM case_reports cr "
                "JOIN reports r ON r.id = cr.report_id WHERE cr.case_id=? ORDER BY cr.added_at",
                (case_id,),
            ).fetchall()
        return CaseDetail(
            id=row[0],
            title=row[1],
            notes=row[2],
            tags=json.loads(row[3]),
            created_at=row[4],
            updated_at=row[5],
            report_count=len(reps),
            reports=[
                ReportSummary(id=r[0], ioc=r[1], ioc_type=r[2], level=r[3], created_at=r[4])
                for r in reps
            ],
        )

    # --- statistics ---------------------------------------------------------------------
    def record_stats(self, results: list[SourceResult]) -> None:
        """Count each source answer of one check: status, cache use and live latency."""
        day = self._day()
        with self._lock, self._db:
            for r in results:
                live = not r.cached and r.status is not Status.SKIPPED
                self._db.execute(
                    "INSERT INTO source_stats (day, source) VALUES (?,?) ON CONFLICT DO NOTHING",
                    (day, r.source),
                )
                self._db.execute(
                    "UPDATE source_stats SET checks=checks+1, ok=ok+?, errors=errors+?, "
                    "rate_limited=rate_limited+?, not_found=not_found+?, cached=cached+?, "
                    "ms=ms+?, fetched=fetched+? WHERE day=? AND source=?",
                    (
                        r.status is Status.OK,
                        r.status is Status.ERROR,
                        r.status is Status.RATE_LIMITED,
                        r.status is Status.NOT_FOUND,
                        r.cached,
                        r.duration_ms if live else 0,
                        live,
                        day,
                        r.source,
                    ),
                )

    def stats(self, days: int = 30) -> Stats:
        since = (self._clock() - timedelta(days=days)).isoformat()
        since_day = (self._clock() - timedelta(days=days)).date().isoformat()
        with self._lock:
            level_rows = self._db.execute(
                "SELECT substr(created_at,1,10), level, count(*) FROM reports "
                "WHERE created_at >= ? GROUP BY 1, 2 ORDER BY 1",
                (since,),
            ).fetchall()
            src_rows = self._db.execute(
                "SELECT source, sum(checks), sum(ok), sum(errors), sum(rate_limited), "
                "sum(not_found), sum(cached), sum(ms), sum(fetched) FROM source_stats "
                "WHERE day >= ? GROUP BY source ORDER BY source",
                (since_day,),
            ).fetchall()
            rec_rows = self._db.execute(
                "SELECT i.value, i.kind, count(DISTINCT i.report_id) AS c, "
                "(SELECT r2.level FROM ioc_index i2 JOIN reports r2 ON r2.id=i2.report_id "
                " WHERE i2.value=i.value ORDER BY r2.created_at DESC LIMIT 1) "
                "FROM ioc_index i JOIN reports r ON r.id=i.report_id "
                "WHERE r.created_at >= ? AND i.kind != 'asn' "
                "GROUP BY i.value, i.kind HAVING c >= 2 ORDER BY c DESC, i.value LIMIT 8",
                (since,),
            ).fetchall()
            fb_rows = self._db.execute(
                "SELECT label, count(*) FROM feedback WHERE created_at >= ? GROUP BY label",
                (since,),
            ).fetchall()
        by_day: dict[str, DayCount] = {}
        for day, level, n in level_rows:
            entry = by_day.setdefault(day, DayCount(day=day))
            if level in ("malicious", "suspicious", "safe", "unknown"):
                setattr(entry, level, int(n))
        return Stats(
            days=days,
            total=sum(int(n) for _, _, n in level_rows),
            by_day=list(by_day.values()),
            sources=[
                SourceHealth(
                    source=s,
                    checks=int(c),
                    ok=int(ok),
                    errors=int(er),
                    rate_limited=int(rl),
                    not_found=int(nf),
                    cached=int(ca),
                    avg_ms=int(ms // fetched) if fetched else 0,
                )
                for s, c, ok, er, rl, nf, ca, ms, fetched in src_rows
            ],
            recurring=[
                Recurring(value=v, kind=k, reports=int(c), last_level=lvl)
                for v, k, c, lvl in rec_rows
            ],
            feedback=FeedbackCounts(
                **{lab: int(n) for lab, n in fb_rows if lab in FEEDBACK_LABELS}
            ),
        )

    # --- watchlist ----------------------------------------------------------------------
    def watch_add(self, ioc: str, ioc_type: str) -> bool:
        """False when the list is full; adding an existing entry is a no-op."""
        with self._lock, self._db:
            if self._db.execute("SELECT 1 FROM watchlist WHERE ioc=?", (ioc,)).fetchone():
                return True
            if self._db.execute("SELECT count(*) FROM watchlist").fetchone()[0] >= WATCHLIST_MAX:
                return False
            self._db.execute(
                "INSERT INTO watchlist (ioc, ioc_type, added_at) VALUES (?,?,?)",
                (ioc, ioc_type, self._clock().isoformat()),
            )
            return True

    def watch_remove(self, ioc: str) -> bool:
        with self._lock, self._db:
            return self._db.execute("DELETE FROM watchlist WHERE ioc=?", (ioc,)).rowcount == 1

    def watch_list(self) -> list[WatchEntry]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ioc, ioc_type, added_at, last_checked_at, last_level, last_report_id "
                "FROM watchlist ORDER BY added_at"
            ).fetchall()
        return [
            WatchEntry.model_validate(dict(zip(WatchEntry.model_fields, r, strict=True)))
            for r in rows
        ]

    def watch_record(self, report: Report) -> str | None:
        """Store the latest result for an entry. Returns the previous level if it changed."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT last_level FROM watchlist WHERE ioc=?", (report.ioc,)
            ).fetchone()
            if row is None:
                return None
            previous: str | None = row[0]
            now = self._clock().isoformat()
            self._db.execute(
                "UPDATE watchlist SET last_checked_at=?, last_level=?, last_report_id=? "
                "WHERE ioc=?",
                (now, report.level.value, report.id, report.ioc),
            )
            if previous is not None and previous != report.level.value:
                self._db.execute(
                    "INSERT INTO watch_events (ioc, from_level, to_level, at, report_id) "
                    "VALUES (?,?,?,?,?)",
                    (report.ioc, previous, report.level.value, now, report.id),
                )
                return previous
            return None

    def watch_events(self, limit: int = 20) -> list[WatchEvent]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ioc, from_level, to_level, at, report_id FROM watch_events "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            WatchEvent.model_validate(dict(zip(WatchEvent.model_fields, r, strict=True)))
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

"""Append-only JSON-lines audit log: one event per check or feedback, for SIEM agents to tail.

Events carry no keys, no vendor raw data and no feed-derived text. The IOC is defanged so a
SIEM or ticketing tool that auto-links indicators does not turn the log into a live link.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verdikt.cache import FeedbackEntry
from verdikt.models import Report
from verdikt.notify.format import defang

log = logging.getLogger(__name__)


MAX_BYTES = 10 * 1024 * 1024  # past this the log moves to `<name>.1` (one generation kept)


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def _write(self, event: dict[str, Any]) -> None:
        line = json.dumps({"ts": datetime.now(UTC).isoformat(), **event}, ensure_ascii=True)
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                if self._path.exists() and self._path.stat().st_size >= MAX_BYTES:
                    self._path.replace(self._path.with_name(self._path.name + ".1"))
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError as exc:  # an unwritable log must not fail a check, but must be visible
            log.warning("audit log write failed (%s)", type(exc).__name__)

    def check(self, report: Report) -> None:
        self._write(
            {
                "event": "check",
                "report_id": report.id,
                "ioc": defang(report.ioc),
                "ioc_type": report.ioc_type.value,
                "level": report.level.value,
                "confidence": report.confidence.value,
                "agreeing": report.agreeing,
                "total": report.total,
                "duration_ms": report.duration_ms,
                "seen_before": len(report.seen_before),
                "sources": [
                    {
                        "source": r.source,
                        "status": r.status.value,
                        "level": r.level.value,
                        "cached": r.cached,
                    }
                    for r in report.results
                ],
            }
        )

    def feedback(self, entry: FeedbackEntry) -> None:
        self._write(
            {
                "event": "feedback",
                "report_id": entry.report_id,
                "ioc": defang(entry.ioc),
                "level": entry.level,
                "label": entry.label,
            }
        )

"""Watchlist re-checks: run every entry again and report verdict changes.

Scheduling is left to the OS (cron, Task Scheduler) via `verdikt watch run`, or to the UI's
"Re-check all" button: a re-check bypasses the cache (that is the point) and spends quota.
"""

from __future__ import annotations

from verdikt.detect import DetectError
from verdikt.engine import Engine
from verdikt.models import Model, Report


class WatchChange(Model):
    ioc: str
    before: str
    after: str
    report_id: str


async def recheck(engine: Engine) -> tuple[list[WatchChange], list[Report]]:
    """Re-check each entry. Returns the changes and the fresh reports of the changed entries."""
    changes: list[WatchChange] = []
    changed_reports: list[Report] = []
    for entry in engine.cache.watch_list():
        try:
            report = await engine.check(entry.ioc, no_cache=True)
        except DetectError:
            continue  # e.g. the indicator became an internal domain after a settings change
        before = engine.cache.watch_record(report)
        if before is not None:
            changes.append(
                WatchChange(
                    ioc=entry.ioc, before=before, after=report.level.value, report_id=report.id
                )
            )
            changed_reports.append(report)
    return changes, changed_reports

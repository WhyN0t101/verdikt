"""Watchlist re-checks: run every entry again and report verdict changes.

Scheduling is left to the OS (cron, Task Scheduler) via `verdikt watch run`, or to the UI's
"Re-check all" button: a re-check bypasses the cache (that is the point) and spends quota.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from verdikt.detect import DetectError
from verdikt.engine import Engine
from verdikt.models import Level, Model, Report, Status

CONCURRENCY = 4  # per-source limiters still pace each vendor; this only overlaps different ones

Progress = Callable[[int, int], None]


class WatchChange(Model):
    ioc: str
    before: str
    after: str
    report_id: str


def failed_lookup(report: Report) -> bool:
    """UNKNOWN because a source errored or was rate limited: not evidence the verdict changed."""
    return report.level is Level.UNKNOWN and any(
        r.status in (Status.ERROR, Status.RATE_LIMITED) for r in report.results
    )


async def recheck(
    engine: Engine, progress: Progress | None = None
) -> tuple[list[WatchChange], list[Report]]:
    """Re-check each entry. Returns the changes and the fresh reports of the changed entries."""
    entries = engine.cache.watch_list()
    gate = asyncio.Semaphore(CONCURRENCY)
    done = 0

    async def one(ioc: str) -> Report | None:
        nonlocal done
        try:
            async with gate:
                return await engine.check(ioc, no_cache=True)
        except DetectError:
            return None  # e.g. the indicator became an internal domain after a settings change
        finally:
            done += 1
            if progress:
                progress(done, len(entries))

    reports = await asyncio.gather(*(one(e.ioc) for e in entries))
    changes: list[WatchChange] = []
    changed_reports: list[Report] = []
    for entry, report in zip(entries, reports, strict=True):
        if report is None:
            continue
        if failed_lookup(report):
            continue  # keep the last good verdict; a transient error must not raise a change event
        before = engine.cache.watch_record(report)
        if before is not None:
            changes.append(
                WatchChange(
                    ioc=entry.ioc, before=before, after=report.level.value, report_id=report.id
                )
            )
            changed_reports.append(report)
    return changes, changed_reports

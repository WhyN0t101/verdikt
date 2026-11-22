"""Watchlist re-checks: run every entry again and report verdict changes.

Scheduling is left to the OS (cron, Task Scheduler) via `verdikt watch run`, or to the UI's
"Re-check all" button: a re-check bypasses the cache (that is the point) and spends quota.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from verdikt.config import Rules
from verdikt.detect import DetectError
from verdikt.diff import diff_reports
from verdikt.engine import Engine
from verdikt.models import Level, Model, Report, Status

CONCURRENCY = 4  # per-source limiters still pace each vendor; this only overlaps different ones

Progress = Callable[[int, int], None]


class WatchChange(Model):
    ioc: str
    before: str
    after: str
    report_id: str
    # the evidence under the verdict moved (a source changed its level, or too few sources still
    # answer); `before == after` then means an evidence-only change
    evidence_changed: bool = False


def failed_lookup(report: Report) -> bool:
    """UNKNOWN because a source errored or was rate limited: not evidence the verdict changed."""
    return report.level is Level.UNKNOWN and any(
        r.status in (Status.ERROR, Status.RATE_LIMITED) for r in report.results
    )


_ANSWERED = (Status.OK, Status.NOT_FOUND)


def evidence_changed(old: Report | None, new: Report, rules: Rules) -> bool:
    """Did the evidence move, apart from sources that only flipped between answering and not?

    A rate limit or timeout makes a source flap; that alone is noise. It counts only when so
    many drop out that fewer than `min_sources_for_safe` verdict-bearing sources still answer.
    """
    if old is None:
        return False
    flapped = False
    for c in diff_reports(old, new).sources:
        both_answered = c.status_from in _ANSWERED and c.status_to in _ANSWERED
        if both_answered and c.level_from != c.level_to:
            return True
        flapped = flapped or not both_answered
    if flapped:
        floor = rules.min_sources_for_safe
        return new.total < floor <= old.total
    return old.confidence != new.confidence


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
            # keep the last good verdict (a transient error is no change event), but the entry
            # was checked just now
            engine.cache.watch_touch(entry.ioc)
            continue
        old = engine.cache.get_report(entry.last_report_id) if entry.last_report_id else None
        moved = evidence_changed(old, report, engine.rules)
        before = engine.cache.watch_record(report)
        if before is not None or moved:
            changes.append(
                WatchChange(
                    ioc=entry.ioc,
                    before=before or report.level.value,
                    after=report.level.value,
                    report_id=report.id,
                    evidence_changed=moved,
                )
            )
            # a verdict change always notifies; evidence alone only with VERDIKT_WATCH_NOTIFY_ANY
            if before is not None or engine.settings.watch_notify_any:
                changed_reports.append(report)
    return changes, changed_reports

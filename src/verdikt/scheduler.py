"""Background jobs inside `verdikt ui`: re-check the watchlist and refresh the local feeds.

Off by default (`VERDIKT_WATCH_EVERY_HOURS`, `VERDIKT_FEEDS_EVERY_HOURS`). Jobs run only while
the UI process is running; for an always-on schedule use cron or Task Scheduler with
`verdikt watch run` and `verdikt feeds update`. The first run happens one interval after start,
so launching the UI never spends quota by itself.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from verdikt.config import Settings
from verdikt.engine import Engine
from verdikt.models import Model
from verdikt.notify import notify
from verdikt.sources.feeds import update_feeds
from verdikt.watch import recheck

log = logging.getLogger(__name__)

JOBS = ("watch", "feeds")


class JobStatus(Model):
    name: str
    every_hours: float  # 0 = not scheduled (it can still be run on demand)
    last_run: datetime | None = None
    last_ok: bool | None = None
    last_detail: str = ""
    next_run: datetime | None = None


class Scheduler:
    def __init__(
        self,
        engine: Engine,
        settings: Settings,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._settings = settings
        self._sleep = sleep
        self._now = now
        self._every = {
            "watch": settings.watch_every_hours,
            "feeds": settings.feeds_every_hours,
        }
        self._status = {n: JobStatus(name=n, every_hours=self._every[n]) for n in JOBS}
        self._tasks: list[asyncio.Task[None]] = []

    # --- lifecycle ----------------------------------------------------------------------
    def start(self) -> None:
        for name in JOBS:
            if self._every[name] > 0:
                self._status[name].next_run = self._now() + timedelta(hours=self._every[name])
                self._tasks.append(asyncio.create_task(self._loop(name), name=f"verdikt-{name}"))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    @property
    def running(self) -> int:
        """Number of background loops."""
        return len(self._tasks)

    def status(self) -> list[JobStatus]:
        return [self._status[n].model_copy() for n in JOBS]

    # --- jobs ---------------------------------------------------------------------------
    async def _loop(self, name: str) -> None:
        hours = self._every[name]
        while True:
            await self._sleep(hours * 3600)
            await self.run(name)
            self._status[name].next_run = self._now() + timedelta(hours=hours)

    async def run(self, name: str) -> JobStatus:
        """Run one job now. A failure is recorded and logged (class name only), never raised."""
        status = self._status[name]
        try:
            status.last_detail = await (self._watch() if name == "watch" else self._feeds())
            status.last_ok = True
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("scheduled %s job failed (%s)", name, type(exc).__name__)
            status.last_detail = f"failed: {type(exc).__name__}"
            status.last_ok = False
        status.last_run = self._now()
        return status.model_copy()

    async def _watch(self) -> str:
        changes, reports = await recheck(self._engine)
        platform = self._settings.watch_notify
        sent = 0
        if platform:
            for report in reports:
                outcome = await notify(
                    report,
                    platform,
                    self._settings,
                    self._engine.http,
                    self._settings.watch_min_level,
                )
                sent += outcome.sent
        return f"{len(changes)} verdict change(s)" + (
            f", {sent} notification(s)" if platform else ""
        )

    async def _feeds(self) -> str:
        results = await update_feeds(self._engine.http, self._settings.resolved_feeds_dir)
        return f"{sum(r.ok for r in results)}/{len(results)} feeds updated"

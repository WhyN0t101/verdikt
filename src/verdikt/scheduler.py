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
from verdikt.models import Level, Model
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
    running: bool = False
    progress: str = ""  # "3/50" while a watch re-check is running


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
        self._locks = {n: asyncio.Lock() for n in JOBS}
        self._manual: dict[str, asyncio.Task[JobStatus]] = {}

    # --- lifecycle ----------------------------------------------------------------------
    def start(self) -> None:
        for name in JOBS:
            if self._every[name] > 0:
                self._status[name].last_run = self._load_last_run(name)
                self._status[name].next_run = self._first_run(name)
                self._tasks.append(asyncio.create_task(self._loop(name), name=f"verdikt-{name}"))

    async def stop(self) -> None:
        for t in (*self._tasks, *self._manual.values()):
            t.cancel()
        await asyncio.gather(*self._tasks, *self._manual.values(), return_exceptions=True)
        self._tasks.clear()
        self._manual.clear()

    @property
    def running(self) -> int:
        """Number of background loops."""
        return len(self._tasks)

    def _load_last_run(self, name: str) -> datetime | None:
        stored = self._engine.cache.kv_get(f"job:{name}:last_run")
        return datetime.fromisoformat(stored) if stored else None

    def _first_run(self, name: str) -> datetime:
        """Keep the cadence across restarts; an overdue job waits a full interval."""
        now = self._now()
        every = timedelta(hours=self._every[name])
        last = self._status[name].last_run
        return last + every if last and last + every > now else now + every

    def status(self) -> list[JobStatus]:
        return [self._status[n].model_copy() for n in JOBS]

    # --- jobs ---------------------------------------------------------------------------
    async def _loop(self, name: str) -> None:
        hours = self._every[name]
        due = self._status[name].next_run or self._now() + timedelta(hours=hours)
        while True:
            await self._sleep(max(0.0, (due - self._now()).total_seconds()))
            await self.run(name)
            due = self._now() + timedelta(hours=hours)
            self._status[name].next_run = due

    async def run(self, name: str) -> JobStatus:
        """Run one job now. A failure is recorded and logged (class name only), never raised.

        A job already running (timer, button or API) is not started twice: its status comes back.
        """
        status = self._status[name]
        lock = self._locks[name]
        if lock.locked():
            return status.model_copy()
        async with lock:
            status.running, status.progress = True, ""
            try:
                status.last_detail = await (self._watch() if name == "watch" else self._feeds())
                status.last_ok = True
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("scheduled %s job failed (%s)", name, type(exc).__name__)
                status.last_detail = f"failed: {type(exc).__name__}"
                status.last_ok = False
            finally:
                status.running = False
            status.last_run = self._now()
            self._engine.cache.kv_set(f"job:{name}:last_run", status.last_run.isoformat())
        return status.model_copy()

    def run_in_background(self, name: str) -> JobStatus:
        """Start a job and return at once; poll `status()` for `running` and `progress`."""
        status = self._status[name]
        task = self._manual.get(name)
        if (task is None or task.done()) and not self._locks[name].locked():
            self._manual[name] = asyncio.create_task(self.run(name), name=f"verdikt-{name}-manual")
            status.running = True
        return status.model_copy()

    async def _watch(self) -> str:
        def progress(done: int, total: int) -> None:
            self._status["watch"].progress = f"{done}/{total}"

        changes, reports = await recheck(self._engine, progress)
        platform = self._settings.watch_notify
        sent = 0
        if platform:
            for report in reports:
                outcome = await notify(
                    report,
                    platform,
                    self._settings,
                    self._engine.http,
                    Level.SAFE
                    if self._settings.watch_notify_any
                    else self._settings.watch_min_level,
                    self._engine.cache,
                )
                sent += outcome.sent
        verdicts = sum(c.before != c.after for c in changes)
        evidence = len(changes) - verdicts
        return (
            f"{verdicts} verdict change(s)"
            + (f", {evidence} evidence change(s)" if evidence else "")
            + (f", {sent} notification(s)" if platform else "")
        )

    async def _feeds(self) -> str:
        results = await update_feeds(self._engine.http, self._settings.resolved_feeds_dir)
        return f"{sum(r.ok for r in results)}/{len(results)} feeds updated"

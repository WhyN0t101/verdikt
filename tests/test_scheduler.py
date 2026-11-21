from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx
from pydantic import ValidationError

from tests.conftest import CountingLimiter, Fake
from tests.test_feeds import mock_all
from verdikt import scheduler as sched_mod
from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.scheduler import Scheduler
from verdikt.sources.base import Source

NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)
HOOK = "https://hooks.slack.test/T0/B0/X"


def make(
    tmp_path: Path,
    http: httpx.AsyncClient,
    vt: Fake | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    **settings: object,
) -> tuple[Scheduler, Engine, Fake]:
    vt = vt or Fake("virustotal", {"malicious": 0, "suspicious": 0})
    ab = Fake("abuseipdb", {"score": 0})
    cfg = Settings(_env_file=None, feeds_dir=tmp_path / "feeds", **settings)  # pyright: ignore[reportCallIssue]
    sources: list[Source] = [vt, ab]
    engine = Engine(
        cfg, load_rules(), Cache(":memory:"), http, sources=sources, limiter_factory=CountingLimiter
    )
    return Scheduler(engine, cfg, sleep=sleep, now=lambda: NOW), engine, vt


def test_intervals_are_off_or_at_least_an_hour() -> None:
    for ok in (0, 1, 6.5, 24):
        assert Settings(_env_file=None, watch_every_hours=ok).watch_every_hours == ok  # pyright: ignore[reportCallIssue]
    for bad in (0.1, 0.99, -1):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, feeds_every_hours=bad)  # pyright: ignore[reportCallIssue]


async def test_nothing_is_scheduled_by_default(tmp_path: Path, client: httpx.AsyncClient) -> None:
    s, _, _ = make(tmp_path, client)
    s.start()
    assert s.running == 0
    assert [(j.name, j.every_hours, j.next_run) for j in s.status()] == [
        ("watch", 0, None),
        ("feeds", 0, None),
    ]
    await s.stop()


async def test_watch_job_reports_changes(tmp_path: Path, client: httpx.AsyncClient) -> None:
    s, engine, vt = make(tmp_path, client)
    first = await engine.check("8.8.8.8")
    engine.cache.watch_add("8.8.8.8", "ip")
    engine.cache.watch_record(first)
    assert (await s.run("watch")).last_detail == "0 verdict change(s)"

    vt.metrics = {"malicious": 20, "suspicious": 0}
    status = await s.run("watch")
    assert (status.last_ok, status.last_detail, status.last_run) == (
        True,
        "1 verdict change(s)",
        NOW,
    )


async def test_watch_job_notifies_changed_entries_only(
    tmp_path: Path, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(200))
    s, engine, vt = make(tmp_path, client, slack_webhook_url=HOOK, watch_notify="slack")
    first = await engine.check("8.8.8.8")
    engine.cache.watch_add("8.8.8.8", "ip")
    engine.cache.watch_record(first)
    assert "0 notification" in (await s.run("watch")).last_detail
    assert not route.called

    vt.metrics = {"malicious": 20, "suspicious": 0}
    detail = (await s.run("watch")).last_detail
    assert detail == "1 verdict change(s), 1 notification(s)"
    assert route.call_count == 1
    assert "8[.]8[.]8[.]8" in route.calls.last.request.content.decode()  # defanged


async def test_feeds_job_downloads_everything(
    tmp_path: Path, client: httpx.AsyncClient, router: respx.MockRouter
) -> None:
    mock_all(router)
    s, _, _ = make(tmp_path, client)
    status = await s.run("feeds")
    assert (status.last_ok, status.last_detail) == (True, "7/7 feeds updated")
    assert (tmp_path / "feeds" / "meta.json").is_file()


async def test_a_failing_job_is_recorded_not_raised(
    tmp_path: Path,
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def boom(_engine: Engine, _progress: object = None) -> None:
        raise RuntimeError("secret detail that must not be logged")

    monkeypatch.setattr(sched_mod, "recheck", boom)
    s, _, _ = make(tmp_path, client)
    status = await s.run("watch")
    assert (status.last_ok, status.last_detail) == (False, "failed: RuntimeError")
    assert "secret detail" not in caplog.text  # class name only
    assert "RuntimeError" in caplog.text


async def test_loop_waits_one_interval_before_the_first_run(
    tmp_path: Path, client: httpx.AsyncClient
) -> None:
    waits: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)
        if len(waits) > 1:
            await asyncio.Event().wait()  # park after the first run

    s, _, _ = make(tmp_path, client, sleep=fake_sleep, watch_every_hours=2)
    s.start()
    assert s.status()[0].next_run is not None
    assert s.status()[0].last_run is None  # nothing ran at start
    for _ in range(50):
        await asyncio.sleep(0)
        if s.status()[0].last_run is not None:
            break
    assert waits[0] == 2 * 3600
    assert s.status()[0].last_run == NOW
    assert s.status()[1].every_hours == 0  # the feeds job stays off
    await s.stop()
    assert s.running == 0


# --- API ----------------------------------------------------------------------------------

AUTH = {"x-verdikt-token": "t"}


async def test_api_scheduler_status_and_run_now(tmp_path: Path, router: respx.MockRouter) -> None:
    mock_all(router)
    async with httpx.AsyncClient() as http:
        s, engine, _ = make(tmp_path, http, feeds_every_hours=12)
        app = create_app(engine, port=8765, token="t", web_dist=tmp_path / "none")
        transport = httpx.ASGITransport(app=app)
        app.state.scheduler = s
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as c:
            got = (await c.get("/api/scheduler", headers=AUTH)).json()
            assert [(j["name"], j["every_hours"]) for j in got] == [("watch", 0), ("feeds", 12)]
            ran = await c.post("/api/scheduler/feeds/run", headers=AUTH, json={})
            assert ran.json()["last_detail"] == "7/7 feeds updated"
            assert (
                await c.post("/api/scheduler/nope/run", headers=AUTH, json={})
            ).status_code == 404
            assert (await c.get("/api/scheduler")).status_code == 401

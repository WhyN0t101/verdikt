"""Regression tests for the review batch: quota display, imports, jobs, notifiers, detect."""

from __future__ import annotations

import asyncio
import json
import smtplib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import httpx
import pytest
import respx

from tests.conftest import CountingLimiter, Fake, make_engine
from tests.test_api import AUTH, PORT, TOKEN
from tests.test_notify import make_report
from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.detect import DetectError, detect
from verdikt.engine import Engine
from verdikt.misp import to_misp
from verdikt.models import Graph, GraphNode, Level, Status
from verdikt.notify import notify
from verdikt.scheduler import Scheduler
from verdikt.sources.importers import NAME, ImportError_, parse_any
from verdikt.sources.passivedns import PassiveDNS
from verdikt.watch import recheck

NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)


# --- quota -----------------------------------------------------------------------------------
def test_shared_quota_group_reports_the_group_spend(settings: Settings, cache: Cache) -> None:
    engine = make_engine(settings, cache, httpx.AsyncClient(), [PassiveDNS("k")])
    cache.charge("virustotal", 500)
    assert engine.source_status()[0].used_today == 1


# --- cache -----------------------------------------------------------------------------------
async def test_zero_ttl_sources_are_not_written_to_the_cache(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    class Local(Fake):
        ttl = timedelta(0)

    engine = make_engine(settings, cache, client, [Local("localfeeds", {})])
    await engine.check("8.8.8.8")
    assert cache.get("localfeeds", "8.8.8.8", timedelta(days=1)) is None


# --- detect ----------------------------------------------------------------------------------
@pytest.mark.parametrize("raw", ["64:ff9b::a00:1", "http://printer.intranet/", "nas.home"])
def test_more_internal_targets_are_refused(raw: str) -> None:
    with pytest.raises(DetectError):
        detect(raw)


def test_nat64_of_a_public_address_is_allowed() -> None:
    assert detect("64:ff9b::808:808").value == "64:ff9b::808:808"


def test_list_names_must_match_fully() -> None:
    assert NAME.fullmatch("ok_list-1")
    assert not NAME.fullmatch("bad\n")


# --- importers / misp -----------------------------------------------------------------------
def test_deeply_nested_json_is_an_import_error_not_a_crash() -> None:
    with pytest.raises(ImportError_):
        parse_any(b"[" * 200_000)


def test_misp_malware_tag_cannot_break_out_of_its_quotes() -> None:
    report = make_report().model_copy(
        update={"graph": Graph(nodes=[GraphNode(id="m:1", label='a"b', kind="malware")], edges=[])}
    )
    names = [t["name"] for a in to_misp(report)["Event"]["Attribute"] for t in a.get("Tag", [])]
    names += [t["name"] for t in to_misp(report)["Event"].get("Tag", [])]
    tag = next(n for n in names if n.startswith("verdikt:malware="))
    assert tag == 'verdikt:malware="a\'b"'


@pytest.fixture
async def api(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    settings = Settings(_env_file=None, feeds_dir=tmp_path / "feeds")  # pyright: ignore[reportCallIssue]
    http = httpx.AsyncClient()
    engine = Engine(
        settings,
        load_rules(),
        Cache(":memory:"),
        http,
        sources=[Fake("virustotal", {"malicious": 0})],
        limiter_factory=CountingLimiter,
    )
    app = create_app(engine, port=PORT, token=TOKEN, web_dist=tmp_path / "none")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://127.0.0.1:{PORT}", headers=AUTH
    ) as c:
        yield c


async def test_feed_import_post_bad_name_and_delete(api: httpx.AsyncClient) -> None:
    misp = {
        "Event": {
            "Attribute": [{"type": "ip-dst", "value": "8.8.4.4", "to_ids": True}],
        }
    }
    body = {"name": "mylist", "content": json.dumps(misp)}
    ok = await api.post("/api/feeds/import", json=body)
    assert ok.json() == {"name": "mylist", "format": "misp", "count": 1}
    bad = await api.post("/api/feeds/import", json={**body, "name": "../x"})
    assert bad.status_code == 422
    gone = await api.delete("/api/feeds/import", params={"name": "mylist"})
    assert gone.status_code == 200
    assert (await api.delete("/api/feeds/import", params={"name": "../x"})).status_code == 422


async def test_scheduler_start_endpoint_rejects_unknown_job(api: httpx.AsyncClient) -> None:
    assert (await api.post("/api/scheduler/nope/start", json={})).status_code == 404


# --- scheduler -------------------------------------------------------------------------------
def make_scheduler(tmp_path: Path, client: httpx.AsyncClient, **kw: object) -> Scheduler:
    cfg = Settings(_env_file=None, feeds_dir=tmp_path / "feeds", **kw)  # pyright: ignore[reportCallIssue]
    engine = Engine(
        cfg,
        load_rules(),
        Cache(":memory:"),
        client,
        sources=[Fake("virustotal", {"malicious": 0}), Fake("abuseipdb", {"score": 0})],
        limiter_factory=CountingLimiter,
    )
    return Scheduler(engine, cfg, now=lambda: NOW)


async def test_a_running_job_is_not_started_twice(
    tmp_path: Path, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = make_scheduler(tmp_path, client)
    started = 0
    release = asyncio.Event()

    async def slow() -> str:
        nonlocal started
        started += 1
        await release.wait()
        return "done"

    monkeypatch.setattr(s, "_watch", slow)
    first = asyncio.create_task(s.run("watch"))
    await asyncio.sleep(0)
    second = await s.run("watch")  # returns the live status instead of starting again
    assert second.running is True
    release.set()
    await first
    assert started == 1


async def test_last_run_survives_a_restart(tmp_path: Path, client: httpx.AsyncClient) -> None:
    s = make_scheduler(tmp_path, client, watch_every_hours=4)
    s._engine.cache.kv_set("job:watch:last_run", (NOW - timedelta(hours=1)).isoformat())  # pyright: ignore[reportPrivateUsage]
    s.start()
    assert s.status()[0].next_run == NOW + timedelta(hours=3)
    await s.stop()


async def test_overdue_job_waits_a_full_interval_after_restart(
    tmp_path: Path, client: httpx.AsyncClient
) -> None:
    s = make_scheduler(tmp_path, client, watch_every_hours=4)
    s._engine.cache.kv_set("job:watch:last_run", (NOW - timedelta(hours=9)).isoformat())  # pyright: ignore[reportPrivateUsage]
    s.start()
    assert s.status()[0].next_run == NOW + timedelta(hours=4)
    await s.stop()


async def test_background_start_reports_progress_and_finishes(
    tmp_path: Path, client: httpx.AsyncClient
) -> None:
    s = make_scheduler(tmp_path, client)
    assert s.run_in_background("feeds").running is True
    assert s.run_in_background("feeds").running is True  # second call joins, no second task
    await s.stop()


# --- watch -----------------------------------------------------------------------------------
async def test_a_failed_lookup_is_not_a_verdict_change(
    settings: Settings, cache: Cache, client: httpx.AsyncClient
) -> None:
    vt = Fake("virustotal", {"malicious": 0})
    ab = Fake("abuseipdb", {"score": 0})
    engine = make_engine(settings, cache, client, [vt, ab], limiter_factory=CountingLimiter)
    first = await engine.check("8.8.8.8")
    cache.watch_add("8.8.8.8", "ip")
    cache.watch_record(first)
    vt._status = Status.RATE_LIMITED  # pyright: ignore[reportPrivateUsage]
    changes, reports = await recheck(engine)
    assert changes == [] and reports == []
    assert cache.watch_events() == []


# --- notifiers -------------------------------------------------------------------------------
async def test_discord_blocks_mentions_and_defangs(client: httpx.AsyncClient) -> None:
    cfg = Settings(_env_file=None, discord_webhook_url="https://discord.test/hook")  # pyright: ignore[reportCallIssue]
    with respx.mock() as r:
        route = r.post("https://discord.test/hook").respond(204)
        out = await notify(make_report(tags=["@everyone"]), "discord", cfg, client)
    assert out.sent
    payload = json.loads(route.calls.last.request.content)  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
    assert payload["allowed_mentions"] == {"parse": []}
    assert "hxxp://evil[.]example" in payload["content"]


async def test_teams_posts_text(client: httpx.AsyncClient) -> None:
    cfg = Settings(_env_file=None, teams_webhook_url="https://teams.test/hook")  # pyright: ignore[reportCallIssue]
    with respx.mock() as r:
        route = r.post("https://teams.test/hook").respond(200)
        out = await notify(make_report(), "teams", cfg, client)
    text = json.loads(route.calls.last.request.content)["text"]  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
    assert out.sent and "MALICIOUS" in text and "\n\n" in text


async def test_email_uses_starttls_and_login(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[object] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            sent.append((host, port))

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def starttls(self, context: object = None) -> None:
            assert context is not None  # a verifying context must be passed
            sent.append("tls")

        def login(self, user: str, password: str) -> None:
            sent.append(("login", user, password))

        def send_message(self, msg: EmailMessage) -> None:
            sent.append(str(msg["Subject"]))

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    cfg = Settings(
        _env_file=None,  # pyright: ignore[reportCallIssue]
        smtp_host="mail.test",
        smtp_user="u",
        smtp_password="p",
        smtp_from="v@test",
        smtp_to="a@test, b@test",
    )
    out = await notify(make_report(), "email", cfg, client)
    assert out.sent
    assert sent[:3] == [("mail.test", 587), "tls", ("login", "u", "p")]
    assert "hxxp://evil[.]example" in str(sent[3])


async def test_email_without_config_says_so(client: httpx.AsyncClient) -> None:
    out = await notify(make_report(), "email", Settings(_env_file=None), client)  # pyright: ignore[reportCallIssue]
    assert not out.sent and "not set" in out.detail


async def test_cooldown_skips_a_repeat_of_the_same_level(client: httpx.AsyncClient) -> None:
    cfg = Settings(
        _env_file=None,  # pyright: ignore[reportCallIssue]
        discord_webhook_url="https://discord.test/hook",
        notify_cooldown_hours=6,
    )
    cache = Cache(":memory:", clock=lambda: NOW)
    with respx.mock() as r:
        route = r.post("https://discord.test/hook").respond(204)
        first = await notify(make_report(), "discord", cfg, client, Level.SUSPICIOUS, cache)
        again = await notify(make_report(), "discord", cfg, client, Level.SUSPICIOUS, cache)
        other = await notify(
            make_report(Level.SUSPICIOUS), "discord", cfg, client, Level.SUSPICIOUS, cache
        )
    assert (first.sent, again.sent, again.quiet, other.sent) == (True, False, True, True)
    assert route.call_count == 2

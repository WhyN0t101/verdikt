from __future__ import annotations

import httpx
import pytest
import respx

from verdikt.config import Settings
from verdikt.models import IOCType, Level, Report, SourceResult, Status
from verdikt.notify import notify
from verdikt.notify.format import defang, slack_message, telegram_message

TG_URL = "https://api.telegram.org/bottok123/sendMessage"
HOOK = "https://hooks.slack.test/T000/B000/XXXX"


def make_report(
    level: Level = Level.MALICIOUS,
    summary: str = "12/94 engines malicious",
    tags: list[str] | None = None,
) -> Report:
    row = SourceResult(
        source="virustotal",
        status=Status.OK,
        level=Level.MALICIOUS,
        summary=summary,
        tags=tags or [],
        link="https://www.virustotal.com/gui/domain/evil.example",  # pyright: ignore[reportArgumentType]
    )
    clean = SourceResult(source="abuseipdb", status=Status.OK, level=Level.SAFE, summary="0%")
    return Report(
        id="r1",
        ioc="http://evil.example/a.exe",
        ioc_type=IOCType.URL,
        level=level,
        agreeing=1,
        total=2,
        results=[row, clean],
    )


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("http://evil.com/a", "hxxp://evil[.]com/a"),
        ("https://evil.com", "hxxps://evil[.]com"),
        ("1.2.3.4", "1[.]2[.]3[.]4"),
        ("evil.com", "evil[.]com"),
        ("a" * 8, "a" * 8),
    ],
)
def test_defang(raw: str, want: str) -> None:
    assert defang(raw) == want


def test_feed_tags_are_defanged_and_single_line() -> None:
    report = make_report(tags=["http://evil.com/x", "a\n🟢 SAFE fake"])
    for msg in (telegram_message(report), slack_message(report)):
        assert "http://evil.com" not in msg
        assert "hxxp://evil[.]com/x" in msg
        assert "\n🟢 SAFE" not in msg


def test_messages_are_defanged_and_list_only_hits() -> None:
    for msg in (telegram_message(make_report()), slack_message(make_report())):
        assert "hxxp://evil[.]example/a[.]exe" in msg
        assert "http://evil.example" not in msg
        assert "virustotal" in msg
        assert "abuseipdb" not in msg  # clean rows are not listed
        assert "MALICIOUS" in msg
        assert "virustotal.com/gui" in msg


def test_telegram_escapes_feed_text() -> None:
    msg = telegram_message(make_report(summary="a<b & c", tags=["<script>x</script>"]))
    assert "a&lt;b &amp; c" in msg
    assert "<script>" not in msg
    assert "&lt;script&gt;" in msg


def test_slack_escapes_fake_link() -> None:
    evil = "<https://evil.test|Open report>"
    msg = slack_message(make_report(summary=evil))
    assert evil not in msg
    assert "&lt;https://evil[.]test|Open report&gt;" in msg


async def test_sends_defanged_to_slack(router: respx.MockRouter, client: httpx.AsyncClient) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(200, text="ok"))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert out.sent
    assert "hxxp://evil[.]example" in route.calls.last.request.content.decode()


async def test_sends_html_to_telegram(router: respx.MockRouter, client: httpx.AsyncClient) -> None:
    route = router.post(TG_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    s = Settings(_env_file=None, telegram_bot_token="tok123", telegram_chat_id="42")  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "telegram", s, client)
    assert out.sent
    body = route.calls.last.request.content.decode()
    assert '"parse_mode":"HTML"' in body.replace(" ", "")


@pytest.mark.parametrize(
    ("report_level", "min_level", "sent"),
    [
        (Level.MALICIOUS, Level.SUSPICIOUS, True),
        (Level.SUSPICIOUS, Level.SUSPICIOUS, True),
        (Level.SAFE, Level.SUSPICIOUS, False),
        (Level.UNKNOWN, Level.SUSPICIOUS, False),
        (Level.SUSPICIOUS, Level.MALICIOUS, False),
        (Level.UNKNOWN, Level.UNKNOWN, True),
    ],
)
async def test_min_level_filter(
    report_level: Level,
    min_level: Level,
    sent: bool,
    router: respx.MockRouter,
    client: httpx.AsyncClient,
) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(200))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(report_level), "slack", s, client, min_level)
    assert out.sent is sent
    assert route.called is sent


async def test_failed_send_is_reported_without_leaking_token(
    router: respx.MockRouter, client: httpx.AsyncClient
) -> None:
    router.post(TG_URL).mock(return_value=httpx.Response(400, json={"ok": False}))
    s = Settings(_env_file=None, telegram_bot_token="tok123", telegram_chat_id="42")  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "telegram", s, client)
    assert not out.sent
    assert "400" in out.detail
    assert "tok123" not in out.detail


async def test_network_error_is_reported(
    router: respx.MockRouter, client: httpx.AsyncClient
) -> None:
    router.post(HOOK).mock(side_effect=httpx.ConnectError("down"))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert not out.sent
    assert "ConnectError" in out.detail


async def test_missing_config_is_reported(client: httpx.AsyncClient) -> None:
    out = await notify(make_report(), "slack", Settings(_env_file=None), client)  # pyright: ignore[reportCallIssue]
    assert not out.sent
    assert "not set" in out.detail

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


# --- Retry-After aware delivery ------------------------------------------------------------


@pytest.fixture
def waits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the pause before a retry instead of sleeping (tests never sleep)."""
    from verdikt import notify as notify_mod

    seen: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        seen.append(seconds)

    monkeypatch.setattr(notify_mod, "_sleep", fake_sleep)
    return seen


async def test_429_with_a_short_retry_after_is_retried_once_and_sent(
    router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    route = router.post(HOOK).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(200)]
    )
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert (out.sent, out.detail) == (True, "sent")
    assert route.call_count == 2
    assert waits == [1.0]


async def test_429_with_a_long_retry_after_is_reported_not_waited_on(
    router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(429, headers={"Retry-After": "120"}))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert out.sent is False
    assert route.call_count == 1
    assert waits == []
    assert "rate limit" in out.detail
    assert "120" in out.detail  # the user learns how long the service asked for


async def test_429_without_retry_after_is_reported_once(
    router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(429))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert (out.sent, route.call_count, waits) == (False, 1, [])
    assert "rate limit" in out.detail


async def test_only_one_retry_even_if_the_second_answer_is_also_429(
    router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(429, headers={"Retry-After": "2"}))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert out.sent is False
    assert route.call_count == 2
    assert waits == [2.0]
    assert "rate limit" in out.detail


async def test_retry_after_at_the_timeout_boundary_is_still_retried(
    router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    from verdikt.notify import TIMEOUT

    router.post(HOOK).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": str(int(TIMEOUT))}),
            httpx.Response(200),
        ]
    )
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    assert (await notify(make_report(), "slack", s, client)).sent is True
    assert waits == [TIMEOUT]


async def test_other_client_errors_are_not_retried(
    router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    route = router.post(HOOK).mock(return_value=httpx.Response(500, headers={"Retry-After": "1"}))
    s = Settings(_env_file=None, slack_webhook_url=HOOK)  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "slack", s, client)
    assert (out.sent, route.call_count, waits) == (False, 1, [])
    assert "HTTP 500" in out.detail


@pytest.mark.parametrize("platform", ["discord", "teams"])
async def test_retry_covers_the_other_webhook_notifiers(
    platform: str, router: respx.MockRouter, client: httpx.AsyncClient, waits: list[float]
) -> None:
    url = f"https://{platform}.hooks.test/abc/SECRET"
    route = router.post(url).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(204)]
    )
    s = Settings(_env_file=None, **{f"{platform}_webhook_url": url})  # pyright: ignore[reportCallIssue, reportArgumentType]
    out = await notify(make_report(), platform, s, client)  # pyright: ignore[reportArgumentType]
    assert out.sent is True
    assert route.call_count == 2


async def test_rate_limit_detail_and_logs_never_contain_the_token(
    router: respx.MockRouter,
    client: httpx.AsyncClient,
    waits: list[float],
    caplog: pytest.LogCaptureFixture,
) -> None:
    router.post(TG_URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "300"}))
    s = Settings(_env_file=None, telegram_bot_token="tok123", telegram_chat_id="42")  # pyright: ignore[reportCallIssue]
    out = await notify(make_report(), "telegram", s, client)
    assert not out.sent
    assert "rate limit" in out.detail
    assert "tok123" not in out.detail
    assert "tok123" not in caplog.text

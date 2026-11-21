"""Slack and Telegram notifications. A failed send is reported, never swallowed."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

import httpx

from verdikt.config import Settings
from verdikt.models import Level, Report
from verdikt.notify.format import SEVERITY, slack_message, telegram_message

log = logging.getLogger(__name__)

Platform = Literal["slack", "telegram"]
TIMEOUT = 10.0


@dataclass(frozen=True)
class NotifyOutcome:
    platform: str
    sent: bool
    detail: str


async def _post(http: httpx.AsyncClient, url: str, payload: dict[str, object]) -> str | None:
    """POST and return an error string (never containing the URL/token) or None."""
    try:
        resp = await http.post(url, timeout=TIMEOUT, json=payload)
    except httpx.HTTPError as exc:
        return f"network error: {type(exc).__name__}"
    if resp.status_code >= 400:
        return f"HTTP {resp.status_code}"
    return None


async def notify(
    report: Report,
    platform: Platform,
    settings: Settings,
    http: httpx.AsyncClient,
    min_level: Level = Level.SUSPICIOUS,
) -> NotifyOutcome:
    if SEVERITY[report.level] < SEVERITY[min_level]:
        return NotifyOutcome(platform, False, f"below min level ({min_level.value})")

    if platform == "slack":
        url = settings.key("slack_webhook_url")
        if not url:
            return NotifyOutcome(platform, False, "VERDIKT_SLACK_WEBHOOK_URL not set")
        error = await _post(http, url, {"text": slack_message(report)})
    else:
        token = settings.key("telegram_bot_token")
        chat = settings.telegram_chat_id
        if not token or not chat:
            return NotifyOutcome(platform, False, "Telegram token/chat id not set")
        error = await _post(
            http,
            f"https://api.telegram.org/bot{token}/sendMessage",
            {
                "chat_id": chat,
                "text": telegram_message(report),
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
        )
    if error:
        log.error("%s notification failed: %s", platform, error)
        return NotifyOutcome(platform, False, f"send failed: {error}")
    return NotifyOutcome(platform, True, "sent")

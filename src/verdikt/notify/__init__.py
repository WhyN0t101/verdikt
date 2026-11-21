"""Slack, Telegram, Discord, Teams and email alerts. A failed send is reported, never swallowed."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Literal

import httpx

from verdikt.cache import Cache
from verdikt.config import Settings
from verdikt.models import Level, Report
from verdikt.notify.format import SEVERITY, plain_message, slack_message, telegram_message

log = logging.getLogger(__name__)

Platform = Literal["slack", "telegram", "discord", "teams", "email"]
TIMEOUT = 10.0


@dataclass(frozen=True)
class NotifyOutcome:
    platform: str
    sent: bool
    detail: str

    @property
    def quiet(self) -> bool:
        """Skipped on purpose (filter or cooldown): not worth telling the user."""
        return self.detail.startswith(("below min", "cooldown"))


async def _post(http: httpx.AsyncClient, url: str, payload: dict[str, object]) -> str | None:
    """POST and return an error string (never containing the URL/token) or None."""
    try:
        resp = await http.post(url, timeout=TIMEOUT, json=payload)
    except httpx.HTTPError as exc:
        return f"network error: {type(exc).__name__}"
    if resp.status_code >= 400:
        return f"HTTP {resp.status_code}"
    return None


def _send_email(settings: Settings, report: Report) -> str | None:
    recipients = [a.strip() for a in (settings.smtp_to or "").split(",") if a.strip()]
    sender = settings.smtp_from or settings.smtp_user
    if not settings.smtp_host or not recipients or not sender:
        return "SMTP host, sender and VERDIKT_SMTP_TO not set"
    body = plain_message(report)
    msg = EmailMessage()
    msg["Subject"] = f"[verdikt] {body.splitlines()[0]}"[:200]
    msg["From"], msg["To"] = sender, ", ".join(recipients)
    msg.set_content(body)
    try:
        # smtplib's default context does not verify the server certificate
        ctx = ssl.create_default_context()
        if settings.smtp_port == 465:
            client = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=TIMEOUT, context=ctx
            )
        else:
            client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=TIMEOUT)
        with client as smtp:
            if settings.smtp_port != 465:
                smtp.starttls(context=ctx)  # login below only runs on the encrypted channel
            if settings.smtp_user and (password := settings.key("smtp_password")):
                smtp.login(settings.smtp_user, password)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        return f"smtp error: {type(exc).__name__}"
    return None


def _cooldown_key(platform: str, report: Report) -> str:
    return f"notified:{platform}:{report.ioc}"


def _in_cooldown(cache: Cache, platform: str, report: Report, hours: float) -> bool:
    stored = cache.kv_get(_cooldown_key(platform, report))
    if hours <= 0 or not stored:
        return False
    level, _, at = stored.partition("|")
    age = cache.now() - datetime.fromisoformat(at)
    return level == report.level.value and age < timedelta(hours=hours)


async def notify(
    report: Report,
    platform: Platform,
    settings: Settings,
    http: httpx.AsyncClient,
    min_level: Level = Level.SUSPICIOUS,
    cache: Cache | None = None,
) -> NotifyOutcome:
    if SEVERITY[report.level] < SEVERITY[min_level]:
        return NotifyOutcome(platform, False, f"below min level ({min_level.value})")
    if cache and _in_cooldown(cache, platform, report, settings.notify_cooldown_hours):
        return NotifyOutcome(platform, False, "cooldown: same level already sent")

    error: str | None
    if platform == "slack":
        url = settings.key("slack_webhook_url")
        if not url:
            return NotifyOutcome(platform, False, "VERDIKT_SLACK_WEBHOOK_URL not set")
        error = await _post(http, url, {"text": slack_message(report)})
    elif platform == "discord":
        url = settings.key("discord_webhook_url")
        if not url:
            return NotifyOutcome(platform, False, "VERDIKT_DISCORD_WEBHOOK_URL not set")
        # feed text is attacker-controlled: never let it ping @everyone or roles
        error = await _post(
            http, url, {"content": plain_message(report)[:1900], "allowed_mentions": {"parse": []}}
        )
    elif platform == "teams":
        url = settings.key("teams_webhook_url")
        if not url:
            return NotifyOutcome(platform, False, "VERDIKT_TEAMS_WEBHOOK_URL not set")
        text = plain_message(report).replace("\n", "\n\n")  # Teams markdown needs blank lines
        error = await _post(http, url, {"text": text})
    elif platform == "email":
        error = await asyncio.to_thread(_send_email, settings, report)
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
    if cache:
        cache.kv_set(
            _cooldown_key(platform, report), f"{report.level.value}|{cache.now().isoformat()}"
        )
    return NotifyOutcome(platform, True, "sent")

"""Defanging, escaping and message text. Feed-derived text is attacker-controlled."""

from __future__ import annotations

import html
from collections.abc import Callable

from verdikt.models import Level, Report, SourceResult, Status

EMOJI = {
    Level.MALICIOUS: "🔴",
    Level.SUSPICIOUS: "🟠",
    Level.SAFE: "🟢",
    Level.UNKNOWN: "⚪",
    Level.INFO: "🔵",
}

# SAFE < UNKNOWN < SUSPICIOUS < MALICIOUS: an unanswered lookup is worse than a clean one.
SEVERITY = {Level.SAFE: 0, Level.INFO: 0, Level.UNKNOWN: 1, Level.SUSPICIOUS: 2, Level.MALICIOUS: 3}


def defang(value: str) -> str:
    """`http://evil.com` -> `hxxp://evil[.]com`."""
    out = value.replace(".", "[.]")
    for scheme, fanged in (("https://", "hxxps://"), ("http://", "hxxp://"), ("ftp://", "fxp://")):
        if out.lower().startswith(scheme):
            return fanged + out[len(scheme) :]
    return out


def _feed_text(text: str) -> str:
    """Feed-derived text: one line (no faked extra rows) and defanged (no live links).

    Every dot is defanged: a heuristic for "link-like" tokens misses IPv6, Unicode hosts and
    odd spellings, and a missed token becomes a live link.
    """
    return defang(" ".join(text.split()))


def _plain_escape(text: str) -> str:
    """Discord and Teams render markdown: parentheses would complete a `[text](url)` link."""
    return text.replace("(", "{").replace(")", "}")


def _hit_line(row: SourceResult, escape: Callable[[str], str]) -> str:
    tags = f" [{escape(_feed_text(', '.join(row.tags[:3])))}]" if row.tags else ""
    return f"• {escape(row.source)}: {escape(_feed_text(row.summary))}{tags}"


def escape_telegram(text: str) -> str:
    return html.escape(text, quote=True)


def escape_slack(text: str) -> str:
    # `*`, `~` and backticks would let feed text restyle the message
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("`", "'").replace("*", "").replace("~", "")


def hit_rows(report: Report) -> list[SourceResult]:
    return [
        r
        for r in report.results
        if r.status is Status.OK and r.level in (Level.MALICIOUS, Level.SUSPICIOUS)
    ]


def _link(report: Report) -> str | None:
    """Prefer the VirusTotal page, then urlscan, for the report's IOC."""
    by_source = {r.source: r for r in report.results if r.link}
    for name in ("virustotal", "urlscan"):
        if name in by_source and by_source[name].link:
            return str(by_source[name].link)
    return None


def _header(report: Report) -> tuple[str, str]:
    return f"{EMOJI[report.level]} {report.level.value.upper()}", defang(report.ioc)


def plain_message(report: Report) -> str:
    """Markup-free text for email, Teams and Discord. Feed text is defanged and single-line."""
    head, ioc = _header(report)
    lines = [f"{head} {ioc} ({report.ioc_type.value})"]
    lines += [_hit_line(r, _plain_escape) for r in hit_rows(report)]
    if link := _link(report):
        lines.append(f"Report: {link}")
    return "\n".join(lines)


def telegram_message(report: Report) -> str:
    head, ioc = _header(report)
    lines = [
        f"<b>{escape_telegram(head)}</b> <code>{escape_telegram(ioc)}</code> "
        f"({escape_telegram(report.ioc_type.value)})"
    ]
    lines += [_hit_line(r, escape_telegram) for r in hit_rows(report)]
    if link := _link(report):
        lines.append(f'<a href="{escape_telegram(link)}">Open report</a>')
    return "\n".join(lines)


def slack_message(report: Report) -> str:
    head, ioc = _header(report)
    lines = [
        f"*{escape_slack(head)}* `{escape_slack(ioc)}` ({escape_slack(report.ioc_type.value)})"
    ]
    lines += [_hit_line(r, escape_slack) for r in hit_rows(report)]
    if link := _link(report):
        # our own link, but strip the characters that would break out of <url|text>
        safe = link.replace("|", "%7C").replace(">", "%3E").replace("<", "%3C")
        lines.append(f"<{safe}|Open report>")
    return "\n".join(lines)

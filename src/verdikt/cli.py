"""Typer CLI. Exit: 0 SAFE, 1 error, 2 usage, 10 SUSPICIOUS, 11 MALICIOUS, 12 UNKNOWN."""

from __future__ import annotations

import asyncio
import os
import secrets
import sys
import threading
import webbrowser
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from verdikt.config import Settings, get_settings
from verdikt.detect import DetectError
from verdikt.engine import Engine, build_engine
from verdikt.models import Level, Report, Status
from verdikt.notify import Platform, notify

app = typer.Typer(add_completion=False, no_args_is_help=True, help="IOC triage.")
cache_app = typer.Typer(help="Cache maintenance.")
app.add_typer(cache_app, name="cache")

out = Console()
err = Console(stderr=True)

EXIT_CODES = {
    Level.SAFE: 0,
    Level.SUSPICIOUS: 10,
    Level.MALICIOUS: 11,
    Level.UNKNOWN: 12,
    Level.INFO: 0,
}
# bulk: highest severity wins
_BULK_ORDER = {0: 0, 12: 1, 10: 2, 11: 3}
LEVEL_STYLE = {
    Level.MALICIOUS: "bold red",
    Level.SUSPICIOUS: "bold yellow",
    Level.SAFE: "bold green",
    Level.UNKNOWN: "bold white",
    Level.INFO: "cyan",
}


def exit_code(level: Level) -> int:
    return EXIT_CODES[level]


def worst(codes: list[int]) -> int:
    return max(codes, key=lambda c: _BULK_ORDER[c]) if codes else 0


def _settings() -> Settings:
    return get_settings()


async def _with_engine[T](
    settings: Settings, fn: Callable[[Engine, httpx.AsyncClient], Awaitable[T]]
) -> T:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        engine = build_engine(settings, http)
        try:
            return await fn(engine, http)
        finally:
            engine.cache.close()


def _render(report: Report) -> None:
    style = LEVEL_STYLE[report.level]
    out.print(
        f"[{style}]{report.level.value.upper()}[/]  [bold]{report.ioc}[/]  "
        f"({report.ioc_type.value})  {report.agreeing}/{report.total} sources · "
        f"{report.duration_ms / 1000:.1f}s",
        markup=True,
        highlight=False,
    )
    for reason in report.reasons:
        out.print(f"  - {reason}", markup=False, highlight=False)
    table = Table(show_header=True, header_style="bold")
    for col in ("source", "level", "status", "summary"):
        table.add_column(col)
    for r in report.results:
        table.add_row(
            r.source,
            r.level.value + (" (cached)" if r.cached else ""),
            r.status.value,
            r.summary,
        )
    out.print(table)
    if report.geo:
        geo = report.geo[0]
        out.print(
            f"geo: {geo.country or '?'} · AS{geo.asn or '?'} {geo.as_org or ''}", markup=False
        )


def _all_failed(report: Report) -> bool:
    return not report.results or all(r.status is Status.ERROR for r in report.results)


def _emit(report: Report, as_json: bool, raw: bool) -> None:
    shown = report if raw else report.without_raw()
    if as_json:
        sys.stdout.write(shown.model_dump_json(indent=2 if raw else None) + "\n")
    else:
        _render(shown)


async def _notify(
    report: Report,
    platforms: list[Platform],
    settings: Settings,
    http: httpx.AsyncClient,
    min_level: Level,
) -> None:
    for platform in platforms:
        outcome = await notify(report, platform, settings, http, min_level)
        if not outcome.sent and not outcome.detail.startswith("below min"):
            err.print(f"notify {platform}: {outcome.detail}", markup=False)
        elif outcome.sent:
            err.print(f"notify {platform}: sent", markup=False)


@app.command()
def check(
    ioc: Annotated[str, typer.Argument(help="IP, domain, URL or hash (defanged input is fine)")],
    json: Annotated[bool, typer.Option("--json", help="Print the Report as JSON")] = False,
    raw: Annotated[bool, typer.Option("--raw", help="Keep vendor `raw` payloads")] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Bypass cached results")] = False,
    notify_to: Annotated[
        Platform | None, typer.Option("--notify", help="slack or telegram")
    ] = None,
    min_level: Annotated[
        Level, typer.Option("--min-level", help="Notify threshold")
    ] = Level.SUSPICIOUS,
) -> None:
    """Check one IOC."""
    settings = _settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> Report:
        report = await engine.check(ioc, no_cache=no_cache)
        if notify_to:
            await _notify(report, [notify_to], settings, http, min_level)
        return report

    try:
        report: Report = asyncio.run(_with_engine(settings, run))
    except DetectError as exc:
        err.print(f"error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    _emit(report, json, raw)
    if _all_failed(report):
        err.print("error: no source answered (check keys in .env and your network)", markup=False)
        raise typer.Exit(1)
    raise typer.Exit(exit_code(report.level))


def _read_iocs(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


@app.command()
def bulk(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    json: Annotated[bool, typer.Option("--json", help="One JSON report per line")] = False,
    notify_to: Annotated[Platform | None, typer.Option("--notify")] = None,
    min_level: Annotated[Level, typer.Option("--min-level")] = Level.SUSPICIOUS,
) -> None:
    """Check one IOC per line. Sequential, so the limiters and daily budgets are respected."""
    settings = _settings()
    iocs = _read_iocs(file)

    async def run(engine: Engine, http: httpx.AsyncClient) -> tuple[list[int], int]:
        codes: list[int] = []
        failures = 0
        for line in iocs:
            try:
                report = await engine.check(line)
            except DetectError as exc:
                failures += 1
                err.print(f"skip {line!r}: {exc}", markup=False)
                continue
            _emit(report, json, raw=False)
            if _all_failed(report):
                failures += 1
            codes.append(exit_code(report.level))
            if notify_to:
                await _notify(report, [notify_to], settings, http, min_level)
        return codes, failures

    codes, failures = asyncio.run(_with_engine(settings, run))
    result = worst(codes)
    if failures and result == 0:
        raise typer.Exit(1)
    raise typer.Exit(result)


@app.command()
def sources() -> None:
    """List sources, whether they are enabled, and today's quota use."""
    settings = _settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> None:
        table = Table(show_header=True, header_style="bold")
        for col in ("source", "enabled", "supports", "used today"):
            table.add_column(col)
        for s in engine.source_status():
            quota = f"{s.used_today}/{s.daily_budget}" if s.daily_budget else str(s.used_today)
            enabled = "yes" if s.enabled else "no (key missing)"
            table.add_row(s.name, enabled, ",".join(s.supports), quota)
        out.print(table)

    asyncio.run(_with_engine(settings, run))


@cache_app.command("clear")
def cache_clear(
    source: Annotated[str | None, typer.Option("--source", help="Only this source")] = None,
) -> None:
    """Delete cached source results (history is kept)."""
    settings = _settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> None:
        n = engine.cache.clear(source)
        out.print(f"cleared {n} cached result(s)", markup=False)

    asyncio.run(_with_engine(settings, run))


@app.command()
def ui(
    port: Annotated[int, typer.Option(help="Port on 127.0.0.1")] = 8765,
    no_open: Annotated[bool, typer.Option("--no-open", help="Do not open a browser")] = False,
    dev: Annotated[bool, typer.Option("--dev", help="Reload on change; fixed dev token")] = False,
) -> None:
    """Start the local web UI (binds 127.0.0.1 only)."""
    import uvicorn

    # a preset token lets Shuffle/Cortex call the API; otherwise one per run
    preset = os.environ.get("VERDIKT_SESSION_TOKEN")
    token = "dev-token" if dev else preset or secrets.token_urlsafe(32)
    os.environ["VERDIKT_PORT"] = str(port)
    os.environ["VERDIKT_SESSION_TOKEN"] = token
    url = f"http://127.0.0.1:{port}/"
    if dev:
        err.print(
            "dev mode: run `npm run dev` in web/ (its proxy sends the dev token)", markup=False
        )
    elif not no_open:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    err.print(f"verdikt ui on {url}", markup=False)
    uvicorn.run(
        "verdikt.api.app:create_app",
        factory=True,
        host="127.0.0.1",
        port=port,
        reload=dev,
        log_level="warning",
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()

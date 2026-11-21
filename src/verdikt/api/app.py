"""FastAPI app: /api/* plus the built SPA. Loopback only; see PLAN.md section 14."""

from __future__ import annotations

import html
import mimetypes
import os
import secrets
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from verdikt.cache import ReportSummary
from verdikt.config import get_settings
from verdikt.detect import DetectError
from verdikt.engine import Engine, SourceInfo, build_engine
from verdikt.models import Model, Report

TOKEN_HEADER = "x-verdikt-token"  # noqa: S105
TOKEN_PLACEHOLDER = "<!--VERDIKT_TOKEN-->"  # noqa: S105
WEB_DIST = Path(__file__).resolve().parent.parent / "web_dist"
# StaticFiles trusts the OS mime table; on Windows the registry can map .js/.css to the wrong
# type, which `nosniff` then turns into a blank page. Pin the types the SPA needs.
MIME_TYPES = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml",
    ".json": "application/json",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class CheckRequest(BaseModel):
    ioc: str
    no_cache: bool = False


class Health(Model):
    status: str


def _get_engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


EngineDep = Annotated[Engine, Depends(_get_engine)]


def create_app(
    engine: Engine | None = None,
    *,
    port: int | None = None,
    token: str | None = None,
    web_dist: Path | None = None,
) -> FastAPI:
    """Build the app. Without arguments, reads port/token from the env `verdikt ui` sets."""
    for ext, mime in MIME_TYPES.items():
        mimetypes.add_type(mime, ext)
    port = port if port is not None else int(os.environ.get("VERDIKT_PORT", "8765"))
    token = token or os.environ.get("VERDIKT_SESSION_TOKEN") or secrets.token_urlsafe(32)
    dist = web_dist if web_dist is not None else WEB_DIST
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        if engine is not None:
            app.state.engine = engine
            yield
            return
        async with httpx.AsyncClient(follow_redirects=False) as http:
            built = build_engine(get_settings(), http)
            app.state.engine = built
            try:
                yield
            finally:
                built.cache.close()

    app = FastAPI(title="verdikt", lifespan=lifespan, docs_url=None, redoc_url=None)
    if engine is not None:
        app.state.engine = engine

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # DNS rebinding: a rebound hostname arrives with the attacker's Host header.
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"detail": "bad host"}, status_code=421)
        path = request.url.path
        if path.startswith("/api") or path == "/openapi.json":
            supplied = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(supplied.encode(), token.encode()):
                return JSONResponse({"detail": "missing or invalid session token"}, status_code=401)
            # JSON-only POST: a cross-site form cannot set this without a CORS preflight.
            if (
                request.method == "POST"
                and request.headers.get("content-type", "").split(";")[0].strip().lower()
                != "application/json"
            ):
                return JSONResponse(
                    {"detail": "content-type must be application/json"}, status_code=415
                )
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/check", response_model=Report)
    async def check(body: CheckRequest, engine: EngineDep) -> Report:
        try:
            report = await engine.check(body.ioc, no_cache=body.no_cache)
        except DetectError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return report.without_raw()

    @app.get("/api/reports", response_model=list[ReportSummary])
    async def reports(
        engine: EngineDep,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[ReportSummary]:
        return engine.cache.list_reports(limit, offset)

    @app.get("/api/reports/{report_id}", response_model=Report)
    async def report(report_id: str, engine: EngineDep, raw: bool = False) -> Report:
        found = engine.cache.get_report(report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        return found if raw else found.without_raw()

    @app.get("/api/sources", response_model=list[SourceInfo])
    async def sources(engine: EngineDep) -> list[SourceInfo]:
        return engine.source_status()

    @app.get("/api/health", response_model=Health)
    async def health() -> Health:
        return Health(status="ok")

    index = dist / "index.html"
    if index.is_file():
        page = index.read_text(encoding="utf-8")
        injected = f'<meta name="verdikt-token" content="{html.escape(token, quote=True)}">'
        page = page.replace(TOKEN_PLACEHOLDER, injected)

        @app.get("/", include_in_schema=False)
        async def spa_root() -> HTMLResponse:
            return HTMLResponse(page, headers={"Cache-Control": "no-store"})

        assets = dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")
    else:

        @app.get("/", include_in_schema=False)
        async def no_ui() -> HTMLResponse:
            return HTMLResponse(
                "<!doctype html><title>verdikt</title><p>UI not built. "
                "Run <code>cd web &amp;&amp; npm run build</code>.</p>"
            )

    return app

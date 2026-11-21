from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from tests.conftest import CountingLimiter, Fake
from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import SCHEMA_VERSION
from verdikt.sources.base import Source

TOKEN = "t0ken"
PORT = 8765
AUTH = {"x-verdikt-token": TOKEN}


@pytest.fixture
async def api(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<head><!--VERDIKT_TOKEN--></head>", encoding="utf-8")
    settings = Settings(_env_file=None, vt_api_key="SUPERSECRETKEY")  # pyright: ignore[reportCallIssue]
    http = httpx.AsyncClient()
    sources: list[Source] = [Fake("virustotal", {"malicious": 20, "suspicious": 0})]
    engine = Engine(
        settings,
        load_rules(),
        Cache(":memory:"),
        http,
        sources=sources,
        limiter_factory=CountingLimiter,
    )
    app = create_app(engine, port=PORT, token=TOKEN, web_dist=dist)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=f"http://127.0.0.1:{PORT}") as c:
        yield c


async def test_requires_token(api: httpx.AsyncClient) -> None:
    assert (await api.get("/api/health")).status_code == 401
    assert (await api.get("/api/health", headers={"x-verdikt-token": "wrong"})).status_code == 401
    assert (await api.get("/api/health", headers=AUTH)).json() == {"status": "ok"}


async def test_openapi_requires_token(api: httpx.AsyncClient) -> None:
    assert (await api.get("/openapi.json")).status_code == 401
    assert (await api.get("/openapi.json", headers=AUTH)).status_code == 200


@pytest.mark.parametrize(
    "host", ["evil.example", "127.0.0.1:9999", "localhost", "127.0.0.1.evil.test:8765"]
)
async def test_rejects_foreign_host_even_with_token(api: httpx.AsyncClient, host: str) -> None:
    r = await api.get("/api/health", headers={**AUTH, "host": host})
    assert r.status_code == 421


async def test_allows_localhost_host(api: httpx.AsyncClient) -> None:
    r = await api.get("/api/health", headers={**AUTH, "host": f"localhost:{PORT}"})
    assert r.status_code == 200


async def test_post_must_be_json(api: httpx.AsyncClient) -> None:
    r = await api.post(
        "/api/check", headers={**AUTH, "content-type": "text/plain"}, content='{"ioc":"8.8.8.8"}'
    )
    assert r.status_code == 415
    r = await api.post("/api/check", headers=AUTH, data={"ioc": "8.8.8.8"})  # form-encoded
    assert r.status_code == 415


async def test_check_happy_path(api: httpx.AsyncClient) -> None:
    r = await api.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8"})
    assert r.status_code == 200
    body = r.json()
    assert body["level"] == "malicious"
    assert body["schema_version"] == SCHEMA_VERSION
    assert body["results"][0]["raw"] is None


async def test_check_without_token_is_401(api: httpx.AsyncClient) -> None:
    assert (await api.post("/api/check", json={"ioc": "8.8.8.8"})).status_code == 401


async def test_check_internal_target_is_422(api: httpx.AsyncClient) -> None:
    r = await api.post("/api/check", headers=AUTH, json={"ioc": "192.168.1.10"})
    assert r.status_code == 422
    assert "internal" in r.json()["detail"]


async def test_history_and_raw(api: httpx.AsyncClient) -> None:
    rid = (await api.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8"})).json()["id"]
    listing = (await api.get("/api/reports", headers=AUTH)).json()
    assert [(x["id"], x["ioc"], x["level"]) for x in listing] == [(rid, "8.8.8.8", "malicious")]
    assert (await api.get(f"/api/reports/{rid}", headers=AUTH)).json()["results"][0]["raw"] is None
    assert (await api.get(f"/api/reports/{rid}?raw=true", headers=AUTH)).json()["results"][0][
        "raw"
    ] == {"fake": True}
    assert (await api.get("/api/reports/nope", headers=AUTH)).status_code == 404


async def test_sources_never_expose_keys(api: httpx.AsyncClient) -> None:
    r = await api.get("/api/sources", headers=AUTH)
    assert r.status_code == 200
    assert "SUPERSECRETKEY" not in r.text
    assert r.json()[0]["name"] == "virustotal"


async def test_no_cors_headers(api: httpx.AsyncClient) -> None:
    r = await api.options(
        "/api/check",
        headers={**AUTH, "origin": "https://evil.test", "access-control-request-method": "POST"},
    )
    assert not any(h.lower().startswith("access-control-") for h in r.headers)
    r = await api.get("/api/health", headers={**AUTH, "origin": "https://evil.test"})
    assert "access-control-allow-origin" not in r.headers


async def test_spa_gets_token_injected_and_csp(api: httpx.AsyncClient) -> None:
    r = await api.get("/")
    assert r.status_code == 200
    assert f'<meta name="verdikt-token" content="{TOKEN}">' in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


async def test_spa_rejects_foreign_host(api: httpx.AsyncClient) -> None:
    assert (await api.get("/", headers={"host": "evil.example"})).status_code == 421


async def test_missing_build_shows_hint(tmp_path: Path) -> None:
    settings = Settings(_env_file=None)  # pyright: ignore[reportCallIssue]
    engine = Engine(settings, load_rules(), Cache(":memory:"), httpx.AsyncClient(), sources=[])
    app = create_app(engine, port=PORT, token=TOKEN, web_dist=tmp_path / "missing")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=f"http://127.0.0.1:{PORT}") as c:
        assert "not built" in (await c.get("/")).text


async def test_assets_get_correct_mime_even_if_os_table_is_wrong(tmp_path: Path) -> None:
    import mimetypes

    mimetypes.add_type("application/json", ".js")  # what a bad Windows registry does
    mimetypes.add_type("application/json", ".css")
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<head><!--VERDIKT_TOKEN--></head>", encoding="utf-8")
    (dist / "assets" / "a.js").write_text("export {}", encoding="utf-8")
    (dist / "assets" / "a.css").write_text("body{}", encoding="utf-8")
    settings = Settings(_env_file=None)  # pyright: ignore[reportCallIssue]
    engine = Engine(settings, load_rules(), Cache(":memory:"), httpx.AsyncClient(), sources=[])
    app = create_app(engine, port=PORT, token=TOKEN, web_dist=dist)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=f"http://127.0.0.1:{PORT}") as c:
        js = await c.get("/assets/a.js")
        css = await c.get("/assets/a.css")
    assert js.headers["content-type"].startswith("text/javascript")
    assert css.headers["content-type"].startswith("text/css")

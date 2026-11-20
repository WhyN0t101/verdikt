# verdikt

IOC triage. Give it an IP, domain, URL or hash; it queries threat-intel sources in parallel, returns one verdict (malicious, suspicious, safe, unknown), can notify Slack or Telegram, and shows the result in a local browser UI with a map and a relationship graph.

The core is a Python library that returns one `Report` model. The CLI, API, UI and SOAR glue only consume it. See `PLAN.md` (spec) and `docs/DESIGN.md` (UI).

## Setup

```bash
uv sync
cp .env.example .env        # add keys; a source with no key is disabled
cd web && npm ci && npm run build   # builds the UI into src/verdikt/web_dist/
```

Keyless sources (InternetDB, urlscan search, OTX, GreyNoise community) work without any key. VirusTotal, AbuseIPDB, abuse.ch (ThreatFox, URLhaus, MalwareBazaar) and Hybrid Analysis need keys. GeoLite2 City and ASN `.mmdb` files (free MaxMind account) go in the folder named by `VERDIKT_GEOIP_DIR`; without them the map is empty.

## Run

```bash
uv run verdikt check 8.8.8.8 [--json] [--raw] [--no-cache] [--notify slack|telegram] [--min-level suspicious]
uv run verdikt bulk iocs.txt          # one IOC per line, sequential, respects limits and daily budgets
uv run verdikt sources                # enabled state and quota used today
uv run verdikt cache clear [--source NAME]
uv run verdikt ui                     # http://127.0.0.1:8765, opens a browser
```

Exit codes: 0 SAFE, 1 error, 2 usage, 10 SUSPICIOUS, 11 MALICIOUS, 12 UNKNOWN. `bulk` exits with the highest severity (MALICIOUS > SUSPICIOUS > UNKNOWN > SAFE).

UI keys: `Ctrl/⌘+K` focus search, `Enter` run, `1/2/3` switch tab, `Esc` clear.

## Develop

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run verdikt ui --dev               # API with reload, fixed dev token
cd web && npm run dev                 # Vite proxies /api to it
cd web && npm run lint && npm run typecheck && npm test && npm run build
cd web && npm run gen:types           # regenerate src/types.ts after API model changes
cd web && npm run e2e                 # Playwright smoke test (needs `npx playwright install chromium` once)
```

No test makes a live network call: sources are tested against fixtures with `respx`.

## Layout

`src/verdikt/` core (`detect`, `engine`, `verdict`, `cache`, `sources/`, `enrich/`, `notify/`, `api/`, `cli`), `web/` React SPA, `integrations/` Cortex analyzer and Shuffle app, `tests/`.

## Security

The API binds to `127.0.0.1`, checks the `Host` header, requires a per-run session token and JSON-only POST, and sends no CORS headers. Keys live only in `.env`. Internal targets (private IPs, `localhost`, single-label and `.local`/`.internal`/`.lan`/`.corp`/`.home.arpa` names, `VERDIKT_INTERNAL_DOMAINS`) are never sent to a third party. Feed data is rendered as text and defanged in notifications.

## Licensing notes

- The VirusTotal public API and Shodan InternetDB forbid commercial products. Check before using verdikt at work.
- IPinfo Lite (not used by default) requires attribution.
- MaxMind GeoLite2 databases are licensed by MaxMind; never commit them.
- Land outline: Natural Earth (public domain) via `world-atlas`.

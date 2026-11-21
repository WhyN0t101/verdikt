# verdikt

verdikt triages indicators of compromise (IOCs). Give it an IP address, domain, URL or file hash. It queries several threat-intelligence sources in parallel, applies a small set of rules, and returns one verdict: malicious, suspicious, safe or unknown. It can post the result to Slack or Telegram, and it ships a local browser UI with a map and a relationship graph.

The core is a Python library that returns a single `Report` model. The CLI, the HTTP API, the UI and the SOAR integrations only consume that model; nothing outside `src/verdikt/sources/` talks to a threat-intelligence API.

| Document | Contents |
|---|---|
| `PLAN.md` | The specification: architecture, data model, verdict rules, milestones |
| `CLAUDE.md` | Working rules for contributors and coding agents |
| `docs/SOURCES.md` | Every source: what it covers, the key it needs, how its answer maps to a verdict |
| `docs/API.md` | HTTP API reference and the security model |
| `docs/INTEGRATIONS.md` | Cortex analyzer, Shuffle app, scripting with exit codes |
| `docs/DESIGN.md` | UI visual direction |

## Contents

- [Quick start](#quick-start)
- [Running without API keys](#running-without-api-keys)
- [Configuration](#configuration)
- [Command line](#command-line)
- [Web UI](#web-ui)
- [How the verdict is decided](#how-the-verdict-is-decided)
- [Input handling and privacy](#input-handling-and-privacy)
- [Notifications](#notifications)
- [Audit log and SIEM](#audit-log-and-siem)
- [STIX export](#stix-export)
- [Caching, rate limits and daily budgets](#caching-rate-limits-and-daily-budgets)
- [Development](#development)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Licensing notes](#licensing-notes)

## Quick start

Requirements: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/), and Node.js 22 or newer for the UI. If `uv` is not on your PATH, run it as `python -m uv`.

```bash
uv sync
cp .env.example .env                 # add the keys you have; see Configuration
cd web && npm ci && npm run build    # builds the UI into src/verdikt/web_dist/
cd ..
uv run verdikt check 8.8.8.8
uv run verdikt ui                    # http://127.0.0.1:8765
```

## Running without API keys

A source whose key is missing is disabled; verdikt never fails because of it. These sources work with no key at all: Shodan InternetDB (IP only), urlscan.io search, AlienVault OTX and GreyNoise Community (IP only).

Without keys you can still look up IPs and domains, but the verdict will usually be `unknown` (exit code 12). InternetDB and GreyNoise only add context, and the sources that decide most verdicts (VirusTotal, abuse.ch, AbuseIPDB) need keys. A `malicious` verdict needs at least one of those. Run `uv run verdikt sources` to see what is enabled.

## Configuration

Secrets and paths come from `.env` in the working directory (copy `.env.example`). Thresholds and weights live in `rules.yaml`, not in `.env`. All variables are prefixed `VERDIKT_`.

| Variable | Purpose |
|---|---|
| `VERDIKT_VT_API_KEY` | VirusTotal (IP, domain, URL, hash) |
| `VERDIKT_ABUSEIPDB_API_KEY` | AbuseIPDB (IP) |
| `VERDIKT_ABUSECH_AUTH_KEY` | One abuse.ch key for ThreatFox, URLhaus and MalwareBazaar |
| `VERDIKT_HYBRID_API_KEY` | Hybrid Analysis (hash) |
| `VERDIKT_URLSCAN_API_KEY` | urlscan.io, optional (higher limits) |
| `VERDIKT_OTX_API_KEY` | AlienVault OTX, optional |
| `VERDIKT_GREYNOISE_API_KEY` | GreyNoise Community, optional |
| `VERDIKT_SLACK_WEBHOOK_URL` | Slack incoming webhook for `--notify slack` |
| `VERDIKT_TELEGRAM_BOT_TOKEN`, `VERDIKT_TELEGRAM_CHAT_ID` | Telegram Bot API for `--notify telegram` |
| `VERDIKT_INTERNAL_DOMAINS` | Comma-separated suffixes of your own domains, never sent to third parties (for example `corp.example.com`) |
| `VERDIKT_GEOIP_DIR` | Folder holding `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`; without them the map is empty |
| `VERDIKT_DB_PATH` | SQLite file for the cache, history and budgets. Default: the user data directory (`%LOCALAPPDATA%\verdikt` on Windows, `~/.local/share/verdikt` elsewhere), never the repository |
| `VERDIKT_RULES_PATH` | Path to a `rules.yaml` that replaces the packaged default |
| `VERDIKT_DNS_RESOLVE` | `true` enables DNS resolution of domains (default `false`, see [privacy](#input-handling-and-privacy)) |
| `VERDIKT_REPORT_RETENTION_DAYS` | Stored reports older than this many days are deleted at startup (default `90`; `0` keeps them forever). Expired cache rows and old budget rows are always deleted. Analyst feedback is kept |
| `VERDIKT_AUDIT_LOG` | Path of the JSON-lines audit log. Default: `audit.jsonl` in the user data directory |
| `VERDIKT_SESSION_TOKEN` | Fixed API token for `verdikt ui`, for automation that calls a long-running instance. Unset: a random token per run |

`.env` is git-ignored. Keys are never logged, never returned by the API and never placed in URLs, with one unavoidable exception: Telegram requires the bot token in the request path.

GeoLite2 needs a free MaxMind account and periodic updates (`geoipupdate`). The databases live outside the repository and must never be committed.

## Command line

```bash
uv run verdikt check <ioc> [--json] [--stix] [--raw] [--no-cache] [--notify slack|telegram] [--min-level suspicious]
uv run verdikt bulk <file> [--json] [--notify slack|telegram] [--min-level suspicious]
uv run verdikt sources
uv run verdikt cache clear [--source NAME]
uv run verdikt ui [--port 8765] [--no-open] [--dev]
```

| Command | What it does |
|---|---|
| `check` | Checks one IOC and prints a verdict, the reasons, and a table of sources. `--json` prints the `Report` as JSON. `--raw` keeps each vendor's raw response (otherwise stripped). `--no-cache` skips cached answers but still stores the new ones. |
| `bulk` | Reads one IOC per line (blank lines and lines starting with `#` are ignored) and checks them one after another, so the rate limiters and daily budgets are respected. `--json` prints one report per line. |
| `sources` | Lists each source, whether it is enabled, what it supports and the requests used today against its daily budget. |
| `cache clear` | Deletes cached source answers (all, or one source). Report history is kept. |
| `ui` | Starts the local web UI on `127.0.0.1` only and opens a browser unless `--no-open`. `--dev` reloads on change and uses the fixed token `dev-token`. |

Input may be defanged (`hxxp://evil[.]com`, `1[.]2[.]3[.]4`); it is refanged first. A leading `--` is handled safely, so an IOC that looks like an option cannot be misread.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | SAFE |
| 1 | Any error: bad or internal-target input, no source answered, crash |
| 2 | Usage error (from Click) |
| 10 | SUSPICIOUS |
| 11 | MALICIOUS |
| 12 | UNKNOWN |

`bulk` exits with the highest severity across all IOCs (MALICIOUS, then SUSPICIOUS, then UNKNOWN, then SAFE). If some lines failed and no line produced a worse verdict, it exits 1 instead of 0.

## Web UI

`uv run verdikt ui` serves the built single-page app and the API from one process. Open the printed address; the page receives a per-run session token, so the API cannot be called from other pages or tools without it.

- **Command bar:** paste an indicator and press Enter. `Ctrl+K` (or `Cmd+K`) focuses it, `Esc` clears it.
- **Verdict card:** level (always shown with an icon and text, never colour alone), the indicator, its type, confidence as `agreeing/total` sources, ASN, country, lookup time, and the reasons behind the verdict. The copy button copies the defanged indicator.
- **Sources table:** one row per source with its level, a one-line result, tags and a link to the source's own page. Rows show a placeholder while a check is running.
- **Source log:** one line per source answer with its timestamp, coloured by level.
- **History:** previous checks grouped by level. Click one to reopen it.
- **Seen before:** earlier reports that share this indicator or its related infrastructure (IPs, domains, URLs, hashes, malware families; ASNs are ignored because they are too common). Click one to reopen it.
- **Feedback and export:** "False positive" and "False negative" record your judgement of a verdict (stored locally, kept after reports expire, included in the audit log); "Export STIX" downloads the report as a STIX 2.1 bundle.
- **Map tab (key `1`):** a dot-matrix world map drawn from a bundled data file, so it makes no map requests. The indicator and related IPs are markers; arcs join the indicator to related infrastructure. Locations are approximate. Click a related marker to check that IP. It needs the GeoLite2 databases.
- **Graph tab (key `2`):** indicators and related infrastructure (IPs, domains, URLs, hashes, malware families, ASNs) with labelled edges. Select a node and choose "Check this IOC" to pivot; each pivot spends source quota and the panel shows what is left.
- **Raw JSON tab (key `3`):** the full stored report including vendor raw responses, as text.
- **Theme:** dark by default, light follows the system setting or the toggle in the top bar.

Feed data is attacker-controlled and is always rendered as text, never as HTML.

## How the verdict is decided

Each source reports plain facts (counts, scores, booleans) as `metrics`. It never sets a level and holds no thresholds. `verdict.decide()` is a pure function that turns the metrics into a level for each row and a final verdict, using `rules.yaml`:

1. Each successful row becomes MALICIOUS, SUSPICIOUS or SAFE from the rules. Context-only sources (InternetDB, GreyNoise) become INFO.
2. Any MALICIOUS row makes the verdict MALICIOUS.
3. Any SUSPICIOUS row makes it SUSPICIOUS, unless a benign override matches (GreyNoise `riot`), which gives SAFE. An override never touches MALICIOUS.
4. Otherwise the verdict is SAFE only if at least `min_sources_for_safe` (default 2) verdict-bearing sources answered successfully, at least `min_high_weight_for_safe` (default 1) of them are strong sources (high-weight sources that are not list-only feeds: today VirusTotal), and no high-weight source returned an error, was rate limited or had no record. Weak sources and list-only feeds alone never give SAFE. A "not listed" answer from ThreatFox, URLhaus or MalwareBazaar is absence of evidence, so it carries no weight in `confidence` either way. OTX and urlscan are context only and never change the verdict.
5. Otherwise it is UNKNOWN.

Every report also carries a `confidence` of low, medium or high. It is the summed `weights` (in `rules.yaml`) of the sources that agree with the verdict, compared with `confidence_high` and `confidence_medium`; conflicting evidence at least as heavy as the agreeing evidence, or an `unknown` verdict, gives low. Confidence never changes the verdict.

Errors and rate limits never count as clean. A source that has no record of the indicator (`not found`) is neither clean nor an error: it does not count towards `min_sources_for_safe` and does not block SAFE.

The default `rules.yaml` is packaged with the library. To change thresholds, copy it, edit it, and point `VERDIKT_RULES_PATH` at your copy. Rules are plain YAML validated against a schema: an integer means "metric is at least this", a boolean means "metric is exactly this", and several keys inside one source are OR'ed. There is no expression language.

Details per source are in `docs/SOURCES.md`.

## Input handling and privacy

verdikt takes care not to leak what you investigate.

- **Internal targets are never sent anywhere.** Private, loopback and link-local IPs, URLs whose host is internal, `localhost`, single-label names, anything ending in `.local`, `.internal`, `.lan`, `.corp` or `.home.arpa`, and any suffix in `VERDIKT_INTERNAL_DOMAINS` are rejected before any request is made. Shorthand IPs such as `127.1` and `0x7f.0.0.1` are rejected too. Input is capped at 2048 characters.
- **DNS resolution is off by default.** Resolving a domain can contact the attacker's name server. Enable it with `VERDIKT_DNS_RESOLVE=true` only if you accept that.
- **urlscan is search only.** verdikt never submits a scan, so it never makes urlscan visit a target and never publishes anything.
- **The map makes no requests.** Tile servers would see what you investigate; the dot-matrix map is drawn from a bundled file.
- **Geolocation is local.** GeoLite2 lookups run on your machine with no quota and no leak.
- **The API is local only.** It binds to `127.0.0.1`, checks the `Host` header, requires a per-run session token, accepts only JSON on POST and sends no CORS headers.

## Notifications

`--notify slack` or `--notify telegram` posts the result when its level is at or above `--min-level` (default `suspicious`). The order is SAFE, UNKNOWN, SUSPICIOUS, MALICIOUS. The message has a level icon, the defanged indicator and type, one line per source that hit, and a link to the VirusTotal or urlscan page. Feed-derived text is escaped before sending (HTML escaping for Telegram, `&`, `<`, `>` for Slack). A failed send is reported in the CLI output, never silently dropped, and never includes the webhook URL or token.

## Audit log and SIEM

Every check and every piece of feedback appends one JSON line to `audit.jsonl` in the user data directory (override with `VERDIKT_AUDIT_LOG`). Point a SIEM agent (Filebeat, Splunk forwarder, Wazuh and similar) at the file. A check event has `ts`, `event`, `report_id`, the defanged `ioc`, `ioc_type`, `level`, `confidence`, `agreeing`, `total`, `duration_ms`, `seen_before` (count) and one entry per source with `status`, `level` and `cached`. The log holds no keys, no vendor raw data and no feed-derived text. A failed write is logged as a warning and never fails a check. There is no rotation; rotate the file externally.

## STIX export

`verdikt check <ioc> --stix` prints a STIX 2.1 bundle, and the UI and `GET /api/reports/{id}/stix` return the same for a stored report. The bundle holds an identity (`verdikt`), one indicator (pattern for the indicator type, `indicator_types` from the verdict level, `confidence` 85, 50 or 15 from the low/medium/high confidence) and a malware object with an `indicates` relationship for each malware family found. Object ids are stable per report. It is plain JSON built without a STIX library, so it is not validated against the full STIX schema.

## Caching, rate limits and daily budgets

- At startup verdikt deletes what can no longer be used: cached answers older than 7 days (the longest source TTL), daily-budget rows older than 7 days, and stored reports older than `VERDIKT_REPORT_RETENTION_DAYS` (default 90, `0` keeps them). Analyst feedback is kept.
- Answers are cached in SQLite per source and indicator with a time to live per source (6 hours to 7 days). Errors and rate-limited answers are never cached. The raw vendor response is always stored, so `--raw` works on a cache hit.
- Each source has its own rate limiter (VirusTotal: 4 requests per minute). Sources with a published daily quota have a daily budget (VirusTotal 500, AbuseIPDB 1000, Hybrid Analysis 200, urlscan 1000) counted per UTC day.
- Every attempt, including each retry, takes a limiter slot and is charged to the daily budget. Rate-limited and server-error answers are retried up to 3 times. A `Retry-After` longer than the 10 second timeout is not waited on: the source reports `rate limited` immediately.
- Limiter state is per process. Running `verdikt ui` and `verdikt bulk` at the same time doubles the rate; the daily budget, which is in SQLite, is shared.

## Development

```bash
uv run pytest                              # backend tests
uv run pytest tests/test_verdict.py -q     # one file
uv run ruff check . && uv run ruff format --check .
uv run pyright                             # strict
uv run verdikt ui --dev                    # API with reload and the fixed dev token
cd web && npm run dev                      # Vite dev server, proxies /api to the API above
cd web && npm run lint && npm run typecheck && npm test && npm run build
cd web && npm run gen:types                # regenerate src/types.ts after API model changes
cd web && npm run gen:land                 # regenerate the land dot grid (rarely needed)
cd web && npm run e2e                      # Playwright end to end test (see below)
```

- A change is done when `ruff check`, `ruff format --check`, `pyright` and `pytest` pass, and for frontend changes also `npm run lint`, `typecheck`, `test` and `build`.
- No test makes a live network call. Sources are tested with `respx` against fixtures in `tests/fixtures/<source>/`. The fixtures are trimmed to the fields each client reads and contain no keys or account data.
- **End to end:** `cd web && npm run build && npm run e2e` starts `scripts/e2e_server.py` (the real API and built UI over fake sources, an in-memory database, no keys, no network) and drives it in a browser: search, verdict, history, "seen before", keyboard shortcuts, graph, feedback, STIX download, theme, the token and Host checks, the CSP, and no console errors. Use an installed browser with `PW_CHANNEL=msedge` (or `chrome`), or run `npx playwright install chromium` once. CI installs Chromium itself.
- `npm run gen:types` dumps the OpenAPI schema offline (the runtime `/openapi.json` needs the session token) and generates `web/src/types.ts`. Never edit that file by hand. Bump `schema_version` in `src/verdikt/models.py` on any breaking change to `Report`.
- To add a source: one file in `src/verdikt/sources/` subclassing `BaseSource`, a line in `sources/__init__.py`, an empty key in `.env.example`, rules in `rules.yaml`, a row in `docs/SOURCES.md`, and tests for hit, miss, error and 429.

## Project layout

```
src/verdikt/
  models.py        Report and the other API-facing models
  detect.py        refang, classify, normalize, reject internal targets
  config.py        Settings (.env) and rules.yaml loading
  rules.yaml       default thresholds and weights
  engine.py        fan-out, cache, enrichment, graph, report assembly
  verdict.py       pure verdict function
  cache.py         SQLite: source cache, report history, daily budget
  sources/         one file per threat-intelligence source
  enrich/          GeoLite2 lookups, optional DNS
  notify/          Slack and Telegram
  api/app.py       FastAPI routes, security checks, static SPA
  cli.py           command line
web/               React single-page app (Vite, Tailwind, TanStack Query, Cytoscape)
integrations/      Cortex analyzer and Shuffle app definition
scripts/           dump_openapi.py
tests/             pytest suite and fixtures
docs/              design notes and reference documents
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Blank page, console says a module was blocked for its MIME type | The OS mapped `.js` or `.css` to the wrong type. The server now pins the correct types; restart `verdikt ui` and hard-refresh. |
| "UI not built" in the browser | Run `cd web && npm run build`. |
| `error: no source answered` (exit 1) | Every source errored. Check your network and keys with `verdikt sources`. |
| Verdict is always `unknown` | Too few verdict-bearing sources are enabled. Add VirusTotal and abuse.ch keys. |
| Map shows "No location" | Set `VERDIKT_GEOIP_DIR` to a folder with the two GeoLite2 `.mmdb` files, and use an IP indicator. |
| A source shows `rate limited` | Its per-minute limit or daily budget is used up, or the service asked for a long wait. Re-run later; the answer was not cached. |
| `refusing internal ...` | The target is private or matches your internal domains. This is deliberate. |
| `uv` not found | Use `python -m uv`, or add the install directory to your PATH. |
| API returns 401 or 421 | Missing session token or a `Host` other than `127.0.0.1:<port>` or `localhost:<port>`. See `docs/API.md`. |

## Licensing notes

- The VirusTotal public API and Shodan InternetDB forbid commercial products. Check before using verdikt at work.
- IPinfo Lite is not used by default and requires attribution if you add it.
- MaxMind GeoLite2 databases are licensed by MaxMind. Never commit them.
- The land outline comes from Natural Earth (public domain) through `world-atlas`, used only by the one-off generator script.
- Free-tier limits for urlscan, OTX and abuse.ch are not published; check each provider's current terms.

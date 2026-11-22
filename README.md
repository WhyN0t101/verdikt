<p align="center"><img src="docs/logo.svg" width="112" height="112" alt="verdikt logo"></p>

# verdikt

verdikt triages indicators of compromise (IOCs). Give it an IP address, domain, URL or file hash. It queries several threat-intelligence sources in parallel, applies a small set of rules, and returns one verdict: malicious, suspicious, safe or unknown. It can post the result to Slack, Telegram, Discord, Microsoft Teams or email, and it ships a local browser UI with a map and a relationship graph.

The core is a Python library that returns a single `Report` model. The CLI, the HTTP API, the UI and the SOAR integrations only consume that model; nothing outside `src/verdikt/sources/` talks to a threat-intelligence API.

| Document | Contents |
|---|---|
| `PLAN.md` | The specification: architecture, data model, verdict rules, milestones |
| `CLAUDE.md` | Working rules for contributors and coding agents |
| `docs/SOURCES.md` | Every source: what it covers, the key it needs, how its answer maps to a verdict |
| `docs/API.md` | HTTP API reference and the security model |
| `docs/INTEGRATIONS.md` | Cortex analyzer, Shuffle app, scripting with exit codes |
| `docs/DESIGN.md` | UI visual direction |
| `docs/CODE_QUALITY.md` | Checklist for code audits: dead code, duplicates, performance, best practices |

## Contents

- [Quick start](#quick-start)
- [Running without API keys](#running-without-api-keys)
- [Configuration](#configuration)
- [Command line](#command-line)
- [Web UI](#web-ui)
- [How the verdict is decided](#how-the-verdict-is-decided)
- [Input handling and privacy](#input-handling-and-privacy)
- [Notifications](#notifications)
- [Local feeds, known-good lists and CVE context](#local-feeds-known-good-lists-and-cve-context)
- [Dashboard, watchlist and batch](#dashboard-watchlist-and-batch)
- [Investigations, exports and the scheduler](#investigations-exports-and-the-scheduler)
- [Audit log and SIEM](#audit-log-and-siem)
- [STIX export](#stix-export)
- [Caching, rate limits and daily budgets](#caching-rate-limits-and-daily-budgets)
- [Development](#development)
- [Project layout](#project-layout)
- [Checking your setup](#checking-your-setup)
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

A source whose key is missing is disabled; verdikt never fails because of it. These sources work with no key at all: Shodan InternetDB (IP only), urlscan.io search, AlienVault OTX, GreyNoise Community (IP only), RDAP (domain age), CIRCL hashlookup (file hashes), the local feeds (`localfeeds`, after `verdikt feeds update`) and crt.sh (off until `VERDIKT_CRTSH=true`).

Without keys you can still look up IPs and domains (domain age comes from RDAP, also keyless), but the verdict will usually be `unknown` (exit code 12). InternetDB and GreyNoise only add context, and the sources that decide most verdicts (VirusTotal, abuse.ch, AbuseIPDB) need keys. A `malicious` verdict needs at least one of those. Run `uv run verdikt sources` to see what is enabled. `uv run verdikt feeds update` adds the local blocklists and known-good lists, which need no key.

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
| `VERDIKT_DISCORD_WEBHOOK_URL`, `VERDIKT_TEAMS_WEBHOOK_URL` | Incoming webhooks for `--notify discord` and `--notify teams` |
| `VERDIKT_SMTP_HOST`, `VERDIKT_SMTP_PORT`, `VERDIKT_SMTP_USER`, `VERDIKT_SMTP_PASSWORD`, `VERDIKT_SMTP_FROM`, `VERDIKT_SMTP_TO` | Email for `--notify email`. Port 465 uses implicit TLS, any other port STARTTLS. `SMTP_TO` is comma-separated |
| `VERDIKT_NOTIFY_COOLDOWN_HOURS` | Skip a repeat alert for the same indicator at the same level for this long. `0` (default) is off |
| `VERDIKT_INTERNAL_DOMAINS` | Comma-separated suffixes of your own domains, never sent to third parties (for example `corp.example.com`) |
| `VERDIKT_GEOIP_DIR` | Folder holding `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`; without them the map is empty |
| `VERDIKT_DB_PATH` | SQLite file for the cache, history and budgets. Default: the user data directory (`%LOCALAPPDATA%\verdikt` on Windows, `~/.local/share/verdikt` elsewhere), never the repository |
| `VERDIKT_RULES_PATH` | Path to a `rules.yaml` that replaces the packaged default |
| `VERDIKT_DNS_RESOLVE` | `true` enables DNS resolution of domains (default `false`, see [privacy](#input-handling-and-privacy)) |
| `VERDIKT_REPORT_RETENTION_DAYS` | Stored reports older than this many days are deleted at startup (default `90`; `0` keeps them forever). Expired cache rows and old budget rows are always deleted. Analyst feedback is kept |
| `VERDIKT_AUDIT_LOG` | Path of the JSON-lines audit log. Default: `audit.jsonl` in the user data directory |
| `VERDIKT_FEEDS_DIR` | Folder for the downloaded feeds (blocklists, OpenPhish, Tor exits, Tranco, KEV, EPSS). Default: `feeds` in the user data directory |
| `VERDIKT_WATCH_EVERY_HOURS`, `VERDIKT_FEEDS_EVERY_HOURS` | Background watchlist re-check and feed refresh inside `verdikt ui`. `0` (default) is off, otherwise at least `1` |
| `VERDIKT_WATCH_NOTIFY`, `VERDIKT_WATCH_MIN_LEVEL`, `VERDIKT_WATCH_NOTIFY_ANY` | `slack`, `telegram`, `discord`, `teams` or `email` for scheduled verdict changes, the lowest level to send (default `suspicious`), and `true` to also report downgrades such as suspicious to safe |
| `VERDIKT_VT_RESOLUTIONS` | `true` adds passive DNS from VirusTotal resolutions. Costs one extra VirusTotal call per domain or IP check and shares its 4/min and 500/day |
| `VERDIKT_CRTSH` | `true` adds crt.sh certificate transparency. Off by default: it takes 10 to 20 seconds and often times out |
| `VERDIKT_SESSION_TOKEN` | Fixed API token for `verdikt ui`, for automation that calls a long-running instance. Unset: a random token per run |

`.env` is git-ignored. Keys are never logged, never returned by the API and never placed in URLs, with one unavoidable exception: Telegram requires the bot token in the request path.

GeoLite2 needs a free MaxMind account and periodic updates (`geoipupdate`). The databases live outside the repository and must never be committed.

## Command line

```bash
uv run verdikt check <ioc> [--json] [--stix] [--raw] [--no-cache] [--notify slack|telegram|discord|teams|email] [--min-level suspicious]
uv run verdikt bulk <file> [--json] [--notify slack|telegram|discord|teams|email] [--min-level suspicious]
uv run verdikt sources
uv run verdikt cache clear [--source NAME]
uv run verdikt feeds update [--top N] | status   # download or inspect the local feeds (Tranco ranks kept, default 100000)
uv run verdikt feeds import <file> --name N  # MISP event or STIX bundle as a local blocklist
uv run verdikt feeds forget N                # remove an imported list
uv run verdikt check <ioc> --misp            # MISP event JSON (--stix gives STIX 2.1)
uv run verdikt watch add|list|remove|run     # watchlist and re-checks
uv run verdikt extract <file|->              # list the indicators in free text
uv run verdikt bulk <file> [--text] [--csv] [--resume]
uv run verdikt ui [--port 8765] [--no-open] [--dev]
```

| Command | What it does |
|---|---|
| `check` | Checks one IOC and prints a verdict, the reasons, and a table of sources. `--json` prints the `Report` as JSON. `--raw` keeps each vendor's raw response (otherwise stripped). `--no-cache` skips cached answers but still stores the new ones. |
| `bulk` | Reads one IOC per line (blank lines and lines starting with `#` are ignored) and checks them one after another, so the rate limiters and daily budgets are respected. `--json` prints one report per line, `--csv` prints a CSV table, `--text` first extracts the indicators from free text, and `--resume` skips anything checked in the last 24 hours. |
| `sources` | Lists each source, whether it is enabled, what it supports and the requests used today against its daily budget. |
| `cache clear` | Deletes cached source answers (all, or one source). Report history is kept. |
| `extract` | Lists the indicators found in free text (a file or `-` for stdin), defanged ones included. Nothing is looked up. |
| `doctor` | Shows which sources are enabled, whether feeds and GeoIP are set up, which notifiers are configured and where the database and audit log live. |
| `watch` | `add`, `list` and `remove` manage the watchlist; `run` re-checks every entry without the cache and records verdict changes (`--notify` sends them). |
| `feeds` | `update` (`--top N` keeps that many Tranco ranks) downloads the local feeds, `status` shows what is downloaded, `import` loads a MISP event or STIX bundle as a local blocklist (`--name`, `--all`) and `forget` removes one. |
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
- **Sources table:** one row per source with its level, a one-line result, tags and a link to the source's own page (shown only for plain `http` or `https` addresses). Each row has a provenance line (`live, fetched 14:02:11` or `cached, fetched 5 h ago`, then the role and weight) and a "Why this counted" panel with the rules that fired. Rows show a placeholder while a check is running.
- **Source log:** one line per source answer with its timestamp, coloured by level.
- **History:** previous checks grouped by level; click one to reopen it. A search box (substring of the indicator), a Verdict and a Type filter and "Clear" narrow the list; "Load more" fetches the next 50 (it stays on screen and reads "No more reports" at the end); "Export list as CSV" downloads the loaded rows.
- **Seen before:** earlier reports that share this indicator or its related infrastructure (IPs, domains, URLs, hashes, malware families; ASNs are ignored because they are too common). Click one to reopen it.
- **Feedback and export:** "False positive" and "False negative" record your judgement of a verdict (stored locally, kept after reports expire, included in the audit log); "Export STIX" downloads the report as a STIX 2.1 bundle.
- **Map tab (key `1`):** a dot-matrix world map drawn from a bundled data file, so it makes no map requests. The indicator and related IPs are markers; arcs join the indicator to related infrastructure. Locations are approximate. Click a related marker to check that IP. It needs the GeoLite2 databases.
- **Graph tab (key `2`):** indicators and related infrastructure (IPs, domains, URLs, hashes, malware families, ASNs) with labelled edges. Select a node and choose "Check this IOC" to pivot; each pivot spends source quota and the panel shows what is left.
- **Raw JSON tab (key `3`):** the full stored report including vendor raw responses, as text.
- **Changes since:** when the indicator was checked before, a block in the side panel shows what moved against the previous report: the verdict, each source whose status, level, summary or metrics changed, and reasons added or removed. A source that now errors or is rate limited is marked "No answer, not a clean result". Differences are never coloured as good or bad.
- **Indicator history:** the reports of this exact indicator (a URL and its host are separate indicators), how often the verdict changed, the cases that hold them and its watch events. Nothing is shown for an indicator seen only once.
- **Overview page:** activity, source health, watchlist, recurring infrastructure, feedback and feeds (see below). Each recent verdict change has a "What changed" button that opens that report.
- **Batch page:** paste text, extract the indicators, check them all, export CSV. After a run a triage bar acts on the results you pick ("Which results": malicious and suspicious, malicious only, or all): "Add N to case" (an existing case or a new "Batch triage, <date>" case) and "Watch N" (shows the 50-entry cap and skips indicators already watched). Both run one at a time, can be stopped, and report what failed.
- **Vulnerabilities:** CVEs found on a host with KEV and EPSS context.
- **Theme:** dark by default, light follows the system setting or the toggle in the top bar.

Feed data is attacker-controlled and is always rendered as text, never as HTML.

## How the verdict is decided

Each source reports plain facts (counts, scores, booleans) as `metrics`. It never sets a level and holds no thresholds. `verdict.decide()` is a pure function that turns the metrics into a level for each row and a final verdict, using `rules.yaml`:

1. Each successful row becomes MALICIOUS, SUSPICIOUS or SAFE from the rules. Context-only sources (InternetDB, GreyNoise, OTX, urlscan, crt.sh, passive DNS) become INFO.
2. Any MALICIOUS row makes the verdict MALICIOUS.
3. Any SUSPICIOUS row makes it SUSPICIOUS, unless a benign override matches (GreyNoise `riot`, hashlookup `known_good`, a Tranco top site in `localfeeds`), which gives SAFE. An override never touches MALICIOUS.
4. Otherwise the verdict is SAFE only if at least `min_sources_for_safe` (default 2) verdict-bearing sources answered successfully, at least `min_high_weight_for_safe` (default 1) of them are strong sources (high-weight sources that are not list-only feeds: today VirusTotal), and no high-weight source returned an error, was rate limited or had no record. Weak sources and list-only feeds alone never give SAFE. A "not listed" answer from ThreatFox, URLhaus or MalwareBazaar is absence of evidence, so it carries no weight in `confidence` either way. The context-only sources never change the verdict.
5. Otherwise it is UNKNOWN.

Every report also carries a `confidence` of low, medium or high. It is the summed `weights` (in `rules.yaml`) of the sources that agree with the verdict, compared with `confidence_high` and `confidence_medium`; conflicting evidence at least as heavy as the agreeing evidence, or an `unknown` verdict, gives low. Confidence never changes the verdict.

In the UI every source row has a **Why** panel: its role (strong, weak, list-only feed, context only or no answer), its weight in the confidence score, and the exact rules that matched. The same fields (`fired`, `weight`, `role`) are in the JSON report.

Two rules came from real data. A host-level URLhaus listing (a host with an online listed URL) is only **suspicious**, because popular hosts such as `github.com` always have some; only an exact URL match is malicious. And RDAP domain age under 30 days (`age_days__lt: 30` in `rules.yaml`, where a `__lt` key means "less than") is suspicious with weight 1: it is a weak signal that many legitimate new sites also trigger.

Errors and rate limits never count as clean. A source that has no record of the indicator (`not found`) is neither clean nor an error: it does not count towards `min_sources_for_safe`, and from a high-weight source (VirusTotal) it blocks SAFE like an error does.

The default `rules.yaml` is packaged with the library. To change thresholds, copy it, edit it, and point `VERDIKT_RULES_PATH` at your copy. Rules are plain YAML validated against a schema: an integer means "metric is at least this", a boolean means "metric is exactly this", and several keys inside one source are OR'ed. There is no expression language.

Details per source are in `docs/SOURCES.md`.

## Input handling and privacy

verdikt takes care not to leak what you investigate.

- **Internal targets are never sent anywhere.** Private, loopback and link-local IPs, URLs whose host is internal, `localhost`, single-label names, anything ending in `.local`, `.internal`, `.lan`, `.corp`, `.home.arpa`, `.intranet`, `.private`, `.home` or `.localdomain`, IPv6 addresses that hide a private IPv4 (NAT64, IPv4-mapped, IPv4-compatible and IPv4-translated forms, 6to4) and the old site-local range `fec0::/10`, and any suffix in `VERDIKT_INTERNAL_DOMAINS` are rejected before any request is made. Shorthand IPs such as `127.1` and `0x7f.0.0.1` are rejected too. Input is capped at 2048 characters.
- **DNS resolution is off by default.** Resolving a domain can contact the attacker's name server. Enable it with `VERDIKT_DNS_RESOLVE=true` only if you accept that.
- **urlscan is search only.** verdikt never submits a scan, so it never makes urlscan visit a target and never publishes anything.
- **Feed text is cleaned.** Terminal escapes, bidirectional overrides, zero-width and tag characters are stripped from summaries, tags and related values when a result is built or loaded (`raw` is kept as received), so a hostile feed cannot recolour or retitle your terminal or reorder a line.
- **The map makes no requests.** Tile servers would see what you investigate; the dot-matrix map is drawn from a bundled file.
- **Geolocation is local.** GeoLite2 lookups run on your machine with no quota and no leak.
- **The API is local only.** (The session token is embedded in the page served to loopback, so on a shared multi-user machine another local user could read it. Run verdikt on a single-user machine.) It binds to `127.0.0.1`, checks the `Host` header, requires a per-run session token, accepts only JSON on POST and sends no CORS headers.

## Notifications

`--notify slack|telegram|discord|teams|email` posts the result when its level is at or above `--min-level` (default `suspicious`). The order is SAFE, UNKNOWN, SUSPICIOUS, MALICIOUS. The message has a level icon, the defanged indicator and type, one line per source that hit, and a link to the VirusTotal or urlscan page. Feed-derived text is made safe before sending: it is put on one line and every dot is defanged; Telegram gets HTML escaping, Slack gets `&`, `<`, `>` escaped and loses backticks, `*` and `~`, Discord and Teams swap `(` and `)` for `{` and `}`, and Discord sends `allowed_mentions: {parse: []}` so nothing pings. A 429 is retried once when the service asks for a wait of 10 seconds or less (from the `Retry-After` header or the JSON body); a longer wait is reported, not slept on. A failed send is reported in the CLI output, never silently dropped, and never includes the webhook URL or token.

## Local feeds, known-good lists and CVE context

`uv run verdikt feeds update` downloads public data files once (about 14 MB, under 5 seconds) into the feeds folder (`VERDIKT_FEEDS_DIR`, default `feeds` in the user data directory). Lookups then run on your machine: no quota, and the indicator never leaves.

| Feed | Used for |
|---|---|
| Feodo Tracker botnet C2 IPs and Spamhaus DROP networks | An IP on either list is **malicious** (source `localfeeds`). Lists imported from MISP or STIX (`feeds import`) are matched the same way |
| OpenPhish community feed | A URL on the list is **malicious** (source `localfeeds`) |
| Tor exit node list | Tags an IP as a Tor exit; context only |
| Tranco top 100,000 sites | An **exact** match of a domain softens a suspicious verdict to safe. `sub.example.com` does not inherit `example.com`, and a top site can never clear a malicious verdict |
| CISA Known Exploited Vulnerabilities and EPSS scores | CVEs that InternetDB reports for a host are shown with a KEV badge and an exploit probability. Context only: a vulnerable host is not a malicious one |

CIRCL hashlookup (an API, no key) answers whether a file hash is in known-file sets. A hit flagged `KnownMalicious` counts as suspicious; a hit without that flag only softens a suspicious verdict. Without downloaded feeds the `localfeeds` source is disabled and everything else works as before. Re-run the update whenever you want fresher lists, or use "Update feeds" on the Overview page.

## Dashboard, watchlist and batch

The **Overview** page shows checks per day by verdict, source health (answer rate, errors, rate limits, cache hits, average latency over live calls), recurring infrastructure from the "seen before" index, verdict feedback counts, the watchlist and the status of the local feeds.

- **Watchlist:** choose "Watch" on a report (or `verdikt watch add <ioc>`). "Re-check all" and `verdikt watch run` check every entry again **without the cache**, so they spend source quota, record any verdict change, and with `--notify` send the changed ones to any of the five notifiers. `verdikt ui` can run the re-check on a schedule (see below); when the UI is not running, use cron or Task Scheduler with `verdikt watch run`. While a re-check runs, the Overview page shows a progress bar (for example `3/50`); it is indeterminate until the first entry finishes. The list is capped at 50 entries.
- **History and changes:** `GET /api/reports` takes `q`, `level` and `type` to search the stored reports, `GET /api/reports/{id}/diff` shows what changed against the previous report of the same indicator, and `GET /api/reports/{id}/history` lists that indicator's reports, cases and watch events (see `docs/API.md`).
- **Batch:** paste a ticket, an email or a list on the **Batch** page. Indicators are found (defanged ones too), normalized and deduplicated; internal targets are listed as skipped and never looked up. "Check all" runs them one at a time and the table can be exported as CSV. The same from the shell: `verdikt extract ticket.txt` lists the indicators, and `verdikt bulk ticket.txt --text --csv > results.csv` checks them (`--resume` skips anything checked in the last 24 hours). CSV cells that start with `=`, `+`, `-` or `@` get a leading apostrophe so a spreadsheet cannot run them as formulas.

## Investigations, exports and the scheduler

- **Cases (the Cases page):** a case groups reports with notes and tags (up to 10 tags). Use "New case" or "Add to case" on a report. A case exports as Markdown or as one self-contained HTML page. Reports that belong to a case are never deleted by report retention, so the evidence stays.
- **Report exports:** each report exports as Markdown, HTML, STIX 2.1 or a MISP event JSON. Exports are made to be shared: indicators are defanged, feed text is escaped (HTML) or put in inline code (Markdown), and the HTML contains no script and no external resource. The MISP event is a file you import into MISP yourself; its shape follows MISP's event format but was never validated against a live MISP. `distribution` is 0 (your organisation only): widen it in MISP on purpose. Each report export ends with an Evidence table: for every source its status, level, when the answer was fetched, whether it came from the cache, the defanged page link and the rules that fired.
- **Import:** `verdikt feeds import event.json --name case-1` (or the Overview page) loads a MISP event file or a STIX 2.1 bundle as a local blocklist. Only MISP attributes marked `to_ids` are used unless you pass `--all`. Imported indicators count as blocklisted, so a match makes the verdict malicious. Remove one with `verdikt feeds forget case-1`.
- **Scheduler:** with `VERDIKT_WATCH_EVERY_HOURS` and `VERDIKT_FEEDS_EVERY_HOURS` set (each 0 for off, otherwise at least 1), `verdikt ui` re-checks the watchlist and refreshes the feeds in the background; the first run happens one interval after the UI starts. `VERDIKT_WATCH_NOTIFY=slack|telegram|discord|teams|email` sends verdict changes at or above `VERDIKT_WATCH_MIN_LEVEL`. Jobs run only while the UI is open; use cron or Task Scheduler with `verdikt watch run` for an always-on schedule. The Overview page shows each job's last result and has a "Run now" button.

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
  notify/          Slack, Telegram, Discord, Teams, email
  api/app.py       FastAPI routes, security checks, static SPA
  cli.py           command line
  extract.py       indicators from free text (ioc-finder + detect)
  watch.py         watchlist re-checks
  audit.py         JSON-lines audit log
  stix.py          STIX 2.1 export
  diff.py          pure diff of two stored reports
  history.py       one indicator's reports, cases and watch events (pure assembly)
  textutil.py      clean_text: the one rule for feed-derived text
  misp.py          MISP event export
  export.py        Markdown and HTML report and case exports
  scheduler.py     background watchlist and feed jobs inside `verdikt ui`
  jsonutil.py     typed access to untrusted JSON
  httputil.py      Retry-After parsing shared by sources and notifiers
  sources/feeds.py local feeds: download, parse, lookup
  sources/importers.py  MISP and STIX files as local blocklists
  enrich/cve.py    CISA KEV and EPSS context
web/               React single-page app (Vite, Tailwind, TanStack Query, Cytoscape)
integrations/      Cortex analyzer and Shuffle app definition
scripts/           dump_openapi.py, e2e_server.py (fake sources for the e2e tests)
tests/             pytest suite and fixtures
docs/              design notes and reference documents
```

## Checking your setup

`verdikt doctor` lists which sources are enabled, whether feeds and GeoIP are set up, which notifiers are configured and where the database and audit log live.

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
| `localfeeds` shows "run `verdikt feeds update`" | The feeds have not been downloaded yet. Run it once (about 14 MB). |
| A POST to the API returns 415 | The API only accepts `Content-Type: application/json`; send `{}` for an empty POST. |
| `uv` not found | Use `python -m uv`, or add the install directory to your PATH. |
| API returns 401 or 421 | Missing session token or a `Host` other than `127.0.0.1:<port>` or `localhost:<port>`. See `docs/API.md`. |

## Licensing notes

- The VirusTotal public API and Shodan InternetDB forbid commercial products. Check before using verdikt at work.
- The OpenPhish community feed is free for non-commercial use only.
- IPinfo Lite is not used by default and requires attribution if you add it.
- MaxMind GeoLite2 databases are licensed by MaxMind. Never commit them.
- The land outline comes from Natural Earth (public domain) through `world-atlas`, used only by the one-off generator script.
- Free-tier limits for urlscan, OTX and abuse.ch are not published; check each provider's current terms.

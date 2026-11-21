# Integrations

All integrations consume the same `Report`. They never talk to threat-intelligence APIs themselves.

## Shell and scripts

`verdikt check` and `verdikt bulk` use exit codes so scripts can branch without parsing output.

| Code | Meaning |
|---|---|
| 0 | SAFE |
| 1 | Error (bad input, internal target, no source answered, crash) |
| 2 | Usage error |
| 10 | SUSPICIOUS |
| 11 | MALICIOUS |
| 12 | UNKNOWN |

```bash
uv run verdikt check "$IOC" --json > report.json
case $? in
  11) echo "block it" ;;
  10) echo "review" ;;
  12) echo "no verdict: add sources or check manually" ;;
esac
```

`--json` prints the full `Report` (see `docs/API.md`). Pass the indicator after `--` if it could start with a dash.

## Cortex analyzer

Files: `integrations/cortex/verdikt.json` (analyzer definition) and `integrations/cortex/verdikt.py` (wrapper).

The wrapper reads the Cortex job from stdin, runs `python -m verdikt check --json -- <observable>` and prints the Cortex result. It maps the verdict level directly onto the Cortex taxonomy: `safe`, `suspicious`, `malicious`, and `info` for an `unknown` verdict. The taxonomy value is `agreeing/total`, and the whole `Report` is returned as the full report. Exit codes 0, 10, 11 and 12 are verdicts; any other exit code becomes a failed job with the error text.

Requirements: verdikt installed in the Python environment that Cortex uses, and a `.env` with your keys in the analyzer's working directory (or the `VERDIKT_*` variables in the environment). Install it by copying `verdikt.json` and `verdikt.py` into a `verdikt/` folder in your Cortex analyzers directory. Handled data types: ip, domain, fqdn, url, hash.

## Shuffle app

File: `integrations/shuffle/verdikt.yaml` (OpenAPI 3 app definition for `POST /api/check`).

Shuffle calls a running verdikt instance over HTTP, so that instance needs a fixed token:

```bash
VERDIKT_SESSION_TOKEN=<secret> uv run verdikt ui --no-open --port 8765
```

In the Shuffle app set the `X-Verdikt-Token` header to the same secret and send `{"ioc": "<observable>"}`. The response is the `Report`; branch on `level`. The verdict is the same one the CLI and Cortex analyzer return, because all three go through the same core.

Network notes:

- verdikt binds to `127.0.0.1` and rejects any `Host` other than `127.0.0.1:<port>` or `localhost:<port>`. Shuffle must run on the same host and call `http://127.0.0.1:8765`.
- A Shuffle worker inside Docker reaches the host under another name (for example `host.docker.internal`), which the Host check rejects. Run verdikt in the same network namespace, or front it with a reverse proxy that rewrites the `Host` header. Do not loosen the check without understanding the DNS-rebinding risk (see `docs/API.md`).
- Treat the token like a password. Anything holding it can spend your source quotas.

## Scheduled watchlist and batch jobs

```bash
# every morning: re-check the watchlist and tell Slack about verdict changes
0 7 * * *  cd /path/to/verdikt && uv run verdikt watch run --notify slack --min-level suspicious

# a ticket exported to a text file -> one CSV row per indicator
uv run verdikt bulk ticket.txt --text --csv > results.csv   # exit code is the worst verdict
```

On Windows use Task Scheduler with the same commands. A watchlist re-check skips the cache and spends source quota for every entry (maximum 50). Refresh the local feeds with `verdikt feeds update` on whatever schedule suits you; there is no built-in scheduler.

## SIEM and STIX

- **SIEM:** tail the JSON-lines audit log (`audit.jsonl`, see the README) with any log shipper. Events are one per check and one per analyst feedback, carry the defanged indicator and the verdict, and contain no keys, raw vendor data or feed text. Alert on `level` and `confidence` in your SIEM rules.
- **STIX:** `verdikt check <ioc> --stix` or `GET /api/reports/{id}/stix` gives a STIX 2.1 bundle (identity, indicator, malware families with `indicates` relationships) to load into a TIP or MISP-style platform. It is plain JSON and has not been validated against a TIP.

## MISP and OpenCTI

- **MISP out:** `verdikt check <ioc> --misp` or `GET /api/reports/{id}/misp` gives an event JSON (Event, Attribute, Tag) that you import into MISP with its UI or API. `to_ids` is set only on the main indicator of a malicious or suspicious report; related indicators are added with `to_ids` false; `distribution` is 0. The format was not validated against a live MISP.
- **MISP and STIX in:** `verdikt feeds import <file> --name <name>` turns a MISP event file (or a STIX 2.1 bundle, for example exported from OpenCTI) into a local blocklist, matched with no lookup. MISP attributes need `to_ids` set unless you pass `--all`.
- **OpenCTI out:** load the STIX bundle from `verdikt check <ioc> --stix` into OpenCTI. There is no live push to MISP or OpenCTI, because there was no instance to test against.

## Planned seams

These are built into the structure but not yet features: third-party sources through a `verdikt.sources` entry-point group, a user `rules.yaml` override (available now through `VERDIKT_RULES_PATH`), notifier plugins (Discord, Teams, email), theme swaps through `web/src/styles/tokens.css`, and independent UI panels for a dashboard layout.

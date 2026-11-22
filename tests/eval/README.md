# Evaluation corpus for `verdict.decide()`

A labelled set of recorded source rows, a report script and a regression gate. Offline, no
network, no keys. **Synthetic labels guard regressions, they do not measure accuracy.**

| File | What |
|---|---|
| `corpus.jsonl` | One sample per line: `id`, defanged `ioc`, `type`, `label` (`min`/`max` over `safe < suspicious < malicious`, or `null` when the tool may abstain), `label_source` (`synthetic`, `vendor-doc`, `public-report`, `analyst`), `provenance`, `split` (`synthetic`, `dev`, `holdout`), `recorded`, and `rows`: `{source, status, metrics}` only (never `raw`, summaries or tags; `decide()` reads nothing else) |
| `baseline.json` | The accepted `(level, confidence)` of every `synthetic` and `holdout` sample, the holdout checksum and the counts the gate must not worsen |
| `indicators.jsonl` | The real-world indicators (266): defanged `ioc`, `type`, `label` interval, `label_source`, `provenance` URL and title, `split` (dev or holdout), optional `note`. Metadata only, no rows; every indicator comes from a published advisory or vendor document, never from a reputation service |
| `recorded.jsonl` | Rows `{source, status, metrics}` recorded by `scripts/eval_record.py` from open-licence sources (abuse.ch, local feeds). Committed |
| `local/` | Git-ignored: rows from the other sources (VirusTotal, AbuseIPDB, GreyNoise, Hybrid, OTX, InternetDB, hashlookup, RDAP) and the recorder's resume state. The report merges them; CI never sees them |

## Recording (one time, live)

`python scripts/eval_record.py` runs the real engine with `no_cache` over `indicators.jsonl` against a throwaway database (your history, cache and audit log are untouched) and saves only `{source, status, metrics}`: never `raw`, summaries or tags. Order: holdout first, then malicious and ambiguous dev, then benign dev. Caps: VirusTotal 250 calls, AbuseIPDB 80, GreyNoise 50, Hybrid 30; urlscan and crt.sh are never queried. It is resumable (state in `local/record_state.json`), skips internal indicators, and stops at once on an auth error (401 or 403) or a quota block. It needs the keys in `.env` and an hour or so (VirusTotal allows 4 requests a minute). Real-world indicators are only evaluated in the report, not gated in CI.

## Run

```
python scripts/eval_report.py                    # confusion matrix, error rates, calibration, per-source, sensitivity
python scripts/eval_report.py --json
python scripts/eval_report.py --rules my.yaml    # what would my rules do?
python scripts/eval_report.py --update-baseline  # accept the current outputs (review the diff!)
pytest tests/test_eval.py                        # the gate
```

Every rate is printed with a Wilson 95% interval. With 100 samples, "0 errors" only supports "under about 4%".

## The gate (`tests/test_eval.py`)

Exact, with no percentage slack: the rows are recorded and `decide()` is pure, so the outputs are deterministic.
- every `synthetic` and `holdout` sample keeps its `(level, confidence)`, and the holdout lines keep their checksum;
- no sample with an error, rate-limited or missing high-weight source comes out `safe`;
- no malicious-labelled sample comes out `safe` (beyond the count in the baseline);
- false alarms on labelled holdout samples, coverage, and each confidence bucket's in-interval share do not fall below the baseline.

A deliberate change of verdict behaviour (a rules edit, a decide() change) fails the gate until
`--update-baseline` is run in the same commit, so the change shows up as a diff of `baseline.json`.

## First slice (87 samples, this commit)

- 41 boundary rows generated from `rules.yaml` (threshold - 1, threshold, threshold + 1 for every rule key), label `synthetic`;
- 29 hand-picked cases migrated from `tests/test_verdict.py` and `tests/test_features.py` (the tests keep their own copy), label `synthetic`;
- 11 degenerate rows: each high-weight source erroring, rate limited or with no record never gives `safe`, and a hit stays a hit when others fail;
- 6 reference rows (`split: holdout`, label from a vendor or standards document, for example EICAR and `example.com`). Their metric values follow `tests/fixtures/` (see `tests/fixtures/README.md` for which files are live recordings; the companion rows are hand-made).

## Labelling rules (for the real, later slices)

A label must come from a published statement made independently of the sources the tool reads, and be fixed before the tool's answer is seen. Never label with VirusTotal, AbuseIPDB, ThreatFox, URLhaus, MalwareBazaar, OpenPhish, Tranco or GreyNoise output: those are the inputs. `unknown` is never a label (it is the tool abstaining). Keep `dev` for tuning rules and `holdout` for checking; do not open the holdout while tuning.

## Licences

Committed rows hold scalar metrics only (counts, scores, booleans). abuse.ch data is CC0; hashlookup, RDAP and crt.sh are public data. Scalar metrics from VirusTotal, AbuseIPDB, GreyNoise and Hybrid Analysis are a grey area under their terms, so they stay in the git-ignored `local/` folder. Verify each source's terms before committing rows from it.

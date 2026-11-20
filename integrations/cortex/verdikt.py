#!/usr/bin/env python3
"""Cortex analyzer wrapper: runs `verdikt check --json` and maps the Report to Cortex output.

Cortex (non-docker) feeds the job as JSON on stdin and reads the result from stdout.
Verdict levels already match the Cortex taxonomy levels (safe/suspicious/malicious/info).
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

DATATYPES = {"ip": "ip", "domain": "domain", "fqdn": "domain", "url": "url", "hash": "hash"}
# verdikt exit codes 0/10/11/12 are verdicts; anything else is a failure
VERDICT_EXIT_CODES = {0, 10, 11, 12}


def build_output(report: dict[str, Any]) -> dict[str, Any]:
    level = "info" if report["level"] == "unknown" else report["level"]
    return {
        "success": True,
        "summary": {
            "taxonomies": [
                {
                    "level": level,
                    "namespace": "verdikt",
                    "predicate": "verdict",
                    "value": f"{report['agreeing']}/{report['total']}",
                }
            ]
        },
        "full": report,
        "operations": [],
    }


def run(job: dict[str, Any]) -> dict[str, Any]:
    data = str(job["data"])
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "verdikt", "check", data, "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode not in VERDICT_EXIT_CODES:
        return {"success": False, "errorMessage": (proc.stderr or "verdikt failed").strip()[:500]}
    return build_output(json.loads(proc.stdout))


if __name__ == "__main__":
    print(json.dumps(run(json.load(sys.stdin))))

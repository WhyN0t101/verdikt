"""CVE context for a host: is it in CISA's KEV catalog, and what is its EPSS exploit probability?

Reads the local feeds only (`verdikt feeds update`); no CVE id is sent anywhere. Context, not
a verdict: a vulnerable host is not a malicious one.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from verdikt.jsonutil import obj
from verdikt.models import CveInfo

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")  # [0-9]: `\d` also matches other scripts' digits
MAX_CVES = 25


class CveStore:
    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._kev: dict[str, dict[str, Any]] = {}
        self._stamp: float | None = None

    def _load_kev(self) -> None:
        try:
            stamp = (self._dir / "kev.json").stat().st_mtime
        except OSError:
            self._kev, self._stamp = {}, None
            return
        if stamp != self._stamp:
            try:
                self._kev = {
                    k: obj(v)
                    for k, v in obj(
                        json.loads((self._dir / "kev.json").read_text(encoding="utf-8"))
                    ).items()
                }
            except (OSError, ValueError):
                self._kev = {}
            self._stamp = stamp

    def _epss(self, ids: list[str]) -> dict[str, tuple[float, float]]:
        path = self._dir / "epss.sqlite"
        if not path.is_file() or not ids:
            return {}
        db = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            marks = ",".join("?" * len(ids))
            sql = f"SELECT cve, score, pct FROM epss WHERE cve IN ({marks})"  # noqa: S608 (placeholders only)
            return {str(c): (float(s), float(p)) for c, s, p in db.execute(sql, ids)}
        except sqlite3.Error:
            return {}
        finally:
            db.close()

    def lookup(self, cve_ids: list[str]) -> list[CveInfo]:
        """KEV entries first, then by EPSS, capped. Ids that are not CVE-shaped are ignored."""
        self._load_kev()
        ids = sorted({c.upper() for c in cve_ids if _CVE.fullmatch(c.upper())})
        scores = self._epss(ids)
        out: list[CveInfo] = []
        for cve in ids:
            kev = self._kev.get(cve)
            epss = scores.get(cve)
            out.append(
                CveInfo(
                    id=cve,
                    kev=kev is not None,
                    kev_name=str(kev["name"]) if kev else None,
                    kev_added=str(kev["added"]) if kev else None,
                    ransomware=bool(kev and kev.get("ransomware")),
                    epss=epss[0] if epss else None,
                    percentile=epss[1] if epss else None,
                )
            )
        out.sort(key=lambda c: (not c.kev, -(c.epss or 0.0), c.id))
        return out[:MAX_CVES]

"""Speed-ups that must change no output: the index, the clean_text fast path, WAL, lazy import."""

from __future__ import annotations

import subprocess
import sys
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

from verdikt.cache import Cache
from verdikt.models import IOCType, Level, Report
from verdikt.textutil import clean_text


def slow_clean(text: str) -> str:
    """The rule written out: tab/LF/CR to a space, drop Cc, Cf, Zl, Zp."""
    flat = text.translate(str.maketrans("\t\n\r", "   "))
    return "".join(c for c in flat if unicodedata.category(c) not in {"Cc", "Cf", "Zl", "Zp"})


def test_the_fast_path_equals_the_rule_for_every_code_point() -> None:
    for cp in range(0x110000):
        c = chr(cp)
        assert clean_text(c) == slow_clean(c), hex(cp)
    for text in ("", "plain ascii", "b\u00fcchers \u4e2d\u6587", "a\tb", "a\u00a0b", "x\u202ey"):
        assert clean_text(text) == slow_clean(text)
        assert clean_text(clean_text(text)) == clean_text(text)  # idempotent


def test_a_printable_string_is_returned_as_is() -> None:
    text = "nothing to clean here"
    assert clean_text(text) is text


def test_reports_ioc_has_an_index_and_the_lookup_uses_it() -> None:
    cache = Cache(":memory:")
    cache.save_report(
        Report(
            id="r",
            ioc="8.8.8.8",
            ioc_type=IOCType.IP,
            level=Level.SAFE,
            agreeing=0,
            total=0,
            created_at=datetime.now(UTC),
        )
    )
    plan = cache._db.execute(  # pyright: ignore[reportPrivateUsage]
        "EXPLAIN QUERY PLAN SELECT id FROM reports WHERE ioc=? ORDER BY created_at DESC LIMIT 5",
        ("8.8.8.8",),
    ).fetchall()
    assert any("reports_ioc" in str(row) for row in plan), plan
    cache.close()


def test_file_databases_use_wal_and_memory_ones_do_not(tmp_path: Path) -> None:
    on_disk = Cache(tmp_path / "v.db")
    mode = on_disk._db.execute("PRAGMA journal_mode").fetchone()[0]  # pyright: ignore[reportPrivateUsage]
    sync = on_disk._db.execute("PRAGMA synchronous").fetchone()[0]  # pyright: ignore[reportPrivateUsage]
    assert (mode, sync) == ("wal", 1)  # 1 = NORMAL
    on_disk.close()
    memory = Cache(":memory:")
    assert memory._db.execute("PRAGMA journal_mode").fetchone()[0] == "memory"  # pyright: ignore[reportPrivateUsage]
    memory.close()


def test_importing_the_cli_does_not_load_ioc_finder() -> None:
    code = "import sys, verdikt.cli, verdikt.extract; print('ioc_finder' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)  # noqa: S603
    assert out.stdout.strip() == "False"


def test_extract_still_works_after_the_lazy_import() -> None:
    from verdikt.extract import extract_iocs

    assert [i.value for i in extract_iocs("see 8.8.8.8 now").items] == ["8.8.8.8"]

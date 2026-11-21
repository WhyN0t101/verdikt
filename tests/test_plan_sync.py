"""PLAN.md is the spec: keep it equal to the code it describes (CLAUDE.md).

These checks read the live rules, API schema and CLI, so adding a route, command or rule without
updating PLAN.md fails here instead of silently drifting.
"""

from __future__ import annotations

import re
from pathlib import Path

import typer.main

from verdikt import cli
from verdikt.api.app import create_app

ROOT = Path(__file__).resolve().parent.parent
PLAN = (ROOT / "PLAN.md").read_text(encoding="utf-8")


def section(number: int) -> str:
    """Text of `## <number>. ...` up to the next `## ` heading."""
    match = re.search(rf"^## {number}\. .*?(?=^## \d+\. |\Z)", PLAN, flags=re.S | re.M)
    assert match, f"PLAN.md has no section {number}"
    return match.group(0)


def test_section_9_yaml_is_the_shipped_rules_file() -> None:
    block = re.search(r"```yaml\n(.*?)```", section(9), flags=re.S)
    assert block, "PLAN.md section 9 has no yaml block"
    shipped = (ROOT / "src" / "verdikt" / "rules.yaml").read_text(encoding="utf-8")
    assert block.group(1).strip() == shipped.strip()


def test_every_api_route_and_method_is_in_section_12() -> None:
    text = section(12)
    schema = create_app(port=8765, token="schema-only").openapi()
    missing: list[str] = []
    for path, ops in schema["paths"].items():
        rows = [ln for ln in text.splitlines() if f"`{path}`" in ln]
        if not rows:
            missing.append(path)
            continue
        cells = rows[0].split("|")[1].upper()
        missing += [f"{m.upper()} {path}" for m in ops if m.upper() not in cells]
    assert not missing, f"not in PLAN.md section 12: {missing}"


def test_section_12_lists_no_route_that_does_not_exist() -> None:
    schema = create_app(port=8765, token="schema-only").openapi()
    documented = set(re.findall(r"`(/api/[A-Za-z0-9_/{}-]+)`", section(12)))
    assert documented <= set(schema["paths"]), documented - set(schema["paths"])


def test_every_cli_command_is_in_section_10() -> None:
    text = section(10)
    root = typer.main.get_command(cli.app)
    commands = getattr(root, "commands", {})
    missing: list[str] = []
    for name, cmd in commands.items():
        subs = getattr(cmd, "commands", None)
        if subs:
            missing += [f"verdikt {name} {s}" for s in subs if f"verdikt {name} {s}" not in text]
        elif f"verdikt {name}" not in text:
            missing.append(f"verdikt {name}")
    assert not missing, f"not in PLAN.md section 10: {missing}"


def test_every_option_of_check_and_bulk_is_in_section_10() -> None:
    text = section(10)
    commands = getattr(typer.main.get_command(cli.app), "commands", {})
    missing: list[str] = []
    for name in ("check", "bulk", "ui"):
        for param in commands[name].params:
            for opt in getattr(param, "opts", []):
                if opt.startswith("--") and opt != "--help" and opt not in text:
                    missing.append(f"{name} {opt}")
    assert not missing, f"options not in PLAN.md section 10: {missing}"


def test_every_notifier_is_in_section_11() -> None:
    from typing import get_args

    from verdikt.notify import Platform

    text = section(11).lower()
    assert [p for p in get_args(Platform) if p not in text] == []


def test_every_source_is_in_section_3() -> None:
    from verdikt.config import Settings
    from verdikt.sources import build_sources

    text = section(3).lower()
    sources = build_sources(Settings(_env_file=None))  # pyright: ignore[reportCallIssue]
    missing = [s.name for s in sources if s.name not in text]
    assert not missing, f"sources not named in PLAN.md section 3: {missing}"

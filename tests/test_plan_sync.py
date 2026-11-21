"""PLAN.md is the spec: keep it equal to the code it describes (CLAUDE.md).

These checks read the live rules, API schema and CLI, so adding a route, command or rule without
updating PLAN.md fails here instead of silently drifting.
"""

from __future__ import annotations

import re
from pathlib import Path

import click
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


def documented_routes() -> dict[str, set[str]]:
    """path -> methods, from every table row of section 12 (a path may span several rows)."""
    found: dict[str, set[str]] = {}
    for line in section(12).splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) > 3 and re.fullmatch(r"`/api/[^`]*`", cells[2]):
            methods = {m.strip().upper() for m in cells[1].split(",")}
            found.setdefault(cells[2].strip("`"), set()).update(methods)
    return found


def test_every_api_route_and_method_is_in_section_12() -> None:
    schema = create_app(port=8765, token="schema-only").openapi()
    documented = documented_routes()
    problems: list[str] = []
    for path, ops in schema["paths"].items():
        want = {m.upper() for m in ops}
        if path not in documented:
            problems.append(f"missing {path}")
        elif documented[path] != want:
            problems.append(f"{path}: PLAN has {sorted(documented[path])}, API has {sorted(want)}")
    assert not problems, problems


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


def all_commands() -> list[tuple[str, click.Command]]:
    """Every leaf command with its `verdikt ...` name, groups expanded."""
    out: list[tuple[str, click.Command]] = []
    for name, cmd in getattr(typer.main.get_command(cli.app), "commands", {}).items():
        subs = getattr(cmd, "commands", None)
        if subs:
            out += [(f"{name} {sub_name}", sub) for sub_name, sub in subs.items()]
        else:
            out.append((name, cmd))
    return out


def test_every_option_of_every_command_is_in_section_10() -> None:
    text = section(10)
    missing = [
        f"{name} {opt}"
        for name, cmd in all_commands()
        for param in cmd.params
        if isinstance(param, click.Option)
        for opt in param.opts
        if opt.startswith("--") and opt != "--help" and opt not in text
    ]
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


# --- the other docs: settings, notifiers ---------------------------------------------------


def env_name(field: str) -> str:
    return "VERDIKT_" + field.upper()


def test_every_setting_is_in_env_example_and_the_readme_config_table() -> None:
    from verdikt.config import Settings

    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    names = [env_name(f) for f in Settings.model_fields]
    assert [n for n in names if n not in env_example] == [], ".env.example is missing a setting"
    assert [n for n in names if n not in readme] == [], "README.md is missing a setting"


def test_every_notifier_is_named_in_the_readme() -> None:
    from typing import get_args

    from verdikt.notify import Platform

    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert [p for p in get_args(Platform) if p not in readme] == []

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from tests.conftest import CountingLimiter, Fake
from verdikt import cli
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import SCHEMA_VERSION, Status
from verdikt.sources.base import Source

runner = CliRunner()
UseProfile = Callable[[str | dict[str, str]], None]

PROFILES: dict[str, list[Fake]] = {
    "safe": [
        Fake("virustotal", {"malicious": 0, "suspicious": 0}),
        Fake("abuseipdb", {"score": 0}),
    ],
    "suspicious": [Fake("virustotal", {"malicious": 1, "suspicious": 0})],
    "malicious": [Fake("virustotal", {"malicious": 20, "suspicious": 0})],
    "unknown": [Fake("abuseipdb", {"score": 0})],
    "error": [Fake("virustotal", status=Status.ERROR)],
    "empty": [],
}


@pytest.fixture
def use_profile(monkeypatch: pytest.MonkeyPatch):
    def _use(profile: str | dict[str, str]) -> None:
        """A profile name, or a map of ioc -> profile name for bulk."""
        settings = Settings(_env_file=None)  # pyright: ignore[reportCallIssue]
        monkeypatch.setattr(cli, "get_settings", lambda: settings)

        def build(_: Settings, http: httpx.AsyncClient) -> Engine:
            engine = Engine(
                settings,
                load_rules(),
                Cache(":memory:"),
                http,
                sources=[],
                geo=None,
                limiter_factory=CountingLimiter,
            )
            original = engine.check

            async def check(raw: str, *, no_cache: bool = False):
                name = profile if isinstance(profile, str) else profile.get(raw, "safe")
                srcs: list[Source] = list(PROFILES[name])
                engine.sources = srcs
                return await original(raw, no_cache=no_cache)

            engine.check = check  # type: ignore[method-assign]
            return engine

        monkeypatch.setattr(cli, "build_engine", build)

    return _use


@pytest.mark.parametrize(
    ("profile", "code"),
    [
        ("safe", 0),
        ("suspicious", 10),
        ("malicious", 11),
        ("unknown", 12),
        ("error", 1),
        ("empty", 1),
    ],
)
def test_check_exit_codes(use_profile: UseProfile, profile: str, code: int) -> None:
    use_profile(profile)
    result = runner.invoke(cli.app, ["check", "8.8.8.8"])
    assert result.exit_code == code, result.output


def test_bad_input_exits_1(use_profile: UseProfile) -> None:
    use_profile("safe")
    result = runner.invoke(cli.app, ["check", "192.168.1.10"])
    assert result.exit_code == 1
    assert "internal" in result.output


def test_usage_error_exits_2() -> None:
    assert runner.invoke(cli.app, ["check"]).exit_code == 2
    assert runner.invoke(cli.app, ["check", "8.8.8.8", "--min-level", "bogus"]).exit_code == 2


def test_json_output_strips_raw_unless_asked(use_profile: UseProfile) -> None:
    use_profile("malicious")
    plain = json.loads(runner.invoke(cli.app, ["check", "8.8.8.8", "--json"]).stdout)
    assert plain["level"] == "malicious"
    assert plain["schema_version"] == SCHEMA_VERSION
    assert plain["results"][0]["raw"] is None
    raw = json.loads(runner.invoke(cli.app, ["check", "8.8.8.8", "--json", "--raw"]).stdout)
    assert raw["results"][0]["raw"] == {"fake": True}


def test_bulk_exits_with_highest_severity(use_profile: UseProfile, tmp_path: Path) -> None:
    f = tmp_path / "iocs.txt"
    f.write_text("# comment\n8.8.8.8\n\n1.1.1.1\n9.9.9.9\n", encoding="utf-8")
    use_profile({"8.8.8.8": "safe", "1.1.1.1": "unknown", "9.9.9.9": "suspicious"})
    assert runner.invoke(cli.app, ["bulk", str(f)]).exit_code == 10
    use_profile({"8.8.8.8": "safe", "1.1.1.1": "unknown", "9.9.9.9": "malicious"})
    assert runner.invoke(cli.app, ["bulk", str(f)]).exit_code == 11
    use_profile({"8.8.8.8": "safe", "1.1.1.1": "unknown", "9.9.9.9": "safe"})
    assert runner.invoke(cli.app, ["bulk", str(f)]).exit_code == 12
    use_profile("safe")
    assert runner.invoke(cli.app, ["bulk", str(f)]).exit_code == 0


def test_bulk_skips_bad_lines_but_does_not_report_success(
    use_profile: UseProfile, tmp_path: Path
) -> None:
    f = tmp_path / "iocs.txt"
    f.write_text("192.168.1.10\n", encoding="utf-8")
    use_profile("safe")
    assert runner.invoke(cli.app, ["bulk", str(f)]).exit_code == 1


def test_bulk_json_is_one_report_per_line(use_profile: UseProfile, tmp_path: Path) -> None:
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\n1.1.1.1\n", encoding="utf-8")
    use_profile("safe")
    out = runner.invoke(cli.app, ["bulk", str(f), "--json"]).stdout.strip().splitlines()
    assert [json.loads(line)["ioc"] for line in out] == ["8.8.8.8", "1.1.1.1"]


def test_worst_helper() -> None:
    assert cli.worst([0, 12, 10]) == 10
    assert cli.worst([0, 12]) == 12
    assert cli.worst([]) == 0


def test_sources_command_lists_enabled_state(use_profile: UseProfile) -> None:
    use_profile("safe")
    result = runner.invoke(cli.app, ["sources"])
    assert result.exit_code == 0


def test_cache_clear(use_profile: UseProfile) -> None:
    use_profile("safe")
    result = runner.invoke(cli.app, ["cache", "clear"])
    assert result.exit_code == 0
    assert "cleared" in result.output


def test_render_survives_rich_markup_in_feed_data() -> None:
    from verdikt.models import IOCType, Level, Report, SourceResult

    row = SourceResult(source="otx", status=Status.OK, summary="[/oops] [bold]x", level=Level.SAFE)
    report = Report(
        id="1", ioc="http://evil.com/[/bold]", ioc_type=IOCType.URL, level=Level.SAFE,
        agreeing=1, total=1, results=[row],
    )  # fmt: skip
    cli._render(report)  # pyright: ignore[reportPrivateUsage]  # must not raise MarkupError


def test_stix_output(use_profile: UseProfile) -> None:
    use_profile("malicious")
    result = runner.invoke(cli.app, ["check", "8.8.8.8", "--stix"])
    assert result.exit_code == 11
    bundle = json.loads(result.stdout)
    assert bundle["type"] == "bundle"
    assert bundle["objects"][1]["pattern"] == "[ipv4-addr:value = '8.8.8.8']"

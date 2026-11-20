from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

from verdikt.engine import build_graph
from verdikt.enrich.geo import GeoLookup
from verdikt.models import IOC, IOCType, Level, RelatedIOC

CORTEX = Path(__file__).parent.parent / "integrations" / "cortex" / "verdikt.py"


def _load_cortex() -> Any:
    spec = importlib.util.spec_from_file_location("cortex_verdikt", CORTEX)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cortex_output_maps_level_and_confidence() -> None:
    mod = _load_cortex()
    out = mod.build_output({"level": "malicious", "agreeing": 4, "total": 6})
    tax = out["summary"]["taxonomies"][0]
    assert (tax["level"], tax["value"]) == ("malicious", "4/6")
    assert (
        mod.build_output({"level": "unknown", "agreeing": 0, "total": 1})["summary"]["taxonomies"][
            0
        ]["level"]
        == "info"
    )


def test_cortex_definition_is_valid_json() -> None:
    data = json.loads(CORTEX.with_suffix(".json").read_text(encoding="utf-8"))
    assert data["command"] == "verdikt/verdikt.py"


def test_graph_dedupes_nodes_and_flips_inbound_edges() -> None:
    ioc = IOC(value="1.2.3.4", type=IOCType.IP)
    related = [
        RelatedIOC(value="a.example", type=IOCType.DOMAIN, relation="resolves_to", inbound=True),
        RelatedIOC(value="a.example", type=IOCType.DOMAIN, relation="resolves_to", inbound=True),
        RelatedIOC(value="Emotet", type="malware", relation="belongs_to"),
    ]
    g = build_graph(ioc, Level.MALICIOUS, related, "AS64500")
    assert len(g.nodes) == 4  # ioc, domain, malware, asn
    edges = {(e.source, e.target, e.label) for e in g.edges}
    assert ("domain:a.example", "ip:1.2.3.4", "resolves_to") in edges
    assert ("ip:1.2.3.4", "malware:Emotet", "belongs_to") in edges
    assert ("ip:1.2.3.4", "asn:AS64500", "belongs_to") in edges
    assert next(n for n in g.nodes if n.id == "ip:1.2.3.4").level is Level.MALICIOUS


def test_geo_without_databases_is_unavailable(tmp_path: Path) -> None:
    assert GeoLookup(None).available is False
    assert GeoLookup(tmp_path).available is False
    assert GeoLookup(tmp_path).lookup("8.8.8.8") is None


def test_cortex_passes_observable_after_option_terminator(monkeypatch: Any) -> None:
    # observable data is attacker-controlled: "--notify" must not be read as an option
    mod = _load_cortex()
    seen: list[list[str]] = []

    class Proc:
        returncode = 0
        stdout = json.dumps({"level": "safe", "agreeing": 2, "total": 2})
        stderr = ""

    def fake_run(cmd: list[str], **_: Any) -> Proc:
        seen.append(cmd)
        return Proc()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    mod.run({"data": "--notify"})
    assert seen[0][-2:] == ["--", "--notify"]

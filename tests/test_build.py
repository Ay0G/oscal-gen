"""The three builders produce schema-valid OSCAL, and stay deterministic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oscalgen.cli import build_all
from oscalgen.util import OscalGenError
from oscalgen.validate import oscal_cli_path, validate_all

from .conftest import deep_merge

PROFILE = "https://example.com/profile.json"


def _build_all(spec: dict, tmp_path: Path, now: str = "2026-01-01T00:00:00Z") -> dict[str, Path]:
    return build_all(spec, out_dir=tmp_path, now=now)


def test_every_document_validates(spec, tmp_path):
    written = _build_all(spec, tmp_path)
    assert set(written) == {
        "component-definition",
        "system-security-plan",
        "plan-of-action-and-milestones",
    }
    if oscal_cli_path() is None:
        pytest.skip("oscal-cli not on PATH")
    result = validate_all(list(written.values()))
    assert result.errors == []


def test_output_is_byte_identical_across_runs(spec, tmp_path):
    first = {name: p.read_bytes() for name, p in _build_all(spec, tmp_path / "a").items()}
    second = {name: p.read_bytes() for name, p in _build_all(spec, tmp_path / "b").items()}
    assert first == second


def test_uuids_are_stable_when_input_is_reordered(spec, tmp_path):
    """Reordering input must not change UUIDs: they key off logical identity."""
    def body(path: Path) -> dict:
        return json.loads(path.read_text())["system-security-plan"]

    first = body(_build_all(spec, tmp_path / "a")["system-security-plan"])
    shuffled = deep_merge(spec, {"controls": list(reversed(spec["controls"]))})
    second = body(_build_all(shuffled, tmp_path / "b")["system-security-plan"])
    def uuids(doc: dict) -> list[str]:
        return [
            r["uuid"] for r in doc["control-implementation"]["implemented-requirements"]
        ]

    assert sorted(uuids(first)) == sorted(uuids(second))


def test_ssp_system_id_matches_component_definition_uuid(spec, tmp_path):
    """The SSP component and the component-definition entry share one UUID."""
    written = _build_all(spec, tmp_path)
    cd = json.loads(written["component-definition"].read_text())["component-definition"]
    ssp = json.loads(written["system-security-plan"].read_text())["system-security-plan"]

    cd_uuid = cd["components"][0]["uuid"]
    impl_uuid = ssp["system-implementation"]["components"][0]["uuid"]
    assert cd_uuid == impl_uuid

    by_component = ssp["control-implementation"]["implemented-requirements"][0]["by-components"][0]
    assert by_component["component-uuid"] == cd_uuid


def test_poam_risks_are_hoisted_and_referenced(spec, tmp_path):
    written = _build_all(spec, tmp_path)
    poam = json.loads(written["plan-of-action-and-milestones"].read_text())[
        "plan-of-action-and-milestones"
    ]
    assert len(poam["risks"]) == 1
    risk_uuid = poam["risks"][0]["uuid"]
    assert poam["poam-items"][0]["related-risks"] == [{"risk-uuid": risk_uuid}]


def test_poam_inherits_system_id_from_ssp(spec, tmp_path):
    written = _build_all(spec, tmp_path)
    poam = json.loads(written["plan-of-action-and-milestones"].read_text())[
        "plan-of-action-and-milestones"
    ]
    assert poam["system-id"] == {
        "identifier-type": "https://acme.example.com/ids/ato",
        "id": "ATO-1",
    }


def test_import_ssp_href_is_relative(spec, tmp_path):
    written = _build_all(spec, tmp_path)
    poam = json.loads(written["plan-of-action-and-milestones"].read_text())[
        "plan-of-action-and-milestones"
    ]
    assert poam["import-ssp"]["href"] == "system-security-plan.json"


def test_json_input_is_accepted(spec, tmp_path):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    written = build_all(
        json.loads(path.read_text()), out_dir=tmp_path / "out", now="2026-01-01T00:00:00Z"
    )
    assert written


def test_only_components_block_generates_only_a_component_definition(spec, tmp_path):
    spec = {k: v for k, v in spec.items() if k not in ("system", "poam", "controls")}
    written = _build_all(spec, tmp_path)
    assert list(written) == ["component-definition"]
    if oscal_cli_path():
        assert validate_all(list(written.values())).errors == []


def test_nothing_to_build_is_an_error(tmp_path):
    with pytest.raises(OscalGenError, match="nothing to build"):
        build_all({"organization": {"name": "Acme"}}, out_dir=tmp_path)
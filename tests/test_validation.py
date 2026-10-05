"""Input validation errors should name the field and say what is wrong."""

from __future__ import annotations

import pytest

from oscalgen.component import build_component_definition
from oscalgen.metadata import build_metadata
from oscalgen.poam import build_poam
from oscalgen.spec import Metadata, Org
from oscalgen.ssp import build_ssp
from oscalgen.util import OscalGenError

from .conftest import deep_merge

PROFILE = "https://example.com/profile.json"


def _ssp(org: Org, system: dict, controls: list) -> dict:
    """Build an SSP and return the document body."""
    doc = build_ssp(org, Metadata(title="t", last_modified="2026-01-01T00:00:00Z"),
                    system, controls, profile_href=PROFILE)
    return doc["system-security-plan"]


# --- component-definition ---------------------------------------------------


def test_component_needs_a_title(org):
    with pytest.raises(OscalGenError, match=r"components\[0\]: needs a 'title'"):
        build_component_definition(org, Metadata("t", "2026-01-01T00:00:00Z"),
                                   [{"description": "x"}], profile_href=PROFILE)


def test_component_type_is_validated(org):
    with pytest.raises(OscalGenError, match="must be one of"):
        build_component_definition(org, Metadata("t", "2026-01-01T00:00:00Z"),
                                   [{"title": "A", "description": "x", "type": "banana"}],
                                   profile_href=PROFILE)


def test_duplicate_component_titles_are_rejected(org):
    entry = {"title": "API", "description": "x"}
    with pytest.raises(OscalGenError, match="duplicate component title"):
        build_component_definition(org, Metadata("t", "2026-01-01T00:00:00Z"),
                                   [entry, dict(entry)], profile_href=PROFILE)


def test_component_without_control_source_is_rejected(org):
    with pytest.raises(OscalGenError, match="control_source"):
        build_component_definition(org, Metadata("t", "2026-01-01T00:00:00Z"),
                                   [{"title": "A", "description": "x"}], profile_href=None)


# --- SSP --------------------------------------------------------------------


def test_ssp_requires_a_profile(org, spec):
    with pytest.raises(OscalGenError, match=r"profile.href is required"):
        build_ssp(org, Metadata("t", "2026-01-01T00:00:00Z"),
                  spec["system"], spec["controls"], profile_href=None)


def test_ssp_requires_information_types(org, spec):
    system = deep_merge(spec["system"], {"information_types": []})
    with pytest.raises(OscalGenError, match="information_types"):
        _ssp(org, system, spec["controls"])


def test_ssp_requires_system_users(org, spec):
    system = deep_merge(spec["system"], {"system_users": []})
    with pytest.raises(OscalGenError, match="system_users"):
        _ssp(org, system, spec["controls"])


def test_ssp_requires_all_three_security_impact_objectives(org, spec):
    system = deep_merge(spec["system"], {"security_impact": {"confidentiality": "fips199-low"}})
    # deep_merge replaces dicts wholesale at the leaf here, but be explicit.
    system["security_impact"] = {"confidentiality": "fips199-low"}
    with pytest.raises(OscalGenError, match="integrity, availability"):
        _ssp(org, system, spec["controls"])


def test_ssp_accepts_an_omitted_security_impact(org, spec):
    system = deep_merge(spec["system"], {"security_impact": None})
    characteristics = _ssp(org, system, spec["controls"])["system-characteristics"]
    assert "security-impact-level" not in characteristics


def test_ssp_requires_components(org, spec):
    system = deep_merge(spec["system"], {"components": []})
    with pytest.raises(OscalGenError, match=r"system.components"):
        _ssp(org, system, spec["controls"])


def test_ssp_requires_an_authorization_boundary(org, spec):
    system = deep_merge(spec["system"], {"authorization_boundary": None})
    with pytest.raises(OscalGenError, match="authorization_boundary"):
        _ssp(org, system, spec["controls"])


def test_ssp_rejects_unknown_status(org, spec):
    system = deep_merge(spec["system"], {"status": "banana"})
    with pytest.raises(OscalGenError, match=r"system.status.state"):
        _ssp(org, system, spec["controls"])


def test_privileges_require_functions_performed(org, spec):
    system = deep_merge(spec["system"], {
        "system_users": [{"title": "u", "authorized-privileges": [{"title": "Deploy"}]}]
    })
    with pytest.raises(OscalGenError, match="functions-performed"):
        _ssp(org, system, spec["controls"])


def test_component_control_must_be_declared_at_top_level(org, spec):
    system = deep_merge(spec["system"], {
        "components": [{
            "title": "API", "type": "service", "description": "d",
            "controls": [{"id": "si-7", "description": "n"}],
        }]
    })
    with pytest.raises(OscalGenError, match="not in the top-level controls list"):
        _ssp(org, system, spec["controls"])


def test_control_status_is_validated(org, spec):
    controls = [{"id": "ac-2", "status": "banana", "description": "n"}]
    with pytest.raises(OscalGenError, match="control status 'banana'"):
        _ssp(org, spec["system"], controls)


def test_control_needs_a_narrative_or_statement(org, spec):
    with pytest.raises(OscalGenError, match="needs a 'description'/'narrative'"):
        _ssp(org, spec["system"], [{"id": "ac-2", "status": "implemented"}])


def test_duplicate_control_ids_are_rejected(org, spec):
    controls = [{"id": "ac-2", "description": "n"}, {"id": "ac-2", "description": "n"}]
    with pytest.raises(OscalGenError, match="duplicate control id: ac-2"):
        _ssp(org, spec["system"], controls)


# --- POA&M ------------------------------------------------------------------


def test_poam_item_needs_a_risk_or_closure(org):
    with pytest.raises(OscalGenError, match="at least one 'risks' entry"):
        build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                   [{"title": "a", "description": "b"}],
                   ssp_href="ssp.json", system_id={"id": "x"})


def test_closed_item_needs_no_risk(org):
    doc = build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                     [{"title": "a", "description": "b", "closed": True}],
                     ssp_href="ssp.json", system_id={"id": "x"})
    item = doc["plan-of-action-and-milestones"]["poam-items"][0]
    assert {
        "name": item["props"][0]["name"], "value": item["props"][0]["value"]
    } == {"name": "status", "value": "closed"}


def test_risk_requires_a_statement(org):
    with pytest.raises(OscalGenError, match="needs a 'statement'"):
        build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                   [{"title": "a", "description": "b",
                     "risks": [{"title": "r", "description": "d"}]}],
                   ssp_href="ssp.json", system_id={"id": "x"})


def test_risk_status_is_validated(org):
    with pytest.raises(OscalGenError, match="status 'banana'"):
        build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                   [{"title": "a", "description": "b",
                     "risks": [{"title": "r", "description": "d", "statement": "s",
                                "status": "banana"}]}],
                   ssp_href="ssp.json", system_id={"id": "x"})


def test_remediation_requires_description(org):
    with pytest.raises(OscalGenError, match="needs a 'description'"):
        build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                   [{"title": "a", "description": "b",
                     "risks": [{"title": "r", "description": "d", "statement": "s",
                                "remediations": [{"title": "fix"}]}]}],
                   ssp_href="ssp.json", system_id={"id": "x"})


def test_risk_deadline_is_optional(org):
    doc = build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                     [{"title": "a", "description": "b",
                       "risks": [{"title": "r", "description": "d", "statement": "s"}]}],
                     ssp_href="ssp.json", system_id={"id": "x"})
    assert "deadline" not in doc["plan-of-action-and-milestones"]["risks"][0]


def test_poam_requires_an_ssp_reference(org):
    with pytest.raises(OscalGenError, match=r"ssp.href is required"):
        build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                   [{"title": "a", "description": "b", "closed": True}],
                   ssp_href=None, system_id={"id": "x"})


def test_deadline_becomes_a_datetime_with_timezone(org):
    doc = build_poam(org, Metadata("t", "2026-01-01T00:00:00Z"),
                     [{"title": "a", "description": "b",
                       "risks": [{"title": "r", "description": "d", "statement": "s",
                                  "deadline": "2026-12-01"}]}],
                     ssp_href="ssp.json", system_id={"id": "x"})
    assert doc["plan-of-action-and-milestones"]["risks"][0]["deadline"] == "2026-12-01T00:00:00Z"


# --- metadata ---------------------------------------------------------------


def test_roles_get_responsible_parties(org):
    meta = build_metadata(org, Metadata("t", "2026-01-01T00:00:00Z"))
    party = meta["parties"][0]["uuid"]
    assert meta["responsible-parties"] == [{"role-id": "system-owner", "party-uuids": [party]}]


def test_roles_never_carry_parties(org):
    """OSCAL 1.1.2 forbids responsible-parties inside a role."""
    meta = build_metadata(org, Metadata("t", "2026-01-01T00:00:00Z"))
    assert all("responsible-parties" not in role for role in meta["roles"])


def test_organization_becomes_the_default_party():
    org = Org.from_spec({"organization": {"name": "Acme"}})
    meta = build_metadata(org, Metadata("t", "2026-01-01T00:00:00Z"))
    assert meta["parties"][0]["name"] == "Acme"
    assert meta["parties"][0]["type"] == "organization"


def test_missing_organization_name_is_an_error():
    with pytest.raises(OscalGenError, match=r"organization.name is required"):
        Org.from_spec({"organization": {}})


# --- CLI --------------------------------------------------------------------


def test_build_reports_a_missing_input_file(tmp_path):
    from oscalgen.spec import load_input

    with pytest.raises(OscalGenError, match="input file not found"):
        load_input(tmp_path / "nope.yaml")


def test_build_rejects_a_non_mapping_top_level(tmp_path):
    from oscalgen.spec import load_input

    path = tmp_path / "list.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(OscalGenError, match="must be a mapping"):
        load_input(path)


def test_cli_build_returns_nonzero_on_schema_error(tmp_path, spec, capsys):
    """A malformed document must fail loudly rather than being written silently."""
    from oscalgen.cli import main

    bad = deep_merge(spec, {"system": {"status": "banana"}})
    path = tmp_path / "bad.yaml"
    import yaml

    path.write_text(yaml.safe_dump(bad), encoding="utf-8")
    assert main(["build", str(path), "-o", str(tmp_path / "out")]) == 2
    assert "system.status.state" in capsys.readouterr().err
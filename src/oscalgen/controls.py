"""Translate friendly control entries into OSCAL control-implementation blocks.

The same input drives two different output shapes:

* **component-definition** -- ``implemented-requirement`` and ``statement`` both
  carry a real ``description`` field, so the narrative goes straight there.
* **SSP** -- neither object has a ``description`` field in OSCAL 1.1.2, so the
  narrative is carried as an ``implementation-narrative`` prop instead.

Keeping that difference in one module means the input YAML stays identical
whichever document you are generating.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .ids import det_uuid
from .metadata import iter_parties
from .util import OscalGenError, as_list, as_props, prune

#: Namespace for props we invent rather than pass through.
OSCAL_NS = "https://csrc.nist.gov/ns/oscal"

#: Prop name holding the narrative when the schema has no `description` field.
NARRATIVE_PROP = "implementation-narrative"

#: Values FedRAMP and friends use for the standard OSCAL `status` prop.
STATUS_VALUES = {"implemented", "partial", "planned", "alternative", "not-applicable"}


def _narrative_prop(narrative: str, prop_ns: str) -> dict[str, Any]:
    return {"ns": prop_ns, "name": NARRATIVE_PROP, "value": narrative}


def _status_props(status: Any) -> list[dict[str, Any]]:
    if not status:
        return []
    status = str(status)
    if status not in STATUS_VALUES:
        raise OscalGenError(
            f"control status {status!r} must be one of: {', '.join(sorted(STATUS_VALUES))}"
        )
    return [{"ns": OSCAL_NS, "name": "status", "value": status}]


def _statements(
    ctrl: Mapping[str, Any],
    control_id: str,
    party_ids: list[str],
    uuid_seed: str,
    prop_ns: str,
    *,
    narrative_field: str | None,
) -> list[dict[str, Any]]:
    """Translate per-statement (enhancement) narratives."""
    out: list[dict[str, Any]] = []
    for stmt in as_list(ctrl.get("statements")):
        if not isinstance(stmt, Mapping):
            raise OscalGenError(f"control {control_id}: statements entries must be mappings")
        stmt_id = stmt.get("id") or stmt.get("statement-id")
        if not stmt_id:
            raise OscalGenError(f"control {control_id}: each statement needs an 'id'")
        stmt_id = str(stmt_id)
        where = f"control {control_id} statement {stmt_id}: "
        narrative = stmt.get("description") or stmt.get("narrative")
        props = as_props(stmt.get("props"), prop_ns)
        if narrative_field and narrative:
            description: str | None = str(narrative)
        elif narrative:
            description = None
            props = [_narrative_prop(str(narrative), prop_ns), *props]
        else:
            raise OscalGenError(
                f"{where}needs a 'description' or 'narrative'"
            )

        out.append(
            prune(
                {
                    "uuid": det_uuid("statement", uuid_seed, stmt_id),
                    "statement-id": stmt_id,
                    "description": description,
                    "props": props,
                    "links": as_list(stmt.get("links")),
                    "responsible-roles": iter_parties(
                        stmt.get("responsible-roles"), party_ids, where=where
                    ),
                    "remarks": stmt.get("remarks"),
                },
                protect=(narrative_field,) if narrative_field else (),
            )
        )
    return out


def build_implemented_requirements(
    controls: list[Mapping[str, Any]],
    party_ids: list[str],
    *,
    uuid_seed: str,
    prop_ns: str,
    narrative_field: str | None,
    extra: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build ``implemented-requirements``.

    ``narrative_field`` names the schema field that holds the narrative
    (``description`` for component-definition, ``None`` for SSP, where it
    becomes a prop).  ``extra`` is merged into each requirement and is how the
    SSP attaches ``by-components``.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for index, ctrl in enumerate(controls):
        if not isinstance(ctrl, Mapping):
            raise OscalGenError(f"controls[{index}] must be a mapping")
        control_id = ctrl.get("id") or ctrl.get("control-id")
        if not control_id:
            raise OscalGenError(f"controls[{index}] is missing an 'id'")
        control_id = str(control_id)
        if control_id in seen:
            raise OscalGenError(f"duplicate control id: {control_id}")
        seen.add(control_id)

        where = f"control {control_id}: "
        narrative = ctrl.get("description") or ctrl.get("narrative")
        props = as_props(ctrl.get("props"), prop_ns)
        description: str | None = None
        if narrative_field and narrative:
            description = str(narrative)
        elif narrative:
            props = [_narrative_prop(str(narrative), prop_ns), *props]

        statements = _statements(
            ctrl, control_id, party_ids, uuid_seed, prop_ns, narrative_field=narrative_field
        )
        # `narrative` (not `description`) is the real test: in an SSP the
        # narrative lands in a prop, so `description` stays None by design.
        if not narrative and not statements:
            raise OscalGenError(
                f"{where}needs a 'description'/'narrative' or at least one 'statement'"
            )

        requirement: dict[str, Any] = {
            "uuid": det_uuid("control", uuid_seed, control_id),
            "control-id": control_id,
            "description": description,
            "props": props + _status_props(ctrl.get("status")),
            "links": as_list(ctrl.get("links")),
            "responsible-roles": iter_parties(
                ctrl.get("responsible-roles"), party_ids, where=where
            ),
            "statements": statements,
            "remarks": ctrl.get("remarks"),
        }
        if extra:
            requirement.update(extra)
        out.append(prune(requirement, protect=(narrative_field,) if narrative_field else ()))
    return out


def build_by_component(
    entry: Mapping[str, Any],
    party_ids: list[str],
    *,
    uuid_seed: str,
    control_id: str,
    component_uuid: str,
    prop_ns: str,
) -> dict[str, Any]:
    """Build one ``by-component`` block for an SSP implemented-requirement.

    In an SSP the per-component narrative lives here rather than on the
    requirement, so a control entry nested under a component becomes exactly
    one by-component block.
    """
    where = f"component control {control_id}: "
    description = entry.get("description") or entry.get("narrative")
    if not description:
        raise OscalGenError(f"{where}needs a 'description'/'narrative'")

    status = entry.get("implementation_status") or entry.get("implementation-status")
    if status and str(status) not in STATUS_VALUES:
        raise OscalGenError(
            f"{where}implementation_status {status!r} must be one of: "
            f"{', '.join(sorted(STATUS_VALUES))}"
        )

    return prune(
        {
            "component-uuid": component_uuid,
            "uuid": det_uuid("by-component", uuid_seed, control_id, component_uuid),
            "description": str(description),
            "props": as_props(entry.get("props"), prop_ns),
            "links": as_list(entry.get("links")),
            "set-parameters": as_list(
                entry.get("set_parameters") or entry.get("set-parameters")
            ),
            "implementation-status": {"state": str(status)} if status else None,
            "responsible-roles": iter_parties(
                entry.get("responsible-roles"), party_ids, where=where
            ),
            "remarks": entry.get("remarks"),
        },
        protect=("description",),
    )


def component_control_implementations(
    controls: list[Mapping[str, Any]],
    party_ids: list[str],
    *,
    uuid_seed: str,
    source: str,
    description: str,
    prop_ns: str,
) -> list[dict[str, Any]]:
    """A component-definition component's ``control-implementations`` array."""
    implemented = build_implemented_requirements(
        controls,
        party_ids,
        uuid_seed=uuid_seed,
        prop_ns=prop_ns,
        narrative_field="description",
    )
    if not implemented:
        return []
    return [
        prune(
            {
                "uuid": det_uuid("control-implementation", uuid_seed),
                "source": source,
                "description": description,
                "props": as_props({"implementation-status": "implemented"}, prop_ns),
                "implemented-requirements": implemented,
            },
            protect=("description",),
        )
    ]


def ssp_control_implementation(
    controls: list[Mapping[str, Any]],
    party_ids: list[str],
    *,
    uuid_seed: str,
    description: str,
    prop_ns: str,
    by_component_index: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """The SSP's single ``control-implementation`` object.

    ``by_component_index`` maps control ids to the ``by-components`` entries
    gathered from the system component declarations, since ``by-components``
    belongs to the requirement but the input nests it under the component.
    """
    implemented: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ctrl in controls:
        control_id = str(ctrl.get("id") or ctrl.get("control-id"))
        if control_id in seen:
            raise OscalGenError(f"duplicate control id: {control_id}")
        seen.add(control_id)
        blocks = (by_component_index or {}).get(control_id, [])
        implemented.extend(
            build_implemented_requirements(
                [ctrl],
                party_ids,
                uuid_seed=uuid_seed,
                prop_ns=prop_ns,
                narrative_field=None,
                extra={"by-components": blocks} if blocks else None,
            )
        )

    if not implemented:
        raise OscalGenError(
            "the SSP's control-implementation requires at least one implemented-requirement; "
            "add controls to your input"
        )
    return prune(
        {
            "description": description,
            "set-parameters": as_list(None),
            "implemented-requirements": implemented,
        },
        protect=("description",),
    )
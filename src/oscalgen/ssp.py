"""Build an OSCAL system-security-plan document.

Schema shape (OSCAL 1.1.2)::

    system-security-plan  = {uuid, metadata, import-profile, system-characteristics,
                              system-implementation, control-implementation, back-matter?}
    system-characteristics= {system-ids, system-name, description, system-information,
                              status, authorization-boundary, network-architecture?,
                              data-flow?, security-impact-level?, date-authorized?,
                              security-sensitivity-level?, props?, links?,
                              responsible-parties?, remarks?}
    system-implementation = {users, components, leveraged-authorizations?,
                              inventory-items?, props?, links?, remarks?}
    control-implementation= {description, implemented-requirements, set-parameters?}

The two 1.0 -> 1.1 changes that bite hardest: ``system-users`` and
``inventory-items`` moved out of ``system-characteristics`` and into
``system-implementation``, and ``control-implementations`` became a single
``control-implementation`` object rather than an array.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .component import component_uuid
from .controls import build_by_component, ssp_control_implementation
from .ids import det_uuid
from .metadata import build_metadata, iter_parties, resolve_party_ids
from .spec import Metadata, Org
from .util import OscalGenError, as_list, as_props, date_or_none, prune

STATUS_STATES = {
    "operational",
    "under-development",
    "under-major-modification",
    "disposition",
    "other",
}

VALID_COMPONENT_TYPES = {
    "this-system",
    "system",
    "interconnection",
    "software",
    "hardware",
    "service",
    "policy",
    "physical",
    "process-procedure",
    "plan",
    "guidance",
    "standard",
    "validation",
    "network",
}


def build_ssp(
    org: Org,
    meta: Metadata,
    system: Mapping[str, Any],
    controls: list[Mapping[str, Any]],
    *,
    profile_href: str | None = None,
) -> dict[str, Any]:
    """Build the whole SSP document."""
    if not isinstance(system, Mapping):
        raise OscalGenError("'system' block is required and must be a mapping")
    if not profile_href:
        raise OscalGenError(
            "profile.href is required: an SSP must declare the profile it implements"
        )

    party_ids = resolve_party_ids(org)
    name = system.get("name") or system.get("system-name")
    if not name:
        raise OscalGenError("system.name is required")
    name = str(name)

    components = _components(system, org, party_ids)
    by_component_index = _by_component_index(system, org, party_ids, controls)

    return {
        "system-security-plan": prune(
            {
                "uuid": det_uuid("system-security-plan", org.name, name),
                "metadata": build_metadata(org, meta),
                "import-profile": {"href": str(profile_href)},
                "system-characteristics": _system_characteristics(
                    system, org, name, party_ids
                ),
                "system-implementation": _system_implementation(
                    system, org, components, party_ids
                ),
                "control-implementation": ssp_control_implementation(
                    controls,
                    party_ids,
                    uuid_seed=f"ssp:{name}",
                    description=str(
                        system.get("control_implementations_description")
                        or f"Control implementation for {name}."
                    ),
                    prop_ns=org.prop_ns,
                    by_component_index=by_component_index,
                ),
                "back-matter": {},
            },
            protect=("uuid", "metadata"),
        )
    }


def _system_characteristics(
    system: Mapping[str, Any], org: Org, name: str, party_ids: list[str]
) -> dict[str, Any]:
    description = system.get("description")
    if not description:
        raise OscalGenError("system.description is required")

    info_types = _information_types(system, org)
    if not info_types:
        raise OscalGenError(
            "system.information_types needs at least one entry: OSCAL requires "
            "system-information.information-types (e.g. the data the system handles)"
        )

    return prune(
        {
            "system-ids": _system_ids(system, name),
            "system-name": name,
            "system-name-short": str(system["system-name-short"])
            if system.get("system-name-short")
            else None,
            "description": str(description),
            "props": as_props(system.get("props"), org.prop_ns),
            "links": as_list(system.get("links")),
            "date-authorized": date_or_none(system.get("date-authorized")),
            "security-sensitivity-level": str(system["security-sensitivity-level"])
            if system.get("security-sensitivity-level")
            else None,
            "system-information": {"information-types": info_types},
            "security-impact-level": _security_impact(system),
            "status": _status(system),
            "responsible-parties": iter_parties(
                system.get("responsible-roles"), party_ids, where="system: "
            ),
            "authorization-boundary": _boundary(
                system.get("authorization_boundary"),
                org,
                field="description",
                required=True,
                label="system.authorization_boundary",
            ),
            "network-architecture": _boundary(
                system.get("network_architecture"), org, field="description"
            ),
            "data-flow": _boundary(system.get("data_flow"), org, field="description"),
            "remarks": system.get("remarks"),
        },
        protect=(
            "system-ids",
            "system-name",
            "description",
            "system-information",
            "status",
            "authorization-boundary",
        ),
    )


def _system_ids(system: Mapping[str, Any], name: str) -> list[dict[str, Any]]:
    entries = as_list(system.get("system-ids") or system.get("id"))
    if not entries:
        raise OscalGenError(
            "system.system-ids is required (an identifier for the system, e.g. an ATO id)"
        )
    out: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, Mapping):
            ident = entry.get("id")
            itype = entry.get("identifier-type") or entry.get("type")
            if not ident:
                raise OscalGenError("each system-ids entry needs an 'id'")
            out.append(
                prune(
                    {
                        "identifier-type": str(itype) if itype else None,
                        "id": str(ident),
                    }
                )
            )
        else:
            out.append(
                {
                    "identifier-type": f"https://oscal-gen.dev/ns/{_slug(name)}-id",
                    "id": str(entry),
                }
            )
    return out


def _slug(name: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in name).strip("-")


def _information_types(system: Mapping[str, Any], org: Org) -> list[dict[str, Any]]:
    """Normalise information-type entries, including their props."""
    raw = system.get("information_types")
    if raw is None and isinstance(system.get("system_information"), Mapping):
        raw = system["system_information"].get("information-types")
    out: list[dict[str, Any]] = []
    for i, entry in enumerate(as_list(raw)):
        where = f"system.information_types[{i}]: "
        if not isinstance(entry, Mapping):
            raise OscalGenError(f"{where}must be a mapping")
        title = entry.get("title")
        if not title:
            raise OscalGenError(f"{where}needs a 'title'")
        if not entry.get("description"):
            raise OscalGenError(f"{where}needs a 'description'")
        out.append(
            prune(
                {
                    "uuid": entry.get("uuid")
                    or det_uuid("information-type", str(title)),
                    "title": str(title),
                    "description": str(entry["description"]),
                    "categorizations": as_list(entry.get("categorizations")),
                    "props": as_props(entry.get("props"), org.prop_ns),
                    "links": as_list(entry.get("links")),
                    "confidentiality-impact": entry.get("confidentiality-impact"),
                    "integrity-impact": entry.get("integrity-impact"),
                    "availability-impact": entry.get("availability-impact"),
                },
                protect=("title", "description"),
            )
        )
    return out


def _security_impact(system: Mapping[str, Any]) -> dict[str, Any] | None:
    """FIPS 199 impact levels; in 1.1.2 these are plain strings.

    All three objectives are required by the schema, so a partial mapping is an
    error rather than something to silently drop.
    """
    raw = system.get("security_impact") or system.get("security-impact-level")
    if not raw:
        return None
    if not isinstance(raw, Mapping):
        raise OscalGenError("system.security_impact must be a mapping")
    missing = [
        key
        for key in ("confidentiality", "integrity", "availability")
        if not raw.get(key)
    ]
    if missing:
        raise OscalGenError(
            f"system.security_impact is missing {', '.join(missing)}: OSCAL requires all "
            "three security-objective values when a security-impact-level is present"
        )
    return {
        "security-objective-confidentiality": str(raw["confidentiality"]),
        "security-objective-integrity": str(raw["integrity"]),
        "security-objective-availability": str(raw["availability"]),
    }


def _status(system: Mapping[str, Any]) -> dict[str, Any]:
    raw = system.get("status")
    state = "operational"
    remarks = None
    if isinstance(raw, Mapping):
        state = str(raw.get("state", "operational"))
        remarks = raw.get("remarks")
    elif isinstance(raw, str):
        state = raw
    if state not in STATUS_STATES:
        raise OscalGenError(
            f"system.status.state {state!r} must be one of: {', '.join(sorted(STATUS_STATES))}"
        )
    return prune({"state": state, "remarks": remarks}, protect=("state",))


def _boundary(
    raw: Any,
    org: Org,
    *,
    field: str = "description",
    required: bool = False,
    label: str = "",
) -> dict[str, Any] | None:
    """authorization-boundary / network-architecture / data-flow share a shape."""
    if isinstance(raw, str):
        raw = {"description": raw}
    if raw is None:
        if required:
            raise OscalGenError(f"{label or 'this section'} is required")
        return None
    if not isinstance(raw, Mapping):
        raise OscalGenError(f"{label or 'boundary section'} must be a mapping or string")
    description = raw.get("description") or raw.get(field)
    if required and not description:
        raise OscalGenError(f"{label or 'this section'} needs a 'description'")
    return prune(
        {
            "description": str(description) if description else None,
            "props": as_props(raw.get("props"), org.prop_ns),
            "links": as_list(raw.get("links")),
            "diagrams": as_list(raw.get("diagrams")),
            "remarks": raw.get("remarks"),
        },
        protect=("description",) if required else (),
    )


def _components(
    system: Mapping[str, Any], org: Org, party_ids: list[str]
) -> list[dict[str, Any]]:
    """``system-implementation.components``: full component objects, not refs."""
    out: list[dict[str, Any]] = []
    for i, comp in enumerate(as_list(system.get("components"))):
        if not isinstance(comp, Mapping):
            raise OscalGenError(f"system.components[{i}] must be a mapping")
        title = comp.get("title") or comp.get("name")
        if not title:
            raise OscalGenError(f"system.components[{i}] needs a 'title'")
        description = comp.get("description")
        if not description:
            raise OscalGenError(f"system.components[{i}] needs a 'description'")
        ctype = str(comp.get("type", "service"))
        if ctype not in VALID_COMPONENT_TYPES:
            raise OscalGenError(
                f"system.components[{i}] type {ctype!r} must be one of: "
                f"{', '.join(sorted(VALID_COMPONENT_TYPES))}"
            )
        status = str(comp.get("status", "operational"))
        if status not in STATUS_STATES:
            raise OscalGenError(
                f"system.components[{i}] status {status!r} must be one of: "
                f"{', '.join(sorted(STATUS_STATES))}"
            )
        out.append(
            prune(
                {
                    "uuid": comp.get("uuid") or component_uuid(org, str(title)),
                    "type": ctype,
                    "title": str(title),
                    "description": str(description),
                    "purpose": str(comp["purpose"]) if comp.get("purpose") else None,
                    "props": as_props(comp.get("props"), org.prop_ns),
                    "links": as_list(comp.get("links")),
                    "status": {"state": status},
                    "responsible-roles": iter_parties(
                        comp.get("responsible-roles"), party_ids,
                        where=f"system.components[{i}]: ",
                    ),
                    "protocols": as_list(comp.get("protocols")),
                    "remarks": comp.get("remarks"),
                },
                protect=("uuid", "type", "title", "description", "status"),
            )
        )
    if not out:
        raise OscalGenError(
            "system.components needs at least one entry: OSCAL requires "
            "system-implementation.components"
        )
    return out


def _by_component_index(
    system: Mapping[str, Any],
    org: Org,
    party_ids: list[str],
    controls: list[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Build the ``by-components`` block for every control, keyed by control id.

    In an SSP the per-component narrative lives in ``by-components`` on the
    requirement rather than on the requirement itself, and OSCAL requires every
    implemented-requirement to be attributed to at least one component -- a
    control with no by-component says nothing about *what* implements it.

    Two input spellings are supported:

    * nesting ``controls:`` under ``system.components[]`` -- the per-component
      narrative is taken from that entry;
    * a top-level control listing ``components: [titles]`` -- the control's own
      narrative is reused for each named component.

    Controls that do neither are attributed to every declared component, which
    is the honest reading of "the platform implements this".
    """
    declared = {str(c.get("id") or c.get("control-id")) for c in controls}
    components: list[tuple[str, str]] = []  # (title, uuid)
    for comp in as_list(system.get("components")):
        if not isinstance(comp, Mapping):
            continue
        title = str(comp.get("title") or comp.get("name") or "")
        components.append((title, str(comp.get("uuid") or component_uuid(org, title))))
    if not components:
        raise OscalGenError(
            "system.components needs at least one entry: OSCAL requires every SSP "
            "implemented-requirement to name at least one implementing component"
        )
    known_titles = {t for t, _ in components}

    index: dict[str, list[dict[str, Any]]] = {}

    # (a) controls nested under a component
    for i, comp in enumerate(as_list(system.get("components"))):
        if not isinstance(comp, Mapping):
            continue
        title = str(comp.get("title") or comp.get("name") or "")
        cuuid = str(comp.get("uuid") or component_uuid(org, title))
        for entry in as_list(comp.get("controls")):
            if not isinstance(entry, Mapping):
                continue
            control_id = str(entry.get("id") or entry.get("control-id") or "")
            if not control_id:
                raise OscalGenError(f"system.components[{i}].controls entries need an 'id'")
            if declared and control_id not in declared:
                raise OscalGenError(
                    f"system.components[{i}] declares control {control_id!r} which is not in "
                    f"the top-level controls list; an SSP cannot implement a control it does "
                    f"not declare"
                )
            index.setdefault(control_id, []).append(
                build_by_component(
                    entry,
                    party_ids,
                    uuid_seed=f"ssp:{title}",
                    control_id=control_id,
                    component_uuid=cuuid,
                    prop_ns=org.prop_ns,
                )
            )

    # (b)/(c) top-level controls, defaulting to every component
    for ctrl in controls:
        control_id = str(ctrl.get("id") or ctrl.get("control-id"))
        if index.get(control_id):
            continue
        targets = [str(t) for t in as_list(ctrl.get("components"))]
        unknown = [t for t in targets if t not in known_titles]
        if unknown:
            raise OscalGenError(
                f"control {control_id} names unknown component(s): {', '.join(unknown)} "
                f"(known: {', '.join(sorted(known_titles))})"
            )
        if not targets:
            targets = [t for t, _ in components]

        blocks = [
            build_by_component(
                ctrl,
                party_ids,
                uuid_seed=f"ssp:{target}",
                control_id=control_id,
                component_uuid=dict(components)[target],
                prop_ns=org.prop_ns,
            )
            for target in targets
        ]
        index[control_id] = blocks

    return index


def _system_implementation(
    system: Mapping[str, Any],
    org: Org,
    components: list[dict[str, Any]],
    party_ids: list[str],
) -> dict[str, Any]:
    users = _users(system, org)
    if not users:
        raise OscalGenError(
            "system.system_users needs at least one entry: OSCAL requires "
            "system-implementation.users (who operates the system)"
        )
    return prune(
        {
            "props": as_props(system.get("implementation_props"), org.prop_ns),
            "leveraged-authorizations": _leveraged(system, org),
            "users": users,
            "components": components,
            "inventory-items": _inventory_items(system, org, party_ids),
            "remarks": (system.get("system_implementation") or {}).get("remarks")
            if isinstance(system.get("system_implementation"), Mapping)
            else None,
        },
        protect=("users", "components"),
    )


def _users(system: Mapping[str, Any], org: Org) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, user in enumerate(as_list(system.get("system_users") or system.get("users"))):
        if not isinstance(user, Mapping):
            raise OscalGenError(f"system.system_users[{i}] must be a mapping")
        if not (user.get("title") or user.get("id") or user.get("uuid")):
            raise OscalGenError(
                f"system.system_users[{i}] needs a 'title' or 'id' so it can be referenced"
            )
        label = str(user.get("title") or user.get("id") or f"user-{i}")
        roles = [r if isinstance(r, str) else str((r or {}).get("role-id", ""))
                 for r in as_list(user.get("roles") or user.get("role-ids"))]
        roles = [r for r in roles if r]
        out.append(
            prune(
                {
                    "uuid": user.get("uuid") or det_uuid("user", label),
                    "title": user.get("title"),
                    "short-name": user.get("short-name"),
                    "description": user.get("description"),
                    "props": as_props(user.get("props"), org.prop_ns),
                    "links": as_list(user.get("links")),
                    "role-ids": roles or None,
                    "authorized-privileges": _privileges(user, i),
                    "remarks": user.get("remarks"),
                },
                protect=("uuid",),
            )
        )
    return out


def _privileges(user: Mapping[str, Any], index: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for j, priv in enumerate(as_list(user.get("authorized-privileges"))):
        label = f"system.system_users[{index}].authorized-privileges[{j}]: "
        if isinstance(priv, str):
            priv = {"title": priv}
        if not isinstance(priv, Mapping) or not priv.get("title"):
            raise OscalGenError(f"{label}needs a 'title'")
        functions = [str(f) for f in as_list(priv.get("functions-performed"))]
        if not functions:
            raise OscalGenError(
                f"{label}needs 'functions-performed' (OSCAL requires at least one)"
            )
        out.append(
            prune(
                {
                    "title": str(priv["title"]),
                    "description": priv.get("description"),
                    "functions-performed": functions,
                },
                protect=("title", "functions-performed"),
            )
        )
    return out


def _inventory_items(
    system: Mapping[str, Any], org: Org, party_ids: list[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, item in enumerate(as_list(system.get("inventory_items"))):
        if not isinstance(item, Mapping):
            raise OscalGenError(f"system.inventory_items[{i}] must be a mapping")
        description = item.get("description")
        if not description:
            raise OscalGenError(f"system.inventory_items[{i}] needs a 'description'")
        out.append(
            prune(
                {
                    "uuid": item.get("uuid") or det_uuid("inventory-item", str(description)),
                    "description": str(description),
                    "props": as_props(item.get("props"), org.prop_ns),
                    "links": as_list(item.get("links")),
                    "responsible-parties": iter_parties(
                        item.get("responsible-parties"), party_ids
                    ),
                    "remarks": item.get("remarks"),
                },
                protect=("uuid", "description"),
            )
        )
    return out


def _leveraged(system: Mapping[str, Any], org: Org) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, auth in enumerate(as_list(system.get("leveraged-authorizations"))):
        if not isinstance(auth, Mapping):
            raise OscalGenError(f"system.leveraged-authorizations[{i}] must be a mapping")
        title = auth.get("title")
        if not title:
            raise OscalGenError(f"system.leveraged-authorizations[{i}] needs a 'title'")
        out.append(
            prune(
                {
                    "uuid": auth.get("uuid") or det_uuid("leveraged", str(title)),
                    "title": str(title),
                    "props": as_props(auth.get("props"), org.prop_ns),
                    "links": as_list(auth.get("links")),
                    "parties": as_list(auth.get("parties")),
                    "date-authorized": date_or_none(auth.get("date-authorized")),
                    "remarks": auth.get("remarks"),
                },
                protect=("uuid", "title"),
            )
        )
    return out
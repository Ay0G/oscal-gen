"""Build an OSCAL component-definition document.

Schema shape (OSCAL 1.1.2)::

    component-definition         = {uuid, metadata, components?, capabilities?,
                                     import-component-definitions?, back-matter?}
    defined-component            = {uuid, type, title, description, purpose?, props?,
                                     links?, responsible-roles?, protocols?,
                                     control-implementations?, remarks?}

Note there is no ``status`` or ``inventory-items`` on a defined-component in
1.1.2 -- those live on the SSP's ``system-implementation.components`` instead,
and ``import-component-definitions`` carries ``href`` only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .controls import component_control_implementations
from .ids import det_uuid
from .metadata import build_metadata, iter_parties, resolve_party_ids
from .spec import Metadata, Org
from .util import OscalGenError, as_list, as_props, prune

COMPONENT_KEEP = ("uuid", "type", "title", "description")

VALID_COMPONENT_TYPES = {
    "service",
    "interconnection",
    "software",
    "hardware",
    "policy",
    "process-procedure",
    "plan",
    "guidance",
    "standard",
    "validation",
}


def build_component_definition(
    org: Org,
    meta: Metadata,
    components: list[Mapping[str, Any]],
    *,
    profile_href: str | None = None,
) -> dict[str, Any]:
    """Build the whole component-definition document."""
    party_ids = resolve_party_ids(org)
    if not components:
        raise OscalGenError(
            "component-definition needs at least one entry under 'components'"
        )

    built: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, comp in enumerate(components):
        if not isinstance(comp, Mapping):
            raise OscalGenError(f"components[{index}] must be a mapping")
        built.append(_component(comp, index, org, party_ids, profile_href))
        title = built[-1]["title"]
        if title in seen:
            raise OscalGenError(f"duplicate component title: {title}")
        seen.add(title)

    return {
        "component-definition": prune(
            {
                "uuid": det_uuid("component-definition", org.name, meta.title),
                "metadata": build_metadata(org, meta),
                "import-component-definitions": [
                    {"href": str(profile_href)}
                ]
                if profile_href
                else [],
                "components": built,
                "back-matter": {},
            },
            protect=("uuid", "metadata"),
        )
    }


def _component(
    comp: Mapping[str, Any],
    index: int,
    org: Org,
    party_ids: list[str],
    profile_href: str | None,
) -> dict[str, Any]:
    where = f"components[{index}]: "
    title = comp.get("title") or comp.get("name")
    if not title:
        raise OscalGenError(f"{where}needs a 'title'")
    title = str(title)

    ctype = str(comp.get("type", "service"))
    if ctype not in VALID_COMPONENT_TYPES:
        raise OscalGenError(
            f"{where}type {ctype!r} must be one of: {', '.join(sorted(VALID_COMPONENT_TYPES))}"
        )

    description = comp.get("description")
    if not description:
        raise OscalGenError(f"{where}needs a 'description'")

    control_source = comp.get("control_source") or profile_href
    if not control_source:
        raise OscalGenError(
            f"{where}needs 'control_source' (or a top-level profile.href) so its control "
            "implementations can point at a catalog or profile"
        )

    controls = [c for c in as_list(comp.get("controls")) if isinstance(c, Mapping)]
    return prune(
        {
            "uuid": comp.get("uuid") or det_uuid("component", org.name, title),
            "type": ctype,
            "title": title,
            "description": str(description),
            "purpose": str(comp["purpose"]) if comp.get("purpose") else None,
            "props": as_props(comp.get("props"), org.prop_ns),
            "links": as_list(comp.get("links")),
            "responsible-roles": iter_parties(
                comp.get("responsible-roles"), party_ids, where=where
            ),
            "protocols": _protocols(comp, title),
            "control-implementations": component_control_implementations(
                controls,
                party_ids,
                uuid_seed=f"component:{title}",
                source=str(control_source),
                description=str(
                    comp.get("control_implementations_description")
                    or f"Control implementation for {title}."
                ),
                prop_ns=org.prop_ns,
            ),
            "remarks": comp.get("remarks"),
        },
        protect=COMPONENT_KEEP,
    )


def _protocols(comp: Mapping[str, Any], title: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for proto in as_list(comp.get("protocols")):
        if isinstance(proto, Mapping):
            name = proto.get("name")
            if not name:
                raise OscalGenError("protocols entries need a 'name'")
            out.append(
                prune(
                    {
                        "uuid": proto.get("uuid") or det_uuid("protocol", title, str(name)),
                        "name": str(name),
                        "title": proto.get("title"),
                        "port-ranges": as_list(proto.get("port-ranges")),
                    },
                    protect=("uuid", "name"),
                )
            )
        else:
            name = str(proto)
            out.append({"uuid": det_uuid("protocol", title, name), "name": name})
    return out


def component_uuid(org: Org, title: str) -> str:
    """The UUID a component gets in the component-definition.

    Exposed so the SSP can build matching ``system-implementation.components``
    entries and ``by-components`` references without duplicating the logic.
    """
    return det_uuid("component", org.name, str(title))
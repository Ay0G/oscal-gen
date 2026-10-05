"""OSCAL ``metadata`` assembly.

Schema notes (OSCAL 1.1.2)::

    metadata.roles[]              = {id, title, short-name?, description?, props?, links?, remarks?}
    metadata.parties[]            = {uuid?, type?, name?, short-name?, external-ids?, props?, ...}
    metadata.responsible-parties[]= {role-id, party-uuids?, props?, links?, remarks?}

Roles do *not* own parties.  Ownership is expressed only by
``metadata.responsible-parties``, which pairs a ``role-id`` with the UUIDs of
the parties filling it.  Every role we emit therefore gets a matching entry.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .ids import det_uuid
from .spec import Metadata, Org
from .util import OscalGenError, as_list, as_props, prune


def party_uuid(org: Org, index: int, party: Mapping[str, Any]) -> str:
    """Stable UUID for a party, preferring an explicit one from the input."""
    explicit = party.get("uuid")
    if explicit:
        return str(explicit)
    seed = party.get("short-name") or party.get("name") or index
    return det_uuid("party", org.name, seed)


def resolve_party_ids(org: Org) -> list[str]:
    """UUIDs of every party that will appear in the document metadata."""
    if org.parties:
        return [party_uuid(org, i, p) for i, p in enumerate(org.parties)]
    return [det_uuid("party", org.name, org.short_name or org.name)]


def build_metadata(org: Org, meta: Metadata, *, prop_ns: str | None = None) -> dict[str, Any]:
    """Assemble a complete OSCAL ``metadata`` object."""
    ns = prop_ns or org.prop_ns

    if org.parties:
        parties = []
        for i, party in enumerate(org.parties):
            entry = dict(party)
            entry["uuid"] = party_uuid(org, i, party)
            parties.append(prune(entry))
    else:
        # No parties declared: the organization is the only actor.
        parties = [
            prune(
                {
                    "uuid": det_uuid("party", org.name, org.short_name or org.name),
                    "type": "organization",
                    "name": org.name,
                    "short-name": org.short_name,
                }
            )
        ]
    party_ids = [p["uuid"] for p in parties]

    roles = [prune(dict(role)) for role in org.roles]
    responsible_parties = [
        {"role-id": role["id"], "party-uuids": party_ids} for role in roles
    ]

    return prune(
        {
            "title": meta.title,
            "published": meta.published,
            "last-modified": meta.last_modified,
            "version": meta.version,
            "oscal-version": meta.oscal_version,
            "props": as_props({"generator": "oscal-gen"}, ns),
            "roles": roles,
            "parties": parties,
            "responsible-parties": responsible_parties,
            "actions": as_list(meta.actions),
            "remarks": meta.remarks,
        },
        protect=("oscal-version",),
    )


def iter_parties(
    entries: Any, party_ids: list[str], *, where: str = ""
) -> list[dict[str, Any]]:
    """Normalise ``responsible-roles`` shorthand into OSCAL objects.

    A bare role id is expanded to ``{role-id, party-uuids}`` pointing at every
    declared party; a mapping form may narrow the party list.
    """
    out: list[dict[str, Any]] = []
    for entry in as_list(entries):
        if isinstance(entry, str):
            out.append({"role-id": entry, "party-uuids": list(party_ids)})
        elif isinstance(entry, Mapping):
            role_id = entry.get("role-id")
            if not role_id:
                raise OscalGenError(f"{where}responsible-role entry needs 'role-id'")
            out.append(
                prune(
                    {
                        "role-id": role_id,
                        "party-uuids": as_list(entry.get("party-uuids"))
                        or list(party_ids),
                    }
                )
            )
        else:
            raise OscalGenError(f"{where}unsupported responsible-role entry: {entry!r}")
    return out
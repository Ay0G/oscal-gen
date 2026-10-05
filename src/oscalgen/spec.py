"""Input loading plus the small structural validators shared by builders."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import DEFAULT_PROP_NS, OscalGenError, as_list, as_props, prune

try:  # PyYAML is the documented dependency; this keeps the error actionable.
    import yaml
except ImportError as exc:  # pragma: no cover - exercised only on bad installs
    raise OscalGenError(
        "PyYAML is required to read YAML input.  Install it with: pip install PyYAML"
    ) from exc


TOP_LEVEL_KEYS = frozenset(
    {
        "organization",
        "metadata",
        "profile",
        "ssp",
        "system",
        "components",
        "controls",
        "poam",
    }
)


def load_input(path: str | Path) -> dict[str, Any]:
    """Load a YAML or JSON document from disk and return it as a dict.

    Rejects unrecognized top-level keys: a typo like ``componenets`` would
    otherwise be silently ignored and the user would only see a confusing
    downstream error about missing content.
    """
    p = Path(path)
    if not p.is_file():
        raise OscalGenError(f"input file not found: {p}")
    text = p.read_text(encoding="utf-8")
    is_json = p.suffix.lower() == ".json"
    try:
        data = json.loads(text) if is_json else yaml.safe_load(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise OscalGenError(f"could not parse {p}: {exc}") from exc
    if data is None:
        raise OscalGenError(f"input file is empty: {p}")
    if not isinstance(data, Mapping):
        raise OscalGenError(
            f"top level of {p} must be a mapping, got {type(data).__name__}"
        )
    unknown = sorted(set(data) - TOP_LEVEL_KEYS)
    if unknown:
        raise OscalGenError(
            f"unknown top-level key(s) in {p}: "
            + ", ".join(repr(k) for k in unknown)
            + "\n  recognized keys: "
            + ", ".join(sorted(TOP_LEVEL_KEYS))
        )
    return dict(data)


@dataclass
class Org:
    """Organization-level metadata shared by every generated document."""

    name: str
    short_name: str | None = None
    parties: list[dict[str, Any]] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)
    prop_ns: str = DEFAULT_PROP_NS

    @classmethod
    def from_spec(cls, spec: Mapping[str, Any]) -> Org:
        org_spec = spec.get("organization") or {}
        if not isinstance(org_spec, Mapping):
            raise OscalGenError("'organization' must be a mapping")
        name = org_spec.get("name")
        if not name:
            raise OscalGenError("organization.name is required")

        parties: list[dict[str, Any]] = []
        for raw in as_list(org_spec.get("parties")):
            if not isinstance(raw, Mapping):
                raise OscalGenError("organization.parties entries must be mappings")
            ptype = str(raw.get("type", "organization"))
            pname = raw.get("name")
            if not pname:
                raise OscalGenError("each organization.parties entry needs a 'name'")
            parties.append(
                {
                    "uuid": str(raw.get("uuid") or ""),  # filled in by metadata()
                    "type": ptype,
                    "name": str(pname),
                    "short-name": str(raw["short-name"]) if raw.get("short-name") else None,
                    "props": as_props(raw.get("props"), cls._ns(raw)),
                    "links": as_list(raw.get("links")),
                    "external-ids": as_list(raw.get("external-ids")),
                    "remarks": str(raw["remarks"]) if raw.get("remarks") else None,
                }
            )

        roles: list[dict[str, Any]] = []
        for raw in as_list(org_spec.get("roles")):
            if not isinstance(raw, Mapping):
                raise OscalGenError("organization.roles entries must be mappings")
            rid = raw.get("id")
            if not rid:
                raise OscalGenError("each organization.roles entry needs an 'id'")
            roles.append(
                prune(
                    {
                        "id": str(rid),
                        "title": raw.get("title"),
                        "description": raw.get("description"),
                        "props": as_props(raw.get("props"), cls._ns(raw)),
                        "links": as_list(raw.get("links")),
                        "remarks": raw.get("remarks"),
                    }
                )
            )

        return cls(
            name=str(name),
            short_name=str(org_spec["short-name"]) if org_spec.get("short-name") else None,
            parties=parties,
            roles=roles,
            prop_ns=str(org_spec.get("prop_ns") or DEFAULT_PROP_NS),
        )

    @staticmethod
    def _ns(raw: Mapping[str, Any]) -> str:
        return str(raw.get("ns") or DEFAULT_PROP_NS)


@dataclass
class Metadata:
    """Values needed to build an OSCAL ``metadata`` object."""

    title: str
    last_modified: str
    version: str = "1.0.0"
    oscal_version: str = "1.1.2"
    published: str | None = None
    remarks: str | None = None
    actions: list[dict[str, Any]] = field(default_factory=list)


def controls_of(spec: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return the normalised control list from either `controls:` or `system:`.

    Controls can live at the document root (typical for a single system) or
    under a named key, so both spellings are accepted and flattened.
    """
    found: list[Mapping[str, Any]] = []
    sources: list[Any] = [spec.get("controls")]
    system = spec.get("system")
    if isinstance(system, Mapping):
        sources.append(system.get("controls"))
    for src in sources:
        for item in as_list(src):
            if isinstance(item, Mapping):
                found.append(item)
    return found
"""Shared helpers: prop normalisation, empty-value pruning, timestamps."""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Mapping
from typing import Any

#: Namespace applied to prop names that are written without one.
DEFAULT_PROP_NS = "https://oscal-gen.dev/ns/default"

#: Prop names that already carry their own namespace are detected by these.
_QUALIFIED = re.compile(r"^[a-z][a-z0-9+.-]*:")


class OscalGenError(Exception):
    """User-facing error raised for bad input."""


def as_list(value: Any) -> list[Any]:
    """Coerce ``None`` / scalar / list into a list without wrapping dicts."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def prune(value: Any, protect: Iterable[str] = ()) -> Any:
    """Recursively drop ``None``, empty strings, empty lists and empty dicts.

    OSCAL schemas mark many elements optional; emitting ``"remarks": ""`` is
    valid but noisy and creates churn.  Keys named in *protect* are kept even
    when empty, which matters for objects the schema requires to be present.
    """
    protected = set(protect)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, val in value.items():
            if key in protected:
                out[key] = val
                continue
            cleaned = prune(val)
            if cleaned is None or cleaned == "" or cleaned == [] or cleaned == {}:
                continue
            out[key] = cleaned
        return out
    if isinstance(value, list):
        return [prune(v) for v in value]
    if isinstance(value, str):
        return value.strip()
    return value


def _is_qualified(name: str) -> bool:
    """True when the name already includes a namespace (e.g. ``cisa:foo``)."""
    return "://" in name or bool(_QUALIFIED.match(name))


def as_prop(name: str, value: Any, ns: str = DEFAULT_PROP_NS) -> dict[str, Any]:
    """Build a single OSCAL ``prop`` object from a friendly name/value pair."""
    name = str(name).strip()
    if not name:
        raise OscalGenError("prop name must not be empty")
    prop: dict[str, Any] = {}
    if not _is_qualified(name):
        prop["ns"] = ns
    prop["name"] = name
    prop["value"] = "" if value is None else str(value)
    return prop


def as_props(value: Any, ns: str = DEFAULT_PROP_NS) -> list[dict[str, Any]]:
    """Normalise the several shapes we accept for ``props``.

    Accepts a mapping (``{name: value}``), a list of ``{name, value}``
    mappings, or an already-built list of OSCAL prop objects (passed through
    untouched apart from ordering).
    """
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [as_prop(k, v, ns) for k, v in value.items()]
    props: list[dict[str, Any]] = []
    for item in as_list(value):
        if not isinstance(item, Mapping):
            raise OscalGenError(
                f"props entries must be mappings, got {type(item).__name__}: {item!r}"
            )
        if "name" not in item:
            raise OscalGenError(f"props entry missing required key 'name': {item!r}")
        prop = {"name": str(item["name"])}
        if item.get("ns"):
            prop["ns"] = str(item["ns"])
        elif not _is_qualified(prop["name"]):
            prop["ns"] = ns
        prop["value"] = "" if item.get("value") is None else str(item["value"])
        if item.get("class"):
            prop["class"] = str(item["class"])
        if item.get("remarks"):
            prop["remarks"] = str(item["remarks"])
        props.append(prop)
    return props


def default_now() -> str:
    """Current time as an OSCAL ``dateTime-with-timezone`` string."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def date_or_none(value: Any) -> str | None:
    """Coerce a date/datetime to an OSCAL ``date`` string, or ``None``."""
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    text = str(value).strip()
    return text or None
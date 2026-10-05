"""Build an OSCAL plan-of-action-and-milestones (POA&M) document.

Schema shape (OSCAL 1.1.2)::

    plan-of-action-and-milestones = {uuid, metadata, import-ssp?, system-id?,
                                      local-definitions?, observations?, risks?,
                                      findings?, poam-items, back-matter?}
    poam-item                     = {uuid?, title, description, props?, links?,
                                      origins?, related-findings?, related-observations?,
                                      related-risks?, remarks?}
    risk                          = {uuid, title, description, statement, status, props?,
                                      links?, origins?, threat-ids?, characterizations?,
                                      mitigating-factors?, deadline?, remediations?,
                                      risk-log?, related-observations?}
    remediation                   = {uuid, lifecycle, title, description, props?, links?,
                                      origins?, required-assets?, tasks?, remarks?}

The 1.1 POA&M dropped the nested ``items``/``deadlines`` structure that older
FedRAMP templates used.  Actions are now modelled as *risks* carrying
*remediations* carrying *tasks*.  Because that reads badly, risks are declared
inline under a POA&M item in the input and hoisted into the document-level
``risks`` array here, with ``related-risks`` back-references filled in.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .ids import det_uuid
from .metadata import build_metadata, iter_parties, resolve_party_ids
from .spec import Metadata, Org
from .util import OscalGenError, as_list, as_props, prune

RISK_STATUSES = {
    "open",
    "investigating",
    "remediating",
    "deviation-requested",
    "deviation-approved",
    "closed",
}

LIFECYCLES = {"recommendation", "planned", "completed"}
TASK_TYPES = {"milestone", "action"}
ACTOR_TYPES = {"tool", "assessment-platform", "party"}


def build_poam(
    org: Org,
    meta: Metadata,
    items: list[Mapping[str, Any]],
    *,
    ssp_href: str | None,
    system_id: Mapping[str, Any] | str | None,
) -> dict[str, Any]:
    """Build the whole POA&M document."""
    if not items:
        raise OscalGenError("POA&M needs at least one entry under 'poam.items'")
    if not ssp_href:
        raise OscalGenError(
            "ssp.href is required: a POA&M must reference the SSP it belongs to"
        )

    party_ids = resolve_party_ids(org)
    risks: list[dict[str, Any]] = []
    built_items = [
        _poam_item(item, index, org, party_ids, risks)
        for index, item in enumerate(items)
    ]

    return {
        "plan-of-action-and-milestones": prune(
            {
                "uuid": det_uuid("poam", org.name, meta.title),
                "metadata": build_metadata(org, meta),
                "import-ssp": {"href": str(ssp_href)},
                "system-id": _system_id(system_id),
                "risks": risks,
                "poam-items": built_items,
                "back-matter": {},
            },
            protect=("uuid", "metadata", "poam-items"),
        )
    }


def _system_id(raw: Mapping[str, Any] | str | None) -> dict[str, Any] | None:
    """OSCAL 1.1 made ``system-id`` an object, not a bare string."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return {"id": raw}
    if not isinstance(raw, Mapping):
        raise OscalGenError("poam system-id must be a mapping or string")
    if not raw.get("id"):
        raise OscalGenError("poam system-id needs an 'id'")
    return prune(
        {
            "identifier-type": str(raw["identifier-type"])
            if raw.get("identifier-type")
            else None,
            "id": str(raw["id"]),
        }
    )


def _poam_item(
    item: Mapping[str, Any],
    index: int,
    org: Org,
    party_ids: list[str],
    risks: list[dict[str, Any]],
) -> dict[str, Any]:
    where = f"poam.items[{index}]: "
    if not isinstance(item, Mapping):
        raise OscalGenError(f"{where}must be a mapping")
    title = item.get("title")
    if not title:
        raise OscalGenError(f"{where}needs a 'title'")
    description = item.get("description")
    if not description:
        raise OscalGenError(f"{where}needs a 'description'")

    title = str(title)
    # Hoist inline risks to the document level and keep back-references.
    related_risks = [
        {"risk-uuid": _risk(r, i, org, party_ids, risks)}
        for i, r in enumerate(as_list(item.get("risks")))
    ]
    if not related_risks and not item.get("closed"):
        # A POA&M item with no risk and no closure is a planning mistake worth
        # catching early rather than at assessment time.
        raise OscalGenError(
            f"{where}needs at least one 'risks' entry, or 'closed: true' if it is resolved"
        )

    props = as_props(item.get("props"), org.prop_ns)
    if item.get("closed"):
        props = [{"ns": "https://csrc.nist.gov/ns/oscal", "name": "status", "value": "closed"},
                 *props]

    return prune(
        {
            "uuid": item.get("uuid") or det_uuid("poam-item", org.name, title),
            "title": title,
            "description": str(description),
            "props": props,
            "links": as_list(item.get("links")),
            "origins": _origins(item, party_ids, where),
            "related-risks": related_risks,
            "related-findings": as_list(item.get("related-findings")),
            "related-observations": as_list(item.get("related-observations")),
            "remarks": item.get("remarks"),
        },
        protect=("title", "description"),
    )


def _risk(
    raw: Any,
    index: int,
    org: Org,
    party_ids: list[str],
    risks: list[dict[str, Any]],
) -> str:
    """Build a risk, append it to the document-level list, return its UUID."""
    where = f"poam.items[].risks[{index}]: "
    if not isinstance(raw, Mapping):
        raise OscalGenError(f"{where}must be a mapping")
    title = raw.get("title")
    if not title:
        raise OscalGenError(f"{where}needs a 'title'")
    for field in ("description", "statement"):
        if not raw.get(field):
            raise OscalGenError(f"{where}needs a '{field}'")

    title = str(title)
    status = str(raw.get("status", "open"))
    if status not in RISK_STATUSES:
        raise OscalGenError(
            f"{where}status {status!r} must be one of: {', '.join(sorted(RISK_STATUSES))}"
        )

    uuid = str(raw.get("uuid") or det_uuid("risk", org.name, title))
    risks.append(
        prune(
            {
                "uuid": uuid,
                "title": title,
                "description": str(raw["description"]),
                "statement": str(raw["statement"]),
                "status": status,
                "props": as_props(raw.get("props"), org.prop_ns),
                "links": as_list(raw.get("links")),
                "origins": _origins(raw, party_ids, where),
                "threat-ids": as_list(raw.get("threat-ids")),
                "mitigating-factors": as_list(raw.get("mitigating-factors")),
                "deadline": _datetime(raw.get("deadline")),
                "remediations": _remediations(raw, where, org, party_ids),
                "related-observations": as_list(raw.get("related-observations")),
            },
            protect=("uuid", "title", "description", "statement", "status"),
        )
    )
    return uuid


def _remediations(
    risk: Mapping[str, Any], where: str, org: Org, party_ids: list[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(as_list(risk.get("remediations"))):
        label = f"{where}remediations[{i}]: "
        if not isinstance(raw, Mapping):
            raise OscalGenError(f"{label}must be a mapping")
        title = raw.get("title")
        description = raw.get("description")
        if not title:
            raise OscalGenError(f"{label}needs a 'title'")
        if not description:
            raise OscalGenError(f"{label}needs a 'description'")
        lifecycle = str(raw.get("lifecycle", "planned"))
        if lifecycle not in LIFECYCLES:
            raise OscalGenError(
                f"{label}lifecycle {lifecycle!r} must be one of: {', '.join(sorted(LIFECYCLES))}"
            )
        out.append(
            prune(
                {
                    "uuid": raw.get("uuid") or det_uuid("remediation", org.name, str(title)),
                    "lifecycle": lifecycle,
                    "title": str(title),
                    "description": str(description),
                    "props": as_props(raw.get("props"), org.prop_ns),
                    "links": as_list(raw.get("links")),
                    "origins": as_list(raw.get("origins")),
                    "required-assets": as_list(raw.get("required-assets")),
                    "tasks": _tasks(raw, label, org, party_ids),
                    "remarks": raw.get("remarks"),
                },
                protect=("uuid", "lifecycle", "title", "description"),
            )
        )
    return out


def _tasks(
    remediation: Mapping[str, Any], label: str, org: Org, party_ids: list[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(as_list(remediation.get("tasks"))):
        task_label = f"{label}tasks[{i}]: "
        if not isinstance(raw, Mapping):
            raise OscalGenError(f"{task_label}must be a mapping")
        title = raw.get("title")
        if not title:
            raise OscalGenError(f"{task_label}needs a 'title'")
        task_type = str(raw.get("type", "action"))
        if task_type not in TASK_TYPES:
            raise OscalGenError(
                f"{task_label}type {task_type!r} must be one of: {', '.join(sorted(TASK_TYPES))}"
            )
        out.append(
            prune(
                {
                    "uuid": raw.get("uuid") or det_uuid("task", org.name, str(title)),
                    "type": task_type,
                    "title": str(title),
                    "description": str(raw["description"]) if raw.get("description") else None,
                    "props": as_props(raw.get("props"), org.prop_ns),
                    "links": as_list(raw.get("links")),
                    "timing": _timing(raw, task_label),
                    "dependencies": as_list(raw.get("dependencies")),
                    "tasks": _tasks(raw, task_label, org, party_ids),
                    "associated-activities": as_list(raw.get("associated-activities")),
                    "subjects": as_list(raw.get("subjects")),
                    "responsible-roles": iter_parties(
                        raw.get("responsible-roles"), party_ids, where=task_label
                    ),
                    "remarks": raw.get("remarks"),
                },
                protect=("uuid", "type", "title"),
            )
        )
    return out


def _timing(task: Mapping[str, Any], label: str) -> dict[str, Any] | None:
    raw = task.get("timing")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise OscalGenError(f"{label}timing must be a mapping")
    out: dict[str, Any] = {}
    if raw.get("on-date") or raw.get("on_date"):
        when = raw.get("on-date") or raw.get("on_date")
        if isinstance(when, str):
            when = {"date": when}
        if not isinstance(when, Mapping) or not when.get("date"):
            raise OscalGenError(f"{label}timing.on-date needs a 'date'")
        out["on-date"] = {
            "date": _datetime(when["date"])
        }
    if raw.get("within-date-range") or raw.get("within_date_range"):
        rng = raw.get("within-date-range") or raw.get("within_date_range")
        if not isinstance(rng, Mapping) or not (rng.get("start") and rng.get("end")):
            raise OscalGenError(f"{label}timing.within-date-range needs 'start' and 'end'")
        out["within-date-range"] = {
            "start": _datetime(rng["start"]),
            "end": _datetime(rng["end"]),
        }
        if not out["within-date-range"]["start"] or not out["within-date-range"]["end"]:
            raise OscalGenError(
                f"{label}timing.within-date-range needs a parseable 'start' and 'end'"
            )
    if raw.get("at-frequency") or raw.get("at_frequency"):
        freq = raw.get("at-frequency") or raw.get("at_frequency")
        if not isinstance(freq, Mapping) or not (freq.get("period") and freq.get("unit")):
            raise OscalGenError(f"{label}timing.at-frequency needs 'period' and 'unit'")
        out["at-frequency"] = {
            "period": int(freq["period"]),
            "unit": str(freq["unit"]),
        }
    if not out:
        raise OscalGenError(
            f"{label}timing needs one of 'on-date', 'within-date-range' or 'at-frequency'"
        )
    return out


def _datetime(value: Any) -> str | None:
    """OSCAL timestamps are dateTime-with-timezone; bare dates get midnight Z."""
    if value is None:
        return None
    text = str(value).strip()
    if len(text) == 10:  # YYYY-MM-DD
        return f"{text}T00:00:00Z"
    if not (text.endswith("Z") or "+" in text[10:]):
        return f"{text}Z"
    return text


def _origins(
    entry: Mapping[str, Any], party_ids: list[str], where: str
) -> list[dict[str, Any]]:
    """Who produced the finding; defaults to the first declared party."""
    raw = entry.get("origins")
    if raw is None:
        if entry.get("source") and party_ids:
            return [{"actors": [{"type": "party", "actor-uuid": party_ids[0]}]}]
        return []

    out: list[dict[str, Any]] = []
    for origin in as_list(raw):
        if not isinstance(origin, Mapping):
            raise OscalGenError(f"{where}origins entries must be mappings")
        actors: list[dict[str, Any]] = []
        for i, actor in enumerate(as_list(origin.get("actors"))):
            label = f"{where}origins[{i}]: "
            if isinstance(actor, str):
                actor = {"type": "party", "actor-uuid": actor}
            if not isinstance(actor, Mapping):
                raise OscalGenError(f"{label}must be a mapping or a party uuid")
            uuid = actor.get("actor-uuid") or actor.get("uuid")
            if not uuid:
                raise OscalGenError(f"{label}needs an 'actor-uuid'")
            atype = str(actor.get("type", "party"))
            if atype not in ACTOR_TYPES:
                raise OscalGenError(
                    f"{label}type {atype!r} must be one of: {', '.join(sorted(ACTOR_TYPES))}"
                )
            actors.append(
                prune(
                    {
                        "type": atype,
                        "actor-uuid": str(uuid),
                        "role-id": str(actor["role-id"]) if actor.get("role-id") else None,
                    },
                    protect=("type", "actor-uuid"),
                )
            )
        if actors:
            out.append({"actors": actors})
    return out
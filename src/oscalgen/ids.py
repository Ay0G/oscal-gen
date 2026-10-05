"""Deterministic UUID generation.

Regenerating a document from unchanged input must produce byte-identical
output, otherwise every run shows up as a diff in version control and breaks
the "OSCAL as code" workflow.  Every UUID we emit is therefore derived from
the document's logical identity rather than randomly generated.
"""

from __future__ import annotations

import uuid

#: Stable namespace for this tool.  Do not change: it would invalidate every
#: previously generated UUID.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://oscal-gen.dev/ns/ids")


def det_uuid(*parts: object) -> str:
    """Return a deterministic RFC 4122 UUID string for a logical path.

    ``parts`` are joined with ``/`` and hashed into a v5 UUID.  Use a stable,
    human-meaningful path such as ``("party", "acme-corp")`` or
    ``("control", "ac-2")`` so the same input always yields the same UUID.
    """
    if not parts:
        raise ValueError("det_uuid() requires at least one part")
    key = "/".join(str(p) for p in parts)
    return str(uuid.uuid5(NAMESPACE, key))
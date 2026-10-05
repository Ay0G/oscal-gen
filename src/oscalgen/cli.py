"""Command line interface: ``oscal-gen``."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .component import build_component_definition
from .poam import build_poam
from .spec import Metadata, Org, controls_of, load_input
from .ssp import build_ssp
from .util import OscalGenError, as_list, default_now
from .validate import validate_all

DEFAULT_OUT_DIR = "oscal-out"
DEFAULT_PROFILE_HREF = "https://example.com/profiles/moderate-baseline/profile.json"

SSP_FILENAME = "system-security-plan.json"
COMPONENT_DEFINITION_FILENAME = "component-definition.json"
POAM_FILENAME = "plan-of-action-and-milestones.json"


def _metadata(
    spec: Mapping[str, Any], *, now: str | None, doc_title: str
) -> Metadata:
    raw = spec.get("metadata") or {}
    if not isinstance(raw, Mapping):
        raise OscalGenError("'metadata' must be a mapping")
    return Metadata(
        title=str(raw.get("title") or doc_title),
        last_modified=str(
            raw.get("last-modified")
            or raw.get("last_modified")
            or now
            or default_now()
        ),
        version=str(raw.get("version", "1.0.0")),
        oscal_version=str(raw.get("oscal-version", "1.1.2")),
        published=str(raw["published"]) if raw.get("published") else None,
        remarks=str(raw["remarks"]) if raw.get("remarks") else None,
        actions=list(as_list(raw.get("actions"))),
    )


def _profile_href(spec: Mapping[str, Any]) -> str:
    profile = spec.get("profile")
    if isinstance(profile, Mapping) and profile.get("href"):
        return str(profile["href"])
    if isinstance(profile, str) and profile:
        return profile
    return DEFAULT_PROFILE_HREF


def _ssp_href(spec: Mapping[str, Any]) -> str:
    """The POA&M's ``import-ssp.href``.

    Defaults to a bare relative filename: the SSP is written alongside the
    POA&M, and a relative reference keeps the output portable and independent
    of where the build ran.
    """
    ssp = spec.get("ssp")
    if isinstance(ssp, Mapping) and ssp.get("href"):
        return str(ssp["href"])
    if isinstance(ssp, str) and ssp:
        return ssp
    return SSP_FILENAME


def _ssp_system_id(spec: Mapping[str, Any]) -> Mapping[str, Any] | str | None:
    """Reuse the SSP's first system-id so the POA&M references the same system."""
    poam = spec.get("poam")
    if isinstance(poam, Mapping):
        if poam.get("system-id"):
            raw = poam["system-id"]
            return str(raw) if isinstance(raw, str) else dict(raw)
        if poam.get("system_id"):
            raw = poam["system_id"]
            return str(raw) if isinstance(raw, str) else dict(raw)

    system = spec.get("system")
    if isinstance(system, Mapping):
        ids = as_list(system.get("system-ids") or system.get("id"))
        if ids:
            first = ids[0]
            if isinstance(first, Mapping):
                return {k: first[k] for k in ("identifier-type", "id") if k in first}
            return str(first)
    return None


def build_all(
    spec: Mapping[str, Any], *, out_dir: Path, now: str | None = None
) -> dict[str, Path]:
    """Build every requested document, write it, and return the paths written."""
    org = Org.from_spec(spec)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    profile_href = _profile_href(spec)
    controls = controls_of(spec)

    components = [c for c in as_list(spec.get("components")) if isinstance(c, Mapping)]
    if components:
        written["component-definition"] = _write(
            out_dir / COMPONENT_DEFINITION_FILENAME,
            build_component_definition(
                org,
                _metadata(
                    spec, now=now, doc_title=f"{org.name} component definitions"
                ),
                components,
                profile_href=profile_href,
            ),
        )

    system = spec.get("system")
    if isinstance(system, Mapping) and system:
        name = system.get("name") or "System"
        written["system-security-plan"] = _write(
            out_dir / SSP_FILENAME,
            build_ssp(
                org,
                _metadata(
                    spec, now=now, doc_title=f"{name} system security plan"
                ),
                system,
                controls,
                profile_href=profile_href,
            ),
        )

    poam = spec.get("poam")
    items = (
        [i for i in as_list(poam.get("items")) if isinstance(i, Mapping)]
        if isinstance(poam, Mapping)
        else []
    )
    if items:
        written["plan-of-action-and-milestones"] = _write(
            out_dir / POAM_FILENAME,
            build_poam(
                org,
                _metadata(
                    spec, now=now, doc_title=f"{org.name} plan of action and milestones"
                ),
                items,
                ssp_href=_ssp_href(spec),
                system_id=_ssp_system_id(spec),
            ),
        )

    if not written:
        raise OscalGenError(
            "nothing to build: provide at least one of 'components', 'system' or 'poam.items'"
        )
    return written


def _json_default(value: Any) -> str:
    """Safety net: YAML auto-parses bare dates into date objects."""
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    raise TypeError(f"cannot serialise {type(value).__name__} to JSON")


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(
        json.dumps(document, indent=2, default=_json_default) + "\n", encoding="utf-8"
    )
    return path


def cmd_build(args: argparse.Namespace) -> int:
    spec = load_input(args.input)
    written = build_all(spec, out_dir=Path(args.out_dir), now=args.now)

    if not args.skip_validate:
        result = validate_all(list(written.values()))
        if result.errors:
            print("schema validation failed:", file=sys.stderr)
            for err in result.errors:
                print(f"  - {err}", file=sys.stderr)
            return 1
        if result.skipped:
            print(
                "warning: oscal-cli not on PATH; output written but unvalidated",
                file=sys.stderr,
            )
        else:
            print(f"schema validation passed ({len(result.checked)} document(s))")

    for name, path in written.items():
        print(f"{name}: {path}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    result = validate_all(args.files)
    if result.skipped:
        print("oscal-cli not on PATH; cannot validate", file=sys.stderr)
        return 1
    for err in result.errors:
        print(f"  - {err}", file=sys.stderr)
    if result.errors:
        return 1
    print(f"ok: {len(result.checked)} document(s) valid")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.output)
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(STARTER_YAML, encoding="utf-8")
    print(f"wrote starter input to {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oscal-gen",
        description=(
            "Generate OSCAL component-definition, system-security-plan and POA&M "
            "documents from a single YAML/JSON description."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="generate OSCAL documents from a YAML/JSON input")
    build.add_argument("input", help="path to the input YAML/JSON file")
    build.add_argument(
        "-o",
        "--out-dir",
        default=DEFAULT_OUT_DIR,
        help=f"directory for generated documents (default: {DEFAULT_OUT_DIR})",
    )
    build.add_argument(
        "--now",
        help="fix metadata.last-modified to this timestamp (default: now, in UTC)",
    )
    build.add_argument(
        "--skip-validate",
        action="store_true",
        help="do not run oscal-cli validation on the output",
    )
    build.set_defaults(func=cmd_build)

    validate = sub.add_parser("validate", help="validate existing OSCAL JSON documents")
    validate.add_argument("files", nargs="+", help="OSCAL JSON files to validate")
    validate.set_defaults(func=cmd_validate)

    init = sub.add_parser("init", help="write a commented starter input file")
    init.add_argument("output", nargs="?", default="oscal-input.yaml")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(func=cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except OscalGenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


STARTER_YAML = '''\
# Starter input for oscal-gen, targeting OSCAL 1.1.2.
#
# Provide at least one of: components, system, poam.items.
# Prop shorthand: `name: value` becomes an OSCAL prop; names without a namespace
# get `organization.prop_ns` applied automatically.

metadata:
  title: Acme Payments Platform -- system security plan
  version: 1.0.0
  # last-modified defaults to now. Pass --now or set it here for reproducible output.

organization:
  name: Acme Corp
  short-name: ACME
  prop_ns: https://acme.example.com/ns
  parties:
    - type: organization
      name: Acme Corp
      short-name: ACME
  roles:
    - id: system-owner
      title: System Owner
    - id: issao
      title: Information System Security Officer

profile:
  href: https://example.com/profiles/moderate-baseline/profile.json

# ---------------------------------------------------------------------------
# component-definition.json
# ---------------------------------------------------------------------------
components:
  - title: Payments API
    type: service
    description: Public-facing payment authorization service.
    purpose: Authorize and tokenize card transactions.
    protocols: [https]
    responsible-roles: [issao]
    props:
      source-repo: https://github.com/acme/payments-api
    controls:
      # component-definition requirements carry a real `description` field.
      - id: ac-2
        status: partial
        description: >-
          Accounts are provisioned through the corporate IdP. Local accounts are
          disabled except for one break-glass account.
        statements:
          - id: ac-2.1
            description: The IdP enforces phishing-resistant MFA for all staff.

# ---------------------------------------------------------------------------
# system-security-plan.json
# ---------------------------------------------------------------------------
system:
  name: Acme Payments Platform
  system-name-short: APP
  id:
    - identifier-type: https://acme.example.com/ids/ato
      id: ATO-2026-0001
  description: >-
    Cardholder-data payment processing platform running on AWS us-east-1.
  status: operational
  security-sensitivity-level: restricted
  date-authorized: 2026-01-15
  security_impact:
    confidentiality: fips199-moderate
    integrity: fips199-moderate
    availability: fips199-moderate
  authorization_boundary:
    description: >-
      Covers the API tier, the worker tier and the Aurora PostgreSQL cluster.
      The AWS-managed control plane is outside the boundary.
  network_architecture:
    description: Public ALB -> private application subnets -> egress via NAT.
  data_flow:
    description: >-
      Card data arrives from merchant POS clients over TLS, is tokenized at the
      API tier, and only token references are persisted.
  information_types:
    - title: Cardholder data
      description: PAN, expiry and cardholder name, tokenized at ingest.
      props:
        pci-data-element: [3, 4]
  responsible-roles: [system-owner]
  system_users:
    - title: Acme platform engineers
      roles: [system-owner]
      authorized-privileges:
        - title: Deploy releases
          functions-performed: [Deploy to the application tier]
  inventory_items:
    - description: Aurora PostgreSQL primary cluster
      props:
        platform: aws-rds
        engine: aurora-postgresql-16.4
  # These land in system-implementation.components. The uuid is derived from
  # the title, so it matches the component-definition entry of the same title.
  components:
    - title: Payments API
      type: service
      description: Public-facing payment authorization service.
      status: operational
      controls:
        # Per-component narratives become `by-components` on the requirement.
        - id: ac-2
          implementation_status: partial
          description: >-
            Role assignment is handled by the IdP; AC-2(1) holds for staff but
            not for the break-glass account.

# Top-level controls become the SSP's control-implementation. Because OSCAL
# 1.1.2 gives SSP requirements no `description` field, narratives are emitted
# as an `implementation-narrative` prop.
controls:
  - id: ac-2
    status: partial
    description: >-
      Accounts are provisioned through the corporate IdP. The break-glass
      account is the documented exception.
  - id: sc-12
    status: implemented
    description: >-
      Key management uses AWS KMS customer-managed keys with annual rotation.
  - id: au-2
    status: partial
    description: >-
      Audit events are centralised, but retention is 400 days against a
      one-year requirement.

# ---------------------------------------------------------------------------
# plan-of-action-and-milestones.json
# ---------------------------------------------------------------------------
poam:
  # system-id is inherited from system.id when omitted.
  items:
    - title: MFA not enforced for the break-glass account
      description: >-
        The break-glass account relies on a password alone, exceeding the
        phishing-resistant MFA requirement in AC-2(1).
      props:
        control-id: ac-2.1
        severity: high
      risks:
        - title: Single-factor administrative access
          description: >-
            A compromised break-glass password grants full administrative access.
          statement: >-
            Credential compromise of the break-glass account could allow an
            attacker to take over the platform with no second factor in the way.
          status: remediating
          props:
            likelihood: low
          deadline: 2026-11-30
          remediations:
            - title: Provision a hardware token for the break-glass account
              description: >-
                Purchase two FIDO2 keys, register one to the account and store
                it in the physical safe.
              lifecycle: planned
              responsible-roles: [issao]
              tasks:
                - title: Order hardware keys
                  type: action
                  description: Order two FIDO2 keys from the approved vendor.
                  timing:
                    on-date:
                      date: 2026-10-01
                  responsible-roles: [issao]
'''
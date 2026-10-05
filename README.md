# oscal-gen

Generate OSCAL [component-definition](https://oscal.nist.gov/specs), [System Security
Plan](https://oscal.nist.gov/specs), and [POA&M](https://oscal.nist.gov/specs) documents
from a single human-friendly YAML file.

The point is to keep the *content* in version control as readable YAML and let the tool
handle UUIDs, metadata wiring, and schema conformance. Output is deterministic: regenerate
with unchanged input and you get a byte-identical file, so diffs only ever show real
changes.

Targets **OSCAL 1.1.2**.

## Install

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
```

Requires Python 3.10+ and PyYAML. Schema validation shells out to
[`oscal-cli`](https://github.com/defenseunicorns/go-oscal) if it is on `PATH`; without it,
documents are still written but reported as unvalidated.

## Usage

```sh
oscal-gen init input.yaml            # write a commented starter file
oscal-gen build input.yaml -o out    # generate + validate
oscal-gen build input.yaml --now 2026-01-01T00:00:00Z   # reproducible timestamps
oscal-gen validate out/*.json        # re-validate existing documents
```

Which documents get built depends on which blocks are present:

| Input block | Output |
|---|---|
| `components:` | `component-definition.json` |
| `system:` | `system-security-plan.json` |
| `poam.items:` | `plan-of-action-and-milestones.json` |

See [`examples/payments-platform.yaml`](examples/payments-platform.yaml) for a complete
worked example.

## Input shape

```yaml
metadata:
  title: Payments Platform SSP
  version: 1.0.0

organization:
  name: Acme Corp
  prop_ns: https://acme.example.com/ns   # namespace for unqualified prop names
  parties:
    - type: organization
      name: Acme Corp
  roles:
    - id: system-owner
      title: System Owner

profile:
  href: https://example.com/profiles/moderate/profile.json

system:
  name: Acme Payments Platform
  id: [{identifier-type: "https://acme.example.com/ids/ato", id: ATO-2026-0001}]
  description: Cardholder-data processing platform.
  security_impact: {confidentiality: fips199-moderate, integrity: ..., availability: ...}
  information_types: [{title: Cardholder data, description: PAN, tokenized at ingest}]
  system_users: [{title: Platform engineers, roles: [system-owner]}]
  components:
    - {title: Payments API, type: service, description: Public API}

controls:
  - id: sc-12
    status: implemented
    description: Key management via AWS KMS with annual rotation.
```

### Convenience over OSCAL verbosity

A few translations happen so the YAML stays readable:

- `status:` on a control becomes the standard `https://csrc.nist.gov/ns/oscal` `status`
  prop, which is what reviewers and POA&M tooling filter on.
- `security_impact: {confidentiality: X, ...}` becomes the SSP's
  `security-impact-level`. All three objectives are required when present.
- Props accept `{name: value}` shorthand; unqualified names get `organization.prop_ns`
  applied, and names that already carry a namespace (`cisa:foo`) are left alone.
- String role references in `responsible-roles:` are expanded to full
  `responsible-parties` objects pointing at every declared party.
- `system.status` accepts either a bare string or `{state: ..., remarks: ...}`.
- POA&M `risks:` are declared inline under an item and hoisted into the document-level
  `risks` array, with `related-risks` back-references filled in automatically.
- Bare dates become `dateTime-with-timezone` (`2026-12-01` → `2026-12-01T00:00:00Z`).

### Where the 1.1 models diverge from 1.0

Most older OSCAL examples and templates are written against 1.0. Two differences matter
enough that the input shape absorbs them:

1. **No narrative field in SSP requirements.** In 1.1.2 `implemented-requirement` and
   `statement` have no `description`, so `oscal-gen` emits the narrative as an
   `implementation-narrative` prop in your own namespace. Control narratives inside a
   component-definition keep their real `description` field.
2. **`control-implementation` is an object, not an array**, and every
   implemented-requirement must name at least one implementing component via
   `by-components`. Nesting `controls:` under `system.components[]` gives you those
   directly; a top-level control can instead list `components: [Titles]`, and a control
   that does neither is attributed to every declared component.

Also note `system-users` and `inventory-items` moved from `system-characteristics` into
`system-implementation`, and a POA&M's actions are now modelled as risks → remediations →
tasks rather than nested items with deadlines.

### Reproducibility

UUIDs are `uuid5` hashes of their logical identity (party name, control id, component
title), so they are stable across runs, machines, and input reordering. To pin
`metadata.last-modified`, pass `--now` or set it explicitly in `metadata`. Relative
references between generated documents (`import-ssp.href`) are bare filenames, so output
does not depend on where the build ran.

## Python API

```python
from pathlib import Path
from oscalgen import build_all, load_input

paths = build_all(load_input("input.yaml"), out_dir=Path("out"))
```

`build_ssp`, `build_component_definition`, and `build_poam` are also importable from their
respective modules if you only need one document.

## Development

```sh
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
```

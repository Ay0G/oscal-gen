"""Shared fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from oscalgen.spec import Metadata, Org

STARTER = {
    "metadata": {"title": "Test SSP", "version": "1.0.0"},
    "organization": {
        "name": "Acme Corp",
        "short-name": "ACME",
        "prop_ns": "https://acme.example.com/ns",
        "parties": [{"type": "organization", "name": "Acme Corp", "short-name": "ACME"}],
        "roles": [{"id": "system-owner", "title": "System Owner"}],
    },
    "profile": {"href": "https://example.com/profile.json"},
    "system": {
        "name": "Test System",
        "id": [{"identifier-type": "https://acme.example.com/ids/ato", "id": "ATO-1"}],
        "description": "A test system.",
        "security_impact": {
            "confidentiality": "fips199-moderate",
            "integrity": "fips199-moderate",
            "availability": "fips199-low",
        },
        "authorization_boundary": {"description": "The boundary."},
        "information_types": [
            {"title": "Cardholder data", "description": "PAN data.", "props": {"pci": "yes"}}
        ],
        "system_users": [
            {
                "title": "Platform engineers",
                "roles": ["system-owner"],
                "authorized-privileges": [
                    {"title": "Deploy", "functions-performed": ["Deploy the application tier"]}
                ],
            }
        ],
        "components": [
            {
                "title": "API",
                "type": "service",
                "description": "The API.",
            }
        ],
    },
    "controls": [{"id": "ac-2", "status": "implemented", "description": "Narrative."}],
    "components": [
        {
            "title": "API",
            "type": "service",
            "description": "The API.",
            "controls": [{"id": "ac-2", "description": "Component narrative."}],
        }
    ],
    "poam": {
        "items": [
            {
                "title": "A gap",
                "description": "Something is missing.",
                "risks": [
                    {
                        "title": "Risk of the gap",
                        "description": "It is risky.",
                        "statement": "It is risky because reasons.",
                        "status": "open",
                        "deadline": "2026-12-01",
                        "remediations": [
                            {
                                "title": "Fix it",
                                "description": "Do the thing.",
                                "lifecycle": "planned",
                            }
                        ],
                    }
                ],
            }
        ]
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    """Merge ``override`` into a copy of ``base`` (lists are replaced wholesale)."""
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


@pytest.fixture
def spec() -> dict:
    """A minimal-but-complete input, deep-copied per test."""
    return json.loads(json.dumps(STARTER))


@pytest.fixture
def spec_path(tmp_path: Path, spec: dict) -> Path:
    path = tmp_path / "input.yaml"
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return path


@pytest.fixture
def org(spec: dict) -> Org:
    return Org.from_spec(spec)


@pytest.fixture
def meta() -> Metadata:
    return Metadata(title="Test", last_modified="2026-01-01T00:00:00Z")
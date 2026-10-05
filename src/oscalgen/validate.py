"""Schema validation via the installed ``oscal-cli``.

``oscal-cli`` owns the official JSON schemas; we shell out to it rather than
vendoring copies so validation always tracks the schema version installed
locally.  If the binary is missing we still emit documents -- we just warn that
they went unvalidated.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

#: Top-level OSCAL key -> the ``oscal-cli`` subcommand that validates it.
MODEL_COMMANDS = {
    "component-definition": "component-definition",
    "system-security-plan": "ssp",
    "plan-of-action-and-milestones": "poam",
    "assessment-plan": "ap",
    "assessment-results": "ar",
    "catalog": "catalog",
    "profile": "profile",
}


@dataclass
class ValidationResult:
    ok: bool
    checked: list[str]
    errors: list[str]
    skipped: bool = False


def oscal_cli_path() -> str | None:
    return shutil.which("oscal-cli")


def validate_document(path: str | Path) -> ValidationResult:
    """Validate a single OSCAL JSON file written by this tool."""
    p = Path(path)
    exe = oscal_cli_path()
    if exe is None:
        return ValidationResult(
            ok=True,
            checked=[],
            errors=[],
            skipped=True,
        )

    try:
        root = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ValidationResult(False, [], [f"{p.name}: invalid JSON: {exc}"])
    if not isinstance(root, dict) or len(root) != 1:
        return ValidationResult(
            False, [], [f"{p.name}: expected exactly one top-level OSCAL key, got {list(root)}"]
        )

    key = next(iter(root))
    command = MODEL_COMMANDS.get(key)
    if command is None:
        return ValidationResult(
            False, [], [f"{p.name}: unknown OSCAL model {key!r}"]
        )

    proc = subprocess.run(
        [exe, command, "validate", str(p)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return ValidationResult(True, [str(p)], [])

    message = (proc.stdout + proc.stderr).strip()
    return ValidationResult(False, [str(p)], [f"{p.name}: {message}"])


def validate_all(paths: Sequence[str | Path]) -> ValidationResult:
    checked: list[str] = []
    errors: list[str] = []
    skipped = False
    for path in paths:
        result = validate_document(path)
        checked.extend(result.checked)
        errors.extend(result.errors)
        skipped = skipped or result.skipped
    return ValidationResult(not errors, checked, errors, skipped)


def validate_in_memory(document: dict, *, tmp_path: str | Path) -> ValidationResult:
    """Validate a document that has not been written yet."""
    tmp = Path(tmp_path)
    tmp.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return validate_document(tmp)
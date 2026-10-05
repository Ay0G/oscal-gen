"""Generate OSCAL documents from a friendly YAML/JSON description.

Public API::

    from oscalgen import build_all, load_input
    paths = build_all(load_input("input.yaml"), out_dir=Path("out"))
"""

from __future__ import annotations

__version__ = "0.1.0"

from .cli import build_all
from .spec import load_input
from .util import OscalGenError

__all__ = ["OscalGenError", "__version__", "build_all", "load_input"]
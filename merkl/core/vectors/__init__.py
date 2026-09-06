"""Committed test vectors for the Merkl receipt format.

Plain JSON, hex strings, no Python-specific types: every fixture in this package
is meant to be loaded and checked by a second implementation (``@merkl-ai/verify``
in JavaScript) as well as by ``tests/core/test_vectors.py``.

Regenerate with ``python -m merkl.core.vectors.generate``; check without writing
with ``--check``.
"""

from __future__ import annotations

import pathlib
from typing import Final

VECTORS_DIR: Final = pathlib.Path(__file__).parent
"""Directory holding the JSON fixtures."""

VECTOR_FILES: Final[tuple[str, ...]] = (
    "merkle.json",
    "action_leaf.json",
    "receipt_leaf.json",
    "approvals.json",
    "policies.json",
    "receipts.json",
    "verdicts.json",
    "tampered.json",
)

__all__ = ["VECTORS_DIR", "VECTOR_FILES"]

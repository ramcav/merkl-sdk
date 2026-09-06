"""Real proof bundles exported by merkl-api, and mutations of them that must fail.

Committed verbatim rather than synthesized: a fixture the SDK generated would
only prove the SDK agrees with itself. ``cases.json`` records, per bundle, the
check names and statuses both implementations must report.
"""

from __future__ import annotations

import pathlib
from typing import Final

BUNDLES_DIR: Final = pathlib.Path(__file__).parent

BUNDLE_FILES: Final[tuple[str, ...]] = (
    "session-v1.1.json",
    "continuation-v1.1.json",
    "receipts-v1.2.json",
)

__all__ = ["BUNDLES_DIR", "BUNDLE_FILES"]

"""XRPL offline-inclusion vectors: real testnet material, and what it proves.

Different in kind from the rest of ``merkl/core/vectors``, the same way
``vectors/attestation`` is: ``fixtures.json`` is real material captured from
XRPL testnet (a ledger's full binary transaction set, two validators'
``STValidation`` messages and their manifests, and a testnet UNL document from
``vl.altnet.rippletest.net``), committed by hand and never regenerated.
``cases.json`` is derived from it by :mod:`merkl.core.vectors.xrpl.generate`,
which runs :mod:`merkl.core.verify.xrpl` over the fixtures and records what it
found — a second implementation (the JavaScript verifier) passes when it
reproduces the same values from the same fixtures, not when it reaches the same
boolean.

Regenerate with::

    python -m merkl.core.vectors.xrpl.generate
    python -m merkl.core.vectors.xrpl.generate --check
"""

from __future__ import annotations

import pathlib
from typing import Final

XRPL_VECTORS_DIR: Final = pathlib.Path(__file__).parent
FIXTURES_FILE: Final = XRPL_VECTORS_DIR / "fixtures.json"
CASES_FILE: Final = XRPL_VECTORS_DIR / "cases.json"

__all__ = ["CASES_FILE", "FIXTURES_FILE", "XRPL_VECTORS_DIR"]

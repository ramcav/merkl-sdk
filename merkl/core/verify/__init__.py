"""Verifiers: everything a stranger runs to check a receipt without asking us.

Pure like the rest of ``merkl.core``. No network, no clock — ``now`` is an
argument everywhere, so a verification is reproducible and a test can pin a
moment inside a certificate's validity window instead of racing it.

* :mod:`merkl.core.verify.cbor` — the CBOR profile the attestation uses
* :mod:`merkl.core.verify.attestation` — AWS Nitro attestation documents

``docs/ATTESTATION-VERIFY.md`` specifies the same thing byte by byte for the
JavaScript verifier, and ``merkl/core/vectors/attestation/`` holds the fixtures
both implementations must agree on.
"""

from __future__ import annotations

from merkl.core.verify.attestation import (
    NITRO_ROOT_G1_PEM,
    NITRO_ROOT_G1_SHA256,
    AttestationDocument,
    AttestationError,
    AttestationTrust,
    parse_attestation,
    verify_attestation,
)

__all__ = [
    "NITRO_ROOT_G1_PEM",
    "NITRO_ROOT_G1_SHA256",
    "AttestationDocument",
    "AttestationError",
    "AttestationTrust",
    "parse_attestation",
    "verify_attestation",
]

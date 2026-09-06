"""Verifiers: everything a stranger runs to check a receipt without asking us.

Pure like the rest of ``merkl.core``. No network, no clock — ``now`` is an
argument everywhere, so a verification is reproducible and a test can pin a
moment inside a certificate's validity window instead of racing it.

* :mod:`merkl.core.verify.cbor` — the CBOR profile the attestation uses
* :mod:`merkl.core.verify.attestation` — AWS Nitro attestation documents
* :mod:`merkl.core.verify.settlement` — what a settlement capture proves
* :mod:`merkl.core.verify.log` — sessions, the transparency log, evidence
* :mod:`merkl.core.verify.receipt` — the whole verdict: every check, both
  settlement lines, the level. Imported from its own module rather than
  re-exported here: :mod:`merkl.core.receipt` reaches into
  :mod:`~merkl.core.verify.attestation` for check 8, so a package-level import of
  the verdict module would close a cycle between the format and its verifier.
* :mod:`merkl.core.verify.render` — the standalone page, for ``merkl disclose``
  and for merkl-api

``js/merkl-verify.js`` is the same algorithms again in JavaScript, published as
``@merkl/verify``. ``docs/RECEIPT-SPEC.md`` and ``docs/ATTESTATION-VERIFY.md``
specify both byte by byte, and ``merkl/core/vectors/`` holds the fixtures they
must agree on — a divergence between the two is a bug in one of them.
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
from merkl.core.verify.log import LogVerdict, verify_evidence, verify_log_bundle
from merkl.core.verify.render import render_verify_html
from merkl.core.verify.settlement import ValidatorTrust, read_settlement_proof

__all__ = [
    "NITRO_ROOT_G1_PEM",
    "NITRO_ROOT_G1_SHA256",
    "AttestationDocument",
    "AttestationError",
    "AttestationTrust",
    "LogVerdict",
    "ValidatorTrust",
    "parse_attestation",
    "read_settlement_proof",
    "render_verify_html",
    "verify_attestation",
    "verify_evidence",
    "verify_log_bundle",
]

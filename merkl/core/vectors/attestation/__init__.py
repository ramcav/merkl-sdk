"""Attestation vectors: real AWS-signed documents, and what a verifier must say.

These fixtures are different in kind from the rest of ``merkl/core/vectors``.
Everything else in that package is *generated* from Merkl's own encodings, so a
second implementation checking them proves the two agree with each other. These
were produced by AWS hardware and signed by the AWS Nitro Attestation PKI, so a
verifier that passes them proves it agrees with **AWS** — which is the only
agreement that matters for an attestation.

``documents.json`` holds the real documents, base64, with their provenance and
the moment each was produced. It is committed by hand and never regenerated.
``cases.json`` is derived from it — one entry per verification case, tamper cases
included, each with the exact ``now`` to pin and the status every named check
must report. Regenerate with::

    python -m merkl.core.vectors.attestation.generate
    python -m merkl.core.vectors.attestation.generate --check

Every document here has expired. That is the point: a fixture whose validity
window is in the past can only be verified by a verifier that takes ``now`` as an
argument, which is exactly the property ``merkl.core`` promises.
"""

from __future__ import annotations

import pathlib
from typing import Final

ATTESTATION_DIR: Final = pathlib.Path(__file__).parent
DOCUMENTS_FILE: Final = ATTESTATION_DIR / "documents.json"
CASES_FILE: Final = ATTESTATION_DIR / "cases.json"
ROOT_PEM_FILE: Final = ATTESTATION_DIR / "aws-nitro-root-g1.pem"
OTHER_ROOT_PEM_FILE: Final = ATTESTATION_DIR / "not-the-aws-root.pem"

__all__ = [
    "ATTESTATION_DIR",
    "CASES_FILE",
    "DOCUMENTS_FILE",
    "OTHER_ROOT_PEM_FILE",
    "ROOT_PEM_FILE",
]

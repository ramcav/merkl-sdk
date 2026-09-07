"""AWS-specific pieces of the Nitro signer: KMS sealing and the CMS it returns.

Everything here is behind the ``[nitro]`` extra and imported by nothing else.
``merkl.signer`` declares a two-method ``SealingPort`` and never learns which
cloud is behind it — the boundary ``tests/signer/test_signer_purity.py`` enforces
by refusing ``boto3`` anywhere under ``merkl/signer``.

* :mod:`merkl.adapters.nitro.kms` — ``kms:Encrypt`` to seal, ``kms:Decrypt`` with
  the enclave's attestation document as the ``Recipient`` to unseal
* :mod:`merkl.adapters.nitro.cms` — opening the CMS envelope KMS answers with
"""

from __future__ import annotations

from merkl.adapters.nitro.cms import CmsError, decrypt_enveloped_data
from merkl.adapters.nitro.kms import KmsError, KmstoolEnclaveKms, RecipientKms

__all__ = [
    "CmsError",
    "KmsError",
    "KmstoolEnclaveKms",
    "RecipientKms",
    "decrypt_enveloped_data",
]

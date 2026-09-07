"""A SignerPort client for the Nitro parent proxy.

Behaviourally identical to ``signer_dev`` from the caller's side — same contract,
same methods, same shapes — plus the question only an attested signer can answer:
is the thing on the other end the enclave I pinned?
"""

from merkl.adapters.signer_nitro.client import (
    NitroSignerClient,
    UnattestedSignerError,
)

__all__ = ["NitroSignerClient", "UnattestedSignerError"]

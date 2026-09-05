"""``merkl.signer`` — the process that holds the policy key and decides.

Depends on ``merkl.core`` and ``merkl.shared`` and nothing else: no rail client,
no HTTP client, no framework. That is what makes it small enough to audit and
small enough to put inside an enclave in phase 3.

* :mod:`~merkl.signer.keystore` — where the key lives, and never leaves.
* :mod:`~merkl.signer.auth` — agent-signed requests with nonce and expiry (D15).
* :mod:`~merkl.signer.state` — sealed, sequenced rule state (D2).
* :mod:`~merkl.signer.engine` — the authoritative flow (plan section 6).
* :mod:`~merkl.signer.server` — JSON over HTTP on a Unix socket; the same
  contract phase 3 speaks over vsock (``docs/SIGNER-RPC.md``).
"""

from merkl.signer.auth import AuthError, SignedRequest, sign_request, verify_request
from merkl.signer.engine import Clock, SignerEngine, SignerError
from merkl.signer.keystore import DevKeystore, KeystoreError, KeystorePort
from merkl.signer.risk import StaticRiskScorer
from merkl.signer.server import PROTOCOL, RpcRouter, build_server, serve
from merkl.signer.state import SealedStateError, SealedStateStore

__all__ = [
    "PROTOCOL",
    "AuthError",
    "Clock",
    "DevKeystore",
    "KeystoreError",
    "KeystorePort",
    "RpcRouter",
    "SealedStateError",
    "SealedStateStore",
    "SignedRequest",
    "SignerEngine",
    "SignerError",
    "StaticRiskScorer",
    "build_server",
    "serve",
    "sign_request",
    "verify_request",
]

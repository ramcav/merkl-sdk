"""The process inside the enclave. Boots the signer, then answers vsock frames.

Everything in this file is measured into PCR0 by ``nitro-cli build-enclave``, so
it is short on purpose and it does one thing at a time:

1. read configuration from the environment the image was built with — never from
   the parent, because a parent that could hand over a policy or a KMS key id
   could hand over *its* policy and *its* key;
2. ask the parent for the sealed key blob (a ciphertext, and nothing else the
   parent supplies is trusted);
3. open it with KMS, or generate a new key if this is the first boot;
4. verify the pinned policy document's signature and compute its hash;
5. bind the keystore to the policy hash so every attestation says which policy
   this enclave is enforcing;
6. serve the RPC on vsock, forever.

Nothing here prints a key, a seed, or a decision. The log lines are boot
milestones and the public key, which is public.

Not executed: this file needs an NSM device and a KMS key, and the machine it was
written on has neither. ``nitro/README.md`` says exactly which steps were run and
which were not.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from merkl.adapters.nitro.kms import KmstoolEnclaveKms, RecipientKms
from merkl.core.policy.document import SignedPolicy
from merkl.signer.attestation import NitroSecureModule
from merkl.signer.engine import SignerEngine
from merkl.signer.keystore import NitroKeystore
from merkl.signer.server import RpcRouter
from merkl.signer.state import SealedStateStore
from merkl.signer.vsock import DEFAULT_PORT, VMADDR_CID_PARENT, VsockRpcClient, VsockRpcServer

log = logging.getLogger("merkl.enclave")

POLICY_PATH = Path(os.environ.get("MERKL_POLICY_PATH", "/app/policy.json"))
"""Baked into the image, so the policy is measured by the same PCR0 as the code."""

STATE_DIR = Path(os.environ.get("MERKL_STATE_DIR", "/run/merkl"))
"""tmpfs. State that matters is sealed and handed to the parent, not kept here."""

CONTROL_PORT = int(os.environ.get("MERKL_CONTROL_PORT", "5006"))
"""Where the parent listens for the enclave's own requests: blobs and credentials."""


class ParentChannel:
    """The enclave's only way to reach anything, and it trusts none of it.

    Three things come back over this channel and each is safe for a different
    reason. The **sealed key blob** is a ciphertext KMS will only open for an
    enclave with the right measurements, so a parent that substitutes one gets a
    signer that fails to boot rather than one holding a key of the parent's
    choosing. The **credentials** grant nothing on their own: the KMS key policy
    requires an attestation the parent cannot produce. The **state snapshot** is
    sealed under a key derived inside the enclave, and its monotonic sequence
    refuses to move backwards, so replaying an old one is an error rather than a
    way to spend a window twice.
    """

    def __init__(self, cid: int = VMADDR_CID_PARENT, port: int = CONTROL_PORT) -> None:
        self._client = VsockRpcClient(cid=cid, port=port)

    def _result(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        answer = self._client.call(method, params)
        result = answer.get("result")
        if not isinstance(result, dict):
            raise SystemExit(f"the parent answered {method} with no result object")
        return result

    def get(self) -> dict[str, str]:
        """AWS credentials, forwarded by the parent from its instance role."""
        result = self._result("credentials")
        return {
            key: str(result.get(key, ""))
            for key in ("access_key_id", "secret_access_key", "session_token")
        }

    def load(self) -> bytes | None:
        blob = self._result("sealed_key").get("blob")
        return base64.b64decode(str(blob)) if blob else None

    def store(self, blob: bytes) -> None:
        self._result("store_sealed_key", {"blob": base64.b64encode(blob).decode()})


def build_sealing(nsm: NitroSecureModule, parent: ParentChannel) -> Any:
    """Pick a KMS backend. One or the other, and the choice is measured."""
    key_id = _required("MERKL_KMS_KEY_ID")
    region = _required("AWS_REGION")
    backend = os.environ.get("MERKL_KMS_BACKEND", "kmstool")
    if backend == "kmstool":
        return KmstoolEnclaveKms(
            key_id=key_id,
            region=region,
            credentials=parent,
            proxy_port=int(os.environ.get("MERKL_KMS_PROXY_PORT", "8000")),
        )
    if backend == "botocore":
        import boto3  # type: ignore[import-not-found]  # noqa: PLC0415 - this backend only

        credentials = parent.get()
        client = boto3.client(
            "kms",
            region_name=region,
            endpoint_url=os.environ.get("MERKL_KMS_ENDPOINT"),
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_session_token=credentials["session_token"],
        )
        return RecipientKms(client=client, key_id=key_id, nsm=nsm)
    raise SystemExit(f"MERKL_KMS_BACKEND must be kmstool or botocore, not {backend!r}")


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is not set; it belongs in the enclave image, not the parent")
    return value


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    signed_policy = SignedPolicy.from_content(json.loads(POLICY_PATH.read_text()))
    log.info(
        "policy %s pinned, hash %s",
        signed_policy.document.version,
        signed_policy.policy_hash,
    )

    parent = ParentChannel()
    nsm = NitroSecureModule()
    keystore = NitroKeystore(
        sealing=build_sealing(nsm, parent), nsm=nsm, sealed_key=parent
    )
    log.info("policy key ready: %s", keystore.public_key())

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = SealedStateStore(STATE_DIR, signed_policy.document.treasury, keystore.seal_key())
    engine = SignerEngine(policy=signed_policy, keystore=keystore, state=state)
    keystore.bind_policy(lambda: engine.policy_hash)

    port = int(os.environ.get("MERKL_VSOCK_PORT", DEFAULT_PORT))
    server = VsockRpcServer(RpcRouter(engine), port=port)
    log.info("serving merkl-signer-rpc-v1 on vsock port %s", server.port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""KMS, called from inside an enclave, with the attestation as the credential.

This is the implementation of :class:`merkl.signer.keystore.SealingPort`, and it
lives out here rather than in ``merkl.signer`` because ``boto3`` is exactly the
kind of dependency ``tests/signer/test_signer_purity.py`` exists to keep out of
the signer. The signer knows two methods; which cloud is behind them is an
adapter's problem.

## The shape of the trick

An enclave has no credentials, no network and no identity of its own. What it has
is the NSM, which will sign a document saying what is running. So:

1. the enclave generates a throwaway RSA keypair, in memory, per call;
2. it asks the NSM for an attestation document with that public key inside;
3. it calls ``kms:Decrypt`` and passes the document as ``Recipient``;
4. KMS validates the document against the **key policy's** PCR conditions, and if
   they match, returns the plaintext encrypted to the public key from the
   document, as a CMS envelope (``CiphertextForRecipient``, no ``Plaintext``);
5. the enclave opens the envelope with the private half, which never left it.

The parent carries every one of those bytes and can read none of them. It can
refuse to carry them — an enclave with no network is a signer that stops signing,
which is the correct failure — but it cannot substitute a plaintext, because it
cannot produce the CMS envelope without the ephemeral private key, and it cannot
produce an attestation, because it has no NSM.

## The direction that has no attestation

``kms:Encrypt`` takes no ``Recipient``: it returns a ciphertext, which is not a
secret, so there is nothing to protect on the way back. That has a consequence
the key policy has to state, and ``nitro/README.md`` does:
``kms:RecipientAttestation:PCR0`` is only evaluated for ``Decrypt``,
``GenerateDataKey``, ``GenerateDataKeyPair`` and ``GenerateRandom``. Putting the
condition on a statement that also allows ``Encrypt`` denies ``Encrypt``
outright, and a first boot then cannot seal the key it just generated. Two
statements, and the sealing one is deliberately unconditioned.

## Two backends

:class:`KmstoolEnclaveKms` shells out to ``kmstool_enclave_cli``, the binary AWS
ships with ``aws-nitro-enclaves-sdk-c``. It does the ephemeral keypair, the
attestation and the CMS unwrap in C, so the enclave image needs no ``boto3`` and
no Python crypto in that path.

:class:`RecipientKms` does it here, with ``botocore``'s ``Recipient`` parameter
and :mod:`merkl.adapters.nitro.cms`. Fewer moving parts in the image, more code
in the trusted path. Pick one and pin its measurement; do not run both.

**Neither has been executed.** There is no ``nitro-cli``, no NSM and no AWS
account on the machine this was written on. What *has* been executed is the part
that can be: the CMS parser, against envelopes ``openssl cms`` produced
(``tests/adapters/test_cms.py``), and the request shaping here, against a fake
client (``tests/adapters/test_kms.py``). The ioctl and the KMS round trip are
written, not run, and ``nitro/README.md`` says so in the runbook.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from typing import Any, Final, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from merkl.adapters.nitro.cms import decrypt_enveloped_data
from merkl.shared.errors import MerklError
from merkl.signer.attestation import NsmPort

KMSTOOL_PATH: Final = "/app/kmstool_enclave_cli"
DEFAULT_PROXY_PORT: Final = 8000
"""Port the parent's ``vsock-proxy`` listens on, forwarding to the KMS endpoint."""

EPHEMERAL_KEY_BITS: Final = 2048
"""What the NSM's ``public_key`` field can carry, and what KMS wraps to."""

KEY_ENCRYPTION_ALGORITHM: Final = "RSAES_OAEP_SHA_256"


class KmsError(MerklError):
    """KMS refused, or answered something this adapter cannot use."""

    error_code = "keystore_error"


class AwsCredentials(Protocol):
    """Where the enclave's credentials come from: the parent, over vsock.

    An enclave cannot reach IMDS. The parent reads its own instance-role
    credentials and forwards them, which sounds alarming and is not: the key
    policy is what grants the decrypt, and it grants it to *an enclave with these
    measurements*, not to whoever holds the credentials. A parent that keeps the
    credentials for itself still gets ``AccessDeniedException``, because it
    cannot produce an attestation document.
    """

    def get(self) -> dict[str, str]:
        """``access_key_id``, ``secret_access_key``, ``session_token``."""
        ...


class KmstoolEnclaveKms:
    """Seal and unseal through ``kmstool_enclave_cli`` from the AWS Nitro SDK.

    The binary owns the ephemeral keypair, the attestation and the CMS unwrap, so
    the only thing that crosses this boundary is base64 on a pipe. It is in the
    enclave image and therefore measured into PCR0 like everything else.

    Plaintext goes in on **stdin**, never on the command line. Inside an enclave
    there is no other process to read ``/proc``, but a habit that depends on
    there being no other process is a habit that breaks the first time there is
    one.
    """

    def __init__(
        self,
        *,
        key_id: str,
        region: str,
        credentials: AwsCredentials,
        binary: str = KMSTOOL_PATH,
        proxy_port: int = DEFAULT_PROXY_PORT,
        runner: Any = None,
    ) -> None:
        self._key_id = key_id
        self._region = region
        self._credentials = credentials
        self._binary = binary
        self._proxy_port = proxy_port
        self._run = runner or subprocess.run

    def available(self) -> bool:
        """Whether the binary is actually in the image."""
        return shutil.which(self._binary) is not None or _exists(self._binary)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._invoke("encrypt", base64.b64encode(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._invoke("decrypt", base64.b64encode(ciphertext))

    def _invoke(self, action: str, payload_b64: bytes) -> bytes:
        credentials = self._credentials.get()
        command = [
            self._binary,
            action,
            "--region",
            self._region,
            "--proxy-port",
            str(self._proxy_port),
            "--aws-access-key-id",
            credentials["access_key_id"],
            "--aws-secret-access-key",
            credentials["secret_access_key"],
            "--aws-session-token",
            credentials["session_token"],
            "--key-id",
            self._key_id,
        ]
        try:
            completed = self._run(
                command, input=payload_b64, capture_output=True, check=False
            )
        except OSError as exc:
            raise KmsError(f"cannot run {self._binary}: {exc}") from exc
        if completed.returncode != 0:
            raise KmsError(f"kmstool {action} failed: {_tail(completed.stderr)}")
        return _payload(completed.stdout)


def _exists(path: str) -> bool:
    try:
        with open(path, "rb"):
            return True
    except OSError:
        return False


def _tail(stderr: bytes | str | None) -> str:
    """The last line of stderr, and never the stdout that might hold a key."""
    if not stderr:
        return "no stderr"
    text = stderr.decode() if isinstance(stderr, bytes) else stderr
    return text.strip().splitlines()[-1][:200]


def _payload(stdout: bytes | str | None) -> bytes:
    """``kmstool_enclave_cli`` prints ``KEY: <base64>`` or bare base64."""
    if not stdout:
        raise KmsError("kmstool produced no output")
    text = stdout.decode() if isinstance(stdout, bytes) else stdout
    last = text.strip().splitlines()[-1].strip()
    if ":" in last:
        last = last.split(":", 1)[1].strip()
    try:
        return base64.b64decode(last, validate=True)
    except ValueError as exc:
        raise KmsError("kmstool's output is not base64") from exc


class RecipientKms:
    """Seal and unseal with ``botocore`` directly, unwrapping the CMS here.

    One fewer binary in the image, one more parser in the trusted path. The
    ephemeral RSA keypair is generated per call and thrown away with the call, so
    a document from one decrypt cannot be replayed to read another.

    ``client`` is injected rather than built here so the caller decides the
    endpoint. Inside an enclave that endpoint is the parent's ``vsock-proxy``
    (see ``nitro/README.md``), and a client that reached the real internet would
    be a client running somewhere it should not be.
    """

    def __init__(self, *, client: Any, key_id: str, nsm: NsmPort) -> None:
        self._client = client
        self._key_id = key_id
        self._nsm = nsm

    def encrypt(self, plaintext: bytes) -> bytes:
        """``kms:Encrypt``. No ``Recipient``: a ciphertext is not a secret."""
        try:
            response = self._client.encrypt(KeyId=self._key_id, Plaintext=plaintext)
        except Exception as exc:
            raise KmsError(f"kms:Encrypt failed: {type(exc).__name__}") from exc
        blob = response.get("CiphertextBlob")
        if not isinstance(blob, bytes) or not blob:
            raise KmsError("kms:Encrypt returned no ciphertext")
        return blob

    def decrypt(self, ciphertext: bytes) -> bytes:
        """``kms:Decrypt`` with this enclave's attestation as the ``Recipient``."""
        ephemeral = rsa.generate_private_key(public_exponent=65537, key_size=EPHEMERAL_KEY_BITS)
        document = self._nsm.attest(
            public_key=ephemeral.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        try:
            response = self._client.decrypt(
                KeyId=self._key_id,
                CiphertextBlob=ciphertext,
                Recipient={
                    "KeyEncryptionAlgorithm": KEY_ENCRYPTION_ALGORITHM,
                    "AttestationDocument": document,
                },
            )
        except Exception as exc:
            raise KmsError(
                f"kms:Decrypt failed: {type(exc).__name__}. If this is AccessDenied, the key "
                "policy's kms:RecipientAttestation PCR conditions do not match this enclave"
            ) from exc
        if response.get("Plaintext"):
            raise KmsError(
                "KMS returned a bare Plaintext, which means the Recipient was ignored and the "
                "parent could have read it; refusing to use it"
            )
        envelope = response.get("CiphertextForRecipient")
        if not isinstance(envelope, bytes) or not envelope:
            raise KmsError("kms:Decrypt returned no CiphertextForRecipient")
        return decrypt_enveloped_data(envelope, ephemeral)

"""What the KMS adapters send, and what they refuse to accept back.

The round trip cannot run here: there is no NSM to produce an attestation and no
AWS account to accept one. What can run is everything on this side of the wire —
which parameters go out, what happens when they come back wrong, and whether a
secret can end up somewhere it should not. Those are the failures that would
otherwise be found in production, at the worst moment, by an enclave that will
not boot.

The one test that is not about plumbing is
``test_a_bare_plaintext_response_is_refused``. If KMS ever answered with
``Plaintext`` instead of ``CiphertextForRecipient`` — an old botocore, a
misconfigured endpoint, a parent that rewrote the request — the plaintext would
have crossed the parent in the clear. Using it anyway would work perfectly and
silently give away the property the whole enclave exists to provide.
"""

from __future__ import annotations

import base64
import subprocess
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from merkl.adapters.nitro.kms import (
    KEY_ENCRYPTION_ALGORITHM,
    KmsError,
    KmstoolEnclaveKms,
    RecipientKms,
)

SEED = bytes(range(32))
KEY_ID = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"


class Credentials:
    def get(self) -> dict[str, str]:
        return {
            "access_key_id": "ASIAEXAMPLE",
            "secret_access_key": "secret",
            "session_token": "token",
        }


class FakeNsm:
    """Records the public key it was asked to attest; returns opaque bytes."""

    def __init__(self) -> None:
        self.attested: list[bytes | None] = []

    def attest(
        self,
        *,
        public_key: bytes | None = None,
        user_data: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        self.attested.append(public_key)
        return b"cbor-attestation-document"

    def random(self, count: int) -> bytes:  # pragma: no cover - unused here
        return bytes(count)


# --------------------------------------------------------------------------- #
# kmstool_enclave_cli
# --------------------------------------------------------------------------- #


class FakeRunner:
    """Stands in for ``subprocess.run``, remembering the command and stdin."""

    def __init__(self, stdout: bytes = b"", returncode: int = 0, stderr: bytes = b"") -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.command: list[str] = []
        self.stdin: bytes | None = None

    def __call__(self, command: list[str], **kwargs: Any) -> Any:
        self.command = command
        self.stdin = kwargs.get("input")
        return subprocess.CompletedProcess(command, self.returncode, self.stdout, self.stderr)


def kmstool(runner: FakeRunner) -> KmstoolEnclaveKms:
    return KmstoolEnclaveKms(
        key_id=KEY_ID, region="us-east-1", credentials=Credentials(), runner=runner
    )


def test_the_plaintext_goes_in_on_stdin_and_never_on_the_command_line() -> None:
    """``/proc/<pid>/cmdline`` is readable. Habits that assume otherwise break."""
    runner = FakeRunner(stdout=b"CIPHERTEXT: " + base64.b64encode(b"sealed"))
    kmstool(runner).encrypt(SEED)
    assert runner.stdin == base64.b64encode(SEED)
    joined = " ".join(runner.command)
    assert base64.b64encode(SEED).decode() not in joined
    assert SEED.hex() not in joined


def test_the_command_carries_the_key_the_region_and_the_proxy_port() -> None:
    runner = FakeRunner(stdout=base64.b64encode(b"sealed"))
    kmstool(runner).encrypt(SEED)
    assert "--key-id" in runner.command
    assert KEY_ID in runner.command
    assert "us-east-1" in runner.command
    assert "8000" in runner.command


def test_a_prefixed_output_line_is_parsed() -> None:
    runner = FakeRunner(stdout=b"noise\nCIPHERTEXT: " + base64.b64encode(b"sealed") + b"\n")
    assert kmstool(runner).encrypt(SEED) == b"sealed"


def test_a_bare_base64_line_is_parsed_too() -> None:
    runner = FakeRunner(stdout=base64.b64encode(b"opened") + b"\n")
    assert kmstool(runner).decrypt(b"blob") == b"opened"


def test_a_nonzero_exit_is_an_error_carrying_only_stderr() -> None:
    runner = FakeRunner(
        stdout=base64.b64encode(SEED), returncode=1, stderr=b"line\nAccessDeniedException"
    )
    with pytest.raises(KmsError) as raised:
        kmstool(runner).decrypt(b"blob")
    assert "AccessDeniedException" in str(raised.value)
    assert base64.b64encode(SEED).decode() not in str(raised.value)


def test_output_that_is_not_base64_is_an_error() -> None:
    with pytest.raises(KmsError, match="not base64"):
        kmstool(FakeRunner(stdout=b"not base64 at all !!")).encrypt(SEED)


def test_no_output_is_an_error() -> None:
    with pytest.raises(KmsError, match="no output"):
        kmstool(FakeRunner(stdout=b"")).encrypt(SEED)


def test_a_missing_binary_is_an_error_naming_it() -> None:
    class Missing:
        def __call__(self, command: list[str], **kwargs: Any) -> Any:
            raise OSError("No such file or directory")

    keystore = KmstoolEnclaveKms(
        key_id=KEY_ID, region="us-east-1", credentials=Credentials(), runner=Missing()
    )
    with pytest.raises(KmsError, match="kmstool_enclave_cli"):
        keystore.encrypt(SEED)


# --------------------------------------------------------------------------- #
# botocore with Recipient
# --------------------------------------------------------------------------- #


class FakeKmsClient:
    """A KMS that wraps the plaintext to the attested key, like the real one."""

    def __init__(self) -> None:
        self.store: dict[bytes, bytes] = {}
        self.decrypt_kwargs: dict[str, Any] = {}
        self.envelope: bytes | None = None
        self.plaintext_instead: bytes | None = None

    def encrypt(self, **kwargs: Any) -> dict[str, Any]:
        blob = b"blob:" + kwargs["Plaintext"]
        self.store[blob] = kwargs["Plaintext"]
        return {"CiphertextBlob": blob}

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.decrypt_kwargs = kwargs
        if self.plaintext_instead is not None:
            return {"Plaintext": self.plaintext_instead}
        return {"CiphertextForRecipient": self.envelope or b""}


def test_encrypt_sends_no_recipient_because_a_ciphertext_is_not_a_secret() -> None:
    client = FakeKmsClient()
    sealed = RecipientKms(client=client, key_id=KEY_ID, nsm=FakeNsm()).encrypt(SEED)
    assert sealed == b"blob:" + SEED


def test_encrypt_refuses_an_empty_ciphertext() -> None:
    class Empty(FakeKmsClient):
        def encrypt(self, **kwargs: Any) -> dict[str, Any]:
            return {}

    with pytest.raises(KmsError, match="no ciphertext"):
        RecipientKms(client=Empty(), key_id=KEY_ID, nsm=FakeNsm()).encrypt(SEED)


def test_decrypt_attests_the_ephemeral_key_it_just_made() -> None:
    """The document has to name *this* keypair, or KMS wraps to somebody else's."""
    nsm = FakeNsm()
    client = FakeKmsClient()
    kms = RecipientKms(client=client, key_id=KEY_ID, nsm=nsm)
    with pytest.raises(KmsError):
        kms.decrypt(b"blob")
    assert len(nsm.attested) == 1
    attested = nsm.attested[0]
    assert attested is not None
    loaded = serialization.load_der_public_key(attested)
    assert isinstance(loaded, rsa.RSAPublicKey)
    assert loaded.key_size == 2048

    assert client.decrypt_kwargs["Recipient"] == {
        "KeyEncryptionAlgorithm": KEY_ENCRYPTION_ALGORITHM,
        "AttestationDocument": b"cbor-attestation-document",
    }
    assert client.decrypt_kwargs["CiphertextBlob"] == b"blob"


def test_a_fresh_keypair_per_call_so_one_document_cannot_be_replayed() -> None:
    nsm = FakeNsm()
    kms = RecipientKms(client=FakeKmsClient(), key_id=KEY_ID, nsm=nsm)
    for _ in range(2):
        with pytest.raises(KmsError):
            kms.decrypt(b"blob")
    assert nsm.attested[0] != nsm.attested[1]


def test_a_bare_plaintext_response_is_refused() -> None:
    """It would work, and the parent would have seen the key on the way through."""
    client = FakeKmsClient()
    client.plaintext_instead = SEED
    with pytest.raises(KmsError, match="parent could have read it"):
        RecipientKms(client=client, key_id=KEY_ID, nsm=FakeNsm()).decrypt(b"blob")


def test_an_access_denied_says_where_to_look() -> None:
    class Denied(FakeKmsClient):
        def decrypt(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("AccessDeniedException")

    with pytest.raises(KmsError, match="RecipientAttestation"):
        RecipientKms(client=Denied(), key_id=KEY_ID, nsm=FakeNsm()).decrypt(b"blob")

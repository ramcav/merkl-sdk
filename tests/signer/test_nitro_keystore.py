"""The enclave keystore and the NSM client.

What can be executed on a machine that is not an enclave: the CBOR framing the
NSM speaks, the ioctl request number, the key lifecycle (generate, seal, hand to
the parent, open again next boot), the state-seal derivation, and the leaf-3
content. What cannot: the ``ioctl`` itself, and KMS. Both are behind ports, and
the ports are what these tests drive.

The fake NSM here signs with a throwaway PKI (``tests/nitro_factory.py``), so the
documents it produces are real COSE_Sign1 messages with a real ES384 signature —
just not AWS's. That is enough to prove the keystore puts the right key and the
right policy hash in the right fields, which is the part this module owns.
"""

from __future__ import annotations

import base64
import datetime

import pytest

from merkl.core.verify import cbor
from merkl.core.verify.attestation import AttestationTrust, parse_attestation, verify_attestation
from merkl.signer.attestation import (
    NSM_IOCTL,
    NsmError,
    attestation_content,
    decode_response,
)
from merkl.signer.keystore import DevKeystore, KeystoreError, NitroKeystore
from tests.nitro_factory import PRODUCTION_PCRS, fake_attestation, fake_pki

AT = datetime.datetime(2026, 4, 1, 9, 30, tzinfo=datetime.UTC)
PKI = fake_pki(
    valid_from=AT - datetime.timedelta(hours=1), valid_to=AT + datetime.timedelta(hours=2)
)
POLICY_HASH = "ab" * 32


# --------------------------------------------------------------------------- #
# Doubles
# --------------------------------------------------------------------------- #


class FakeNsm:
    """An NSM that signs with the test PKI and records what it was asked for."""

    def __init__(self) -> None:
        self.calls: list[dict[str, bytes | None]] = []
        self.entropy_requests: list[int] = []

    def attest(
        self,
        *,
        public_key: bytes | None = None,
        user_data: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        self.calls.append({"public_key": public_key, "user_data": user_data, "nonce": nonce})
        return fake_attestation(
            PKI, at=AT, public_key=public_key, user_data=user_data, nonce=nonce
        )

    def random(self, count: int) -> bytes:
        self.entropy_requests.append(count)
        return bytes((i * 7 + 3) % 256 for i in range(count))


class FakeKms:
    """A sealing port that is honest about one thing: it is not reversible by
    anyone who cannot call ``decrypt``."""

    def __init__(self) -> None:
        self.sealed: bytes | None = None
        self.refuse = False

    def encrypt(self, plaintext: bytes) -> bytes:
        return b"kms:" + plaintext[::-1]

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.refuse:
            raise RuntimeError("AccessDeniedException: PCR0 does not match")
        if not ciphertext.startswith(b"kms:"):
            raise ValueError("not a ciphertext from this key")
        return ciphertext[4:][::-1]


class MemoryBlob:
    """Stands in for the parent's disk."""

    def __init__(self, blob: bytes | None = None) -> None:
        self.blob = blob
        self.writes = 0

    def load(self) -> bytes | None:
        return self.blob

    def store(self, blob: bytes) -> None:
        self.blob = blob
        self.writes += 1


def build(blob: MemoryBlob | None = None, nsm: FakeNsm | None = None) -> NitroKeystore:
    keystore = NitroKeystore(
        sealing=FakeKms(),
        nsm=nsm or FakeNsm(),
        sealed_key=blob or MemoryBlob(),
        policy_hash=lambda: POLICY_HASH,
    )
    return keystore


# --------------------------------------------------------------------------- #
# The NSM wire format
# --------------------------------------------------------------------------- #


def test_the_ioctl_number_is_the_drivers() -> None:
    """_IOWR(0x0A, 0, sizeof(struct nsm_message)) on 64-bit Linux."""
    assert NSM_IOCTL == 0xC0200A00


def test_an_attestation_response_decodes() -> None:
    raw = cbor.encode({"Attestation": {"document": b"\x84\x40\xa0\x40\x40"}})
    assert decode_response(raw) == {"Attestation": {"document": b"\x84\x40\xa0\x40\x40"}}


def test_an_error_response_becomes_an_exception() -> None:
    with pytest.raises(NsmError, match="InvalidArgument"):
        decode_response(cbor.encode({"Error": "InvalidArgument"}))


@pytest.mark.parametrize(
    "raw",
    [b"", b"\xff", cbor.encode("GetRandom"), cbor.encode({"a": 1, "b": 2}), cbor.encode([1])],
)
def test_a_response_that_is_not_a_single_variant_is_refused(raw: bytes) -> None:
    with pytest.raises(NsmError):
        decode_response(raw)


def test_the_device_is_not_there_on_a_laptop() -> None:
    from merkl.signer.attestation import NitroSecureModule

    with pytest.raises(NsmError, match="not running inside a Nitro Enclave"):
        NitroSecureModule("/dev/definitely-not-nsm")


def test_leaf_three_content_is_the_frozen_shape() -> None:
    content = attestation_content(b"\x01\x02", "ab" * 32)
    assert content == {
        "format": "aws-nitro",
        "document": base64.b64encode(b"\x01\x02").decode(),
        "policy_public_key": "ab" * 32,
    }


# --------------------------------------------------------------------------- #
# The key lifecycle
# --------------------------------------------------------------------------- #


def test_first_boot_generates_the_key_and_hands_the_parent_a_ciphertext() -> None:
    blob = MemoryBlob()
    keystore = build(blob)
    assert blob.writes == 1
    assert blob.blob is not None
    assert keystore.public_key() not in blob.blob.hex()


def test_the_seed_mixes_the_nsm_with_the_process_csprng() -> None:
    """A fault in either source still leaves the other's unpredictability."""
    nsm = FakeNsm()
    first = build(MemoryBlob(), nsm).public_key()
    second = build(MemoryBlob(), FakeNsm()).public_key()
    assert nsm.entropy_requests == [32]
    assert first != second


def test_a_later_boot_opens_the_same_key() -> None:
    blob = MemoryBlob()
    first = build(blob)
    second = build(blob)
    assert second.public_key() == first.public_key()
    assert blob.writes == 1


def test_an_enclave_that_measures_differently_cannot_open_the_blob() -> None:
    blob = MemoryBlob()
    build(blob)
    sealing = FakeKms()
    sealing.refuse = True
    with pytest.raises(KeystoreError, match="does not measure the same"):
        NitroKeystore(sealing=sealing, nsm=FakeNsm(), sealed_key=blob)


def test_a_damaged_blob_is_refused_rather_than_guessed_at() -> None:
    with pytest.raises(KeystoreError):
        NitroKeystore(sealing=FakeKms(), nsm=FakeNsm(), sealed_key=MemoryBlob(b"kms:short"))


def test_the_signature_verifies_under_the_public_key() -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    keystore = build()
    message = b"merkl-signer-test"
    public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(keystore.public_key()))
    public.verify(bytes.fromhex(keystore.sign(message)), message)


def test_the_state_seal_key_is_stable_across_boots_and_unlike_the_signing_key() -> None:
    blob = MemoryBlob()
    first = build(blob)
    second = build(blob)
    assert first.seal_key() == second.seal_key()
    assert len(first.seal_key()) == 32
    assert first.seal_key().hex() != first.public_key()


def test_the_seal_key_differs_between_keystores() -> None:
    assert build().seal_key() != build().seal_key()


def test_nothing_in_the_repr_is_a_secret() -> None:
    keystore = build()
    assert keystore.public_key()[:16] in repr(keystore)
    assert len(repr(keystore)) < 80


# --------------------------------------------------------------------------- #
# Attestation
# --------------------------------------------------------------------------- #


def test_attestation_binds_the_policy_key_and_the_policy_hash() -> None:
    nsm = FakeNsm()
    keystore = build(nsm=nsm)
    content = keystore.attestation()
    assert isinstance(content, dict)
    assert content["policy_public_key"] == keystore.public_key()
    assert nsm.calls[-1]["public_key"] == bytes.fromhex(keystore.public_key())
    assert nsm.calls[-1]["user_data"] == bytes.fromhex(POLICY_HASH)


def test_the_document_it_produces_verifies_against_its_own_pki() -> None:
    keystore = build()
    content = keystore.attestation()
    assert isinstance(content, dict)
    document = base64.b64decode(str(content["document"]))
    result = verify_attestation(
        document,
        trust=AttestationTrust(
            pcrs={i: PRODUCTION_PCRS[i].hex() for i in (0, 1, 2, 8)}, root_pem=PKI.root_pem
        ),
        now=AT + datetime.timedelta(seconds=5),
        expected_public_key=bytes.fromhex(keystore.public_key()),
        expected_user_data=bytes.fromhex(POLICY_HASH),
    )
    assert result.ok and result.complete, [(c.name, c.detail) for c in result.checks]


def test_every_call_asks_for_a_fresh_document() -> None:
    """An attestation is a statement about a moment, so it is not cached."""
    nsm = FakeNsm()
    keystore = build(nsm=nsm)
    keystore.attestation()
    keystore.attestation()
    assert len(nsm.calls) == 2


def test_a_policy_update_reaches_the_next_attestation() -> None:
    """Bound as a callable, so nothing has to remember to re-bind after D16."""
    current = {"hash": POLICY_HASH}
    keystore = NitroKeystore(
        sealing=FakeKms(),
        nsm=FakeNsm(),
        sealed_key=MemoryBlob(),
        policy_hash=lambda: current["hash"],
    )
    first = keystore.attestation()
    current["hash"] = "cd" * 32
    second = keystore.attestation()
    assert isinstance(first, dict) and isinstance(second, dict)
    first_doc = parse_attestation(base64.b64decode(str(first["document"])))
    second_doc = parse_attestation(base64.b64decode(str(second["document"])))
    assert first_doc.user_data == bytes.fromhex(POLICY_HASH)
    assert second_doc.user_data == bytes.fromhex("cd" * 32)


def test_an_unbound_keystore_attests_without_user_data_rather_than_inventing_one() -> None:
    keystore = NitroKeystore(sealing=FakeKms(), nsm=FakeNsm(), sealed_key=MemoryBlob())
    content = keystore.attestation()
    assert isinstance(content, dict)
    document = parse_attestation(base64.b64decode(str(content["document"])))
    assert document.user_data is None


def test_bind_policy_can_be_called_after_the_engine_exists() -> None:
    keystore = NitroKeystore(sealing=FakeKms(), nsm=FakeNsm(), sealed_key=MemoryBlob())
    keystore.bind_policy(lambda: POLICY_HASH)
    content = keystore.attestation()
    assert isinstance(content, dict)
    document = parse_attestation(base64.b64decode(str(content["document"])))
    assert document.user_data == bytes.fromhex(POLICY_HASH)


def test_the_dev_keystore_still_reports_no_attestation(tmp_path: object) -> None:
    """Phase 3 must not quietly attest a dev signer (plan D3)."""
    keystore = DevKeystore(str(tmp_path), passphrase="test")
    assert keystore.attestation() is None

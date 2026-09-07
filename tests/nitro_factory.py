"""Build a Nitro-shaped attestation document, signed by a throwaway PKI.

Deliberately in ``tests/`` and not in the package. This forges documents: the
only thing separating one of these from a real attestation is which root you pin,
and code that manufactures attestations does not belong in a library whose whole
job is deciding whether to believe one.

What it is for, and what it is not:

* **is for** — the receipt-level wiring (does leaf 3 reach the verifier with the
  right key and policy hash?) and the signer-side NSM client, neither of which
  can use a real document: a real one vouches for a key AWS's hardware held in
  2022, and a receipt under test needs one that vouches for the key in *its*
  envelope.
* **is not for** — proving the verifier works. That is
  ``tests/core/test_attestation.py``, against documents AWS actually signed. A
  verifier checked only against documents its own test suite produced proves
  that the suite agrees with itself.

Every document this makes chains to a root generated here and thrown away, so it
verifies only when a caller explicitly pins that root. Against the real AWS root
— which is the default everywhere in the package — it fails at the chain check.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from merkl.core.verify import cbor

PRODUCTION_PCRS: dict[int, bytes] = {
    0: bytes(range(1, 49)),
    1: bytes(range(51, 99)),
    2: bytes(range(101, 149)),
    3: bytes(48),
    4: bytes(48),
    8: bytes(range(151, 199)),
}
"""Plausible non-zero measurements, so ``debug_mode`` reads as production."""

DEBUG_PCRS: dict[int, bytes] = {index: bytes(48) for index in (0, 1, 2, 3, 4, 8)}


@dataclass(frozen=True)
class FakeNitroPki:
    """A root, an intermediate and an NSM leaf, all P-384, all made here."""

    root_pem: str
    root_der: bytes
    intermediate_der: bytes
    leaf_der: bytes
    leaf_key: ec.EllipticCurvePrivateKey

    @property
    def cabundle(self) -> list[bytes]:
        return [self.root_der, self.intermediate_der]


def _certificate(
    subject: str,
    issuer_name: x509.Name | None,
    key: ec.EllipticCurvePrivateKey,
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    ca: bool,
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(signing_key, hashes.SHA384())


def fake_pki(
    *,
    valid_from: datetime.datetime,
    valid_to: datetime.datetime,
) -> FakeNitroPki:
    """A three-certificate chain whose leaf is valid for the given window."""
    root_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())

    root = _certificate(
        "test.nitro-enclaves",
        None,
        root_key,
        root_key,
        not_before=valid_from - datetime.timedelta(days=365),
        not_after=valid_to + datetime.timedelta(days=365),
        ca=True,
    )
    intermediate = _certificate(
        "test-zone.nitro-enclaves",
        root.subject,
        intermediate_key,
        root_key,
        not_before=valid_from - datetime.timedelta(days=30),
        not_after=valid_to + datetime.timedelta(days=30),
        ca=True,
    )
    leaf = _certificate(
        "i-test-enc.nitro-enclaves",
        intermediate.subject,
        leaf_key,
        intermediate_key,
        not_before=valid_from,
        not_after=valid_to,
        ca=False,
    )
    return FakeNitroPki(
        root_pem=root.public_bytes(serialization.Encoding.PEM).decode(),
        root_der=root.public_bytes(serialization.Encoding.DER),
        intermediate_der=intermediate.public_bytes(serialization.Encoding.DER),
        leaf_der=leaf.public_bytes(serialization.Encoding.DER),
        leaf_key=leaf_key,
    )


def fake_attestation(
    pki: FakeNitroPki,
    *,
    at: datetime.datetime,
    public_key: bytes | None = None,
    user_data: bytes | None = None,
    nonce: bytes | None = None,
    pcrs: dict[int, bytes] | None = None,
    module_id: str = "i-test-enc0000000000000000",
) -> bytes:
    """A COSE_Sign1 in the NSM's shape, signed by ``pki``'s leaf key."""
    payload = cbor.encode(
        {
            "module_id": module_id,
            "digest": "SHA384",
            "timestamp": int(at.timestamp() * 1000),
            "pcrs": {index: value for index, value in sorted((pcrs or PRODUCTION_PCRS).items())},
            "certificate": pki.leaf_der,
            "cabundle": list(pki.cabundle),
            "public_key": public_key,
            "user_data": user_data,
            "nonce": nonce,
        }
    )
    protected = cbor.encode({1: -35})
    sig_structure = cbor.encode(["Signature1", protected, b"", payload])
    der = pki.leaf_key.sign(sig_structure, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return cbor.encode([protected, {}, payload, signature])

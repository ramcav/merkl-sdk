"""Verify an AWS Nitro Enclaves attestation document. Pure, offline, per check.

Leaf 3 of a receipt says *what code held the policy key*. On its own that is a
claim; this module is what turns it into evidence. It takes the CBOR document the
Nitro Secure Module produced, and answers, separately and by name:

* is this a COSE_Sign1 signed with ES384, the only shape the NSM emits;
* does its certificate chain reach **the** AWS Nitro Attestation PKI root — the
  one published at ``https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip``
  and embedded below, not a root the document brought with it;
* was every certificate in that chain valid at the moment the document claims;
* does the ES384 signature verify under the leaf certificate's P-384 key;
* is the document recent enough for the caller to care about;
* do its PCRs match the allowlist **the verifier pinned**, not one the document
  suggests;
* was the enclave built in production mode (a debug enclave reports PCR0 as
  forty-eight zero bytes, and its measurements mean nothing);
* is the key the document vouches for the key that signed the receipt, and is the
  policy it names the policy the receipt was decided under.

Two rules shape the interface.

**Nothing is read from a clock.** ``now`` is an argument. A verifier that reads
the wall clock cannot be tested against a real attestation document, because a
real one expires — the fixtures in ``merkl/core/vectors/attestation/`` are from
2022 and 2023, and pinning ``now`` inside their windows is how the signature and
chain logic get exercised against bytes AWS actually signed.

**An absent input is never a pass.** No allowlist pinned, no document, a format
this verifier does not know: each reports ``not_implemented`` by name. The reader
is told which questions went unanswered rather than shown a verdict that quietly
skipped them.

The trust anchor is embedded rather than fetched. A verifier that downloads its
own root at verification time trusts whoever answers the request.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from merkl.core.canonical import ContentError
from merkl.core.checks import Check, CheckStatus, VerificationResult, no_data, outcome
from merkl.core.verify import cbor

__all__ = [
    "ATTESTATION_FORMATS",
    "CHECK_CHAIN",
    "CHECK_CERT_VALIDITY",
    "CHECK_DEBUG_MODE",
    "CHECK_FORMAT",
    "CHECK_PCRS",
    "CHECK_PUBLIC_KEY",
    "CHECK_SIGNATURE",
    "CHECK_TIMESTAMP",
    "CHECK_USER_DATA",
    "NITRO_ROOT_G1_PEM",
    "NITRO_ROOT_G1_SHA256",
    "NITRO_ROOT_G1_ZIP_SHA256",
    "PCR_LENGTHS",
    "AttestationDocument",
    "AttestationError",
    "AttestationTrust",
    "parse_attestation",
    "verify_attestation",
]

NITRO_ROOT_G1_PEM: Final = """-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
"""
"""The AWS Nitro Attestation PKI root, G1. Valid 2019-10-28 to 2049-10-28.

Published by AWS as a zip at
``https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip``, whose
SHA-256 AWS documents alongside it (see :data:`NITRO_ROOT_G1_ZIP_SHA256`).
Embedding it is the point: a verifier that fetches its own trust anchor at
verification time trusts whoever answered the request.
"""

NITRO_ROOT_G1_SHA256: Final = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
"""SHA-256 of the root certificate's DER encoding. Checked at import."""

NITRO_ROOT_G1_ZIP_SHA256: Final = (
    "8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c"
)
"""SHA-256 of the published zip, as AWS documents it. Recorded, not checked here.

Re-verify with::

    curl -sO https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
    shasum -a 256 AWS_NitroEnclaves_Root-G1.zip
"""

ATTESTATION_FORMATS: Final[frozenset[str]] = frozenset({"aws-nitro", "aws-nitro-v1"})
"""Leaf-3 ``format`` tokens this verifier knows. ``aws-nitro`` is the canonical one."""

COSE_ES384: Final = -35
"""RFC 9053 §2.1: ECDSA with SHA-384, the only algorithm the NSM signs with."""

PCR_LENGTHS: Final[frozenset[int]] = frozenset({32, 48, 64})
"""SHA-256, SHA-384 or SHA-512 measurements. The NSM emits SHA-384 (48 bytes)."""

MAX_PCR_INDEX: Final = 31
MAX_CHAIN_LENGTH: Final = 16
DEFAULT_MAX_AGE_SECONDS: Final = 300

CHECK_FORMAT: Final = "attestation.format"
CHECK_CHAIN: Final = "attestation.certificate_chain"
CHECK_CERT_VALIDITY: Final = "attestation.certificate_validity"
CHECK_SIGNATURE: Final = "attestation.signature"
CHECK_TIMESTAMP: Final = "attestation.timestamp"
CHECK_PCRS: Final = "attestation.pcrs"
CHECK_DEBUG_MODE: Final = "attestation.debug_mode"
CHECK_PUBLIC_KEY: Final = "attestation.public_key"
CHECK_USER_DATA: Final = "attestation.user_data"

ATTESTATION_CHECKS: Final[tuple[str, ...]] = (
    CHECK_FORMAT,
    CHECK_CHAIN,
    CHECK_CERT_VALIDITY,
    CHECK_SIGNATURE,
    CHECK_TIMESTAMP,
    CHECK_PCRS,
    CHECK_DEBUG_MODE,
    CHECK_PUBLIC_KEY,
    CHECK_USER_DATA,
)
"""Every check this module reports, in the order it reports them."""


class AttestationError(ContentError):
    """The bytes are not an attestation document this verifier can read."""

    error_code = "content_error"


# --------------------------------------------------------------------------- #
# The parsed document
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AttestationDocument:
    """The NSM's payload, decoded. Nothing here has been checked yet.

    Parsing and verifying are separate on purpose: a caller that wants to *look*
    at a document — print its PCRs, show its module id — should not have to
    pretend to trust it first, and a verifier that could only report a boolean
    would be no use to a person reading a receipt.
    """

    module_id: str
    digest: str
    timestamp_ms: int
    pcrs: Mapping[int, bytes]
    certificate: bytes
    cabundle: tuple[bytes, ...]
    public_key: bytes | None
    user_data: bytes | None
    nonce: bytes | None
    protected: bytes
    payload: bytes
    signature: bytes

    @property
    def timestamp(self) -> datetime.datetime:
        """When the NSM says it produced this document, UTC."""
        return datetime.datetime.fromtimestamp(self.timestamp_ms / 1000, datetime.UTC)

    @property
    def debug_mode(self) -> bool:
        """True when PCR0 is all zeros, which is what a debug enclave reports.

        A debug enclave's measurements are meaningless — it can be started with
        any image and its console is readable from the parent — so this is the
        single most important thing to notice about a document.
        """
        pcr0 = self.pcrs.get(0)
        return pcr0 is not None and not any(pcr0)

    def pcr_hex(self) -> dict[str, str]:
        """PCRs as ``{"0": "<hex>", …}``, for display and for pinning."""
        return {str(index): value.hex() for index, value in sorted(self.pcrs.items())}

    def sig_structure(self) -> bytes:
        """RFC 9052 §4.4: the bytes the signature is actually over.

        ``["Signature1", protected, external_aad, payload]`` re-encoded as CBOR.
        Rebuilding it rather than trusting an offset is what makes the check
        meaningful — a document whose payload was swapped produces a different
        ``Sig_structure`` and fails here.
        """
        return cbor.encode(["Signature1", self.protected, b"", self.payload])


def parse_attestation(document: bytes) -> AttestationDocument:
    """Decode COSE_Sign1 and its CBOR payload. Raises on anything malformed."""
    try:
        message = cbor.loads(document)
    except cbor.CborError as exc:
        raise AttestationError(f"attestation document is not CBOR: {exc}") from exc
    if not isinstance(message, list) or len(message) != 4:
        raise AttestationError("attestation document is not a four-element COSE_Sign1")
    protected, unprotected, payload, signature = message
    if not isinstance(protected, bytes) or not isinstance(payload, bytes):
        raise AttestationError("COSE_Sign1 protected header and payload must be byte strings")
    if not isinstance(signature, bytes):
        raise AttestationError("COSE_Sign1 signature must be a byte string")
    if not isinstance(unprotected, dict):
        raise AttestationError("COSE_Sign1 unprotected header must be a map")

    body = _payload_map(payload)
    return AttestationDocument(
        module_id=_text(body, "module_id"),
        digest=_text(body, "digest"),
        timestamp_ms=_timestamp(body),
        pcrs=_pcrs(body),
        certificate=_bytes(body, "certificate"),
        cabundle=_cabundle(body),
        public_key=_optional_bytes(body, "public_key"),
        user_data=_optional_bytes(body, "user_data"),
        nonce=_optional_bytes(body, "nonce"),
        protected=protected,
        payload=payload,
        signature=signature,
    )


def _payload_map(payload: bytes) -> Mapping[int | str, Any]:
    try:
        body = cbor.loads(payload)
    except cbor.CborError as exc:
        raise AttestationError(f"attestation payload is not CBOR: {exc}") from exc
    if not isinstance(body, dict):
        raise AttestationError("attestation payload is not a CBOR map")
    return body


def _text(body: Mapping[int | str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise AttestationError(f"attestation {key} must be a non-empty text string")
    return value


def _bytes(body: Mapping[int | str, Any], key: str) -> bytes:
    value = body.get(key)
    if not isinstance(value, bytes) or not value:
        raise AttestationError(f"attestation {key} must be a non-empty byte string")
    return value


def _optional_bytes(body: Mapping[int | str, Any], key: str) -> bytes | None:
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, bytes):
        raise AttestationError(f"attestation {key} must be a byte string or null")
    return value


def _timestamp(body: Mapping[int | str, Any]) -> int:
    value = body.get("timestamp")
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise AttestationError("attestation timestamp must be a positive integer")
    return value


def _pcrs(body: Mapping[int | str, Any]) -> Mapping[int, bytes]:
    value = body.get("pcrs")
    if not isinstance(value, dict) or not value:
        raise AttestationError("attestation pcrs must be a non-empty map")
    pcrs: dict[int, bytes] = {}
    for index, measurement in value.items():
        in_range = isinstance(index, int) and not isinstance(index, bool)
        if not in_range or not 0 <= index <= MAX_PCR_INDEX:
            raise AttestationError(f"attestation PCR index {index!r} is out of range")
        if not isinstance(measurement, bytes) or len(measurement) not in PCR_LENGTHS:
            raise AttestationError(f"attestation PCR{index} is not a 32, 48 or 64 byte digest")
        pcrs[index] = measurement
    return pcrs


def _cabundle(body: Mapping[int | str, Any]) -> tuple[bytes, ...]:
    value = body.get("cabundle")
    if not isinstance(value, list) or not value:
        raise AttestationError("attestation cabundle must be a non-empty array")
    if len(value) > MAX_CHAIN_LENGTH:
        raise AttestationError(f"attestation cabundle is longer than {MAX_CHAIN_LENGTH}")
    certificates: list[bytes] = []
    for entry in value:
        if not isinstance(entry, bytes) or not entry:
            raise AttestationError("every cabundle entry must be a non-empty byte string")
        certificates.append(entry)
    return tuple(certificates)


# --------------------------------------------------------------------------- #
# What the verifier pinned
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AttestationTrust:
    """What the *verifier* decided to trust, before it saw the document.

    ``pcrs`` is the allowlist: index to lowercase hex. Only the indices named are
    checked, because an operator pins the measurements that matter to them —
    PCR0 (the enclave image), PCR1 (the kernel and bootstrap), PCR2 (the
    application) and PCR8 (the signing certificate of a signed image). An empty
    allowlist is not "everything is fine": it reports ``not_implemented``, since a
    document whose measurements nobody compared to anything proves only that some
    enclave, somewhere, produced it.

    ``max_age_seconds`` bounds replay. An attestation document is a statement
    about a moment; one from last year proves the enclave was running then, not
    now. Set it to ``None`` to check a receipt long after the fact, where the
    right window is the certificate validity rather than freshness.
    """

    pcrs: Mapping[int, str] = dataclasses.field(default_factory=dict)
    root_pem: str = NITRO_ROOT_G1_PEM
    max_age_seconds: int | None = DEFAULT_MAX_AGE_SECONDS
    require_production_mode: bool = True

    def __post_init__(self) -> None:
        for index, expected in self.pcrs.items():
            if not 0 <= index <= MAX_PCR_INDEX:
                raise AttestationError(f"PCR index {index} is out of range")
            if expected != expected.lower() or len(expected) // 2 not in PCR_LENGTHS:
                raise AttestationError(
                    f"PCR{index} allowlist entry must be lowercase hex of a 32, 48 or 64 byte "
                    "digest"
                )
            try:
                bytes.fromhex(expected)
            except ValueError as exc:
                raise AttestationError(f"PCR{index} allowlist entry is not hex") from exc
        if self.max_age_seconds is not None and self.max_age_seconds <= 0:
            raise AttestationError("max_age_seconds must be positive, or None")

    def root(self) -> x509.Certificate:
        """The pinned root, parsed."""
        try:
            return x509.load_pem_x509_certificate(self.root_pem.encode())
        except ValueError as exc:
            raise AttestationError(f"the pinned root is not a PEM certificate: {exc}") from exc


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify_attestation(
    document: bytes,
    *,
    trust: AttestationTrust,
    now: datetime.datetime,
    expected_public_key: bytes | None = None,
    expected_user_data: bytes | None = None,
) -> VerificationResult:
    """Run every check and report each by name.

    ``expected_public_key`` is the receipt's ``signer_public_key`` as raw bytes,
    and ``expected_user_data`` its ``policy_hash`` as raw bytes. Leave either
    ``None`` and that binding reports ``not_implemented`` rather than passing: a
    document that vouches for *a* key says nothing about *this* receipt until the
    two are held together.
    """
    if now.tzinfo is None:
        raise AttestationError("now must be timezone-aware")
    try:
        parsed = parse_attestation(document)
    except AttestationError as exc:
        return VerificationResult(
            tuple(
                Check(name, CheckStatus.FAIL, str(exc))
                if name == CHECK_FORMAT
                else no_data(name, "the document could not be parsed")
                for name in ATTESTATION_CHECKS
            )
        )

    chain, chain_check = _chain(parsed, trust)
    return VerificationResult(
        (
            _format_check(parsed),
            chain_check,
            _validity_check(chain, parsed),
            _signature_check(chain, parsed),
            _timestamp_check(parsed, trust, now),
            _pcr_check(parsed, trust),
            _debug_check(parsed, trust),
            _binding_check(
                CHECK_PUBLIC_KEY,
                parsed.public_key,
                expected_public_key,
                "the document vouches for the key that signed this receipt",
                "the attested key is not the key the receipt names",
                "the document carries no public_key",
                "no expected public key was supplied",
            ),
            _binding_check(
                CHECK_USER_DATA,
                parsed.user_data,
                expected_user_data,
                "the document was produced under the policy the receipt names",
                "the attested user_data is not the receipt's policy hash",
                "the document carries no user_data",
                "no expected policy hash was supplied",
            ),
        )
    )


def _format_check(parsed: AttestationDocument) -> Check:
    try:
        header = cbor.loads(parsed.protected)
    except cbor.CborError as exc:
        return Check(CHECK_FORMAT, CheckStatus.FAIL, f"protected header is not CBOR: {exc}")
    if not isinstance(header, dict):
        return Check(CHECK_FORMAT, CheckStatus.FAIL, "protected header is not a CBOR map")
    algorithm = header.get(1)
    if algorithm != COSE_ES384:
        return Check(
            CHECK_FORMAT,
            CheckStatus.FAIL,
            f"COSE alg is {algorithm!r}, and the NSM signs with ES384 ({COSE_ES384})",
        )
    if parsed.digest != "SHA384":
        return Check(
            CHECK_FORMAT, CheckStatus.FAIL, f"document digest is {parsed.digest!r}, not 'SHA384'"
        )
    if len(parsed.signature) != 96:
        return Check(
            CHECK_FORMAT,
            CheckStatus.FAIL,
            f"an ES384 signature is 96 bytes, this one is {len(parsed.signature)}",
        )
    return outcome(CHECK_FORMAT, True, f"COSE_Sign1 / ES384, module {parsed.module_id}")


def _chain(
    parsed: AttestationDocument, trust: AttestationTrust
) -> tuple[tuple[x509.Certificate, ...], Check]:
    """Root first, leaf last. Returns the chain it managed to build, and a check."""
    try:
        root = trust.root()
    except AttestationError as exc:
        return (), Check(CHECK_CHAIN, CheckStatus.FAIL, str(exc))

    root_der = root.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(root_der).hexdigest()
    if trust.root_pem == NITRO_ROOT_G1_PEM and fingerprint != NITRO_ROOT_G1_SHA256:
        return (), Check(CHECK_CHAIN, CheckStatus.FAIL, "the embedded root has been altered")

    if parsed.cabundle[0] != root_der:
        return (), Check(
            CHECK_CHAIN,
            CheckStatus.FAIL,
            "the document's chain does not start at the pinned AWS Nitro root; it starts at "
            f"sha256:{hashlib.sha256(parsed.cabundle[0]).hexdigest()[:16]}…",
        )

    try:
        chain = tuple(
            x509.load_der_x509_certificate(der) for der in (*parsed.cabundle, parsed.certificate)
        )
    except ValueError as exc:
        return (), Check(CHECK_CHAIN, CheckStatus.FAIL, f"a certificate is not valid DER: {exc}")

    for index in range(1, len(chain)):
        child, parent = chain[index], chain[index - 1]
        if child.issuer != parent.subject:
            return chain, Check(
                CHECK_CHAIN,
                CheckStatus.FAIL,
                f"certificate {index} is not issued by certificate {index - 1}",
            )
        if not _signed_by(child, parent):
            return chain, Check(
                CHECK_CHAIN,
                CheckStatus.FAIL,
                f"certificate {index} is not signed by certificate {index - 1}",
            )
    return chain, outcome(
        CHECK_CHAIN,
        True,
        f"{len(chain)} certificates from the pinned AWS Nitro root to {_common_name(chain[-1])}",
    )


def _signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    key = parent.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        return False
    algorithm = child.signature_hash_algorithm
    if algorithm is None:
        return False
    try:
        key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(algorithm))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _common_name(certificate: x509.Certificate) -> str:
    names = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    value = names[0].value if names else "?"
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _validity_check(chain: Sequence[x509.Certificate], parsed: AttestationDocument) -> Check:
    """Every certificate must have been valid *when the document was produced*.

    Not "now". A receipt is checked long after its enclave stopped, and the leaf
    certificate the NSM used lives about three hours. Checking the chain against
    the moment it signed is what lets an old receipt still verify; freshness is a
    separate question, asked by :func:`_timestamp_check` against the caller's
    ``now``.
    """
    if not chain:
        return no_data(CHECK_CERT_VALIDITY, "the chain could not be built")
    at = parsed.timestamp
    expired = [
        _common_name(certificate)
        for certificate in chain
        if not certificate.not_valid_before_utc <= at <= certificate.not_valid_after_utc
    ]
    if expired:
        return Check(
            CHECK_CERT_VALIDITY,
            CheckStatus.FAIL,
            f"not valid at {at.isoformat()}: {', '.join(expired)}",
        )
    return outcome(
        CHECK_CERT_VALIDITY,
        True,
        f"every certificate was valid at {at.isoformat()}",
    )


def _signature_check(chain: Sequence[x509.Certificate], parsed: AttestationDocument) -> Check:
    if not chain:
        return no_data(CHECK_SIGNATURE, "the chain could not be built, so there is no key to use")
    key = chain[-1].public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
        return Check(
            CHECK_SIGNATURE, CheckStatus.FAIL, "the leaf certificate does not hold a P-384 key"
        )
    if len(parsed.signature) != 96:
        return Check(
            CHECK_SIGNATURE,
            CheckStatus.FAIL,
            f"an ES384 signature is 96 bytes, this one is {len(parsed.signature)}",
        )
    r = int.from_bytes(parsed.signature[:48], "big")
    s = int.from_bytes(parsed.signature[48:], "big")
    try:
        key.verify(encode_dss_signature(r, s), parsed.sig_structure(), ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        return Check(
            CHECK_SIGNATURE,
            CheckStatus.FAIL,
            "the COSE_Sign1 signature does not verify under the leaf certificate",
        )
    return outcome(CHECK_SIGNATURE, True, "ES384 over the COSE Sig_structure verifies")


def _timestamp_check(
    parsed: AttestationDocument, trust: AttestationTrust, now: datetime.datetime
) -> Check:
    at = parsed.timestamp
    age = (now - at).total_seconds()
    if age < 0:
        return Check(
            CHECK_TIMESTAMP,
            CheckStatus.FAIL,
            f"the document is dated {at.isoformat()}, which is after now",
        )
    if trust.max_age_seconds is None:
        return outcome(
            CHECK_TIMESTAMP,
            True,
            f"produced {at.isoformat()}; no freshness bound was asked for",
        )
    if age > trust.max_age_seconds:
        return Check(
            CHECK_TIMESTAMP,
            CheckStatus.FAIL,
            f"the document is {int(age)}s old, over the {trust.max_age_seconds}s bound",
        )
    return outcome(CHECK_TIMESTAMP, True, f"produced {int(age)}s ago")


def _pcr_check(parsed: AttestationDocument, trust: AttestationTrust) -> Check:
    if not trust.pcrs:
        return no_data(
            CHECK_PCRS,
            "no PCR allowlist was pinned, so nothing says which enclave image this is",
        )
    disagreements: list[str] = []
    for index, expected in sorted(trust.pcrs.items()):
        measured = parsed.pcrs.get(index)
        if measured is None:
            disagreements.append(f"PCR{index} is absent from the document")
        elif measured.hex() != expected:
            disagreements.append(f"PCR{index} is {measured.hex()[:16]}…, pinned {expected[:16]}…")
    if disagreements:
        return Check(CHECK_PCRS, CheckStatus.FAIL, "; ".join(disagreements))
    return outcome(
        CHECK_PCRS,
        True,
        f"PCR{', PCR'.join(str(i) for i in sorted(trust.pcrs))} match the pinned allowlist",
    )


def _debug_check(parsed: AttestationDocument, trust: AttestationTrust) -> Check:
    if not trust.require_production_mode:
        return no_data(
            CHECK_DEBUG_MODE, "the verifier chose not to require a production-mode enclave"
        )
    if parsed.debug_mode:
        return Check(
            CHECK_DEBUG_MODE,
            CheckStatus.FAIL,
            "PCR0 is all zeros: this enclave ran in debug mode, so its measurements mean "
            "nothing and its memory was readable from the parent",
        )
    return outcome(CHECK_DEBUG_MODE, True, "PCR0 is non-zero: a production-mode enclave")


def _binding_check(
    name: str,
    attested: bytes | None,
    expected: bytes | None,
    passed: str,
    failed: str,
    missing: str,
    unasked: str,
) -> Check:
    if expected is None:
        return no_data(name, unasked)
    if attested is None:
        return Check(name, CheckStatus.FAIL, missing)
    return outcome(name, attested == expected, passed if attested == expected else failed)

"""Signature verification for the co-signer, and the byte encodings around it.

Pure functions over bytes: a key, a signature and a message go in, a boolean
comes out. Nothing here reads a clock, a file or a network socket, and nothing
here *makes* a signature — signing lives behind :class:`merkl.core.ports.SignerPort`
because the private key never enters ``merkl.core``.

Two algorithms, because two things sign in this system:

* **Ed25519** — the policy key, the agent key, the admin key that signs a policy
  document, and an approver who is not using a passkey. Raw 32-byte public keys,
  64-byte signatures, both carried as lowercase hex.
* **ECDSA P-256** — WebAuthn passkeys, whose authenticators are required to
  support ES256. Public keys are the uncompressed SEC1 point (65 bytes,
  ``0x04 || X || Y``) and signatures are DER, as the authenticator emits them.

``cryptography`` is a declared runtime dependency of ``merkl-sdk`` already; it is
the one non-stdlib import ``merkl.core`` makes, and it makes it for verification
only. See ``docs/RECEIPT-SPEC.md`` section 10.
"""

from __future__ import annotations

import base64
from typing import Final

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from merkl.core.canonical import ContentError
from merkl.shared.hashing import SHA256Hash

NUL: Final = b"\x00"

ED25519_PUBLIC_KEY_BYTES: Final = 32
ED25519_SIGNATURE_BYTES: Final = 64
P256_UNCOMPRESSED_POINT_BYTES: Final = 65


class CryptoError(ContentError):
    """Raised when a key or signature is not well formed.

    A *malformed* key is an error; a *wrong* signature is a ``False`` return.
    Callers that conflate the two end up reporting "invalid key" for a forgery,
    which is the wrong sentence to put in front of an auditor.
    """

    error_code = "crypto_error"


def hex_bytes(value: object, field: str, *, length: int | None = None) -> bytes:
    """Decode lowercase hex into bytes, with a useful error message.

    Every key, signature and opaque blob that crosses a Merkl boundary is
    lowercase hex: one encoding, readable from any language, and it survives JSON
    without a base64 alphabet argument.
    """
    if not isinstance(value, str):
        raise CryptoError(f"{field} must be a hex string, got {type(value).__name__}")
    if value != value.lower():
        raise CryptoError(f"{field} must be lowercase hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise CryptoError(f"{field} is not hex: {value!r}") from exc
    if length is not None and len(raw) != length:
        raise CryptoError(f"{field} must be {length} bytes, got {len(raw)}")
    return raw


def b64url_decode(value: str, field: str) -> bytes:
    """Decode unpadded base64url, the encoding WebAuthn uses inside clientDataJSON."""
    if not isinstance(value, str):
        raise CryptoError(f"{field} must be a base64url string")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise CryptoError(f"{field} is not base64url: {value!r}") from exc


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def tagged(tag: bytes, *parts: bytes) -> bytes:
    """``tag || NUL || parts[0] || NUL || parts[1] ...`` — the Merkl pre-image shape.

    Same construction as the leaf hashes: the domain tag comes first, ``NUL``
    separates every field, and no field may contain a ``NUL``, so the encoding is
    unambiguous and a digest from one structure can never be read as a digest
    from another.
    """
    return tag + NUL + NUL.join(parts)


def tagged_digest(tag: bytes, *parts: bytes) -> SHA256Hash:
    """SHA-256 over :func:`tagged`."""
    return SHA256Hash.from_bytes(tagged(tag, *parts))


def ed25519_verify(public_key: str, signature: str, message: bytes) -> bool:
    """True when ``signature`` is this key's Ed25519 signature over ``message``.

    Both arguments are lowercase hex: 32 bytes of key, 64 of signature.
    """
    key = hex_bytes(public_key, "ed25519 public key", length=ED25519_PUBLIC_KEY_BYTES)
    sig = hex_bytes(signature, "ed25519 signature", length=ED25519_SIGNATURE_BYTES)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
    except InvalidSignature:
        return False
    except ValueError as exc:  # pragma: no cover - length is checked above
        raise CryptoError(f"ed25519 public key is not on the curve: {exc}") from exc
    return True


def p256_verify(public_key: str, signature: str, message: bytes) -> bool:
    """True when ``signature`` is this P-256 key's ECDSA-SHA256 signature over ``message``.

    ``public_key`` is the hex of the uncompressed SEC1 point (``0x04 || X || Y``)
    and ``signature`` is the hex of the DER sequence the authenticator produced.
    WebAuthn signatures are DER, not the raw ``r || s`` of some other stacks, and
    re-encoding them here would be a place to lose bytes.
    """
    point = hex_bytes(public_key, "p-256 public key")
    if len(point) != P256_UNCOMPRESSED_POINT_BYTES or point[0] != 0x04:
        raise CryptoError(
            "p-256 public key must be the uncompressed SEC1 point "
            f"(65 bytes starting 0x04), got {len(point)} bytes"
        )
    sig = hex_bytes(signature, "p-256 signature")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise CryptoError(f"p-256 public key is not on the curve: {exc}") from exc
    try:
        key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True

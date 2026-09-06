"""Open the CMS envelope KMS returns to an enclave. RFC 5652, the narrow path.

When an enclave calls ``kms:Decrypt`` with its attestation document as the
``Recipient``, KMS does not send the plaintext back. It sends
``CiphertextForRecipient``: a CMS ``EnvelopedData`` whose content-encryption key
is wrapped to the ephemeral RSA public key embedded in that very attestation
document. The parent proxies the HTTPS and sees only this envelope, and the
private half exists only inside the enclave that produced the attestation. That
is the whole reason the parent can be assumed hostile and still be handed the
network.

So something has to open it, and ``cryptography`` does not do CMS. The choices
were a general ASN.1 library in the enclave image, a subprocess to OpenSSL, or
this: a DER reader that walks exactly one structure and refuses everything else.
The structure is fixed by AWS — RSAES-OAEP key transport, one recipient, AES-CBC
content encryption — so the parser is a hundred lines and every branch it does
not need is a branch it rejects.

Refusals worth naming, because each is a real attack on a lax parser:

* **more than one recipient** — an envelope encrypted to a second key as well is
  an envelope somebody else can also read;
* **PKCS#1 v1.5 key transport** — Bleichenbacher. Only OAEP is accepted, and only
  with SHA-256 or better;
* **non-minimal DER lengths, indefinite lengths, trailing bytes** — two encodings
  of one structure is one structure too many;
* **an unexpected content type or cipher** — anything not on the list is refused
  by name rather than guessed at, ``AuthEnvelopedData`` included.

Executed on this machine: ``tests/adapters/test_cms.py`` decrypts an envelope
produced by ``openssl cms``, which is the same structure and not our own encoder,
so the parser is checked against an implementation nobody here wrote.
"""

from __future__ import annotations

from typing import Final

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from merkl.shared.errors import MerklError

OID_ENVELOPED_DATA: Final = "1.2.840.113549.1.7.3"
OID_DATA: Final = "1.2.840.113549.1.7.1"
OID_RSAES_OAEP: Final = "1.2.840.113549.1.1.7"
OID_RSA_ENCRYPTION: Final = "1.2.840.113549.1.1.1"
OID_MGF1: Final = "1.2.840.113549.1.1.8"

HASHES: Final[dict[str, hashes.HashAlgorithm]] = {
    "2.16.840.1.101.3.4.2.1": hashes.SHA256(),
    "2.16.840.1.101.3.4.2.2": hashes.SHA384(),
    "2.16.840.1.101.3.4.2.3": hashes.SHA512(),
}
"""OAEP digests we accept. SHA-1 is absent on purpose; KMS uses SHA-256."""

AES_CBC: Final[dict[str, int]] = {
    "2.16.840.1.101.3.4.1.2": 128,
    "2.16.840.1.101.3.4.1.22": 192,
    "2.16.840.1.101.3.4.1.42": 256,
}
OID_AUTH_ENVELOPED_DATA: Final = "1.2.840.113549.1.9.16.1.23"
"""RFC 5083. An AEAD content cipher lives here, not in EnvelopedData.

Refused rather than implemented. KMS returns ``EnvelopedData`` with AES-CBC, and
a parser that also accepted ``AuthEnvelopedData`` would be carrying a second
structure — with its own MAC placement and its own ways to be wrong — for a case
that does not arise. If AWS ever changes, this constant is where the error
message comes from and the change is deliberate.
"""

MAX_PLAINTEXT_BYTES: Final = 64 * 1024


class CmsError(MerklError):
    """The CMS envelope is not the shape this parser accepts."""

    error_code = "keystore_error"


# --------------------------------------------------------------------------- #
# A DER reader that only reads what it needs
# --------------------------------------------------------------------------- #


class _Der:
    """Positional DER reader. Every method consumes exactly one TLV."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._at

    def end(self) -> None:
        if self.remaining:
            raise CmsError(f"{self.remaining} trailing DER bytes")

    def peek_tag(self) -> int | None:
        return self._data[self._at] if self.remaining else None

    def read(self, tag: int) -> bytes:
        """The value of the next element, which must carry this tag."""
        found = self.peek_tag()
        if found != tag:
            raise CmsError(f"expected DER tag 0x{tag:02x}, found {found and hex(found)}")
        return self._value()

    def read_optional(self, tag: int) -> bytes | None:
        return self._value() if self.peek_tag() == tag else None

    def skip(self) -> None:
        self._value()

    def _value(self) -> bytes:
        if not self.remaining:
            raise CmsError("DER ended in the middle of an element")
        self._at += 1
        length = self._length()
        end = self._at + length
        if end > len(self._data):
            raise CmsError("DER element runs past the end of the buffer")
        value = self._data[self._at : end]
        self._at = end
        return value

    def _length(self) -> int:
        if not self.remaining:
            raise CmsError("DER ended before its length")
        first = self._data[self._at]
        self._at += 1
        if first < 0x80:
            return first
        if first == 0x80:
            raise CmsError("indefinite-length DER is not accepted")
        count = first & 0x7F
        if count > 4:
            raise CmsError("DER length is longer than four bytes")
        if self.remaining < count:
            raise CmsError("DER ended in the middle of a length")
        raw = self._data[self._at : self._at + count]
        self._at += count
        length = int.from_bytes(raw, "big")
        if raw[0] == 0 or length < 0x80:
            raise CmsError("non-minimal DER length")
        return length


SEQUENCE: Final = 0x30
SET: Final = 0x31
INTEGER: Final = 0x02
OCTET_STRING: Final = 0x04
OID: Final = 0x06
CONTEXT_0: Final = 0xA0
CONTEXT_0_PRIMITIVE: Final = 0x80
CONTEXT_1: Final = 0xA1


def _oid(raw: bytes) -> str:
    """Decode an OBJECT IDENTIFIER's value bytes into dotted notation."""
    if not raw:
        raise CmsError("empty OID")
    first, rest = divmod(raw[0], 40)
    if first > 2:
        first, rest = 2, raw[0] - 80
    parts = [str(first), str(rest)]
    value = 0
    for index, byte in enumerate(raw[1:], start=1):
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
        elif index == len(raw) - 1:
            raise CmsError("OID ends mid-arc")
    return ".".join(parts)


def _algorithm(raw: bytes) -> tuple[str, bytes]:
    """An ``AlgorithmIdentifier``: its OID and its (possibly empty) parameters."""
    reader = _Der(raw)
    oid = _oid(reader.read(OID))
    parameters = raw[len(raw) - reader.remaining :] if reader.remaining else b""
    return oid, parameters


# --------------------------------------------------------------------------- #
# The one structure
# --------------------------------------------------------------------------- #


def decrypt_enveloped_data(envelope: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Return the plaintext inside a single-recipient CMS ``EnvelopedData``."""
    content = _enveloped_content(envelope)
    body = _Der(content)
    version = body.read(INTEGER)
    if int.from_bytes(version, "big") > 4:
        raise CmsError(f"EnvelopedData version {int.from_bytes(version, 'big')} is not supported")
    if body.peek_tag() == CONTEXT_0:
        body.skip()  # originatorInfo, which key transport does not use

    recipients = _Der(body.read(SET))
    recipient = recipients.read(SEQUENCE)
    if recipients.remaining:
        raise CmsError(
            "the envelope names more than one recipient, so somebody else can read it too"
        )
    key = _unwrap_key(recipient, private_key)

    return _decrypt_content(body.read(SEQUENCE), key)


def _enveloped_content(envelope: bytes) -> bytes:
    outer = _Der(envelope)
    info = _Der(outer.read(SEQUENCE))
    outer.end()
    content_type = _oid(info.read(OID))
    if content_type == OID_AUTH_ENVELOPED_DATA:
        raise CmsError(
            "this is an AuthEnvelopedData (RFC 5083), and only EnvelopedData is accepted; "
            "KMS returns EnvelopedData with AES-CBC"
        )
    if content_type != OID_ENVELOPED_DATA:
        raise CmsError(f"content type {content_type} is not id-envelopedData")
    inner = _Der(info.read(CONTEXT_0))
    content = inner.read(SEQUENCE)
    inner.end()
    info.end()
    return content


def _unwrap_key(recipient: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    reader = _Der(recipient)
    reader.read(INTEGER)  # version
    if reader.peek_tag() == SEQUENCE:
        reader.skip()  # issuerAndSerialNumber
    elif reader.peek_tag() == CONTEXT_0_PRIMITIVE:
        reader.skip()  # subjectKeyIdentifier
    else:
        raise CmsError("recipient identifier is neither issuerAndSerial nor subjectKeyIdentifier")

    oid, parameters = _algorithm(reader.read(SEQUENCE))
    if oid == OID_RSA_ENCRYPTION:
        raise CmsError(
            "the key is wrapped with PKCS#1 v1.5, which this parser refuses; KMS uses "
            "RSAES-OAEP and a v1.5 envelope here would be a downgrade"
        )
    if oid != OID_RSAES_OAEP:
        raise CmsError(f"key encryption algorithm {oid} is not RSAES-OAEP")
    digest = _oaep_digest(parameters)
    wrapped = reader.read(OCTET_STRING)
    reader.end()

    try:
        return private_key.decrypt(
            wrapped,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=digest), algorithm=digest, label=None
            ),
        )
    except ValueError as exc:
        raise CmsError(
            "the wrapped key does not open with this enclave's ephemeral private key"
        ) from exc


def _oaep_digest(parameters: bytes) -> hashes.HashAlgorithm:
    """RFC 4055 ``RSAES-OAEP-params``. Absent parameters mean SHA-1, so refuse."""
    if not parameters:
        raise CmsError("RSAES-OAEP with default parameters means SHA-1, which is refused")
    reader = _Der(parameters)
    fields = _Der(reader.read(SEQUENCE))
    reader.end()
    hash_field = fields.read_optional(CONTEXT_0)
    if hash_field is None:
        raise CmsError("RSAES-OAEP parameters do not name a hash, so they mean SHA-1")
    oid, _ = _algorithm(_Der(hash_field).read(SEQUENCE))
    digest = HASHES.get(oid)
    if digest is None:
        raise CmsError(f"OAEP digest {oid} is not accepted")
    mgf_field = fields.read_optional(CONTEXT_1)
    if mgf_field is not None:
        mgf_oid, mgf_parameters = _algorithm(_Der(mgf_field).read(SEQUENCE))
        if mgf_oid != OID_MGF1:
            raise CmsError(f"mask generation function {mgf_oid} is not MGF1")
        mgf_digest, _ = _algorithm(_Der(mgf_parameters).read(SEQUENCE))
        if HASHES.get(mgf_digest) is None or mgf_digest != oid:
            raise CmsError("the MGF1 digest must match the OAEP digest")
    return digest


def _decrypt_content(encrypted_content_info: bytes, key: bytes) -> bytes:
    reader = _Der(encrypted_content_info)
    content_type = _oid(reader.read(OID))
    if content_type != OID_DATA:
        raise CmsError(f"encrypted content type {content_type} is not id-data")
    oid, parameters = _algorithm(reader.read(SEQUENCE))
    ciphertext = reader.read_optional(CONTEXT_0_PRIMITIVE)
    if ciphertext is None:
        ciphertext = reader.read_optional(CONTEXT_0)
    if ciphertext is None:
        raise CmsError("the envelope carries no encrypted content")
    if len(ciphertext) > MAX_PLAINTEXT_BYTES:
        raise CmsError(f"encrypted content is {len(ciphertext)} bytes, more than any key needs")

    if oid in AES_CBC:
        _expect_key_length(key, AES_CBC[oid], oid)
        iv = _Der(parameters).read(OCTET_STRING)
        if len(iv) != 16:
            raise CmsError(f"AES-CBC needs a 16-byte IV, this one is {len(iv)}")
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise CmsError(
                "the content does not unpad, so the key or the bytes are wrong"
            ) from exc
    raise CmsError(f"content encryption algorithm {oid} is not an accepted AES-CBC mode")


def _expect_key_length(key: bytes, bits: int, oid: str) -> None:
    if len(key) * 8 != bits:
        raise CmsError(f"{oid} needs a {bits // 8}-byte key, the envelope wrapped {len(key)}")

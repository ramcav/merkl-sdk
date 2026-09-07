"""The CMS parser, checked against envelopes OpenSSL produced.

The point of this file is that Merkl did not write the encoder. A parser tested
against its own encoder proves the two agree; a parser tested against
``openssl cms -encrypt`` proves it reads what the rest of the world writes, which
is the claim that matters when the writer is AWS KMS.

The RSA key is generated in the test and never touches disk — OpenSSL only needs
the *certificate* to encrypt, so nothing here is a private key in a file, and
there is no fixture to gitignore. The tests skip, loudly, on a machine without
``openssl``.
"""

from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from merkl.adapters.nitro.cms import CmsError, decrypt_enveloped_data

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(
    OPENSSL is None, reason="openssl is what produces the envelopes these tests read"
)

PLAINTEXT = bytes(range(32))
"""Thirty-two bytes, the size of the thing KMS actually wraps here: an Ed25519 seed."""


@pytest.fixture(scope="module")
def recipient() -> tuple[rsa.RSAPrivateKey, bytes]:
    """An ephemeral RSA key and its certificate, standing in for the enclave's."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "enclave-ephemeral")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.PEM)


def envelope(
    recipient: tuple[rsa.RSAPrivateKey, bytes],
    tmp_path: Path,
    *,
    cipher: str = "-aes-256-cbc",
    oaep: bool = True,
    plaintext: bytes = PLAINTEXT,
) -> bytes:
    """``openssl cms -encrypt``, DER out."""
    _, certificate_pem = recipient
    certificate = tmp_path / "recipient.pem"
    certificate.write_bytes(certificate_pem)
    source = tmp_path / "plaintext.bin"
    source.write_bytes(plaintext)
    out = tmp_path / "envelope.der"
    command = [
        str(OPENSSL),
        "cms",
        "-encrypt",
        cipher,
        "-recip",
        str(certificate),
        "-binary",
        "-outform",
        "DER",
        "-in",
        str(source),
        "-out",
        str(out),
    ]
    if oaep:
        command += [
            "-keyopt",
            "rsa_padding_mode:oaep",
            "-keyopt",
            "rsa_oaep_md:sha256",
        ]
    subprocess.run(command, check=True, capture_output=True)
    return out.read_bytes()


@pytest.mark.parametrize("cipher", ["-aes-256-cbc", "-aes-192-cbc", "-aes-128-cbc"])
def test_an_openssl_envelope_opens(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path, cipher: str
) -> None:
    key, _ = recipient
    assert decrypt_enveloped_data(envelope(recipient, tmp_path, cipher=cipher), key) == PLAINTEXT


def test_an_auth_enveloped_data_is_refused_by_name(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path
) -> None:
    """``openssl -aes-256-gcm`` emits AuthEnvelopedData (RFC 5083), not this.

    KMS returns EnvelopedData with AES-CBC. Carrying a second structure — its own
    MAC placement, its own ways to be wrong — for a case that does not arise is
    trusted-path code earning nothing, so it is refused with its own message.
    """
    key, _ = recipient
    with pytest.raises(CmsError, match="AuthEnvelopedData"):
        decrypt_enveloped_data(envelope(recipient, tmp_path, cipher="-aes-256-gcm"), key)


@pytest.mark.parametrize("size", [1, 15, 16, 17, 1024])
def test_padding_is_handled_at_every_block_boundary(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path, size: int
) -> None:
    key, _ = recipient
    plaintext = bytes(range(256)) * 8
    plaintext = plaintext[:size]
    opened = decrypt_enveloped_data(envelope(recipient, tmp_path, plaintext=plaintext), key)
    assert opened == plaintext


def test_a_pkcs1_v15_envelope_is_refused(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path
) -> None:
    """Bleichenbacher. KMS uses OAEP, so a v1.5 envelope here is a downgrade."""
    key, _ = recipient
    with pytest.raises(CmsError, match="PKCS#1 v1.5"):
        decrypt_enveloped_data(envelope(recipient, tmp_path, oaep=False), key)


def test_another_key_cannot_open_it(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path
) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(CmsError, match="does not open"):
        decrypt_enveloped_data(envelope(recipient, tmp_path), other)


def test_two_recipients_are_refused(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path
) -> None:
    """An envelope somebody else can also read is not one to unwrap a key from."""
    key, certificate_pem = recipient
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "someone-else")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    second_certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(second.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(second, hashes.SHA256())
    )
    first_path = tmp_path / "first.pem"
    first_path.write_bytes(certificate_pem)
    second_path = tmp_path / "second.pem"
    second_path.write_bytes(second_certificate.public_bytes(serialization.Encoding.PEM))
    source = tmp_path / "plaintext.bin"
    source.write_bytes(PLAINTEXT)
    out = tmp_path / "two.der"
    # openssl takes extra recipients positionally, and -keyopt only applies to a
    # -recip, so this envelope is PKCS#1 v1.5. It does not matter: the recipient
    # count is checked before the key encryption algorithm is even looked at.
    subprocess.run(
        [
            str(OPENSSL),
            "cms",
            "-encrypt",
            "-aes-256-cbc",
            "-binary",
            "-outform",
            "DER",
            "-in",
            str(source),
            "-out",
            str(out),
            str(first_path),
            str(second_path),
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(CmsError, match="more than one recipient"):
        decrypt_enveloped_data(out.read_bytes(), key)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda raw: raw + b"\x00", "trailing"),
        (lambda raw: raw[:-1], "past the end"),
        (lambda raw: b"", "expected DER tag"),
        (lambda raw: b"\x30\x80" + raw[2:], "indefinite"),
    ],
)
def test_malformed_der_is_refused(
    recipient: tuple[rsa.RSAPrivateKey, bytes],
    tmp_path: Path,
    mutate: object,
    match: str,
) -> None:
    key, _ = recipient
    raw = envelope(recipient, tmp_path)
    with pytest.raises(CmsError, match=match):
        decrypt_enveloped_data(mutate(raw), key)  # type: ignore[operator]


def test_a_content_type_that_is_not_an_envelope_is_refused(
    recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path
) -> None:
    """Content type is checked before anything else is read."""
    key, _ = recipient
    signed = tmp_path / "signed.der"
    source = tmp_path / "plaintext.bin"
    source.write_bytes(PLAINTEXT)
    subprocess.run(
        [
            str(OPENSSL),
            "cms",
            "-sign",
            "-nocerts",
            "-noattr",
            "-binary",
            "-outform",
            "DER",
            "-in",
            str(source),
            "-out",
            str(signed),
            "-signer",
            str(_certificate_file(recipient, tmp_path)),
            "-inkey",
            str(_key_file(recipient, tmp_path)),
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(CmsError, match="is not id-envelopedData"):
        decrypt_enveloped_data(signed.read_bytes(), key)


def _certificate_file(recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path) -> Path:
    path = tmp_path / "signer.pem"
    path.write_bytes(recipient[1])
    return path


def _key_file(recipient: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path) -> Path:
    """The throwaway key, in a pytest temp directory and never in the repo."""
    path = tmp_path / "signer.key"
    path.write_bytes(
        recipient[0].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path

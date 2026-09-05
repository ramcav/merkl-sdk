"""The keystore — where the policy key lives and never leaves.

``DevKeystore`` keeps an Ed25519 key in a file, encrypted at rest with AES-GCM
under a key derived from a passphrase. That is honest development storage and
nothing more: the operating system can read the file, and so can anything running
as the same user. The point of the interface is that ``NitroKeystore`` (phase 3)
drops into the same three methods with the key sealed to an enclave measurement,
and nothing above this module changes.

Three rules the code enforces rather than documents:

* the private key is never returned, only used — :meth:`sign` is the whole API;
* nothing here prints, logs or formats a seed, a passphrase or a private key;
* the file is written with mode ``0600`` and created atomically, so it never
  exists briefly as a world-readable file.

Ed25519 is the algorithm because XRPL accepts Ed25519 signers directly (public
keys prefixed ``ED``), which means one key type covers the rail signature, the
agent request signatures and the policy document signature.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Final, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from merkl.core.canonical import JSONValue
from merkl.shared.errors import MerklError

KEY_FILE: Final = "policy-ed25519.json"
PASSPHRASE_FILE: Final = "passphrase"
PASSPHRASE_ENV: Final = "MERKL_SIGNER_PASSPHRASE"
KDF_ITERATIONS: Final = 600_000
"""PBKDF2-HMAC-SHA256 rounds. OWASP's 2023 floor, and this runs once at boot."""

SEAL_INFO: Final = b"merkl-signer-state-seal-v1"


class KeystoreError(MerklError):
    """Raised when a keystore cannot be opened, created or used."""

    error_code = "keystore_error"


class KeystorePort(Protocol):
    """What the signer needs from wherever the policy key is held.

    Deliberately three methods. An enclave keystore, a KMS-backed one and the dev
    file all differ in how the key is protected and not at all in what it does.
    """

    def public_key(self) -> str:
        """The policy public key, lowercase hex (32 raw Ed25519 bytes)."""
        ...

    def sign(self, message: bytes) -> str:
        """Sign exactly these bytes. Lowercase hex."""
        ...

    def seal_key(self) -> bytes:
        """A 32-byte key for sealing state snapshots, bound to this keystore."""
        ...

    def attestation(self) -> JSONValue:
        """The attestation document, or ``None`` when the signer is unattested."""
        ...


def _write_private(path: Path, payload: bytes) -> None:
    """Write a secret file that is never briefly readable by anyone else."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _derive(passphrase: bytes, salt: bytes, info: bytes = b"") -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt + info, iterations=KDF_ITERATIONS
    )
    return kdf.derive(passphrase)


class DevKeystore:
    """An Ed25519 policy key in an encrypted file. Unattested, and says so.

    Created on first boot if it does not exist. The passphrase comes from
    ``MERKL_SIGNER_PASSPHRASE`` if set, otherwise from a ``0600`` file beside the
    key that is generated once — which protects the key against a stolen backup
    of the key file alone, and against nothing else. ``attestation()`` returns
    ``None`` so every receipt this signer produces records, as a proven fact,
    that no enclave vouched for it (plan D3).
    """

    def __init__(self, directory: Path | str, *, passphrase: str | None = None) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, stat.S_IRWXU)
        self._path = self._dir / KEY_FILE
        self._passphrase = self._resolve_passphrase(passphrase)
        self._key, self._salt = self._load_or_create()

    # -- construction ------------------------------------------------------ #

    def _resolve_passphrase(self, given: str | None) -> bytes:
        if given is not None:
            return given.encode()
        from_env = os.environ.get(PASSPHRASE_ENV)
        if from_env:
            return from_env.encode()
        path = self._dir / PASSPHRASE_FILE
        if path.exists():
            return path.read_bytes().strip()
        generated = secrets.token_hex(32).encode()
        _write_private(path, generated + b"\n")
        return generated

    def _load_or_create(self) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
        if self._path.exists():
            return self._load()
        return self._create()

    def _create(self) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
        key = ed25519.Ed25519PrivateKey.generate()
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        raw = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        sealed = AESGCM(_derive(self._passphrase, salt)).encrypt(nonce, raw, None)
        _write_private(
            self._path,
            json.dumps(
                {
                    "format": "merkl-dev-keystore-v1",
                    "algorithm": "ed25519",
                    "kdf": {"name": "pbkdf2-hmac-sha256", "iterations": KDF_ITERATIONS},
                    "salt": salt.hex(),
                    "nonce": nonce.hex(),
                    "ciphertext": sealed.hex(),
                    "public_key": self._public_hex(key),
                },
                indent=2,
            ).encode()
            + b"\n",
        )
        return key, salt

    def _load(self) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
        try:
            document = json.loads(self._path.read_text())
        except json.JSONDecodeError as exc:
            raise KeystoreError(f"keystore at {self._path} is not valid JSON") from exc
        if document.get("format") != "merkl-dev-keystore-v1":
            raise KeystoreError(f"unknown keystore format {document.get('format')!r}")
        salt = bytes.fromhex(document["salt"])
        try:
            raw = AESGCM(_derive(self._passphrase, salt)).decrypt(
                bytes.fromhex(document["nonce"]), bytes.fromhex(document["ciphertext"]), None
            )
        except Exception as exc:
            raise KeystoreError(
                "the keystore passphrase is wrong, or the key file is damaged"
            ) from exc
        key = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        if self._public_hex(key) != document.get("public_key"):
            raise KeystoreError("the keystore's public key does not match its private key")
        return key, salt

    # -- the port ---------------------------------------------------------- #

    @staticmethod
    def _public_hex(key: ed25519.Ed25519PrivateKey) -> str:
        return (
            key.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )

    def public_key(self) -> str:
        return self._public_hex(self._key)

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def seal_key(self) -> bytes:
        """A separate key for state sealing, derived from the same passphrase.

        Separate so that a state snapshot can never be decrypted with anything
        that would also reveal the signing key, and derived rather than stored so
        there is one secret to protect instead of two.
        """
        return _derive(self._passphrase, self._salt, SEAL_INFO)

    def attestation(self) -> JSONValue:
        """``None``: a dev signer is unattested, and the receipt records that."""
        return None

    def __repr__(self) -> str:  # pragma: no cover - never leaks key material
        return f"DevKeystore(dir={self._dir!s}, public_key={self.public_key()[:16]}…)"

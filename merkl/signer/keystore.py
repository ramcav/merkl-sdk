"""The keystore — where the policy key lives and never leaves.

Two implementations, one four-method port, and nothing above this module knows
which it is holding.

``DevKeystore`` keeps an Ed25519 key in a file, encrypted at rest with AES-GCM
under a key derived from a passphrase. That is honest development storage and
nothing more: the operating system can read the file, and so can anything running
as the same user. Its ``attestation()`` is ``None``, and every receipt it
produces commits to that absence (plan D3).

``NitroKeystore`` generates the key inside an AWS Nitro Enclave, from the NSM's
entropy, and seals it with KMS under a key policy that refuses to decrypt for any
enclave whose measurements differ. Its ``attestation()`` is a fresh NSM document
binding the policy public key and the policy hash. The swap between them is a
constructor argument, which is the whole point of the port existing.

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

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Final, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from merkl.core.canonical import JSONValue
from merkl.shared.errors import MerklError
from merkl.signer.attestation import NsmPort, attestation_content

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


def _public_hex(key: ed25519.Ed25519PrivateKey) -> str:
    """The public half, lowercase hex. The private half has no such function."""
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


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
                    "public_key": _public_hex(key),
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
        if _public_hex(key) != document.get("public_key"):
            raise KeystoreError("the keystore's public key does not match its private key")
        return key, salt

    # -- the port ---------------------------------------------------------- #

    def public_key(self) -> str:
        return _public_hex(self._key)

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


# --------------------------------------------------------------------------- #
# Nitro
# --------------------------------------------------------------------------- #


class SealingPort(Protocol):
    """Encrypt to, and decrypt inside, this enclave. Implemented by KMS.

    Two methods and no key material crosses the boundary, which is the only way
    this can be a port at all. ``decrypt`` is the interesting half: on AWS it is
    ``kms:Decrypt`` carrying the enclave's *attestation document* as the
    ``Recipient``, so KMS returns the plaintext encrypted to an ephemeral public
    key that exists only inside this enclave. The parent proxies the HTTPS and
    learns nothing; the KMS key policy refuses the call unless the attestation's
    PCRs match. See ``merkl.adapters.nitro.kms`` for the implementations and
    ``nitro/README.md`` for the key policy.
    """

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return a ciphertext only this enclave measurement can open."""
        ...

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Open a ciphertext this enclave measurement produced."""
        ...


class SealedKeyPort(Protocol):
    """Where the parent keeps the sealed key blob between boots.

    The parent holds it because the enclave has no disk and no identity that
    survives a restart. It is a ciphertext KMS will only open for an enclave with
    the right measurements, so a parent that reads it, copies it, or hands it to
    another instance still cannot use it.
    """

    def load(self) -> bytes | None:
        """The stored blob, or ``None`` on the first boot."""
        ...

    def store(self, blob: bytes) -> None:
        """Keep this blob for the next boot."""
        ...


class NitroKeystore:
    """The policy key, generated inside an enclave and sealed to its measurements.

    First boot: the key is generated here, from the NSM's entropy, and has never
    existed anywhere else. It is encrypted through :class:`SealingPort` and the
    ciphertext is handed to the parent. Later boots: the parent hands the
    ciphertext back and KMS opens it only for an enclave whose PCRs match the key
    policy. There is no path — not a bug, not a parent with root, not an AWS
    operator — by which the private key leaves this process, because there is no
    code here that returns it.

    ``attestation()`` asks the NSM for a fresh document on every call, with the
    policy public key as ``public_key`` and the current policy hash as
    ``user_data``. Fresh, rather than cached, because an attestation is a
    statement about a moment and a verifier is entitled to bound how old that
    moment is. The policy hash comes from a callable rather than a value so a
    ``policy_update`` (plan D16) is reflected in the very next attestation
    without anything having to remember to re-bind it.
    """

    def __init__(
        self,
        *,
        sealing: SealingPort,
        nsm: NsmPort,
        sealed_key: SealedKeyPort,
        policy_hash: Callable[[], str] | None = None,
    ) -> None:
        self._sealing = sealing
        self._nsm = nsm
        self._sealed = sealed_key
        self._policy_hash = policy_hash
        self._key = self._load_or_create()

    def bind_policy(self, policy_hash: Callable[[], str]) -> None:
        """Tell the keystore where to read the current policy hash.

        Called once, after the engine exists, because the engine needs the
        keystore to be constructed first. A keystore that never gets bound
        attests without ``user_data``, and ``merkl.core``'s check 8 then fails on
        the missing binding rather than passing — the absence is visible.
        """
        self._policy_hash = policy_hash

    # -- construction ------------------------------------------------------ #

    def _load_or_create(self) -> ed25519.Ed25519PrivateKey:
        blob = self._sealed.load()
        if blob is None:
            return self._create()
        try:
            raw = self._sealing.decrypt(blob)
        except KeystoreError:
            raise
        except Exception as exc:
            raise KeystoreError(
                "the sealed policy key could not be opened; either this enclave does not "
                "measure the same as the one that sealed it, or the blob is damaged"
            ) from exc
        if len(raw) != 32:
            raise KeystoreError("the sealed blob is not a 32-byte Ed25519 seed")
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

    def _create(self) -> ed25519.Ed25519PrivateKey:
        """Generate the key here, from the NSM's entropy, and seal it.

        The seed is mixed with ``secrets.token_bytes`` rather than taken from the
        NSM alone: two independent sources means a fault in either one still
        leaves a key the other made unpredictable.
        """
        hardware, software = self._nsm.random(32), secrets.token_bytes(32)
        seed = bytes(a ^ b for a, b in zip(hardware, software, strict=True))
        key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        try:
            blob = self._sealing.encrypt(seed)
        except Exception as exc:
            raise KeystoreError(f"the new policy key could not be sealed: {exc}") from exc
        if not blob:
            raise KeystoreError("sealing produced an empty blob")
        self._sealed.store(blob)
        return key

    # -- the port ---------------------------------------------------------- #

    def public_key(self) -> str:
        return _public_hex(self._key)

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def seal_key(self) -> bytes:
        """A state-sealing key derived from the policy key, never stored.

        Derived rather than sealed separately so there is one secret to protect
        instead of two, and derived with a fixed salt so a snapshot written
        before a reboot is still readable after it.
        """
        seed = self._key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(bytes.fromhex(self.public_key())).digest(),
            info=SEAL_INFO,
        ).derive(seed)

    def attestation(self) -> JSONValue:
        """Receipt leaf 3: a fresh NSM document over this key and this policy."""
        user_data = None
        if self._policy_hash is not None:
            user_data = bytes.fromhex(self._policy_hash())
        document = self._nsm.attest(
            public_key=bytes.fromhex(self.public_key()), user_data=user_data
        )
        return attestation_content(document, self.public_key())

    def __repr__(self) -> str:  # pragma: no cover - never leaks key material
        return f"NitroKeystore(public_key={self.public_key()[:16]}…)"

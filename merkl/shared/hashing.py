"""SHA-256 hash value object for Merkl."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any


@dataclasses.dataclass(frozen=True)
class SHA256Hash:
    """Immutable SHA-256 hash value object (32 bytes)."""

    digest: bytes

    def __post_init__(self) -> None:
        if len(self.digest) != 32:
            raise ValueError(f"SHA-256 digest must be 32 bytes, got {len(self.digest)}")

    @classmethod
    def from_bytes(cls, data: bytes) -> SHA256Hash:
        """Compute SHA-256 hash of the given data."""
        return cls(digest=hashlib.sha256(data).digest())

    def hex(self) -> str:
        """Return the hash as a 64-character hex string."""
        return self.digest.hex()

    @property
    def bytes(self) -> bytes:
        """Access the raw 32-byte digest."""
        return self.digest


def canonical_bytes(value: Any) -> bytes:
    """Serialize a value to canonical, deterministic bytes for hashing.

    Uses JSON with sorted keys so dict insertion order does not change
    the output. Non-JSON types fall through to ``str()`` via ``default=str``.
    This is the single serialization shared by SDK, hooks, and server-side
    verification — diverging from it breaks proof equality.
    """
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()


def canonical_hash(value: Any) -> SHA256Hash:
    """Hash any JSON-serializable value deterministically."""
    return SHA256Hash.from_bytes(canonical_bytes(value))

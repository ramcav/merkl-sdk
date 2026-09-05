"""Sealed state — the signer's rule state, on disk, encrypted, ordered.

The value semantics live in :class:`merkl.core.policy.state.LedgerState`; this
adds durability and nothing else. Every mutation writes a new sealed snapshot
before it returns, so a signer that dies mid-payment comes back having either
recorded the reservation or not — never having answered a caller about a
reservation it then forgot.

Two properties the file format carries:

* **Sealed.** AES-GCM under a key derived from the keystore, so a snapshot on its
  own reveals nothing about who was paid what. Phase 3 swaps the key derivation
  for KMS with a PCR condition and this module does not change.
* **Ordered.** The snapshot carries its monotonic sequence, and :meth:`restore`
  refuses to move backwards. Rolling a signer back to an old snapshot is how you
  spend a window twice, so it is an error rather than a load.

Reconciliation is a hook rather than a loop: hand it what
``SettlementPort.history()`` returned and it says whether the rail knows about
outflows this state never authorized.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from merkl.core.policy.state import (
    LedgerState,
    NonceEntry,
    Outflow,
    Reconciliation,
    SpendEntry,
    StateView,
    reconcile,
)
from merkl.shared.errors import MerklError
from merkl.shared.hashing import canonical_bytes

STATE_FILE: Final = "state.sealed"
SEAL_HEADER: Final = b"merkl-signer-state-v1"
NONCE_BYTES: Final = 12


class SealedStateError(MerklError):
    """Raised when signer state cannot be sealed, opened, or moved forward."""

    error_code = "signer_state_error"


class SealedStateStore:
    """A :class:`~merkl.core.policy.state.StateStore` backed by one sealed file."""

    def __init__(self, directory: Path | str, treasury: str, seal_key: bytes) -> None:
        if len(seal_key) != 32:
            raise SealedStateError("the seal key must be 32 bytes")
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, stat.S_IRWXU)
        self._path = self._dir / STATE_FILE
        self._aead = AESGCM(seal_key)
        self._state = self._open(treasury)

    # -- durability -------------------------------------------------------- #

    def _open(self, treasury: str) -> LedgerState:
        if not self._path.exists():
            return LedgerState(treasury=treasury)
        blob = self._path.read_bytes()
        if not blob.startswith(SEAL_HEADER):
            raise SealedStateError(f"{self._path} is not a Merkl sealed state file")
        body = blob[len(SEAL_HEADER) :]
        nonce, ciphertext = body[:NONCE_BYTES], body[NONCE_BYTES:]
        try:
            plaintext = self._aead.decrypt(nonce, ciphertext, SEAL_HEADER)
        except InvalidTag as exc:
            raise SealedStateError(
                "sealed state will not open: wrong key, or the file was tampered with"
            ) from exc
        import json

        state = LedgerState.from_content(json.loads(plaintext.decode()))
        if state.treasury != treasury:
            raise SealedStateError(
                f"sealed state is for treasury {state.treasury}, this signer serves {treasury}"
            )
        return state

    def _seal(self, state: LedgerState) -> None:
        nonce = secrets.token_bytes(NONCE_BYTES)
        ciphertext = self._aead.encrypt(nonce, canonical_bytes(state.to_content()), SEAL_HEADER)
        tmp = self._path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        try:
            os.write(fd, SEAL_HEADER + nonce + ciphertext)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)

    def _commit(self, state: LedgerState) -> int:
        if state.sequence < self._state.sequence:
            raise SealedStateError(
                f"refusing to move state from sequence {self._state.sequence} back to "
                f"{state.sequence}"
            )
        self._seal(state)
        self._state = state
        return state.sequence

    # -- the port ---------------------------------------------------------- #

    @property
    def sequence(self) -> int:
        return self._state.sequence

    @property
    def path(self) -> Path:
        return self._path

    def view(self) -> StateView:
        return self._state.view()

    def reserve(self, entry: SpendEntry) -> int:
        return self._commit(self._state.with_reservation(entry))

    def release(self, reservation_id: str) -> int:
        return self._commit(self._state.with_release(reservation_id))

    def settle(self, reservation_id: str, settlement_ref: str) -> int:
        return self._commit(self._state.with_settlement(reservation_id, settlement_ref))

    def nonces_seen(self, agent_id: str) -> frozenset[str]:
        return frozenset(n.nonce for n in self._state.nonces if n.agent_id == agent_id)

    def record_nonce(self, entry: NonceEntry) -> int:
        return self._commit(self._state.with_nonce(entry))

    def snapshot(self) -> LedgerState:
        return self._state

    def restore(self, state: LedgerState) -> int:
        return self._commit(state)

    # -- housekeeping ------------------------------------------------------ #

    def prune(self, *, now: str, keep_seconds: int) -> int:
        """Forget entries older than the longest window and expired nonces."""
        pruned = self._state.pruned(now=now, keep_seconds=keep_seconds)
        if pruned is self._state:
            return self._state.sequence
        return self._commit(pruned)

    def reconcile(self, outflows: Iterable[Outflow]) -> Reconciliation:
        """Compare the rail's validated history to what this state authorized.

        Called on boot and periodically (plan D2). An outflow with no matching
        reservation means either that this snapshot is behind what the signer
        actually wrote, or that funds moved without the policy key — and the
        caller must treat both as a reason to stop, not to catch up quietly.
        """
        return reconcile(self._state, outflows)

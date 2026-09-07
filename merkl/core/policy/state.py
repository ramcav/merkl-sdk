"""Rule state — reservations, spend windows and replay nonces.

Rule state lives in the signer and nowhere else (plan D2). It is never supplied
by the caller, because a limit whose counter travels with the request is not a
limit. What lives here is the *shape* of that state: a pure, immutable ledger
that a store can snapshot, seal and restore, plus the read-only view the policy
engine sees.

Two things make the window honest:

* **In-flight reservations count.** A payment counts against the window from the
  moment the signer authorizes it, not from the moment it settles. Otherwise ten
  parallel proposals each see an empty window and ten payments go out.
* **Nothing is counted twice.** A reservation that settles stays the same entry,
  now carrying its settlement reference. Reconciliation against the rail's
  validated history compares those references rather than adding to the total.

A reservation is released only when the attempt provably failed. An abandoned
reservation ages out of the window on its own, which fails closed.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
from typing import Any, Protocol

from merkl.core.canonical import (
    ContentError,
    JSONObject,
    decimal_string,
    drop_none,
    instant,
    parse_decimal,
    parse_instant,
    shift_instant,
    token,
)


class StateError(ContentError):
    """Raised when signer state is not well formed, or a mutation is impossible."""

    error_code = "state_error"


class SpendStatus(enum.StrEnum):
    """Where a reservation is in its life."""

    RESERVED = "reserved"
    SETTLED = "settled"


@dataclasses.dataclass(frozen=True)
class SpendEntry:
    """One authorized outflow, counted against the window from the moment it exists."""

    reservation_id: str
    agent_id: str
    asset: str
    value: str
    at: str
    status: str = SpendStatus.RESERVED.value
    commitment: str | None = None
    settlement_ref: str | None = None

    def __post_init__(self) -> None:
        token(self.reservation_id, "spend.reservation_id", max_length=128)
        token(self.agent_id, "spend.agent_id", max_length=128)
        token(self.asset, "spend.asset", max_length=256)
        decimal_string(self.value, "spend.value", positive=False)
        instant(self.at, "spend.at")
        if self.status not in tuple(SpendStatus):
            raise StateError(f"spend.status must be one of {[s.value for s in SpendStatus]}")
        if self.commitment is not None:
            token(self.commitment, "spend.commitment", max_length=128)
        if self.settlement_ref is not None:
            token(self.settlement_ref, "spend.settlement_ref", max_length=256)

    @property
    def amount(self) -> Decimal:
        return parse_decimal(self.value, "spend.value")

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "reservation_id": self.reservation_id,
                "agent_id": self.agent_id,
                "asset": self.asset,
                "value": self.value,
                "at": self.at,
                "status": self.status,
                "commitment": self.commitment,
                "settlement_ref": self.settlement_ref,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> SpendEntry:
        obj = _object(data, "spend")
        return cls(
            reservation_id=_required(obj, "reservation_id", "spend"),
            agent_id=_required(obj, "agent_id", "spend"),
            asset=_required(obj, "asset", "spend"),
            value=_required(obj, "value", "spend"),
            at=_required(obj, "at", "spend"),
            status=obj.get("status", SpendStatus.RESERVED.value),
            commitment=obj.get("commitment"),
            settlement_ref=obj.get("settlement_ref"),
        )


@dataclasses.dataclass(frozen=True)
class NonceEntry:
    """One request nonce the signer has already answered (plan D15)."""

    agent_id: str
    nonce: str
    expires_at: str

    def __post_init__(self) -> None:
        token(self.agent_id, "nonce.agent_id", max_length=128)
        token(self.nonce, "nonce.nonce", max_length=128)
        instant(self.expires_at, "nonce.expires_at")

    def to_content(self) -> JSONObject:
        return {"agent_id": self.agent_id, "nonce": self.nonce, "expires_at": self.expires_at}

    @classmethod
    def from_content(cls, data: Any) -> NonceEntry:
        obj = _object(data, "nonce")
        return cls(
            agent_id=_required(obj, "agent_id", "nonce"),
            nonce=_required(obj, "nonce", "nonce"),
            expires_at=_required(obj, "expires_at", "nonce"),
        )


def _object(data: Any, owner: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise StateError(f"{owner} must be an object, got {type(data).__name__}")
    return data


def _required(data: Mapping[str, Any], key: str, owner: str) -> Any:
    if key not in data:
        raise StateError(f"{owner} requires {key}")
    return data[key]


# --------------------------------------------------------------------------- #
# The read side
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class StateView:
    """What the policy engine is allowed to know about history.

    Read-only and scoped to one treasury. The engine cannot reserve, release or
    settle: it decides, and the signer records. Keeping the two apart is what
    makes ``evaluate`` a pure function of its arguments.
    """

    treasury: str
    entries: tuple[SpendEntry, ...] = ()
    nonces: frozenset[tuple[str, str]] = frozenset()

    def spent_within(self, *, agent_id: str, asset: str, since: str, until: str) -> Decimal:
        """Total authorized outflow for one agent and asset in ``[since, until]``.

        Includes reservations that have not settled — that is the point of
        reserving. Excludes nothing else: a settled entry is the same entry.
        """
        start = parse_instant(since, "window.since")
        end = parse_instant(until, "window.until")
        total = Decimal(0)
        for entry in self.entries:
            if entry.agent_id != agent_id or entry.asset != asset:
                continue
            at = parse_instant(entry.at, "spend.at")
            if start <= at <= end:
                total += entry.amount
        return total

    def excluding_reservation(self, reservation_id: str) -> StateView:
        """This view with one reservation removed, for re-evaluating its own intent.

        Re-checking an escalation against the window means asking "has *other*
        activity filled it since", not "does this payment's own still-open
        reservation plus this payment's own amount fit" — ``spent_within``
        already counts an unsettled reservation (that is the point of
        reserving), so evaluating an intent against a view that still holds
        that intent's own entry would add its amount twice.
        """
        return dataclasses.replace(
            self, entries=tuple(e for e in self.entries if e.reservation_id != reservation_id)
        )

    def nonce_seen(self, agent_id: str, nonce: str) -> bool:
        """True when this agent has already used this nonce."""
        return (agent_id, nonce) in self.nonces


@dataclasses.dataclass(frozen=True)
class LedgerState:
    """The signer's whole rule state, as one immutable value.

    Every mutation returns a new ``LedgerState`` with ``sequence`` one higher. The
    sequence is what makes a sealed snapshot orderable: a signer that boots on an
    older snapshot than the one it last wrote can tell, and a snapshot that
    replays an earlier sequence is a rollback attempt, not a restore.
    """

    treasury: str
    sequence: int = 0
    entries: tuple[SpendEntry, ...] = ()
    nonces: tuple[NonceEntry, ...] = ()

    def __post_init__(self) -> None:
        token(self.treasury, "state.treasury", max_length=128)
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise StateError("state.sequence must be an integer")
        if self.sequence < 0:
            raise StateError("state.sequence must not be negative")

    # -- reads ------------------------------------------------------------- #

    def view(self) -> StateView:
        return StateView(
            treasury=self.treasury,
            entries=self.entries,
            nonces=frozenset((n.agent_id, n.nonce) for n in self.nonces),
        )

    def entry(self, reservation_id: str) -> SpendEntry | None:
        for candidate in self.entries:
            if candidate.reservation_id == reservation_id:
                return candidate
        return None

    # -- writes ------------------------------------------------------------ #

    def _next(self, **changes: Any) -> LedgerState:
        return dataclasses.replace(self, sequence=self.sequence + 1, **changes)

    def with_reservation(self, entry: SpendEntry) -> LedgerState:
        if self.entry(entry.reservation_id) is not None:
            raise StateError(f"reservation {entry.reservation_id} already exists")
        return self._next(entries=(*self.entries, entry))

    def with_release(self, reservation_id: str) -> LedgerState:
        """Drop a reservation whose attempt provably failed."""
        existing = self.entry(reservation_id)
        if existing is None:
            raise StateError(f"no reservation {reservation_id}")
        if existing.status == SpendStatus.SETTLED.value:
            raise StateError(f"reservation {reservation_id} settled; it cannot be released")
        return self._next(
            entries=tuple(e for e in self.entries if e.reservation_id != reservation_id)
        )

    def with_settlement(self, reservation_id: str, settlement_ref: str) -> LedgerState:
        """Mark a reservation settled. The amount stays counted; only the label changes."""
        existing = self.entry(reservation_id)
        if existing is None:
            raise StateError(f"no reservation {reservation_id}")
        settled = dataclasses.replace(
            existing, status=SpendStatus.SETTLED.value, settlement_ref=settlement_ref
        )
        return self._next(
            entries=tuple(
                settled if e.reservation_id == reservation_id else e for e in self.entries
            )
        )

    def with_nonce(self, entry: NonceEntry) -> LedgerState:
        if any(n.agent_id == entry.agent_id and n.nonce == entry.nonce for n in self.nonces):
            raise StateError(f"nonce {entry.nonce} was already used by {entry.agent_id}")
        return self._next(nonces=(*self.nonces, entry))

    def pruned(self, *, now: str, keep_seconds: int) -> LedgerState:
        """Forget spend entries older than the longest window and expired nonces.

        Pruning is a mutation like any other: it bumps the sequence, so a pruned
        snapshot never looks like an older one.
        """
        horizon = parse_instant(shift_instant(now, -keep_seconds), "prune.horizon")
        entries = tuple(e for e in self.entries if parse_instant(e.at, "spend.at") >= horizon)
        moment = parse_instant(now, "prune.now")
        nonces = tuple(
            n for n in self.nonces if parse_instant(n.expires_at, "nonce.expires_at") >= moment
        )
        if len(entries) == len(self.entries) and len(nonces) == len(self.nonces):
            return self
        return self._next(entries=entries, nonces=nonces)

    # -- snapshot ---------------------------------------------------------- #

    def to_content(self) -> JSONObject:
        return {
            "treasury": self.treasury,
            "sequence": self.sequence,
            "entries": [e.to_content() for e in self.entries],
            "nonces": [n.to_content() for n in self.nonces],
        }

    @classmethod
    def from_content(cls, data: Any) -> LedgerState:
        obj = _object(data, "state")
        entries = obj.get("entries", [])
        nonces = obj.get("nonces", [])
        if not isinstance(entries, list) or not isinstance(nonces, list):
            raise StateError("state.entries and state.nonces must be arrays")
        return cls(
            treasury=_required(obj, "treasury", "state"),
            sequence=obj.get("sequence", 0),
            entries=tuple(SpendEntry.from_content(e) for e in entries),
            nonces=tuple(NonceEntry.from_content(n) for n in nonces),
        )


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #


class StateStore(Protocol):
    """Where rule state is kept, sealed and restored.

    An implementation owns durability; the value semantics are
    :class:`LedgerState`'s. Every mutation returns the new monotonic sequence, so
    a caller can assert that a snapshot it took is the one it wrote.
    """

    @property
    def sequence(self) -> int:
        """The current monotonic sequence."""
        ...

    def view(self) -> StateView:
        """The read-only view handed to the policy engine."""
        ...

    def reserve(self, entry: SpendEntry) -> int:
        """Record an authorized outflow, counted against the window immediately."""
        ...

    def release(self, reservation_id: str) -> int:
        """Drop a reservation whose attempt failed."""
        ...

    def settle(self, reservation_id: str, settlement_ref: str) -> int:
        """Mark a reservation settled, keeping the amount counted."""
        ...

    def nonces_seen(self, agent_id: str) -> frozenset[str]:
        """Every nonce this agent has already used."""
        ...

    def record_nonce(self, entry: NonceEntry) -> int:
        """Remember a nonce so the request cannot be replayed."""
        ...

    def snapshot(self) -> LedgerState:
        """The current state as one immutable value."""
        ...

    def restore(self, state: LedgerState) -> int:
        """Adopt a snapshot. Refuses to go backwards."""
        ...


# --------------------------------------------------------------------------- #
# Reconciliation
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Outflow:
    """One validated outflow read back from the rail (plan D17)."""

    tx_hash: str
    treasury: str
    destination: str
    value: str
    asset: str
    ledger_index: int
    close_time: str
    anchor: str | None = None

    def __post_init__(self) -> None:
        token(self.tx_hash, "outflow.tx_hash", max_length=128)
        token(self.treasury, "outflow.treasury", max_length=128)
        token(self.destination, "outflow.destination", max_length=128)
        decimal_string(self.value, "outflow.value", positive=False)
        token(self.asset, "outflow.asset", max_length=256)
        instant(self.close_time, "outflow.close_time")
        if self.anchor is not None:
            token(self.anchor, "outflow.anchor", max_length=2048)

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "tx_hash": self.tx_hash,
                "treasury": self.treasury,
                "destination": self.destination,
                "value": self.value,
                "asset": self.asset,
                "ledger_index": self.ledger_index,
                "close_time": self.close_time,
                "anchor": self.anchor,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> Outflow:
        """Rebuild an outflow from JSON, validating on the way in.

        The reader is the enclave, and what it is reading came from the parent —
        the party this design assumes may be compromised. So this is not a
        convenience: it is the boundary where untrusted history becomes a value
        object with checked fields, or an error. Reconciliation compares it to
        state; it never takes a decision from it.
        """
        obj = _object(data, "outflow")
        return cls(
            tx_hash=_required(obj, "tx_hash", "outflow"),
            treasury=_required(obj, "treasury", "outflow"),
            destination=_required(obj, "destination", "outflow"),
            value=_required(obj, "value", "outflow"),
            asset=_required(obj, "asset", "outflow"),
            ledger_index=_ledger_index(obj),
            close_time=_required(obj, "close_time", "outflow"),
            anchor=obj.get("anchor"),
        )


def _ledger_index(obj: Mapping[str, Any]) -> int:
    value = obj.get("ledger_index")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StateError("outflow.ledger_index must be a non-negative integer")
    return value


@dataclasses.dataclass(frozen=True)
class Reconciliation:
    """Treasury outflows against signer state, in both directions (plan D17).

    ``unmatched_outflows`` is the line that matters: money left the treasury and
    the signer has no record of authorizing it. Either the snapshot is stale — the
    signer booted on an older sequence than the one it wrote — or something moved
    funds without the policy key, which is the failure the whole design exists to
    make visible.
    """

    matched: tuple[str, ...] = ()
    unmatched_outflows: tuple[str, ...] = ()
    unsettled_reservations: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.unmatched_outflows

    @property
    def stale_snapshot(self) -> bool:
        """True when the rail knows about outflows this state never recorded."""
        return bool(self.unmatched_outflows)

    def to_content(self) -> JSONObject:
        return {
            "matched": list(self.matched),
            "unmatched_outflows": list(self.unmatched_outflows),
            "unsettled_reservations": list(self.unsettled_reservations),
            "clean": self.clean,
        }


def reconcile(state: LedgerState, outflows: Iterable[Outflow]) -> Reconciliation:
    """Match validated rail outflows to the reservations that authorized them.

    An outflow matches when its settlement reference is one the state settled, or
    when the anchor it carries is a commitment the state reserved. The anchor path
    is the one that survives a crash between submitting and recording: the memo on
    the ledger *is* the receipt's LEFT, so the outflow identifies itself.
    """
    by_ref = {e.settlement_ref: e for e in state.entries if e.settlement_ref}
    by_commitment = {e.commitment: e for e in state.entries if e.commitment}
    matched: list[str] = []
    unmatched: list[str] = []
    seen: set[str] = set()
    for outflow in outflows:
        entry = by_ref.get(outflow.tx_hash)
        if entry is None and outflow.anchor:
            entry = by_commitment.get(outflow.anchor)
        if entry is None:
            unmatched.append(outflow.tx_hash)
            continue
        matched.append(outflow.tx_hash)
        seen.add(entry.reservation_id)
    unsettled = tuple(
        e.reservation_id
        for e in state.entries
        if e.status == SpendStatus.RESERVED.value and e.reservation_id not in seen
    )
    return Reconciliation(
        matched=tuple(matched),
        unmatched_outflows=tuple(unmatched),
        unsettled_reservations=unsettled,
    )


def outflows_from_content(values: Sequence[Any]) -> tuple[Outflow, ...]:
    """Parse rail history back into outflows (used by the reconciliation hook)."""
    parsed: list[Outflow] = []
    for value in values:
        obj = _object(value, "outflow")
        parsed.append(
            Outflow(
                tx_hash=_required(obj, "tx_hash", "outflow"),
                treasury=_required(obj, "treasury", "outflow"),
                destination=_required(obj, "destination", "outflow"),
                value=_required(obj, "value", "outflow"),
                asset=_required(obj, "asset", "outflow"),
                ledger_index=_required(obj, "ledger_index", "outflow"),
                close_time=_required(obj, "close_time", "outflow"),
                anchor=obj.get("anchor"),
            )
        )
    return tuple(parsed)

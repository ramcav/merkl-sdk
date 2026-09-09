"""The agent's own books: what it remembers, what it owes, what it wrote down.

Three things live here and they are deliberately separate from the receipts.

``State`` is the small JSON file that lets the process die and come back without
lying about what happened. It holds the cycle counter, the last refusal the
agent was told about, an escalation still waiting on people, and — the part that
matters most — the receipt id and nonce of an action that was *started*. The
nonce is written to disk before the proposal leaves the process, so a crash
between proposing and journalling can never turn into a second proposal: on the
way back up the agent looks that receipt up in its own store and journals what
actually happened, and if it cannot find it, it says so and moves on. It never
re-sends. A trading agent that retries on restart is a trading agent that
double-trades on a bad afternoon.

``Bill`` is the agent's cost of existing. It counts its own tokens from what the
API reported, prices them at the rate in the config, and once a week proposes to
pay the operator for them out of the treasury. This is the honest part of the
story: the agent is not free, it knows what it costs, and if it cannot cover
that cost it stops rather than quietly running on somebody else's money.

``Journal`` is the public diary — two lines a cycle in ``journal.md``, the same
facts as data in ``journal.jsonl``. It is not evidence and does not pretend to
be; the receipt is the evidence. This is the part a human reads over coffee.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from decimal import ROUND_UP, Decimal
from pathlib import Path
from typing import Any, Final

from merkl.core.canonical import JSONObject, format_decimal

DROP: Final = Decimal("0.000001")
MILLION: Final = Decimal(1_000_000)
SECONDS_PER_DAY: Final = Decimal(86_400)
WEEKDAYS: Final = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


# -- state ------------------------------------------------------------------ #


@dataclasses.dataclass
class InFlight:
    """An action that was started. Written before the proposal, cleared after."""

    receipt_id: str
    nonce: str
    kind: str
    at: str

    def to_content(self) -> JSONObject:
        return {
            "receipt_id": self.receipt_id,
            "nonce": self.nonce,
            "kind": self.kind,
            "at": self.at,
        }

    @classmethod
    def from_content(cls, data: dict[str, Any]) -> InFlight:
        return cls(
            receipt_id=str(data["receipt_id"]),
            nonce=str(data["nonce"]),
            kind=str(data.get("kind", "swap")),
            at=str(data.get("at", "")),
        )


@dataclasses.dataclass
class Pending:
    """An escalation the signer opened, and everything needed to finish it."""

    challenge: str
    expires_at: str
    quorum: int
    receipt_id: str
    intent: JSONObject
    instruction: JSONObject
    reasoning: JSONObject | None
    opened_at: str

    def to_content(self) -> JSONObject:
        return {
            "challenge": self.challenge,
            "expires_at": self.expires_at,
            "quorum": self.quorum,
            "receipt_id": self.receipt_id,
            "intent": self.intent,
            "instruction": self.instruction,
            "reasoning": self.reasoning,
            "opened_at": self.opened_at,
        }

    @classmethod
    def from_content(cls, data: dict[str, Any]) -> Pending:
        return cls(
            challenge=str(data["challenge"]),
            expires_at=str(data["expires_at"]),
            quorum=int(data["quorum"]),
            receipt_id=str(data["receipt_id"]),
            intent=dict(data["intent"]),
            instruction=dict(data["instruction"]),
            reasoning=dict(data["reasoning"]) if data.get("reasoning") else None,
            opened_at=str(data.get("opened_at", "")),
        )


@dataclasses.dataclass
class Bill:
    """What the agent owes for its own compute, and when it last settled up."""

    accrued_usd: Decimal = Decimal(0)
    tokens_in: int = 0
    tokens_out: int = 0
    cycles: int = 0
    """Cycles since the last bill — the denominator of the burn rate."""

    last_paid: str = ""
    """``YYYY-MM-DD`` of the last bill that settled. Empty until the first one."""

    def accrue(
        self, *, tokens_in: int, tokens_out: int, per_million_in: Decimal, per_million_out: Decimal
    ) -> Decimal:
        """Price one cycle's tokens and add them to the tab. Returns this cycle's cost."""
        cost = (
            Decimal(tokens_in) * per_million_in + Decimal(tokens_out) * per_million_out
        ) / MILLION
        self.accrued_usd += cost
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.cycles += 1
        return cost

    def settled(self, day: str) -> None:
        """The bill was paid. Reset the tab, keep nothing but the date."""
        self.accrued_usd = Decimal(0)
        self.tokens_in = 0
        self.tokens_out = 0
        self.cycles = 0
        self.last_paid = day

    def daily_usd(self, interval_seconds: int) -> Decimal | None:
        """Burn per day at the rate this agent has actually been running at."""
        if self.cycles <= 0 or interval_seconds <= 0:
            return None
        per_cycle = self.accrued_usd / Decimal(self.cycles)
        return per_cycle * (SECONDS_PER_DAY / Decimal(interval_seconds))

    def due(self, now: datetime, bill_day: str) -> bool:
        """True on the configured weekday, at most once on that day."""
        today = now.date().isoformat()
        if self.last_paid == today:
            return False
        return WEEKDAYS[now.weekday()] == bill_day and self.accrued_usd > 0

    def to_content(self) -> JSONObject:
        return {
            "accrued_usd": format_decimal(self.accrued_usd),
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cycles": self.cycles,
            "last_paid": self.last_paid,
        }

    @classmethod
    def from_content(cls, data: dict[str, Any]) -> Bill:
        return cls(
            accrued_usd=Decimal(str(data.get("accrued_usd", "0"))),
            tokens_in=int(data.get("tokens_in", 0)),
            tokens_out=int(data.get("tokens_out", 0)),
            cycles=int(data.get("cycles", 0)),
            last_paid=str(data.get("last_paid", "")),
        )


@dataclasses.dataclass
class State:
    """Everything the agent needs to survive being killed between cycles."""

    cycle: int = 0
    lesson: str = ""
    """The last refusal, in the signer's own words. Fed back to the model."""

    pending: Pending | None = None
    in_flight: InFlight | None = None
    bill: Bill = dataclasses.field(default_factory=Bill)

    def to_content(self) -> JSONObject:
        return {
            "cycle": self.cycle,
            "lesson": self.lesson,
            "pending": self.pending.to_content() if self.pending else None,
            "in_flight": self.in_flight.to_content() if self.in_flight else None,
            "bill": self.bill.to_content(),
        }

    @classmethod
    def from_content(cls, data: dict[str, Any]) -> State:
        return cls(
            cycle=int(data.get("cycle", 0)),
            lesson=str(data.get("lesson", "")),
            pending=Pending.from_content(data["pending"]) if data.get("pending") else None,
            in_flight=(
                InFlight.from_content(data["in_flight"]) if data.get("in_flight") else None
            ),
            bill=Bill.from_content(data.get("bill") or {}),
        )

    @classmethod
    def load(cls, path: Path) -> State:
        """Read the file, or start fresh. A corrupt file is an error, not a reset."""
        if not path.exists():
            return cls()
        return cls.from_content(json.loads(path.read_text()))

    def save(self, path: Path) -> None:
        """Write atomically: a half-written state file is worse than none."""
        path.parent.mkdir(parents=True, exist_ok=True)
        scratch = path.with_suffix(path.suffix + ".tmp")
        scratch.write_text(json.dumps(self.to_content(), indent=2) + "\n")
        scratch.replace(path)


# -- the journal ------------------------------------------------------------ #


@dataclasses.dataclass(frozen=True)
class Entry:
    """One cycle, as the public sees it."""

    at: str
    cycle: int
    balances: dict[str, Decimal]
    headline: str
    action: str
    outcome: str
    receipt_id: str | None = None
    runway_days: Decimal | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: Decimal = Decimal(0)

    def lines(self) -> tuple[str, str]:
        """The two lines. Balances and runway first, then what it did."""
        holdings = " + ".join(
            f"{format_decimal(_trim(value))} {code}" for code, value in self.balances.items()
        )
        runway = (
            f"runway {format_decimal(self.runway_days.quantize(Decimal('1')))} days"
            if self.runway_days is not None
            else "runway unknown"
        )
        tail = f" receipt {self.receipt_id}" if self.receipt_id else ""
        return f"{self.at} — {holdings} — {runway}", f"{self.headline}{tail}"

    def to_content(self) -> JSONObject:
        return {
            "at": self.at,
            "cycle": self.cycle,
            "balances": {code: format_decimal(value) for code, value in self.balances.items()},
            "headline": self.headline,
            "action": self.action,
            "outcome": self.outcome,
            "receipt_id": self.receipt_id,
            "runway_days": (
                None if self.runway_days is None else format_decimal(_trim(self.runway_days))
            ),
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd": format_decimal(self.cost_usd),
        }


class Journal:
    """Two files, appended, never rewritten."""

    def __init__(self, markdown: Path, jsonl: Path) -> None:
        self._markdown = markdown
        self._jsonl = jsonl

    def append(self, entry: Entry) -> tuple[str, str]:
        """Write the cycle to both files and return the two lines written."""
        first, second = entry.lines()
        self._markdown.parent.mkdir(parents=True, exist_ok=True)
        with self._markdown.open("a") as handle:
            handle.write(f"{first}\n{second}\n\n")
        with self._jsonl.open("a") as handle:
            handle.write(json.dumps(entry.to_content()) + "\n")
        return first, second

    def note(self, at: str, text: str) -> None:
        """A line that is not a cycle: out of business, a resumed escalation."""
        self._markdown.parent.mkdir(parents=True, exist_ok=True)
        with self._markdown.open("a") as handle:
            handle.write(f"{at} — {text}\n\n")
        with self._jsonl.open("a") as handle:
            handle.write(json.dumps({"at": at, "action": "note", "headline": text}) + "\n")


# -- money ------------------------------------------------------------------ #


def bill_in_xrp(accrued_usd: Decimal, price_usd: Decimal) -> Decimal:
    """The tab, converted at one stated price, rounded up to the nearest drop.

    Up, not nearest: the rounding error is a fraction of a drop and it belongs to
    the party who is owed the money, not the party who owes it.
    """
    if price_usd <= 0:
        raise ValueError("cannot convert a bill at a non-positive price")
    return (accrued_usd / price_usd).quantize(DROP, rounding=ROUND_UP)


def runway_days(
    balances: dict[str, Decimal],
    *,
    base: str,
    quote: str,
    price: Decimal | None,
    daily_usd: Decimal | None,
) -> Decimal | None:
    """Days of compute the treasury can still pay for, at the current burn.

    The quote asset is a dollar stablecoin, so it counts at face value; the base
    asset is converted at ``price``. Both may be unavailable — a book with no
    offers, a first cycle with no burn history — and the answer is then ``None``
    rather than a number nobody can defend.
    """
    if daily_usd is None or daily_usd <= 0 or price is None or price <= 0:
        return None
    funds = balances.get(base, Decimal(0)) * price + balances.get(quote, Decimal(0))
    return funds / daily_usd


def _trim(value: Decimal) -> Decimal:
    """Six places is what a drop is worth; more is noise in a journal line."""
    return value.quantize(DROP) + Decimal(0)


__all__ = [
    "Bill",
    "Entry",
    "InFlight",
    "Journal",
    "Pending",
    "State",
    "bill_in_xrp",
    "runway_days",
]

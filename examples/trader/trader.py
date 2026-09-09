"""The loop. Read the market, ask the model, act at most once, write it down.

    python -m examples.trader --config trader.toml

That is the whole program. It is a plain process — no scheduler, no queue, no
daemon — and it is meant to be run under whatever already restarts things on the
machine you have. What makes a restart safe is not the supervisor, it is
``ledger.State``: the nonce and receipt id of an action are on disk *before* the
proposal leaves this process, so coming back up is a matter of looking up what
happened rather than guessing, and nothing is ever re-proposed.

The order inside a cycle is deliberate:

1. finish anything that was in flight when the process last died;
2. resolve any escalation a human has now answered, before deciding anything new
   — an agent that made a fresh decision while a human was still thinking about
   its last one would be an agent whose escalations mean nothing;
3. read the market and the treasury;
4. if the compute bill is due, pay it — that is this cycle's one action;
5. otherwise ask the model, and act on at most one thing it says;
6. journal, sleep.

Every refusal becomes the next cycle's lesson, in the signer's own words. That
feedback loop is the only channel through which this agent ever learns what its
policy says.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from examples.trader import config as configuration
from examples.trader import decide as decisions
from examples.trader import ledger as books
from examples.trader import market as markets
from merkl.adapters.notary import HttpNotary
from merkl.adapters.signer_dev import DevSignerClient
from merkl.adapters.xrpl import XrplSettlementAdapter, load_wallets
from merkl.core.canonical import ContentError, JSONObject, JSONValue, format_decimal, shift_instant
from merkl.core.intent import Amount, CurrencyRef, Intent, IssuedCurrency, SwapBuy, SwapSell
from merkl.core.receipt import Instruction, PolicyOutcome, Reasoning
from merkl.sdk.receipt_store import LocalReceiptStore
from merkl.sdk.receipts import ReceiptBuilder, ReceiptOutcome, SystemClock
from merkl.shared.hashing import SHA256Hash

RAIL: Final = "xrpl"
INTENT_TTL_SECONDS: Final = 600
NONCE_LENGTH: Final = 32
RECEIPTS_SHOWN: Final = 20


class OutOfBusiness(Exception):
    """The agent cannot pay for itself. There is no recovering from this in code."""


# --------------------------------------------------------------------------- #
# The notary, as this agent uses it: a place to ask whether people have answered
# --------------------------------------------------------------------------- #


class EscalationQueue:
    """``GET /v1/escalations/{challenge}`` — has a human decided yet?

    Only a read. Approvals are signed by people through the dashboard and
    relayed to the co-signer by merkl-api; this agent has no standing to approve
    anything and never asks to. What it wants back is the co-signer's own
    decision, which merkl-api hands to whichever caller's approval completed the
    quorum. When that caller is the notary rather than this process, the
    settlement material — the LEFT, the signature, the reservation — never
    reaches here, and the agent says so in the journal instead of inventing a
    decision nobody made.
    """

    def __init__(self, url: str, api_key: str, client: httpx.AsyncClient | None = None) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def get(self, challenge: str) -> JSONObject | None:
        """The escalation, or ``None`` when the notary cannot say."""
        try:
            response = await self._client.get(
                f"{self._url}/v1/escalations/{challenge}",
                headers={"X-Merkl-API-Key": self._api_key} if self._api_key else {},
            )
        except httpx.HTTPError:
            return None
        if not response.is_success:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        return body if isinstance(body, dict) else None


# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Cycle:
    """What one pass produced, before it is written down."""

    entry: books.Entry
    fatal: str = ""


class Trader:
    """One treasury, one policy it cannot read, one decision at a time."""

    def __init__(
        self,
        settings: configuration.Config,
        *,
        builder: ReceiptBuilder,
        agent_public_key: str,
        reader: markets.MarketReader,
        store: LocalReceiptStore,
        model: decisions.ModelPort,
        journal: books.Journal,
        queue: EscalationQueue | None = None,
        rail: Any | None = None,
        clock: Any | None = None,
        dry_run: bool = False,
    ) -> None:
        self.settings = settings
        self.builder = builder
        self.agent_public_key = agent_public_key
        self.reader = reader
        self.store = store
        self.model = model
        self.journal = journal
        self.queue = queue
        self.rail = rail
        self.clock = clock or SystemClock()
        self.dry_run = dry_run
        self.state = books.State.load(settings.loop.state_file)

    async def aclose(self) -> None:
        """Let go of every socket this agent opened."""
        await self.reader.aclose()
        if self.queue is not None:
            await self.queue.aclose()
        close = getattr(self.rail, "close", None)
        if close is not None:
            await close()

    # -- the cycle ---------------------------------------------------------- #

    async def cycle(self) -> Cycle:
        """One pass. Never raises for a refusal; raises only when it cannot go on."""
        now = self.clock.now()
        self.state.cycle += 1

        await self._recover(now)
        await self._resolve_escalation(now)

        snapshot = await self.reader.snapshot(now)
        price = self._price(snapshot)
        burn = self.state.bill.daily_usd(self.settings.loop.interval_seconds)
        runway = books.runway_days(
            snapshot.balances,
            base=snapshot.base,
            quote=snapshot.quote,
            price=price,
            daily_usd=burn,
        )

        if self.state.pending is not None:
            return self._entry(
                now,
                snapshot,
                runway,
                headline=(
                    "Waiting on a human: an earlier proposal was escalated and is still open."
                ),
                action="wait",
                outcome="escalated",
            )

        if self.state.bill.due(_moment(now), self.settings.bill.bill_day):
            return await self._pay_the_bill(now, snapshot, price, runway)

        return await self._trade(now, snapshot, runway, burn)

    # -- step 1: what was in flight ---------------------------------------- #

    async def _recover(self, now: str) -> None:
        """Look up an action that was started before the process died. Never resend."""
        in_flight = self.state.in_flight
        if in_flight is None:
            return
        found = await self.store.get(in_flight.receipt_id)
        if found is None:
            self.journal.note(
                now,
                f"restarted with {in_flight.kind} {in_flight.receipt_id} in flight and no "
                "receipt for it. Not re-proposing: the nonce is spent either way.",
            )
        else:
            _, leaves = found
            outcome = leaves.result.outcome if leaves.result else "unknown"
            self.journal.note(
                now,
                f"restarted; {in_flight.kind} {in_flight.receipt_id} had already "
                f"{outcome} before the crash.",
            )
        self.state.in_flight = None
        self._save()

    # -- step 2: escalations ------------------------------------------------ #

    async def _resolve_escalation(self, now: str) -> None:
        """Ask the notary whether people have answered, and finish if they have."""
        pending = self.state.pending
        if pending is None or self.queue is None:
            return
        answer = await self.queue.get(pending.challenge)
        if answer is None:
            return
        status = str(answer.get("status", "pending"))
        if status == "pending":
            return

        decision = answer.get("signer_decision")
        if isinstance(decision, dict):
            await self._resume(now, pending, decision)
            return

        self.state.pending = None
        if status == "approved":
            self.state.lesson = (
                "Your last proposal was approved by a human, but the co-signer handed the "
                "signed transaction to the notary that relayed the approval, not to you, so "
                "it was never submitted from here. Propose it again if it is still the right "
                "move."
            )
            self.journal.note(
                now,
                f"escalation {pending.challenge[:12]}… was approved; the settlement material "
                "went to the relaying notary and never reached this process. Nothing was "
                "submitted from here.",
            )
        else:
            self.state.lesson = f"Your last proposal was escalated to a human and was {status}."
            self.journal.note(
                now, f"escalation {pending.challenge[:12]}… was {status}. Nothing settled."
            )
        self._save()

    async def _resume(self, now: str, pending: books.Pending, decision: JSONObject) -> None:
        """Finish a payment a human decided out of band (``ReceiptBuilder.resume``)."""
        receipt_id = str(SHA256Hash.from_bytes(f"resume:{pending.challenge}".encode()).hex()[:32])
        self.state.in_flight = books.InFlight(
            receipt_id=receipt_id, nonce=str(pending.intent.get("nonce", "")), kind="resume", at=now
        )
        self.state.pending = None
        self._save()
        outcome = await self.builder.resume(
            instruction=Instruction.from_content(pending.instruction),
            intent=Intent.from_content(pending.intent),
            decision=decision,
            receipt_id=receipt_id,
            reasoning=(Reasoning.from_content(pending.reasoning) if pending.reasoning else None),
        )
        self.state.in_flight = None
        self.state.lesson = "" if outcome.settled else _lesson(outcome)
        self.journal.note(
            now,
            f"a human answered escalation {pending.challenge[:12]}…; the resumed proposal "
            f"{outcome.outcome} and {'settled' if outcome.settled else 'did not settle'}. "
            f"receipt {outcome.envelope.receipt_id}",
        )
        self._save()

    # -- step 4: the compute bill ------------------------------------------ #

    async def _pay_the_bill(
        self,
        now: str,
        snapshot: markets.Snapshot,
        price: Decimal | None,
        runway: Decimal | None,
    ) -> Cycle:
        """Pay the operator for the tokens this agent has burned. One action."""
        owed = self.state.bill.accrued_usd
        if price is None:
            return self._entry(
                now,
                snapshot,
                runway,
                headline=(
                    f"Compute bill of ${format_decimal(owed)} is due, but nothing would price "
                    f"{snapshot.base} this cycle. Holding it over."
                ),
                action="bill",
                outcome="none",
            )
        amount = books.bill_in_xrp(owed, price)
        held = snapshot.balance(snapshot.base)
        if amount > held:
            raise OutOfBusiness(
                f"the compute bill is {format_decimal(amount)} {snapshot.base} and the "
                f"treasury holds {format_decimal(held)}."
            )
        if self.dry_run:
            return self._entry(
                now,
                snapshot,
                runway,
                headline=(
                    f"Dry run: would pay {format_decimal(amount)} {snapshot.base} to the "
                    f"operator for ${format_decimal(owed)} of compute."
                ),
                action="bill",
                outcome="none",
            )

        intent = self._payment_intent(
            now,
            destination=self.settings.bill.operator,
            amount=Amount(value=format_decimal(amount), currency=snapshot.base),
            receipt_id=self._receipt_id("bill"),
        )
        outcome = await self._execute(
            now,
            intent=intent,
            kind="bill",
            reasoning=(
                f"Weekly compute bill: {self.state.bill.tokens_in} input and "
                f"{self.state.bill.tokens_out} output tokens over {self.state.bill.cycles} "
                f"cycles, ${format_decimal(owed)} at {format_decimal(price)} "
                f"{snapshot.quote} per {snapshot.base}."
            ),
            source="mandate",
        )
        if outcome.settled:
            self.state.bill.settled(_moment(now).date().isoformat())
            self._save()
            return self._entry(
                now,
                snapshot,
                runway,
                headline=(
                    f"Paid the operator {format_decimal(amount)} {snapshot.base} for "
                    f"${format_decimal(owed)} of compute."
                ),
                action="bill",
                outcome="settled",
                receipt_id=outcome.envelope.receipt_id,
            )
        if outcome.outcome == PolicyOutcome.ESCALATE.value:
            return self._entry(
                now,
                snapshot,
                runway,
                headline=(
                    f"The compute bill of {format_decimal(amount)} {snapshot.base} went to a "
                    "human. It is unpaid until they answer."
                ),
                action="bill",
                outcome="escalated",
                receipt_id=outcome.envelope.receipt_id,
            )
        raise OutOfBusiness(
            f"the compute bill was refused: {outcome.reason or outcome.outcome}. "
            f"receipt {outcome.envelope.receipt_id}"
        )

    # -- step 5: the trade -------------------------------------------------- #

    async def _trade(
        self,
        now: str,
        snapshot: markets.Snapshot,
        runway: Decimal | None,
        burn: Decimal | None,
    ) -> Cycle:
        """Ask the model, and do at most one of the things it asks for."""
        decision = await decisions.decide(
            model=self.model,
            model_name=self.settings.model.name,
            max_tokens=self.settings.model.max_tokens,
            situation=self._situation(now, runway, burn),
            market=lambda: _ready(snapshot.to_content()),
            receipts=self._receipts,
        )
        cost = self.state.bill.accrue(
            tokens_in=decision.usage.input_tokens,
            tokens_out=decision.usage.output_tokens,
            per_million_in=self.settings.model.usd_per_million_input,
            per_million_out=self.settings.model.usd_per_million_output,
        )
        self._save()

        def entry(headline: str, outcome: str, receipt_id: str | None = None) -> Cycle:
            return self._entry(
                now,
                snapshot,
                runway,
                headline=headline,
                action=decision.kind,
                outcome=outcome,
                receipt_id=receipt_id,
                usage=decision.usage,
                cost=cost,
            )

        if not decision.acts:
            return entry(_held(decision), "none")
        if self.dry_run:
            return entry(f"Dry run: would have {_described(decision)}", "none")

        try:
            intent = self._intent(now, decision)
        except (ContentError, ValueError) as exc:
            self.state.lesson = (
                f"Your last proposal could not be built into an intent: {exc}. "
                "Amounts must be plain decimal strings and assets must be ones get_market names."
            )
            self._save()
            return entry(f"Refused to build the proposal: {exc}", "malformed")

        outcome = await self._execute(
            now, intent=intent, kind=decision.kind, reasoning=decision.reasoning, source="mandate"
        )
        if outcome.settled:
            return entry(
                f"{_described(decision)} Settled.", "settled", outcome.envelope.receipt_id
            )
        if outcome.outcome == PolicyOutcome.ESCALATE.value:
            return entry(
                f"{_described(decision)} Escalated to a human.",
                "escalated",
                outcome.envelope.receipt_id,
            )
        return entry(
            f"{_described(decision)} Refused: {outcome.reason or outcome.outcome}",
            "denied",
            outcome.envelope.receipt_id,
        )

    # -- acting ------------------------------------------------------------- #

    async def _execute(
        self, now: str, *, intent: Intent, kind: str, reasoning: str, source: str
    ) -> ReceiptOutcome:
        """Propose, remembering the nonce first so a crash cannot double-propose."""
        receipt_id = self._receipt_id(f"{kind}-{self.state.cycle}")
        self.state.in_flight = books.InFlight(
            receipt_id=receipt_id, nonce=intent.nonce, kind=kind, at=now
        )
        self._save()

        outcome = await self.builder.execute(
            instruction=Instruction(
                source=source,
                content_hash=SHA256Hash.from_bytes(self.settings.agent.mandate.encode()).hex(),
                ref=f"cycle-{self.state.cycle}",
            ),
            intent=intent,
            reasoning=_reasoning(reasoning),
            receipt_id=receipt_id,
        )
        self.state.in_flight = None
        self.state.lesson = "" if outcome.settled else _lesson(outcome)
        if outcome.pending_escalation is not None:
            self.state.pending = books.Pending(
                challenge=str(outcome.pending_escalation["challenge"]),
                expires_at=str(outcome.pending_escalation["expires_at"]),
                quorum=int(str(outcome.pending_escalation["quorum"])),
                receipt_id=outcome.envelope.receipt_id,
                intent=intent.to_content(),
                instruction=(
                    outcome.receipt.leaves.instruction.to_content()
                    if outcome.receipt.leaves.instruction
                    else {}
                ),
                reasoning=(
                    outcome.receipt.leaves.reasoning.to_content()
                    if outcome.receipt.leaves.reasoning
                    else None
                ),
                opened_at=now,
            )
        if outcome.notary_error:
            self.journal.note(
                now,
                f"receipt {outcome.envelope.receipt_id} is on this disk but did not reach the "
                f"notary: {outcome.notary_error}",
            )
        self._save()
        return outcome

    # -- intents ------------------------------------------------------------ #

    def _intent(self, now: str, decision: decisions.Decision) -> Intent:
        if decision.kind == "swap":
            return self._swap_intent(
                now,
                sell=self._asset(decision.sell_asset),
                sell_max=decision.sell_max_amount,
                buy=self._asset(decision.buy_asset),
                buy_amount=decision.buy_amount,
                receipt_id=self._receipt_id(f"swap-{self.state.cycle}"),
            )
        return self._payment_intent(
            now,
            destination=decision.destination,
            amount=Amount(value=decision.amount, currency=self._asset(decision.asset)),
            receipt_id=self._receipt_id(f"payment-{self.state.cycle}"),
        )

    def _swap_intent(
        self,
        now: str,
        *,
        sell: CurrencyRef,
        sell_max: str,
        buy: CurrencyRef,
        buy_amount: str,
        receipt_id: str,
    ) -> Intent:
        treasury = self.settings.treasury.address
        return Intent(
            type="swap",
            rail=RAIL,
            treasury=treasury,
            destination=treasury,
            sell=SwapSell(currency=sell, max_amount=sell_max),
            buy=SwapBuy(currency=buy, amount=buy_amount),
            policy_version=self.settings.treasury.policy_version,
            agent_public_key=self.agent_public_key,
            nonce=_nonce(receipt_id),
            expires_at=shift_instant(now, INTENT_TTL_SECONDS, "now"),
        )

    def _payment_intent(
        self, now: str, *, destination: str, amount: Amount, receipt_id: str
    ) -> Intent:
        return Intent(
            rail=RAIL,
            treasury=self.settings.treasury.address,
            destination=destination,
            amount=amount,
            policy_version=self.settings.treasury.policy_version,
            agent_public_key=self.agent_public_key,
            nonce=_nonce(receipt_id),
            expires_at=shift_instant(now, INTENT_TTL_SECONDS, "now"),
        )

    def _asset(self, code: str) -> CurrencyRef:
        """An asset code from the model, resolved to what the ledger calls it."""
        if code == self.settings.market.base:
            return self.settings.market.base
        if code == self.settings.market.quote_code:
            return IssuedCurrency(
                code=self.settings.market.quote_code, issuer=self.settings.market.quote_issuer
            )
        raise ValueError(
            f"{code!r} is not an asset this agent trades "
            f"({self.settings.market.base} or {self.settings.market.quote_code})"
        )

    def _receipt_id(self, label: str) -> str:
        """Derived from the cycle, so a restart reaches for the same file."""
        seed = f"{self.settings.agent.agent_id}:{self.settings.treasury.address}:{label}"
        return SHA256Hash.from_bytes(seed.encode()).hex()[:32]

    # -- what the model is shown -------------------------------------------- #

    def _situation(self, now: str, runway: Decimal | None, burn: Decimal | None) -> JSONObject:
        bill = self.state.bill
        return {
            "now": now,
            "cycle": self.state.cycle,
            "your_mandate": self.settings.agent.mandate,
            "you_wake_up_every_minutes": self.settings.loop.interval_seconds // 60,
            "compute_bill": {
                "owed_usd": format_decimal(bill.accrued_usd),
                "burn_usd_per_day": None if burn is None else format_decimal(burn),
                "billed_on": self.settings.bill.bill_day,
                "days_until_billed": _days_until(_moment(now), self.settings.bill.bill_day),
                "last_paid": bill.last_paid or None,
            },
            "runway_days": None if runway is None else format_decimal(runway.quantize(Decimal(1))),
            "last_refusal": self.state.lesson or None,
            "reminder": "Call get_market before you decide anything.",
        }

    async def _receipts(self, limit: int) -> JSONValue:
        """The agent's own history, as the ``read_receipts`` tool returns it."""
        envelopes = await self.store.list(self.settings.treasury.address)
        rows: list[JSONValue] = []
        for envelope in envelopes[-max(1, min(limit, RECEIPTS_SHOWN)) :]:
            found = await self.store.get(envelope.receipt_id)
            if found is None:  # pragma: no cover - listed a moment ago
                continue
            _, leaves = found
            rows.append(_summary(envelope.receipt_id, leaves))
        return rows

    # -- plumbing ----------------------------------------------------------- #

    def _price(self, snapshot: markets.Snapshot) -> Decimal | None:
        """What one unit of the base asset is worth, in dollars.

        The book first: the quote asset is a dollar stablecoin and the book is on
        the same ledger as the money, so it cannot be down independently of the
        thing it is pricing. The external reference is the fallback, and when
        neither is available the answer is nothing rather than a number.
        """
        if snapshot.book.mid is not None:
            return snapshot.book.mid
        return snapshot.reference.price

    def _entry(
        self,
        now: str,
        snapshot: markets.Snapshot,
        runway: Decimal | None,
        *,
        headline: str,
        action: str,
        outcome: str,
        receipt_id: str | None = None,
        usage: decisions.Usage | None = None,
        cost: Decimal = Decimal(0),
    ) -> Cycle:
        self._save()
        return Cycle(
            entry=books.Entry(
                at=now,
                cycle=self.state.cycle,
                balances=dict(snapshot.balances),
                headline=headline,
                action=action,
                outcome=outcome,
                receipt_id=receipt_id,
                runway_days=runway,
                tokens_in=usage.input_tokens if usage else 0,
                tokens_out=usage.output_tokens if usage else 0,
                cost_usd=cost,
            )
        )

    def _save(self) -> None:
        self.state.save(self.settings.loop.state_file)

    # -- running ------------------------------------------------------------ #

    async def run(self, *, once: bool = False) -> int:
        """Cycle forever, or once. Returns the process exit code."""
        while True:
            try:
                result = await self.cycle()
            except OutOfBusiness as exc:
                self.journal.note(
                    self.clock.now(), f"**Out of business.** {exc} Nothing further will run."
                )
                print(f"out of business: {exc}", file=sys.stderr, flush=True)
                return 1
            except markets.MarketError as exc:
                print(f"could not read the market: {exc}", file=sys.stderr, flush=True)
                if once:
                    return 2
                await asyncio.sleep(self.settings.loop.interval_seconds)
                continue
            first, second = self.journal.append(result.entry)
            print(first, flush=True)
            print(second, flush=True)
            if once:
                return 0
            await asyncio.sleep(self.settings.loop.interval_seconds)


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #


async def build(settings: configuration.Config, *, dry_run: bool = False) -> Trader:
    """Assemble the real thing: signer over HTTPS, XRPL, notary, local store."""
    material = settings.agent.key_file.read_bytes()
    loaded = serialization.load_pem_private_key(material, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise configuration.ConfigError(f"{settings.agent.key_file} is not an Ed25519 private key")
    agent_public_key = (
        loaded.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )

    token = (
        configuration.read_secret_file(settings.signer.token_file)
        if settings.signer.token_file
        else None
    )
    signer = DevSignerClient(base_url=settings.signer.url, bearer_token=token)
    policy_public_key = await signer.public_key()

    wallets = load_wallets(settings.treasury.wallet_file)
    if settings.treasury.wallet_name not in wallets:
        raise configuration.ConfigError(
            f"{settings.treasury.wallet_file} has no wallet called "
            f"{settings.treasury.wallet_name!r}"
        )
    rail = XrplSettlementAdapter(
        treasury=settings.treasury.address,
        agent_wallet=wallets[settings.treasury.wallet_name],
        policy_public_key=policy_public_key,
        json_rpc_url=settings.rail.json_rpc_url,
        websocket_url=settings.rail.websocket_url,
    )

    store = LocalReceiptStore(settings.loop.receipt_dir)
    api_key = configuration.read_secret_env(settings.notary.api_key_env)
    builder = ReceiptBuilder(
        signer=signer,
        settlement=rail,
        agent_id=settings.agent.agent_id,
        agent_public_key=agent_public_key,
        agent_sign=lambda message: loaded.sign(message).hex(),
        receipt_store=store,
        notary=HttpNotary(settings.notary.url, api_key=api_key),
        rail=RAIL,
    )
    return Trader(
        settings,
        builder=builder,
        agent_public_key=agent_public_key,
        rail=rail,
        reader=markets.MarketReader(
            json_rpc_url=settings.rail.json_rpc_url,
            treasury=settings.treasury.address,
            base=settings.market.base,
            quote_code=settings.market.quote_code,
            quote_issuer=settings.market.quote_issuer,
            depths=settings.market.depths,
            reference_url=settings.market.reference_url,
            reference_path=settings.market.reference_path,
            reference_source=settings.market.reference_source,
        ),
        store=store,
        model=decisions.AnthropicModel(configuration.read_secret_env(settings.model.api_key_env)),
        journal=books.Journal(settings.loop.journal_md, settings.loop.journal_jsonl),
        queue=EscalationQueue(settings.notary.url, api_key),
        dry_run=dry_run,
    )


async def _run(arguments: argparse.Namespace) -> int:
    settings = configuration.load(arguments.config)
    trader = await build(settings, dry_run=bool(arguments.dry_run))
    try:
        return await trader.run(once=bool(arguments.once))
    finally:
        await trader.aclose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m examples.trader",
        description="A trading agent that pays its own bills and receipts every decision.",
    )
    parser.add_argument("--config", required=True, help="path to the TOML config")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="decide and journal, but propose nothing"
    )
    arguments = parser.parse_args(argv)
    try:
        return asyncio.run(_run(arguments))
    except configuration.ConfigError as exc:
        print(f"configuration: {exc}", file=sys.stderr)
        return 2


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


async def _ready(value: JSONValue) -> JSONValue:
    """The snapshot this cycle already read, handed to the tool that asks for it."""
    return value


def _nonce(receipt_id: str) -> str:
    return SHA256Hash.from_bytes(receipt_id.encode()).hex()[:NONCE_LENGTH]


def _moment(now: str) -> datetime:
    return datetime.fromisoformat(now.replace("Z", "+00:00")).astimezone(UTC)


def _days_until(now: datetime, weekday: str) -> int:
    target = books.WEEKDAYS.index(weekday)
    return (target - now.weekday()) % 7


def _reasoning(text: str) -> Reasoning | None:
    """Leaf 6: the hash of everything the model said, and the first line of it."""
    if not text:
        return None
    return Reasoning(
        content_hash=SHA256Hash.from_bytes(text.encode()).hex(),
        source="claude",
        note=_flat(text)[: decisions.NOTE_LENGTH],
    )


def _flat(text: str) -> str:
    """One line, printable. A receipt leaf holds no control characters."""
    return " ".join(text.split())


def _lesson(outcome: ReceiptOutcome) -> str:
    """A refusal in the signer's own words, ready to hand back to the model."""
    failed = [
        f"{rule.name}: {rule.detail or rule.outcome}"
        for rule in outcome.decision.rules
        if rule.outcome != "pass"
    ]
    detail = "; ".join(failed) or outcome.reason or outcome.outcome
    return f"Your last proposal was {outcome.outcome}: {_flat(detail)}"


def _held(decision: decisions.Decision) -> str:
    said = _flat(decision.reasoning) or _flat(decision.note) or "no reason given"
    return f"Did nothing. {said[: decisions.NOTE_LENGTH]}"


def _described(decision: decisions.Decision) -> str:
    if decision.kind == "swap":
        return (
            f"Bought {decision.buy_amount} {decision.buy_asset} for at most "
            f"{decision.sell_max_amount} {decision.sell_asset}."
        )
    return f"Paid {decision.amount} {decision.asset} to {decision.destination[:12]}…."


def _summary(receipt_id: str, leaves: Any) -> JSONObject:
    """One receipt, as much as the model needs to learn from it."""
    intent, decision, result = leaves.intent, leaves.policy_decision, leaves.result
    failed: list[JSONValue] = [
        {"rule": rule.name, "detail": rule.detail}
        for rule in (decision.rules if decision else ())
        if rule.outcome != "pass"
    ]
    return {
        "receipt_id": receipt_id,
        "what_you_asked_for": _asked(intent),
        "decision": decision.outcome if decision else None,
        "rules_that_failed": failed,
        "outcome": result.outcome if result else None,
        "delivered": result.delivered.to_content() if result and result.delivered else None,
        "spent": result.spent.to_content() if result and result.spent else None,
        "reasoning": leaves.reasoning.note if leaves.reasoning else None,
    }


def _asked(intent: Intent | None) -> JSONValue:
    if intent is None:  # pragma: no cover - every receipt has leaf 1
        return None
    if intent.is_swap:
        return {
            "type": "swap",
            "sell_at_most": intent.outflow.to_content(),
            "buy_exactly": intent.deliver_amount.to_content(),
        }
    return {
        "type": "payment",
        "amount": intent.outflow.to_content(),
        "destination": intent.destination,
    }


__all__ = ["Cycle", "EscalationQueue", "OutOfBusiness", "Trader", "build", "main"]

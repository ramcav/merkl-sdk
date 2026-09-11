"""The reference trading agent, end to end on the in-memory rail.

Everything below the model is real: a real ``SignerEngine`` with a real
encrypted keystore and real sealed window state, a real ``ReceiptBuilder``, real
receipts on disk. Two things are stubbed, and only two — the language model
(a scripted list of responses, so no key and no network) and the XRPL node
(``httpx.MockTransport``, so ``market.py``'s own JSON-RPC parsing is exercised
rather than skipped).

What the suite is actually asserting is the five behaviours a trading agent has
to get right or it should not be allowed near money: it trades, it hears a
refusal and carries it forward, it waits for a human and finishes when they
answer, it stops when it cannot pay for itself, and it never re-proposes an
action after a crash.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from examples.trader import config as configuration
from examples.trader import decide as decisions
from examples.trader import ledger as books
from examples.trader import market as markets
from examples.trader import trader as agent
from merkl.adapters.fake import FakeLedger, FakeSettlementAdapter
from merkl.adapters.signer_dev import LocalSignerClient
from merkl.adapters.xrpl import currency_code
from merkl.core.canonical import format_instant, shift_instant
from merkl.core.intent import IssuedCurrency
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    AgentSection,
    ApproverCredential,
    AssetLimit,
    HumanTier,
    PolicyDocument,
    SignedPolicy,
    Tiers,
    WindowRule,
)
from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.vectors import fixtures
from merkl.sdk.receipt_store import LocalReceiptStore
from merkl.sdk.receipts import ReceiptBuilder
from merkl.signer.engine import SignerEngine
from merkl.signer.keystore import DevKeystore
from merkl.signer.risk import StaticRiskScorer
from merkl.signer.state import SealedStateStore

TREASURY = "rTREASURYexampleaccount0000000000"
OPERATOR = "rOPERATORexampleaccount000000000"
ISSUER = "rISSUERexampleaccount00000000000"
STRANGER = "rSTRANGERexampleaccount000000000"
QUOTE = "RLUSD"
RLUSD = IssuedCurrency(code=QUOTE, issuer=ISSUER)
POLICY_VERSION = "2026.09.16"
AGENT_ID = "agent-trader"

ADMIN = fixtures.ed25519_key("trader-example-admin")
AGENT = fixtures.ed25519_key("trader-example-agent")
ALICE = fixtures.ed25519_key("trader-example-alice")
BOB = fixtures.ed25519_key("trader-example-bob")

XRP_PER_RLUSD = Decimal("1.9")
"""What the in-memory book charges: one RLUSD costs 1.9 XRP."""

ASK = Decimal("0.530000")
BID = Decimal("0.520000")
MID = (ASK + BID) / 2


# --------------------------------------------------------------------------- #
# A clock a test can move
# --------------------------------------------------------------------------- #


class Clock:
    def __init__(self, start: str = "2026-09-16T09:00:00Z") -> None:
        self._now = start

    def now(self) -> str:
        return self._now

    def advance(self, seconds: int) -> str:
        self._now = shift_instant(self._now, seconds, "now")
        return self._now

    def set_weekday(self, weekday: int) -> str:
        moment = datetime.fromisoformat(self._now.replace("Z", "+00:00")).astimezone(UTC)
        self._now = format_instant(moment + timedelta(days=(weekday - moment.weekday()) % 7))
        return self._now


# --------------------------------------------------------------------------- #
# The model, scripted
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Block:
    type: str
    text: str = ""
    name: str = ""
    input: dict[str, Any] = dataclasses.field(default_factory=dict)
    id: str = "toolu_test"

    def model_dump(self) -> dict[str, Any]:
        if self.type == "text":
            return {"type": "text", "text": self.text}
        return {"type": "tool_use", "id": self.id, "name": self.name, "input": self.input}


@dataclasses.dataclass
class Usage:
    input_tokens: int = 1200
    output_tokens: int = 300


@dataclasses.dataclass
class Reply:
    content: list[Block]
    stop_reason: str = "tool_use"
    usage: Usage = dataclasses.field(default_factory=Usage)


class ScriptedModel:
    """A list of replies, handed out in order. No key, no network, no beta."""

    def __init__(self, *replies: Reply) -> None:
        self._replies = list(replies)
        self.requests: list[dict[str, Any]] = []

    def then(self, reply: Reply) -> None:
        """Add a reply mid-test, when a later cycle needs one."""
        self._replies.append(reply)

    async def create(self, **request: Any) -> Reply:
        self.requests.append(request)
        if not self._replies:  # pragma: no cover - a test ran the loop too far
            raise AssertionError("the model was asked for more turns than the script has")
        return self._replies.pop(0)


def looks_at_the_market() -> Block:
    return Block(type="tool_use", name="get_market", input={}, id="toolu_market")


def swaps(sell: str, buy: str, *, why: str = "the spread was inside my limit") -> Reply:
    return Reply(
        content=[
            Block(type="text", text="Checked the book."),
            Block(
                type="tool_use",
                name="propose_swap",
                id="toolu_swap",
                input={
                    "sell_asset": "XRP",
                    "sell_max_amount": sell,
                    "buy_asset": QUOTE,
                    "buy_amount": buy,
                    "reasoning": why,
                },
            ),
        ]
    )


def holds(why: str) -> Reply:
    return Reply(content=[Block(type="text", text=why)], stop_reason="end_turn")


# --------------------------------------------------------------------------- #
# A fake XRPL node
# --------------------------------------------------------------------------- #


def node(*, xrp: str, rlusd: str, book: bool = True) -> httpx.MockTransport:
    """``book_offers``, ``account_info``, ``account_lines`` and a price feed."""

    def offer(gets: Any, pays: Any) -> dict[str, Any]:
        return {"TakerGets": gets, "TakerPays": pays, "quality": "ignored"}

    def issued(value: str) -> dict[str, str]:
        return {"currency": currency_code(QUOTE), "issuer": ISSUER, "value": value}

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"amount": "0.5290"}})
        body = json.loads(request.content)
        method, params = body["method"], body["params"][0]
        if method == "book_offers":
            if not book:
                return httpx.Response(200, json={"result": {"offers": []}})
            selling_xrp = params["taker_gets"].get("currency") == "XRP"
            offers = (
                # The maker gives XRP and takes RLUSD: this is where we buy XRP.
                [offer("1000000000", issued(str(Decimal(1000) * ASK)))]
                if selling_xrp
                # The maker gives RLUSD and takes XRP: this is where we sell it.
                else [offer(issued(str(Decimal(1000) * BID)), "1000000000")]
            )
            return httpx.Response(200, json={"result": {"offers": offers}})
        if method == "account_info":
            drops = str(int(Decimal(xrp) * 1_000_000))
            return httpx.Response(200, json={"result": {"account_data": {"Balance": drops}}})
        if method == "account_lines":
            return httpx.Response(
                200,
                json={
                    "result": {
                        "lines": [
                            {
                                "currency": currency_code(QUOTE),
                                "account": ISSUER,
                                "balance": rlusd,
                            }
                        ]
                    }
                },
            )
        raise AssertionError(f"the agent asked the node for {method}")  # pragma: no cover

    return httpx.MockTransport(handle)


# --------------------------------------------------------------------------- #
# The policy, and the world under it
# --------------------------------------------------------------------------- #


def policy(
    *,
    per_tx_cap: str = "5",
    human_threshold: str = "20",
    destinations: tuple[str, ...] = (TREASURY, OPERATOR),
) -> PolicyDocument:
    return PolicyDocument(
        version=POLICY_VERSION,
        treasury=TREASURY,
        rail="fake",
        admin_public_key=fixtures.ed25519_public_hex(ADMIN),
        agents=(
            AgentSection(
                agent_id=AGENT_ID,
                public_key=fixtures.ed25519_public_hex(AGENT),
                allowlist_destinations=destinations,
                allowlist_assets=("XRP", RLUSD),
                may_swap=True,
                per_tx_cap=(AssetLimit(asset="XRP", amount=per_tx_cap),),
                windows=(WindowRule(asset="XRP", amount="100", seconds=3600),),
            ),
        ),
        tiers=Tiers(
            human=HumanTier(
                thresholds=(AssetLimit(asset="XRP", amount=human_threshold),),
                quorum=2,
                expires_seconds=3600,
            )
        ),
        approvers=(
            ApproverCredential(
                id="alice@example.com",
                credential_type=CREDENTIAL_ED25519,
                public_key=fixtures.ed25519_public_hex(ALICE),
            ),
            ApproverCredential(
                id="bob@example.com",
                credential_type=CREDENTIAL_ED25519,
                public_key=fixtures.ed25519_public_hex(BOB),
            ),
        ),
    )


def settings(home: Path, *, bill_day: str = "sunday", interval: int = 900) -> configuration.Config:
    return configuration.parse(
        {
            "agent": {
                "agent_id": AGENT_ID,
                "key_file": str(home / "unused.pem"),
                "mandate": "Grow the treasury and pay your own way.",
            },
            "treasury": {
                "address": TREASURY,
                "policy_version": POLICY_VERSION,
                "wallet_file": str(home / "unused.json"),
                "wallet_name": "agent-0",
            },
            "rail": {"name": "fake", "json_rpc_url": "https://node.invalid:51234"},
            "market": {
                "base": "XRP",
                "quote_code": QUOTE,
                "quote_issuer": ISSUER,
                "depths": ["10", "100"],
                "reference_url": "https://price.invalid/spot",
                "reference_path": "data.amount",
                "reference_source": "a price feed",
            },
            "signer": {"url": "https://signer.invalid"},
            "notary": {"url": "https://notary.invalid", "api_key_env": "MERKL_API_KEY_UNSET"},
            "model": {
                "name": "claude-sonnet-5",
                "api_key_env": "ANTHROPIC_API_KEY_UNSET",
                "max_tokens": 4096,
                "usd_per_million_input": "2.00",
                "usd_per_million_output": "10.00",
            },
            "loop": {"interval_seconds": interval, "home": str(home)},
            "bill": {"bill_day": bill_day, "operator": OPERATOR},
        }
    )


class Queue:
    """Stands in for merkl-api's escalation endpoint."""

    def __init__(self) -> None:
        self.answer: dict[str, Any] | None = None
        self.asked: list[str] = []

    async def get(self, challenge: str) -> dict[str, Any] | None:
        self.asked.append(challenge)
        return self.answer

    async def aclose(self) -> None:
        return None


class SpyBuilder(ReceiptBuilder):
    """Records what the state file said at the moment a proposal went out."""

    def __init__(self, state_file: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._state_file = state_file
        self.state_when_called: list[dict[str, Any]] = []

    async def execute(self, **kwargs: Any) -> Any:
        self.state_when_called.append(json.loads(self._state_file.read_text()))
        return await super().execute(**kwargs)


@dataclasses.dataclass
class Rig:
    trader: agent.Trader
    ledger: FakeLedger
    engine: SignerEngine
    rail: FakeSettlementAdapter
    clock: Clock
    queue: Queue
    model: ScriptedModel
    home: Path

    def journal(self) -> str:
        return (self.home / "journal.md").read_text()

    def rows(self) -> list[dict[str, Any]]:
        path = self.home / "journal.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line]


def build(
    home: Path,
    model: ScriptedModel,
    *,
    document: PolicyDocument | None = None,
    xrp: str = "500",
    rlusd: str = "40",
    treasury_xrp: str = "500",
    bill_day: str = "sunday",
    book: bool = True,
    clock: Clock | None = None,
) -> Rig:
    """One signer, one policy, one in-memory ledger, one scripted model."""
    document = document or policy()
    signed = SignedPolicy(
        document=document,
        signature=ADMIN.sign(document.pre_image()).hex(),
        signer_public_key=fixtures.ed25519_public_hex(ADMIN),
    )
    clock = clock or Clock()
    keystore = DevKeystore(home / "keystore", passphrase="trader-example-tests")
    engine = SignerEngine(
        policy=signed,
        keystore=keystore,
        state=SealedStateStore(home / "signer-state", TREASURY, keystore.seal_key()),
        clock=clock,
        risk=StaticRiskScorer.of(()),
    )
    agent_public_key = fixtures.ed25519_public_hex(AGENT)
    fake = FakeLedger(
        signers=frozenset({agent_public_key, keystore.public_key()}),
        rates={("XRP", f"{QUOTE}.{ISSUER}"): XRP_PER_RLUSD},
    )
    fake.credit(TREASURY, "XRP", treasury_xrp)
    rail = FakeSettlementAdapter(
        fake, agent_key=AGENT, agent_public_key=agent_public_key, clock=clock
    )
    conf = settings(home, bill_day=bill_day)
    store = LocalReceiptStore(conf.loop.receipt_dir)
    queue = Queue()
    builder = SpyBuilder(
        conf.loop.state_file,
        signer=LocalSignerClient(engine),
        settlement=rail,
        agent_id=AGENT_ID,
        agent_public_key=agent_public_key,
        agent_sign=lambda message: AGENT.sign(message).hex(),
        clock=clock,
        receipt_store=store,
        rail="fake",
    )
    trader = agent.Trader(
        conf,
        builder=builder,
        agent_public_key=agent_public_key,
        reader=markets.MarketReader(
            json_rpc_url=conf.rail.json_rpc_url,
            treasury=TREASURY,
            base="XRP",
            quote_code=QUOTE,
            quote_issuer=ISSUER,
            depths=conf.market.depths,
            reference_url=conf.market.reference_url,
            reference_path=conf.market.reference_path,
            reference_source=conf.market.reference_source,
            client=httpx.AsyncClient(transport=node(xrp=xrp, rlusd=rlusd, book=book)),
        ),
        store=store,
        model=model,
        journal=books.Journal(conf.loop.journal_md, conf.loop.journal_jsonl),
        queue=queue,  # type: ignore[arg-type]
        clock=clock,
    )
    return Rig(
        trader=trader,
        ledger=fake,
        engine=engine,
        rail=rail,
        clock=clock,
        queue=queue,
        model=model,
        home=home,
    )


# --------------------------------------------------------------------------- #
# 1. It trades
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_cycle_that_swaps(tmp_path: Path) -> None:
    model = ScriptedModel(Reply(content=[looks_at_the_market()]), swaps(sell="4", buy="2"))
    rig = build(tmp_path, model)

    result = await rig.trader.cycle()
    first, second = rig.trader.journal.append(result.entry)

    assert result.entry.outcome == "settled"
    assert result.entry.receipt_id
    assert "Bought 2 RLUSD for at most 4 XRP." in second
    assert "500 XRP" in first and "40 RLUSD" in first
    # The ledger charged 1.9 XRP for the 2 RLUSD and delivered exactly 2.
    assert rig.ledger.balance(TREASURY, f"{QUOTE}.{ISSUER}") == "2"
    assert Decimal(rig.ledger.balance(TREASURY, "XRP")) == Decimal("500") - Decimal("3.8")

    stored = await rig.trader.store.get(result.entry.receipt_id or "")
    assert stored is not None
    _, leaves = stored
    assert leaves.reasoning is not None
    assert leaves.reasoning.source == "claude"
    assert leaves.reasoning.note == "the spread was inside my limit"
    assert leaves.instruction is not None and leaves.instruction.source == "mandate"
    assert leaves.result is not None and leaves.result.outcome == "settled"

    # The model was shown the book, and the book came off the (mock) ledger.
    shown = json.loads(model.requests[1]["messages"][2]["content"][0]["content"])
    assert shown["book"]["best_ask"] == "0.530000"
    assert shown["book"]["mid"] == "0.525000"
    assert shown["balances"] == {"XRP": "500", QUOTE: "40"}
    assert shown["reference"]["source"] == "a price feed"

    # And it was charged for the tokens it burned.
    assert rig.trader.state.bill.tokens_in == 2400
    assert rig.trader.state.bill.accrued_usd > 0


@pytest.mark.asyncio
async def test_only_one_action_reaches_the_rail_per_cycle(tmp_path: Path) -> None:
    """Two proposals in one turn is one proposal made. The cap is structural."""
    greedy = Reply(
        content=[
            Block(
                type="tool_use",
                name="propose_swap",
                id="a",
                input={
                    "sell_asset": "XRP",
                    "sell_max_amount": "4",
                    "buy_asset": QUOTE,
                    "buy_amount": "2",
                    "reasoning": "first",
                },
            ),
            Block(
                type="tool_use",
                name="propose_swap",
                id="b",
                input={
                    "sell_asset": "XRP",
                    "sell_max_amount": "4",
                    "buy_asset": QUOTE,
                    "buy_amount": "2",
                    "reasoning": "second",
                },
            ),
        ]
    )
    rig = build(tmp_path, ScriptedModel(greedy))
    result = await rig.trader.cycle()

    assert result.entry.outcome == "settled"
    assert len(rig.ledger.outflows) == 1
    assert len(rig.model.requests) == 1


# --------------------------------------------------------------------------- #
# 2. It hears a refusal, and carries it forward
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_refusal_is_fed_back_to_the_model(tmp_path: Path) -> None:
    model = ScriptedModel(
        swaps(sell="9", buy="4", why="sizing up while the book is deep"),
        holds("last time I was told 9 was over the cap, so I am waiting"),
    )
    rig = build(tmp_path, model)

    refused = await rig.trader.cycle()
    assert refused.entry.outcome == "denied"
    assert "per_tx_cap" in refused.entry.headline
    assert not rig.ledger.outflows, "nothing may reach the rail on a denial"

    # The denial is a receipt like any other.
    stored = await rig.trader.store.get(refused.entry.receipt_id or "")
    assert stored is not None
    _, leaves = stored
    assert leaves.policy_decision is not None and leaves.policy_decision.outcome == "deny"
    assert leaves.result is not None and leaves.result.outcome == "denied"

    # And it is what the model is told next time, in the signer's own words.
    assert "per_tx_cap" in rig.trader.state.lesson
    rig.clock.advance(900)
    held = await rig.trader.cycle()
    situation = json.loads(model.requests[-1]["messages"][0]["content"])
    assert "per_tx_cap" in (situation["last_refusal"] or "")
    assert held.entry.outcome == "none"
    assert held.entry.action == "hold"

    # A settled cycle clears the lesson rather than nagging forever.
    rig.clock.advance(900)
    rig.model.then(swaps(sell="4", buy="2"))
    settled = await rig.trader.cycle()
    assert settled.entry.outcome == "settled"
    assert rig.trader.state.lesson == ""


@pytest.mark.asyncio
async def test_an_amount_the_ledger_cannot_read_never_becomes_an_intent(tmp_path: Path) -> None:
    model = ScriptedModel(swaps(sell="4.0e1", buy="2"))
    rig = build(tmp_path, model)

    result = await rig.trader.cycle()

    assert result.entry.outcome == "malformed"
    assert not rig.ledger.outflows
    assert "decimal" in rig.trader.state.lesson.lower()


# --------------------------------------------------------------------------- #
# 3. It waits for a human, and finishes when they answer
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_escalation_is_waited_on_and_then_resumed(tmp_path: Path) -> None:
    model = ScriptedModel(swaps(sell="25", buy="12", why="a large but sensible rotation"))
    # A cap above the human threshold: 25 XRP is inside what the agent may spend
    # and above what it may spend without a person saying so.
    rig = build(tmp_path, model, document=policy(per_tx_cap="50", human_threshold="20"))

    escalated = await rig.trader.cycle()
    assert escalated.entry.outcome == "escalated"
    assert not rig.ledger.outflows
    pending = rig.trader.state.pending
    assert pending is not None and pending.quorum == 2

    # While it is open, the agent does not decide anything new.
    rig.clock.advance(900)
    waiting = await rig.trader.cycle()
    assert waiting.entry.action == "wait"
    assert len(rig.model.requests) == 1, "the model is not asked while a human is deciding"
    assert rig.queue.asked == [pending.challenge]

    # Two people sign. merkl-api relays them and hands back the signer's own
    # decision, which is the only thing that can finish the payment.
    rig.queue.answer = {
        "status": "approved",
        "signer_decision": await approve(rig, pending),
    }
    rig.clock.advance(900)
    rig.model.then(holds("nothing to do"))
    after = await rig.trader.cycle()

    assert rig.trader.state.pending is None
    assert len(rig.ledger.outflows) == 1, "the resumed trade reaches the rail"
    assert "a human answered escalation" in rig.journal()
    assert after.entry.action == "hold"


@pytest.mark.asyncio
async def test_a_pending_saved_by_one_process_is_resumed_by_another(tmp_path: Path) -> None:
    """The escalation outlives the process that opened it, and so must its transaction.

    An agent is a plain process somebody restarts. When it comes back to a
    pending escalation it has the state file and nothing else — no memoised
    autofill, no prepared transaction in memory — so if ``prepared_tx`` did not
    survive to disk, finishing the payment would mean preparing it again against
    a ledger that has moved, and the bytes would no longer be the ones the policy
    key signed.
    """
    model = ScriptedModel(swaps(sell="25", buy="12", why="a rotation worth asking about"))
    rig = build(tmp_path, model, document=policy(per_tx_cap="50", human_threshold="20"))

    await rig.trader.cycle()
    pending = rig.trader.state.pending
    assert pending is not None
    assert pending.prepared_tx is not None, "the state file carries what the signer was shown"

    # Round-trip through the file the way a restart does, and forget everything
    # the rail memoised — a second process memoised nothing.
    reloaded = books.Pending.from_content(json.loads(json.dumps(pending.to_content())))
    assert reloaded.prepared_tx == pending.prepared_tx
    rig.trader.state.pending = reloaded
    rig.rail._sequences.clear()

    rig.queue.answer = {"status": "approved", "signer_decision": await approve(rig, reloaded)}
    rig.clock.advance(900)
    rig.model.then(holds("nothing to do"))
    await rig.trader.cycle()

    assert rig.trader.state.pending is None
    assert len(rig.ledger.outflows) == 1, "the approved trade reached the rail"
    assert "a human answered escalation" in rig.journal()


@pytest.mark.asyncio
async def test_an_escalation_answered_without_the_signer_decision_is_not_invented(
    tmp_path: Path,
) -> None:
    """merkl-api hands the decision to whoever completed the quorum. If that was
    not this process, nothing settles here and the agent says so."""
    model = ScriptedModel(swaps(sell="25", buy="12"), holds("waiting to be told more"))
    rig = build(tmp_path, model, document=policy(per_tx_cap="50", human_threshold="20"))
    await rig.trader.cycle()

    rig.queue.answer = {"status": "rejected"}
    rig.clock.advance(900)
    await rig.trader.cycle()

    assert rig.trader.state.pending is None
    assert not rig.ledger.outflows
    assert "was rejected" in rig.journal()
    assert "rejected" in rig.trader.state.lesson


async def approve(rig: Rig, pending: books.Pending) -> dict[str, Any]:
    """What merkl-api's relay does: two signed approvals, straight to the signer."""
    from merkl.core.intent import Intent

    intent = Intent.from_content(pending.intent)
    # The relay has the transaction from the propose request, not a fresh one —
    # the same content the agent kept, which is the whole point of keeping it.
    if pending.prepared_tx is not None:
        unsigned = await rig.rail.anchored_from_content(
            pending.prepared_tx, ANCHOR_PLACEHOLDER_HEX
        )
    else:
        unsigned = await rig.rail.prepare(
            intent, ANCHOR_PLACEHOLDER_HEX, agent_id=AGENT_ID, task_id=pending.receipt_id
        )
    assertions = [
        fixtures.ed25519_assertion(
            approver_id="alice@example.com",
            key=ALICE,
            challenge=bytes.fromhex(pending.challenge),
            signed_at=rig.clock.now(),
        ),
        fixtures.ed25519_assertion(
            approver_id="bob@example.com",
            key=BOB,
            challenge=bytes.fromhex(pending.challenge),
            signed_at=rig.clock.now(),
        ),
    ]
    return rig.engine.approve(
        pending.challenge, [a.to_content() for a in assertions], unsigned.to_content()
    )


# --------------------------------------------------------------------------- #
# 4. It pays for itself, or it stops
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_bill_is_proposed_and_settles(tmp_path: Path) -> None:
    clock = Clock()
    rig = build(tmp_path, ScriptedModel(), bill_day=_today(clock), clock=clock)
    rig.trader.state.bill.accrued_usd = Decimal("0.50")
    rig.trader.state.bill.cycles = 20

    result = await rig.trader.cycle()

    assert result.entry.action == "bill"
    assert result.entry.outcome == "settled"
    # $0.50 at the book's mid of 0.525 RLUSD per XRP, rounded up to the drop.
    assert "0.952381 XRP" in result.entry.headline
    assert rig.ledger.outflows[-1].destination == OPERATOR
    assert rig.trader.state.bill.accrued_usd == 0
    assert rig.trader.state.bill.last_paid == _date(clock)
    assert not rig.model.requests, "the bill is the cycle's one action; the model is not asked"


@pytest.mark.asyncio
async def test_a_refused_bill_puts_the_agent_out_of_business(tmp_path: Path) -> None:
    clock = Clock()
    rig = build(
        tmp_path,
        ScriptedModel(),
        document=policy(destinations=(TREASURY, STRANGER)),
        bill_day=_today(clock),
        clock=clock,
    )
    rig.trader.state.bill.accrued_usd = Decimal("0.50")
    rig.trader.state.bill.cycles = 20

    code = await rig.trader.run(once=True)

    assert code == 1
    journal = rig.journal()
    assert "Out of business." in journal
    assert "the compute bill was refused" in journal
    assert "destination" in journal


@pytest.mark.asyncio
async def test_a_bill_the_treasury_cannot_cover_puts_the_agent_out_of_business(
    tmp_path: Path,
) -> None:
    clock = Clock()
    rig = build(tmp_path, ScriptedModel(), bill_day=_today(clock), clock=clock, xrp="1")
    rig.trader.state.bill.accrued_usd = Decimal("40")
    rig.trader.state.bill.cycles = 500

    code = await rig.trader.run(once=True)

    assert code == 1
    assert "Out of business." in rig.journal()
    assert "the treasury holds 1" in rig.journal()
    assert not rig.ledger.outflows, "nothing is proposed when the money is not there"


@pytest.mark.asyncio
async def test_runway_is_reported_every_cycle(tmp_path: Path) -> None:
    rig = build(tmp_path, ScriptedModel(holds("quiet market")))
    rig.trader.state.bill.accrued_usd = Decimal("0.96")
    rig.trader.state.bill.cycles = 96  # a day of 15-minute cycles: $0.96/day

    result = await rig.trader.cycle()
    first, _ = result.entry.lines()

    # 500 XRP at 0.525 plus 40 RLUSD is $302.50, against just under a dollar a day.
    assert "runway 3" in first and "days" in first
    assert result.entry.runway_days is not None


# --------------------------------------------------------------------------- #
# 5. It never re-proposes after a crash
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_nonce_is_on_disk_before_the_proposal_goes_out(tmp_path: Path) -> None:
    rig = build(tmp_path, ScriptedModel(swaps(sell="4", buy="2")))

    await rig.trader.cycle()

    spy = rig.trader.builder
    assert isinstance(spy, SpyBuilder)
    recorded = spy.state_when_called[0]["in_flight"]
    assert recorded is not None
    assert recorded["kind"] == "swap"
    assert len(recorded["nonce"]) == 32
    assert rig.trader.state.in_flight is None, "and it is cleared once the answer is in"


@pytest.mark.asyncio
async def test_a_restart_reads_the_receipt_rather_than_reproposing(tmp_path: Path) -> None:
    first = build(tmp_path, ScriptedModel(swaps(sell="4", buy="2")))
    settled = await first.trader.cycle()
    first.trader.journal.append(settled.entry)

    # The process died between proposing and journalling: put the state back.
    state = books.State.load(first.trader.settings.loop.state_file)
    state.in_flight = books.InFlight(
        receipt_id=settled.entry.receipt_id or "", nonce="n", kind="swap", at=first.clock.now()
    )
    state.save(first.trader.settings.loop.state_file)

    resumed = build(tmp_path, ScriptedModel(holds("already traded this cycle")), clock=first.clock)
    resumed.ledger.balances.update(first.ledger.balances)
    resumed.clock.advance(900)
    after = await resumed.trader.cycle()

    assert "had already settled before the crash" in resumed.journal()
    assert not resumed.ledger.outflows, "the trade is not made a second time"
    assert resumed.trader.state.in_flight is None
    assert after.entry.action == "hold"


@pytest.mark.asyncio
async def test_a_restart_with_no_receipt_says_so_and_still_does_not_repropose(
    tmp_path: Path,
) -> None:
    rig = build(tmp_path, ScriptedModel(holds("nothing worth doing")))
    rig.trader.state.in_flight = books.InFlight(
        receipt_id="0" * 32, nonce="n", kind="swap", at=rig.clock.now()
    )
    rig.trader.state.save(rig.trader.settings.loop.state_file)

    await rig.trader.cycle()

    assert "Not re-proposing" in rig.journal()
    assert not rig.ledger.outflows
    assert rig.trader.state.in_flight is None


# --------------------------------------------------------------------------- #
# The dry run, and the things that must never be in the record
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_dry_run_decides_and_journals_but_proposes_nothing(tmp_path: Path) -> None:
    rig = build(tmp_path, ScriptedModel(swaps(sell="4", buy="2")))
    rig.trader.dry_run = True

    result = await rig.trader.cycle()

    assert result.entry.outcome == "none"
    assert result.entry.headline.startswith("Dry run: would have Bought 2 RLUSD")
    assert not rig.ledger.outflows
    assert rig.trader.state.bill.accrued_usd > 0, "the tokens were still spent"


def test_the_system_prompt_never_states_a_policy_number() -> None:
    """The agent learns its limits from refusals. Leaking one here would end that."""
    prompt = decisions.SYSTEM
    assert "cannot read it" in prompt
    assert "refusal" in prompt
    for forbidden in ("per_tx_cap", "5 XRP", "threshold of", "window of"):
        assert forbidden not in prompt


def test_the_four_tools_are_the_four_tools() -> None:
    names = [tool["name"] for tool in decisions.TOOLS]
    assert names == ["get_market", "read_receipts", "propose_swap", "propose_payment"]
    for tool in decisions.TOOLS:
        schema = tool["input_schema"]
        assert tool["strict"] is True
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
    swap = next(t for t in decisions.TOOLS if t["name"] == "propose_swap")
    for field in ("sell_max_amount", "buy_amount"):
        assert swap["input_schema"]["properties"][field]["type"] == "string", (
            "amounts are decimal strings, never JSON numbers"
        )


@pytest.mark.asyncio
async def test_nothing_secret_reaches_the_journal(tmp_path: Path) -> None:
    rig = build(tmp_path, ScriptedModel(swaps(sell="4", buy="2")))
    result = await rig.trader.cycle()
    rig.trader.journal.append(result.entry)

    written = rig.journal() + json.dumps(rig.rows()) + (rig.home / "state.json").read_text()
    assert "BEGIN PRIVATE KEY" not in written
    assert "trader-example-tests" not in written, "the keystore passphrase"
    assert fixtures.ed25519_public_hex(AGENT) not in written


# --------------------------------------------------------------------------- #


def _today(clock: Clock) -> str:
    moment = datetime.fromisoformat(clock.now().replace("Z", "+00:00")).astimezone(UTC)
    return books.WEEKDAYS[moment.weekday()]


def _date(clock: Clock) -> str:
    return clock.now()[:10]

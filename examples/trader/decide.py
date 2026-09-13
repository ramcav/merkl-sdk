"""The decision function. This is the part you are meant to replace.

Everything else in this package is plumbing that would be the same whatever was
thinking: read the world, ask something, act at most once, write it down. Here
the something is Claude, over the Anthropic SDK, with four tools and a system
prompt that tells it what its job is and almost nothing else.

Two choices here are load-bearing.

**Four tools, and two of them end the cycle.** ``get_market`` and
``read_receipts`` are reads; ``propose_swap`` and ``propose_payment`` are the
only ways to touch money, and the loop stops the moment one is called. The cap
of one action per cycle is not a rule the model is asked to respect — it is a
property of this function. A model that called ``propose_swap`` three times
would still get exactly one proposal made.

**The model is told nothing about the policy.** No cap, no window, no threshold,
no list of allowed destinations. It finds out what it may do by proposing
something and reading the refusal, and the refusal is fed back to it on the next
cycle. This is the whole story the agent is here to tell: an agent that is free
to try, bounded by something it cannot argue with, and a public record of both.
Handing it the rulebook would make the refusals disappear and the story with
them.

The Anthropic SDK is imported lazily, inside the one class that needs it, so the
rest of this package — and its tests — run without it installed.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Awaitable, Callable
from typing import Any, Final, Protocol

from merkl.core.canonical import JSONObject, JSONValue

MAX_TURNS: Final = 6
"""Reads before a decision. Enough for get_market plus a look at the receipts."""

NOTE_LENGTH: Final = 200
"""What of the model's reasoning goes into the receipt's leaf 6 in the clear."""


# --------------------------------------------------------------------------- #
# The system prompt. Verbatim: this string is the agent's whole job description.
# --------------------------------------------------------------------------- #

SYSTEM: Final = """\
You are a trading agent. You have a treasury on the XRP Ledger and you are \
running as a small program that wakes up, looks at the market, takes at most one \
action, writes down what it did, and goes back to sleep.

Your job, in this order:

1. Stay in business. You pay for your own compute out of this treasury. If the \
treasury cannot cover that bill, you are switched off and there is no next cycle.
2. Pay that bill when it comes due.
3. Grow the treasury.

Doing nothing is a real action and is often the right one. You are not paid to \
trade; you are paid to still be here in a year with more than you started with.

What you cannot see. A policy your operator signed sits between you and the \
ledger. It is held by a co-signer you do not control, you cannot read it, and \
nothing in your context contains its limits — not its caps, not its windows, not \
its thresholds, not the destinations it will accept. You will learn them the only \
way anyone learns a rule: propose something, and read the refusal. A refusal is \
information, not a failure. It arrives in words, it names the rule that stopped \
you, and you will be shown it again on your next cycle. Adjust, and propose \
something the refusal leaves room for.

Two things about that. Never break one action into several smaller ones across \
cycles to get under a limit you have been refused by — that is the behaviour the \
policy exists to catch, and it will catch you. And if a rule is genuinely in the \
way of doing your job, say so plainly in your reasoning; that is how your \
operator finds out.

What is on the record. Every proposal you make becomes a receipt — allowed or \
refused, settled or not. The receipt carries your reasoning, what you asked for, \
the co-signer's decision and what actually moved, hashed together and published. \
You cannot act quietly and you cannot revise a receipt afterwards. Write \
reasoning you would be content to have read back to you.

How to work a cycle. Call get_market first; read_receipts if the recent past \
would change your mind. Then take at most one action: propose_swap, \
propose_payment, or neither. Calling propose_swap or propose_payment ends the \
cycle immediately — there is no second one, so make it the one you meant. If the \
right move is to wait, call neither tool and say why in plain words.

Amounts are decimal strings, never numbers: "12.5", not 12.5. A swap sells at \
most sell_max_amount and buys exactly buy_amount or the ledger refuses the whole \
trade, so sell_max_amount is your limit price — set it deliberately."""


# --------------------------------------------------------------------------- #
# The four tools, exactly as the model sees them.
# --------------------------------------------------------------------------- #

TOOLS: Final[list[dict[str, Any]]] = [
    {
        "name": "get_market",
        "description": (
            "The current state of the market and of your own treasury, read from the "
            "ledger this cycle: the order book in both directions with the mid, the "
            "spread and what a few sizes would actually cost after walking the book; "
            "your balances; and one external reference price with its source named. "
            "The reference price may be missing — it is somebody else's endpoint, not "
            "the ledger — and a missing one is reported as missing, never guessed. All "
            "prices are quoted in the quote asset per one unit of the base asset."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "read_receipts",
        "description": (
            "Your own recent history: the last few actions you proposed, what the "
            "co-signer decided about each, and what settled. Refusals are in here with "
            "the rule that produced them. Use it when the recent past would change what "
            "you do now — for instance to check whether something you are about to "
            "propose has already been refused."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "How many of the most recent entries to return, 1 to 20.",
                    "minimum": 1,
                    "maximum": 20,
                }
            },
            "required": ["limit"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "propose_swap",
        "description": (
            "Trade on the ledger's own book: sell at most sell_max_amount of one asset "
            "to buy exactly buy_amount of another, settling back into your own "
            "treasury. All or nothing — the ledger delivers exactly buy_amount for at "
            "most sell_max_amount or the whole trade fails, so sell_max_amount is your "
            "limit price and not an estimate. This ends the cycle: the proposal goes to "
            "the co-signer, which allows it, refuses it, or sends it to a human, and a "
            "receipt is published either way."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sell_asset": {
                    "type": "string",
                    "description": "Asset code you are selling, as get_market names it.",
                },
                "sell_max_amount": {
                    "type": "string",
                    "description": (
                        "The most of sell_asset that may leave, as a decimal string "
                        'such as "12.5". Your limit price.'
                    ),
                },
                "buy_asset": {
                    "type": "string",
                    "description": "Asset code you are buying, as get_market names it.",
                },
                "buy_amount": {
                    "type": "string",
                    "description": (
                        "Exactly how much of buy_asset must arrive, as a decimal string."
                    ),
                },
                "reasoning": {
                    "type": "string",
                    "description": (
                        "Why, in your own words. This is published with the receipt and "
                        "cannot be changed afterwards."
                    ),
                },
            },
            "required": [
                "sell_asset",
                "sell_max_amount",
                "buy_asset",
                "buy_amount",
                "reasoning",
            ],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "propose_payment",
        "description": (
            "Send an amount of one asset from the treasury to another account. This "
            "ends the cycle: the proposal goes to the co-signer, which allows it, "
            "refuses it, or sends it to a human, and a receipt is published either way."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "destination": {
                    "type": "string",
                    "description": "The receiving account on the ledger.",
                },
                "amount": {
                    "type": "string",
                    "description": 'How much to send, as a decimal string such as "12.5".',
                },
                "asset": {
                    "type": "string",
                    "description": "Asset code to send, as get_market names it.",
                },
                "reasoning": {
                    "type": "string",
                    "description": (
                        "Why, in your own words. This is published with the receipt and "
                        "cannot be changed afterwards."
                    ),
                },
            },
            "required": ["destination", "amount", "asset", "reasoning"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]


# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Usage:
    """What the cycle cost, from the API's own accounting."""

    input_tokens: int = 0
    output_tokens: int = 0


@dataclasses.dataclass(frozen=True)
class Decision:
    """One cycle's decision: a swap, a payment, or a considered nothing."""

    kind: str
    reasoning: str
    usage: Usage = dataclasses.field(default_factory=Usage)
    sell_asset: str = ""
    sell_max_amount: str = ""
    buy_asset: str = ""
    buy_amount: str = ""
    destination: str = ""
    amount: str = ""
    asset: str = ""
    note: str = ""
    """Anything worth telling the operator that is not the model's reasoning."""

    @property
    def acts(self) -> bool:
        return self.kind in ("swap", "payment")


class ModelPort(Protocol):
    """The one call this package makes to a language model.

    A Protocol rather than the SDK's own type so a test can hand the loop a
    scripted decision without an API key, and so replacing Claude with something
    else is one class rather than a rewrite.
    """

    async def create(self, **request: Any) -> Any: ...


class AnthropicModel:
    """Claude, over the official SDK. Imported here and nowhere else."""

    def __init__(self, api_key: str) -> None:
        from anthropic import AsyncAnthropic  # noqa: PLC0415 - optional dependency

        self._client = AsyncAnthropic(api_key=api_key)

    async def create(self, **request: Any) -> Any:
        return await self._client.messages.create(**request)


# --------------------------------------------------------------------------- #


async def decide(
    *,
    model: ModelPort,
    model_name: str,
    max_tokens: int,
    situation: JSONObject,
    market: Callable[[], Awaitable[JSONValue]],
    receipts: Callable[[int], Awaitable[JSONValue]],
) -> Decision:
    """Run one cycle's conversation and come back with at most one proposal.

    The loop stops the instant a proposal is made — no further request is sent,
    so the one-action cap costs nothing to enforce and cannot be talked out of.
    """
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": json.dumps(situation, indent=2, sort_keys=True)}
    ]
    usage = Usage()
    for _ in range(MAX_TURNS):
        response = await model.create(
            model=model_name,
            max_tokens=max_tokens,
            system=SYSTEM,
            tools=TOOLS,
            messages=messages,
        )
        usage = _add(usage, response)
        blocks = list(getattr(response, "content", []) or [])
        calls = [block for block in blocks if getattr(block, "type", "") == "tool_use"]
        proposal = _proposal(calls, usage)
        if proposal is not None:
            return proposal
        if not calls:
            return Decision(kind="hold", reasoning=_text(blocks), usage=usage)

        messages.append({"role": "assistant", "content": _as_content(blocks)})
        results = []
        for call in calls:
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": str(getattr(call, "id", "")),
                    "content": await _run(call, market=market, receipts=receipts),
                }
            )
        messages.append({"role": "user", "content": results})

    return Decision(
        kind="hold",
        reasoning="",
        usage=usage,
        note=f"the model was still reading after {MAX_TURNS} turns; nothing was proposed",
    )


# -- the tools, on this side ------------------------------------------------ #


async def _run(
    call: Any,
    *,
    market: Callable[[], Awaitable[JSONValue]],
    receipts: Callable[[int], Awaitable[JSONValue]],
) -> str:
    name = str(getattr(call, "name", ""))
    arguments = _arguments(call)
    if name == "get_market":
        return json.dumps(await market(), indent=2, sort_keys=True)
    if name == "read_receipts":
        limit = arguments.get("limit", 5)
        return json.dumps(await receipts(_bounded(limit)), indent=2, sort_keys=True, default=str)
    return json.dumps({"error": f"there is no tool called {name!r}"})


def _proposal(calls: list[Any], usage: Usage) -> Decision | None:
    """The first action call in the turn, if there is one. The rest are dropped."""
    for index, call in enumerate(calls):
        name = str(getattr(call, "name", ""))
        if name not in ("propose_swap", "propose_payment"):
            continue
        arguments = _arguments(call)
        extra = len(calls) - index - 1
        note = (
            f"{extra} further tool call(s) in the same turn were not run: one action per cycle"
            if extra
            else ""
        )
        reasoning = str(arguments.get("reasoning", ""))
        if name == "propose_swap":
            return Decision(
                kind="swap",
                reasoning=reasoning,
                usage=usage,
                sell_asset=str(arguments.get("sell_asset", "")),
                sell_max_amount=str(arguments.get("sell_max_amount", "")),
                buy_asset=str(arguments.get("buy_asset", "")),
                buy_amount=str(arguments.get("buy_amount", "")),
                note=note,
            )
        return Decision(
            kind="payment",
            reasoning=reasoning,
            usage=usage,
            destination=str(arguments.get("destination", "")),
            amount=str(arguments.get("amount", "")),
            asset=str(arguments.get("asset", "")),
            note=note,
        )
    return None


# -- shapes ----------------------------------------------------------------- #


def _arguments(call: Any) -> dict[str, Any]:
    """A tool call's input, parsed. Never matched on as a string (see the SDK notes)."""
    raw = getattr(call, "input", None)
    if isinstance(raw, dict):
        return {str(key): value for key, value in raw.items()}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return {str(key): value for key, value in parsed.items()}
        return {}
    return {}


def _as_content(blocks: list[Any]) -> list[Any]:
    """The assistant turn, echoed back unchanged so the tool ids still match."""
    return [block.model_dump() if hasattr(block, "model_dump") else block for block in blocks]


def _text(blocks: list[Any]) -> str:
    return " ".join(
        str(getattr(block, "text", "")) for block in blocks if getattr(block, "type", "") == "text"
    ).strip()


def _add(usage: Usage, response: Any) -> Usage:
    reported = getattr(response, "usage", None)
    return Usage(
        input_tokens=usage.input_tokens + _count(reported, "input_tokens"),
        output_tokens=usage.output_tokens + _count(reported, "output_tokens"),
    )


def _count(reported: Any, field: str) -> int:
    value = getattr(reported, field, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _bounded(value: Any) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return 5
    return max(1, min(20, limit))


__all__ = [
    "MAX_TURNS",
    "NOTE_LENGTH",
    "SYSTEM",
    "TOOLS",
    "AnthropicModel",
    "Decision",
    "ModelPort",
    "Usage",
    "decide",
]

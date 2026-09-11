"""Two things a transaction has to survive: a person thinking, and a new process.

An escalation is somebody reading an email. The transaction the policy key signs
is built *before* they are asked, so it has to still be submittable when they
answer — and it has to be reproducible by whichever process does the submitting,
which is often not the one that proposed.

Both are the agent side of the boundary. Nothing under ``merkl/signer/`` changes:
the signer signs bytes and the comparison against those bytes is still the last
word before anything reaches the ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.wallet import Wallet

from merkl.adapters.xrpl import adapter as xrpl_adapter
from merkl.adapters.xrpl.adapter import (
    LEDGER_MARGIN,
    MIN_LEDGER_WINDOW,
    XrplAdapterError,
    XrplSettlementAdapter,
    last_ledger_for,
)
from merkl.core.canonical import format_instant, shift_instant
from merkl.core.intent import Amount, Intent, IssuedCurrency, Reference
from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX, UnsignedTx

NOW = "2026-09-11T09:00:00Z"
LEDGER = 1_000_000
# Real, well-formed classic addresses: the binary codec encodes AccountID fields
# and will not accept a readable placeholder. None of them is anybody's account
# that matters — two are testnet accounts this repository created and threw away,
# the issuer is RLUSD's public mainnet issuer.
TREASURY = "rwDyM7iiNowdPKYgorGiPcbJWUPMiFESY6"
SUPPLIER = "rEudyyVnfkjwFrgaWKCwfcwTNJW6VNG5Ti"
ATTACKER = "rN41Js6vLxkTQkcDQbgR8CZc7u43S5ycpY"
ISSUER = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"
POLICY_KEY = "ab" * 32


class TestTheLedgerWindow:
    """``ceil(seconds / 3.5) + 4``, floored at twenty, from the intent's own expiry."""

    def test_an_hour_of_intent_is_an_hour_of_transaction(self) -> None:
        expires = shift_instant(NOW, 3600, "now")
        # 3600 / 3.5 = 1028.57… -> 1029, plus the margin.
        assert last_ledger_for(expires, now=NOW, current_ledger=LEDGER) == LEDGER + 1029 + 4

    def test_the_division_rounds_up_rather_than_down(self) -> None:
        """A transaction that dies one ledger early is a payment nobody can make."""
        expires = shift_instant(NOW, 8, "now")  # 8 / 3.5 = 2.28…
        assert (
            last_ledger_for(expires, now=NOW, current_ledger=LEDGER) == LEDGER + MIN_LEDGER_WINDOW
        )

    def test_a_long_intent_is_the_arithmetic_and_not_the_floor(self) -> None:
        expires = shift_instant(NOW, 70, "now")  # 70 / 3.5 = 20 exactly
        assert (
            last_ledger_for(expires, now=NOW, current_ledger=LEDGER) == LEDGER + 20 + LEDGER_MARGIN
        )

    def test_a_short_intent_never_goes_below_xrpl_pys_own_default(self) -> None:
        """The signer refuses a near-expired intent; the ledger should not do it first."""
        expires = shift_instant(NOW, 5, "now")
        assert (
            last_ledger_for(expires, now=NOW, current_ledger=LEDGER) == LEDGER + MIN_LEDGER_WINDOW
        )

    def test_an_intent_that_already_expired_is_not_a_negative_window(self) -> None:
        expires = shift_instant(NOW, -600, "now")
        assert (
            last_ledger_for(expires, now=NOW, current_ledger=LEDGER) == LEDGER + MIN_LEDGER_WINDOW
        )

    def test_it_is_always_ahead_of_the_ledger_it_was_given(self) -> None:
        for seconds in (0, 1, 60, 900, 3600, 86400):
            expires = shift_instant(NOW, seconds, "now")
            assert last_ledger_for(expires, now=NOW, current_ledger=LEDGER) > LEDGER


def real_now() -> str:
    """The adapter reads its own clock, so an intent it prepares must too.

    The *arithmetic* is pinned against a fixed clock by ``TestTheLedgerWindow``
    above; these tests only check that ``prepare`` applies it, which needs the
    intent's deadline to be in the adapter's future rather than in 2026's past.
    """
    return format_instant(datetime.now(tz=UTC))


def an_intent(*, seconds: int = 3600) -> Intent:
    rlusd = IssuedCurrency(code="RLUSD", issuer=ISSUER)
    return Intent(
        rail="xrpl",
        treasury=TREASURY,
        destination=SUPPLIER,
        amount=Amount(value="250.00", currency=rlusd),
        policy_version="2026.09.1",
        agent_public_key="cd" * 32,
        nonce="ab" * 16,
        expires_at=shift_instant(real_now(), seconds, "now"),
        reference=Reference(kind="invoice", id="INV-1", hash="ef" * 32),
    )


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> XrplSettlementAdapter:
    """A real adapter whose two network calls answer from a script."""
    built = XrplSettlementAdapter(
        treasury=TREASURY,
        agent_wallet=Wallet.create(),
        policy_public_key=POLICY_KEY,
        capture_validations=False,
    )

    async def fake_autofill(payment: Any, _client: Any, **_: Any) -> Any:
        from xrpl.models.transactions import Payment

        return Payment.from_xrpl(
            {
                **payment.to_xrpl(),
                "Fee": "20",
                "Sequence": 42,
                "LastLedgerSequence": LEDGER + 20,
            }
        )

    async def fake_ledger(_client: Any) -> int:
        return LEDGER

    monkeypatch.setattr(xrpl_adapter, "autofill", fake_autofill)
    monkeypatch.setattr(xrpl_adapter, "get_latest_validated_ledger_sequence", fake_ledger)
    return built


@pytest.mark.asyncio
class TestPrepareUsesTheIntentsDeadline:
    async def test_the_transaction_lives_as_long_as_the_intent_says(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        intent = an_intent(seconds=3600)
        unsigned = await adapter.prepare(intent, ANCHOR_PLACEHOLDER_HEX)

        expected = last_ledger_for(intent.expires_at, now=real_now(), current_ledger=LEDGER)
        assert abs(int(unsigned.fields["last_ledger_sequence"]) - expected) <= 2
        assert unsigned.fields["last_ledger_sequence"] > LEDGER + 20, "not xrpl-py's default"
        assert unsigned.fields["last_ledger_sequence"] > LEDGER + 1000, "an hour of ledgers"

    async def test_a_short_intent_keeps_the_default_window(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        unsigned = await adapter.prepare(an_intent(seconds=5), ANCHOR_PLACEHOLDER_HEX)
        assert unsigned.fields["last_ledger_sequence"] == LEDGER + MIN_LEDGER_WINDOW

    async def test_both_preparations_of_one_intent_still_agree(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        """The memoisation this always had: two calls, 32 bytes apart, no more."""
        intent = an_intent()
        first = await adapter.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
        second = await adapter.prepare(intent, "11" * 32)

        assert first.fields == second.fields
        assert len(first.payload_bytes) == len(second.payload_bytes)
        pairs = zip(first.payload_bytes, second.payload_bytes, strict=True)
        differing = sum(a != b for a, b in pairs)
        assert differing <= 32


@pytest.mark.asyncio
class TestRebuildingFromContent:
    async def test_it_reproduces_what_the_signer_signed_without_the_ledger(
        self, adapter: XrplSettlementAdapter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        intent = an_intent()
        proposed = await adapter.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
        left = "ab" * 32
        expected = await adapter.prepare(intent, left)

        # A new process: nothing memoised, and the network is not there at all.
        fresh = XrplSettlementAdapter(
            treasury=TREASURY,
            agent_wallet=Wallet.create(),
            policy_public_key=POLICY_KEY,
            capture_validations=False,
        )

        async def refuse(*_a: Any, **_k: Any) -> Any:  # pragma: no cover - must not run
            raise AssertionError("anchored_from_content asked the ledger for something")

        monkeypatch.setattr(xrpl_adapter, "autofill", refuse)
        monkeypatch.setattr(xrpl_adapter, "get_latest_validated_ledger_sequence", refuse)

        rebuilt = await fresh.anchored_from_content(proposed.to_content(), left)

        assert rebuilt.signing_payload == expected.signing_payload
        assert rebuilt.commitment == left
        assert rebuilt.handle is not None, "and it can still sign and submit"

    async def test_the_rebuilt_handle_signs(self, adapter: XrplSettlementAdapter) -> None:
        intent = an_intent()
        proposed = await adapter.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
        rebuilt = await adapter.anchored_from_content(proposed.to_content(), "ab" * 32)

        partial = await adapter.agent_sign(rebuilt)
        assert partial.signatures[0].signature

    async def test_fields_that_disagree_with_the_payload_are_refused(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        """Sign one transaction and submit another: the whole thing this prevents."""
        proposed = await adapter.prepare(an_intent(), ANCHOR_PLACEHOLDER_HEX)
        content = proposed.to_content()
        content["fields"] = {**content["fields"], "destination": ATTACKER}

        with pytest.raises(XrplAdapterError, match="do not re-encode"):
            await adapter.anchored_from_content(content, "ab" * 32)

    async def test_a_tampered_amount_is_refused_too(self, adapter: XrplSettlementAdapter) -> None:
        proposed = await adapter.prepare(an_intent(), ANCHOR_PLACEHOLDER_HEX)
        content = proposed.to_content()
        fields = dict(content["fields"])
        fields["amount"] = {**fields["amount"], "value": "9999.00"}
        content["fields"] = fields

        with pytest.raises(XrplAdapterError, match="do not re-encode"):
            await adapter.anchored_from_content(content, "ab" * 32)

    async def test_another_rail_s_transaction_is_refused(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        proposed = await adapter.prepare(an_intent(), ANCHOR_PLACEHOLDER_HEX)
        content = {**proposed.to_content(), "rail": "fake"}
        with pytest.raises(XrplAdapterError, match="settles xrpl"):
            await adapter.anchored_from_content(content, "ab" * 32)

    async def test_a_swap_round_trips_with_its_send_max(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        """A trade names a ceiling as well as a delivery; both have to come back."""
        from merkl.core.intent import SwapBuy, SwapSell

        intent = Intent(
            type="swap",
            rail="xrpl",
            treasury=TREASURY,
            destination=TREASURY,
            sell=SwapSell(
                currency=IssuedCurrency(code="RLUSD", issuer=ISSUER), max_amount="100.00"
            ),
            buy=SwapBuy(currency="XRP", amount="40.00"),
            policy_version="2026.09.1",
            agent_public_key="cd" * 32,
            nonce="cd" * 16,
            expires_at=shift_instant(real_now(), 600, "now"),
        )
        proposed = await adapter.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
        expected = await adapter.prepare(intent, "ab" * 32)

        rebuilt = await adapter.anchored_from_content(proposed.to_content(), "ab" * 32)

        assert rebuilt.signing_payload == expected.signing_payload
        assert rebuilt.fields["send_max"] == proposed.fields["send_max"]

    async def test_the_rebuild_is_the_recorded_payload_spliced_and_nothing_else(
        self, adapter: XrplSettlementAdapter
    ) -> None:
        proposed = await adapter.prepare(an_intent(), ANCHOR_PLACEHOLDER_HEX)
        rebuilt = await adapter.anchored_from_content(proposed.to_content(), "ab" * 32)

        spliced = UnsignedTx.from_content(proposed.to_content()).with_anchor("ab" * 32)
        assert rebuilt.signing_payload == spliced.signing_payload
        assert rebuilt.anchor_offset == proposed.anchor_offset
        handle = rebuilt.handle
        assert handle is not None
        assert (
            encode_for_multisigning(handle.to_xrpl(), adapter.policy_address).lower()  # type: ignore[attr-defined]
            == rebuilt.signing_payload
        )

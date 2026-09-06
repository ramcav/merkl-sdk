"""Adapters: the in-memory rail's quorum, and XRPL's encodings without a network."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from merkl.adapters.fake import FakeLedger, FakeRailError, FakeSettlementAdapter
from merkl.core.intent import Amount, IssuedCurrency
from merkl.core.rail import (
    ANCHOR_BYTES,
    ANCHOR_PLACEHOLDER,
    ANCHOR_PLACEHOLDER_HEX,
    Signature,
    fake_tx_id,
    tx_id_from_blob,
    xrpl_tx_id,
)
from tests.scenarios.harness import AGENT, ISSUER, FrozenClock, build_rig, digest

pytestmark = pytest.mark.asyncio

RLUSD = IssuedCurrency(code="RLUSD", issuer=ISSUER)


class TestFakeRail:
    async def test_preparing_twice_differs_only_in_the_anchor(self, tmp_path: Path) -> None:
        """The property the whole anchor-splice design rests on."""
        rig = build_rig(tmp_path)
        intent = rig.intent()
        placeholder = await rig.rail.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
        anchored = await rig.rail.prepare(intent, digest("a commitment"))
        left = placeholder.payload_bytes
        right = anchored.payload_bytes
        assert len(left) == len(right)
        differing = [i for i in range(len(left)) if left[i] != right[i]]
        assert differing == list(
            range(placeholder.anchor_offset, placeholder.anchor_offset + ANCHOR_BYTES)
        )

    async def test_the_placeholder_appears_exactly_once(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        unsigned = await rig.rail.prepare(rig.intent(), ANCHOR_PLACEHOLDER_HEX)
        assert unsigned.payload_bytes.count(ANCHOR_PLACEHOLDER) == 1
        assert unsigned.anchor == ANCHOR_PLACEHOLDER

    async def test_one_signature_is_bad_quorum(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        unsigned = await rig.rail.prepare(rig.intent(), digest("c"))
        partial = await rig.rail.agent_sign(unsigned)
        signed = await rig.rail.attach_policy_signature(
            partial, Signature(public_key="ab" * 32, signature="cd" * 64)
        )
        with pytest.raises(FakeRailError) as caught:
            await rig.rail.submit(signed)
        assert caught.value.engine_result == "BAD_QUORUM"

    async def test_a_signature_from_someone_not_on_the_list_does_not_count(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        stranger = AGENT  # a real key, but we will present it under an unlisted identity
        unsigned = await rig.rail.prepare(rig.intent(), digest("c"))
        partial = await rig.rail.agent_sign(unsigned)
        outsider = Signature(
            public_key="ff" * 32, signature=stranger.sign(unsigned.payload_bytes)
        )
        signed = await rig.rail.attach_policy_signature(partial, outsider)
        with pytest.raises(FakeRailError, match="quorum"):
            await rig.rail.submit(signed)

    async def test_an_unfunded_treasury_cannot_pay(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path, starting_balance="10.00")
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent(value="250.00")
        )
        assert outcome.receipt.leaves.result.engine_result == "tecUNFUNDED_PAYMENT"
        assert not outcome.settled

    async def test_a_failed_submission_releases_the_reservation(self, tmp_path: Path) -> None:
        """A rail that refused must not permanently consume the agent's window."""
        rig = build_rig(tmp_path, starting_balance="10.00")
        await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent(value="250.00")
        )
        assert rig.engine._state.snapshot().entries == ()

    async def test_history_and_reconciliation_agree(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent()
        )
        outflows = await rig.rail.history(rig.policy.treasury, "2020-01-01T00:00:00Z")
        assert [o.tx_hash for o in outflows] == [outcome.settlement.tx_hash]
        report = rig.engine.reconcile(outflows)
        assert report.clean
        assert report.matched == (outcome.settlement.tx_hash,)

    async def test_the_transaction_id_re_derives_from_the_blob(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent()
        )
        blob = outcome.receipt.leaves.settlement.signed_tx_blob
        assert fake_tx_id(bytes.fromhex(blob)) == outcome.settlement.tx_hash

    async def test_the_proof_names_what_it_carries(self, tmp_path: Path) -> None:
        """The fake rail captures everything an offline inclusion proof needs.

        Phase 4 gave it a transaction-set root, a path to it and signed
        validations, so ``missing`` is empty here and ``proven-offline`` is a
        state the suite actually reaches. XRPL still names ``shamap_path``.
        """
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent()
        )
        assert outcome.proof.missing == ()
        assert "shamap_path" in outcome.proof.captured
        assert outcome.proof.tx_path is not None


class TestTxIdRules:
    async def test_an_unknown_rail_has_no_rule(self) -> None:
        assert tx_id_from_blob("solana", "ab") is None

    async def test_xrpl_uses_sha512half_over_the_txn_prefix(self) -> None:
        import hashlib

        blob = bytes.fromhex("1200002200000000")
        expected = hashlib.sha512(bytes.fromhex("54584E00") + blob).digest()[:32].hex().upper()
        assert xrpl_tx_id(blob) == expected


class TestXrplEncodings:
    """Offline: the pieces of the XRPL adapter that need no ledger."""

    async def test_a_three_letter_code_travels_as_itself(self) -> None:
        from merkl.adapters.xrpl import currency_code

        assert currency_code("USD") == "USD"

    async def test_rlusd_becomes_the_forty_hex_form(self) -> None:
        from merkl.adapters.xrpl import currency_code

        assert currency_code("RLUSD") == "524C555344" + "0" * 30
        assert len(currency_code("RLUSD")) == 40

    async def test_xrp_amounts_become_drops_without_a_float(self) -> None:
        from merkl.adapters.xrpl import to_xrpl_amount

        assert to_xrpl_amount(Amount(value="1.000001", currency="XRP")) == "1000001"
        assert to_xrpl_amount(Amount(value="0.1", currency="XRP")) == "100000"

    async def test_an_issued_amount_keeps_its_decimal_string(self) -> None:
        from merkl.adapters.xrpl import to_xrpl_amount

        amount = to_xrpl_amount(Amount(value="250.00", currency=RLUSD))
        assert amount.value == "250.00"
        assert amount.issuer == ISSUER

    async def test_a_foreign_native_asset_is_refused(self) -> None:
        from merkl.adapters.xrpl import XrplAdapterError, to_xrpl_amount

        with pytest.raises(XrplAdapterError, match="native asset is XRP"):
            to_xrpl_amount(Amount(value="1", currency="SOL"))

    async def test_the_signer_address_derives_from_the_raw_key(self) -> None:
        from xrpl.core import keypairs

        from merkl.adapters.xrpl import signer_address

        key = "01" * 32
        assert signer_address(key) == keypairs.derive_classic_address("ED" + key.upper())

    async def test_ripple_time_converts_to_a_canonical_instant(self) -> None:
        from merkl.adapters.xrpl import ripple_time

        assert ripple_time(0) == "2000-01-01T00:00:00Z"

    async def test_the_multisigning_payload_has_one_placeholder_run(self) -> None:
        """The property the signer relies on, checked against xrpl-py's own encoder."""
        from xrpl.core.binarycodec import encode_for_multisigning
        from xrpl.models.transactions import Memo, Payment

        from merkl.adapters.xrpl import signer_address
        from merkl.core.rail import MEMO_TYPE

        address = signer_address("02" * 32)
        payment = Payment(
            account=address,
            destination=signer_address("03" * 32),
            amount="1000000",
            fee="30",
            sequence=7,
            last_ledger_sequence=99,
            memos=[
                Memo(
                    memo_type=MEMO_TYPE.encode().hex().upper(),
                    memo_data=ANCHOR_PLACEHOLDER_HEX.upper(),
                )
            ],
            signing_pub_key="",
        )
        payload = bytes.fromhex(encode_for_multisigning(payment.to_xrpl(), address))
        assert payload.count(ANCHOR_PLACEHOLDER) == 1


class TestLedger:
    async def test_balances_are_decimals_not_floats(self) -> None:
        ledger = FakeLedger()
        ledger.credit("rA", "XRP", "0.1")
        ledger.credit("rA", "XRP", "0.2")
        assert Decimal(ledger.balance("rA", "XRP")) == Decimal("0.3")

    async def test_an_adapter_reports_its_anchor_capability(self) -> None:
        adapter = FakeSettlementAdapter(
            FakeLedger(),
            agent_key=AGENT.raw(),
            agent_public_key=AGENT.public_key,
            clock=FrozenClock(),
        )
        assert adapter.anchor_capability().value == "immutable"

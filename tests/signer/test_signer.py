"""The signer: keystore, auth, sealed state, the engine, and the RPC surface."""

from __future__ import annotations

import dataclasses
import json
import threading
from pathlib import Path

import httpx
import pytest

from merkl.adapters.fake import FakeLedger, FakeSettlementAdapter
from merkl.core.canonical import shift_instant
from merkl.core.policy.document import CREDENTIAL_WEBAUTHN, AdminCredential, SignedPolicy
from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.receipt import PolicyOutcome, escalation_challenge
from merkl.signer.auth import AuthError, SignedRequest, sign_request, verify_request
from merkl.signer.binding import BindingError, decode_classic_address, missing_bindings
from merkl.signer.engine import SignerEngine, SignerError
from merkl.signer.keystore import DevKeystore, KeystoreError
from merkl.signer.relay_auth import RelayToken, generate_token, hash_token
from merkl.signer.server import build_server
from merkl.signer.state import SealedStateError, SealedStateStore
from tests.scenarios.harness import (
    ADMIN,
    AGENT,
    AGENT_ID,
    BOB,
    FrozenClock,
    build_policy,
    sign_policy,
)


def make_engine(tmp_path: Path, **overrides) -> tuple[SignerEngine, FrozenClock, DevKeystore]:
    policy = overrides.pop("policy", None) or build_policy()
    clock = overrides.pop("clock", None) or FrozenClock()
    keystore = DevKeystore(tmp_path / "keystore", passphrase="unit-test")
    state = SealedStateStore(tmp_path / "state", policy.treasury, keystore.seal_key())
    return (
        SignerEngine(policy=sign_policy(policy), keystore=keystore, state=state, clock=clock),
        clock,
        keystore,
    )


def request_for(clock: FrozenClock, params: dict, *, method: str = "propose", **overrides):
    fields = {
        "method": method,
        "agent_id": AGENT_ID,
        "nonce": overrides.pop("nonce", "n-" + clock.now()),
        "expires_at": shift_instant(clock.now(), 300),
        "params": params,
        "agent_public_key": AGENT.public_key,
        "sign": AGENT.sign,
    }
    fields.update(overrides)
    return sign_request(**fields)


class TestKeystore:
    def test_a_key_is_created_once_and_reopened(self, tmp_path: Path) -> None:
        first = DevKeystore(tmp_path, passphrase="p")
        second = DevKeystore(tmp_path, passphrase="p")
        assert first.public_key() == second.public_key()

    def test_the_wrong_passphrase_does_not_open_it(self, tmp_path: Path) -> None:
        DevKeystore(tmp_path, passphrase="right")
        with pytest.raises(KeystoreError, match="passphrase is wrong"):
            DevKeystore(tmp_path, passphrase="wrong")

    def test_the_key_file_is_not_world_readable(self, tmp_path: Path) -> None:
        DevKeystore(tmp_path, passphrase="p")
        mode = (tmp_path / "policy-ed25519.json").stat().st_mode & 0o777
        assert mode == 0o600

    def test_the_private_key_never_appears_on_disk_in_the_clear(self, tmp_path: Path) -> None:
        keystore = DevKeystore(tmp_path, passphrase="p")
        document = json.loads((tmp_path / "policy-ed25519.json").read_text())
        assert set(document) >= {"salt", "nonce", "ciphertext", "public_key"}
        assert document["public_key"] == keystore.public_key()

    def test_the_repr_does_not_leak(self, tmp_path: Path) -> None:
        keystore = DevKeystore(tmp_path, passphrase="p")
        assert "passphrase" not in repr(keystore)

    def test_a_dev_signer_is_unattested_and_says_so(self, tmp_path: Path) -> None:
        assert DevKeystore(tmp_path, passphrase="p").attestation() is None

    def test_the_seal_key_is_not_the_signing_key(self, tmp_path: Path) -> None:
        keystore = DevKeystore(tmp_path, passphrase="p")
        assert keystore.seal_key().hex() != keystore.public_key()
        assert len(keystore.seal_key()) == 32


class TestSealedState:
    def test_state_survives_a_restart(self, tmp_path: Path) -> None:
        keystore = DevKeystore(tmp_path / "k", passphrase="p")
        store = SealedStateStore(tmp_path / "s", "rTREASURY", keystore.seal_key())
        sequence = store.reserve(_entry())
        reopened = SealedStateStore(tmp_path / "s", "rTREASURY", keystore.seal_key())
        assert reopened.sequence == sequence
        assert reopened.snapshot().entry("r1") is not None

    def test_a_snapshot_will_not_open_with_the_wrong_key(self, tmp_path: Path) -> None:
        store = SealedStateStore(tmp_path / "s", "rTREASURY", b"\x01" * 32)
        store.reserve(_entry())
        with pytest.raises(SealedStateError, match="wrong key"):
            SealedStateStore(tmp_path / "s", "rTREASURY", b"\x02" * 32)

    def test_state_for_another_treasury_is_refused(self, tmp_path: Path) -> None:
        SealedStateStore(tmp_path / "s", "rONE", b"\x01" * 32).reserve(_entry())
        with pytest.raises(SealedStateError, match="is for treasury"):
            SealedStateStore(tmp_path / "s", "rTWO", b"\x01" * 32)

    def test_a_rollback_is_refused(self, tmp_path: Path) -> None:
        """Restoring an older sequence is how a window gets spent twice."""
        store = SealedStateStore(tmp_path / "s", "rTREASURY", b"\x01" * 32)
        old = store.snapshot()
        store.reserve(_entry())
        with pytest.raises(SealedStateError, match="back to"):
            store.restore(old)


def _entry():
    from merkl.core.policy.state import SpendEntry

    return SpendEntry(
        reservation_id="r1",
        agent_id="agent-ap",
        asset="XRP",
        value="1",
        at="2026-01-02T03:00:00Z",
    )


class TestAuth:
    def test_a_signed_request_verifies(self, tmp_path: Path) -> None:
        clock = FrozenClock()
        policy = build_policy()
        request = request_for(clock, {})
        section = verify_request(
            request, policy, now=clock.now(), seen_nonces=frozenset(), expected_method="propose"
        )
        assert section.agent_id == AGENT_ID

    def test_the_params_are_inside_the_signature(self, tmp_path: Path) -> None:
        clock = FrozenClock()
        request = request_for(clock, {"amount": "1"})
        tampered = SignedRequest.from_content({**request.to_content(), "params": {"amount": "9"}})
        with pytest.raises(AuthError, match="does not verify"):
            verify_request(tampered, build_policy(), now=clock.now(), seen_nonces=frozenset())

    def test_an_expired_request_is_refused(self) -> None:
        clock = FrozenClock()
        request = request_for(clock, {})
        with pytest.raises(AuthError, match="expired"):
            verify_request(
                request,
                build_policy(),
                now=shift_instant(clock.now(), 400),
                seen_nonces=frozenset(),
            )

    def test_a_replayed_nonce_is_refused(self) -> None:
        clock = FrozenClock()
        request = request_for(clock, {}, nonce="used")
        with pytest.raises(AuthError, match="already been used"):
            verify_request(
                request, build_policy(), now=clock.now(), seen_nonces=frozenset({"used"})
            )

    def test_a_key_the_policy_does_not_hold_is_refused(self) -> None:
        clock = FrozenClock()
        request = request_for(clock, {}, agent_public_key="ab" * 32)
        with pytest.raises(AuthError, match="key the policy does not hold"):
            verify_request(request, build_policy(), now=clock.now(), seen_nonces=frozenset())

    def test_a_request_for_another_method_is_refused(self) -> None:
        clock = FrozenClock()
        request = request_for(clock, {}, method="approve")
        with pytest.raises(AuthError, match="not 'propose'"):
            verify_request(
                request,
                build_policy(),
                now=clock.now(),
                seen_nonces=frozenset(),
                expected_method="propose",
            )


VALID_ADDRESS = "r31tMdHuY2hzyxqFkyMof7WQxD9ZVRMrXH"


class TestBinding:
    def test_a_classic_address_decodes_to_twenty_bytes(self) -> None:
        assert len(decode_classic_address(VALID_ADDRESS)) == 20

    def test_the_decoding_agrees_with_xrpl_py(self) -> None:
        """The signer decodes addresses itself; it must decode them the same way."""
        import xrpl.core.addresscodec as addresscodec

        assert decode_classic_address(VALID_ADDRESS) == addresscodec.decode_classic_address(
            VALID_ADDRESS
        )

    def test_a_bad_checksum_is_refused(self) -> None:
        with pytest.raises(BindingError, match="checksum"):
            decode_classic_address(VALID_ADDRESS[:-1] + "4")

    def test_an_unknown_rail_offers_no_evidence_rather_than_false_evidence(self) -> None:
        assert missing_bindings("fake", b"", {"destination": "whatever"}) == []


class TestEngineFlow:
    @pytest.mark.asyncio
    async def test_propose_refuses_a_transaction_that_is_not_the_intent(
        self, tmp_path: Path
    ) -> None:
        """The signer checks what it signs against what it was asked to authorize."""
        from tests.scenarios.harness import SUPPLIER, build_rig

        rig = build_rig(tmp_path)
        intent = rig.intent()
        unsigned = await rig.rail.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
        lying = unsigned.to_content()
        lying["fields"] = {**unsigned.fields, "destination": "rSOMEONEELSE"}
        request = request_for(
            rig.clock,
            {
                "instruction": rig.instruction().to_content(),
                "intent": intent.to_content(),
                "prepared_tx": lying,
            },
        )
        with pytest.raises(SignerError, match="does not match the intent"):
            rig.engine.propose(request.to_content())
        assert SUPPLIER  # the honest destination is still what the intent names

    @pytest.mark.asyncio
    async def test_propose_refuses_a_payload_whose_anchor_is_already_filled(
        self, tmp_path: Path
    ) -> None:
        from tests.scenarios.harness import build_rig

        rig = build_rig(tmp_path)
        intent = rig.intent()
        unsigned = await rig.rail.prepare(intent, "ab" * 32)
        request = request_for(
            rig.clock,
            {
                "instruction": rig.instruction().to_content(),
                "intent": intent.to_content(),
                "prepared_tx": unsigned.to_content(),
            },
        )
        with pytest.raises(SignerError, match="placeholder"):
            rig.engine.propose(request.to_content())

    def test_a_denial_reserves_nothing(self, tmp_path: Path) -> None:
        engine, clock, _ = make_engine(tmp_path)
        before = engine.health()["state_sequence"]
        result = engine.propose(
            request_for(
                clock,
                {
                    "instruction": {
                        "source": "human_input",
                        "content_hash": "ab" * 32,
                    },
                    "intent": _intent_content(clock, destination="rATTACKER"),
                },
            ).to_content()
        )
        assert result["outcome"] == PolicyOutcome.DENY.value
        # one sequence step for the nonce, none for a reservation
        assert engine.health()["state_sequence"] == before + 1

    @pytest.mark.asyncio
    async def test_approving_its_own_reservation_does_not_double_count_the_window(
        self, tmp_path: Path
    ) -> None:
        """Re-evaluating at approve time asks whether *other* activity has
        filled the window since (SIGNER-RPC.md §4: "minutes have passed and
        the window may have filled") — not whether this payment's own
        still-open reservation, counted a second time on top of itself,
        no longer fits. A payment sized to use the window right up to its cap
        must still be approvable when nothing else has spent from it.
        """
        from tests.scenarios.harness import approvals_for, build_policy, build_rig

        policy = build_policy(
            per_tx_cap="1000.00", human_threshold="500.00", window=("1000.00", 86400)
        )
        rig = build_rig(tmp_path, policy=policy)
        intent = rig.intent(value="1000.00")
        pending = await rig.builder.execute(instruction=rig.instruction(), intent=intent)
        assert pending.outcome == "escalate"
        challenge = escalation_challenge(pending.receipt.leaves).hex()

        assertions = [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())]
        decision = rig.engine.approve(challenge, assertions)
        assert decision["outcome"] == "allow", decision.get("reason")

    def test_health_names_the_signer_unattested(self, tmp_path: Path) -> None:
        engine, _, _ = make_engine(tmp_path)
        health = engine.health()
        assert health["attested"] is False
        assert "UNATTESTED" in health["warning"]

    def test_a_policy_signed_by_the_wrong_admin_will_not_load(self, tmp_path: Path) -> None:
        from merkl.core.policy.document import SignedPolicy

        policy = build_policy()
        keystore = DevKeystore(tmp_path / "k", passphrase="p")
        state = SealedStateStore(tmp_path / "s", policy.treasury, keystore.seal_key())
        forged = SignedPolicy(
            document=policy, signature="ab" * 64, signer_public_key=policy.admin_public_key
        )
        with pytest.raises(SignerError, match="admin signature does not verify"):
            SignerEngine(policy=forged, keystore=keystore, state=state)


def _intent_content(clock: FrozenClock, **overrides) -> dict:
    from merkl.core.intent import Amount, Intent, IssuedCurrency, Reference
    from tests.scenarios.harness import INVOICE_HASH, ISSUER, SUPPLIER, TREASURY

    fields = {
        "rail": "fake",
        "treasury": TREASURY,
        "destination": SUPPLIER,
        "amount": Amount(value="250.00", currency=IssuedCurrency(code="RLUSD", issuer=ISSUER)),
        "policy_version": "2026.01.0",
        "agent_public_key": AGENT.public_key,
        "nonce": "intent-nonce",
        "expires_at": shift_instant(clock.now(), 600),
        "reference": Reference(kind="invoice", id="INV-2026-0042", hash=INVOICE_HASH),
    }
    fields.update(overrides)
    return Intent(**fields).to_content()


class TestPolicyUpdate:
    def test_a_new_policy_signed_by_the_pinned_admin_is_adopted(self, tmp_path: Path) -> None:
        engine, _, _ = make_engine(tmp_path)
        old_hash = engine.policy_hash
        updated = sign_policy(build_policy(per_tx_cap="2000.00"))
        result = engine.policy_update(updated.to_content())
        assert result["change"]["old_hash"] == old_hash
        assert result["change"]["new_hash"] == updated.policy_hash
        assert result["change"]["credential_type"] == "ed25519"
        assert engine.policy_hash == updated.policy_hash
        assert engine.policy_changes()[0]["old_hash"] == old_hash

    def test_a_policy_signed_by_someone_else_is_refused(self, tmp_path: Path) -> None:
        from merkl.core.policy.document import SignedPolicy
        from merkl.core.vectors import fixtures

        engine, _, _ = make_engine(tmp_path)
        rogue_key = fixtures.ed25519_key("rogue-admin")
        rogue_document = build_policy()
        rogue = SignedPolicy(
            document=rogue_document,
            signature=rogue_key.sign(rogue_document.pre_image()).hex(),
            signer_public_key=fixtures.ed25519_public_hex(rogue_key),
        )
        with pytest.raises(SignerError, match="admin credential this signer has pinned"):
            engine.policy_update(rogue.to_content())

    def test_a_policy_update_cannot_move_the_treasury(self, tmp_path: Path) -> None:
        engine, _, _ = make_engine(tmp_path)
        elsewhere = sign_policy(build_policy(treasury="rSOMEWHEREELSE0000000000000000000"))
        with pytest.raises(SignerError, match="which treasury"):
            engine.policy_update(elsewhere.to_content())

    def _webauthn_admin(self) -> AdminCredential:
        return AdminCredential(
            credential_type=CREDENTIAL_WEBAUTHN,
            public_key=BOB.public_key,
            origins=("https://app.merkl.ai",),
            rp_id="app.merkl.ai",
            user_verification=True,
        )

    def test_an_admin_can_rotate_to_a_webauthn_credential(self, tmp_path: Path) -> None:
        """The old (legacy Ed25519) admin signs a document naming a new admin (D16)."""
        engine, _, _ = make_engine(tmp_path)
        assert engine.admin.credential_type == "ed25519"
        new_document = dataclasses.replace(
            engine.document,
            admin_public_key=None,
            admin=self._webauthn_admin(),
            version="2026.02.0",
        )
        updated = SignedPolicy(
            document=new_document,
            signature=ADMIN.sign(new_document.pre_image()),
            signer_public_key=ADMIN.public_key,
        )
        result = engine.policy_update(updated.to_content())
        assert result["policy_hash"] == new_document.policy_hash()
        assert engine.admin.credential_type == "webauthn"
        assert engine.admin.public_key == BOB.public_key

    def test_after_rotation_the_old_admin_key_no_longer_authorizes_anything(
        self, tmp_path: Path
    ) -> None:
        engine, _, _ = make_engine(tmp_path)
        rotated = dataclasses.replace(
            engine.document,
            admin_public_key=None,
            admin=self._webauthn_admin(),
            version="2026.02.0",
        )
        engine.policy_update(
            SignedPolicy(
                document=rotated,
                signature=ADMIN.sign(rotated.pre_image()),
                signer_public_key=ADMIN.public_key,
            ).to_content()
        )
        another = dataclasses.replace(rotated, version="2026.02.1")
        forged = SignedPolicy(
            document=another,
            signature=ADMIN.sign(another.pre_image()),
            signer_public_key=ADMIN.public_key,
        )
        with pytest.raises(SignerError, match="admin credential this signer has pinned"):
            engine.policy_update(forged.to_content())


class TestRpcServer:
    def _serve(self, tmp_path: Path):
        engine, clock, keystore = make_engine(tmp_path)
        server = build_server(engine, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        return server, f"http://{host}:{port}", engine, clock, keystore

    def test_health_and_public_key_over_http(self, tmp_path: Path) -> None:
        server, base, _, _, keystore = self._serve(tmp_path)
        try:
            health = httpx.post(base, json={"method": "health"}).json()
            assert health["protocol"] == "merkl-signer-rpc-v1"
            assert health["result"]["attested"] is False
            key = httpx.post(base, json={"method": "public_key"}).json()["result"]
            assert key["public_key"] == keystore.public_key()
            assert httpx.get(f"{base}/health").json()["result"]["status"] == "ok"
        finally:
            server.shutdown()

    def test_an_unknown_method_is_an_error_not_a_decision(self, tmp_path: Path) -> None:
        server, base, _, _, _ = self._serve(tmp_path)
        try:
            response = httpx.post(base, json={"method": "sign_whatever_i_want"})
            assert response.status_code == 400
            assert response.json()["error"]["code"] == "signer_error"
            assert "result" not in response.json()
        finally:
            server.shutdown()

    def test_an_unauthenticated_propose_is_rejected_with_401(self, tmp_path: Path) -> None:
        server, base, _, clock, _ = self._serve(tmp_path)
        try:
            request = request_for(clock, {"instruction": {}, "intent": {}}).to_content()
            request["signature"] = "ab" * 64
            response = httpx.post(base, json={"method": "propose", "params": {"request": request}})
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "signer_auth_error"
        finally:
            server.shutdown()

    def test_the_server_refuses_a_non_loopback_bind(self, tmp_path: Path) -> None:
        engine, _, _ = make_engine(tmp_path)
        with pytest.raises(SignerError, match="refusing to bind"):
            build_server(engine, host="0.0.0.0", port=0)


class TestRelayAuthOverHttp:
    """docs/SIGNER-RPC.md, "Who may call what" — enforced at the server, both transports."""

    def _serve_with_token(self, tmp_path: Path):
        engine, clock, _ = make_engine(tmp_path)
        bearer = generate_token("ci")
        tokens = (RelayToken(id="ci", token_sha256=hash_token(bearer)),)
        server = build_server(engine, host="127.0.0.1", port=0, relay_tokens=tokens)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        return server, f"http://{host}:{port}", clock, bearer

    def test_with_no_relay_tokens_configured_health_needs_nothing(self, tmp_path: Path) -> None:
        engine, _, _ = make_engine(tmp_path)
        server = build_server(engine, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        try:
            response = httpx.post(f"http://{host}:{port}", json={"method": "health"})
            assert response.status_code == 200
        finally:
            server.shutdown()

    def test_a_bearer_is_required_once_a_token_is_configured(self, tmp_path: Path) -> None:
        server, base, _, _ = self._serve_with_token(tmp_path)
        try:
            response = httpx.post(base, json={"method": "health"})
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "signer_auth_error"
        finally:
            server.shutdown()

    def test_the_bare_get_health_endpoint_also_requires_it(self, tmp_path: Path) -> None:
        server, base, _, _ = self._serve_with_token(tmp_path)
        try:
            assert httpx.get(f"{base}/health").status_code == 401
        finally:
            server.shutdown()

    def test_a_wrong_bearer_is_refused(self, tmp_path: Path) -> None:
        server, base, _, _ = self._serve_with_token(tmp_path)
        try:
            response = httpx.post(
                base,
                json={"method": "health"},
                headers={"Authorization": "Bearer ci:wrong-secret"},
            )
            assert response.status_code == 401
        finally:
            server.shutdown()

    def test_the_right_bearer_is_accepted(self, tmp_path: Path) -> None:
        server, base, _, bearer = self._serve_with_token(tmp_path)
        try:
            response = httpx.post(
                base, json={"method": "health"}, headers={"Authorization": f"Bearer {bearer}"}
            )
            assert response.status_code == 200
            assert (
                httpx.get(f"{base}/health", headers={"Authorization": f"Bearer {bearer}"}).json()[
                    "result"
                ]["status"]
                == "ok"
            )
        finally:
            server.shutdown()

    def test_propose_needs_no_bearer_even_when_tokens_are_configured(self, tmp_path: Path) -> None:
        server, base, clock, _ = self._serve_with_token(tmp_path)
        try:
            request = request_for(clock, {"instruction": {}, "intent": {}}).to_content()
            request["signature"] = "ab" * 64
            response = httpx.post(base, json={"method": "propose", "params": {"request": request}})
            # 401 because the *agent* signature does not verify, not because a
            # relay bearer was required — propose never needs one.
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "signer_auth_error"
        finally:
            server.shutdown()


class TestUnixSocket:
    @pytest.mark.asyncio
    async def test_the_socket_is_owner_only_and_answers(self, tmp_path: Path) -> None:
        import tempfile

        from merkl.adapters.signer_dev import DevSignerClient

        engine, _, keystore = make_engine(tmp_path)
        # macOS caps AF_UNIX paths at ~104 bytes and pytest's tmp_path is longer.
        socket_dir = tempfile.mkdtemp(prefix="mk")
        socket_path = Path(socket_dir) / "s.sock"
        server = build_server(engine, socket_path=socket_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            assert socket_path.stat().st_mode & 0o777 == 0o600
            async with DevSignerClient(socket_path=socket_path) as client:
                assert await client.public_key() == keystore.public_key()
                assert (await client.health())["attested"] is False
        finally:
            server.shutdown()


def test_the_fake_rail_is_available_for_the_engine_tests() -> None:
    ledger = FakeLedger()
    assert (
        FakeSettlementAdapter(
            ledger, agent_key=AGENT.raw(), agent_public_key=AGENT.public_key, clock=FrozenClock()
        )
        .anchor_capability()
        .value
        == "immutable"
    )

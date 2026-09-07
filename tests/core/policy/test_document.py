"""The policy document: hashed, signed, and unable to name its own admin."""

from __future__ import annotations

import dataclasses
import json

import pytest

from merkl.core.canonical import ContentError
from merkl.core.intent import IssuedCurrency
from merkl.core.policy.approvals import verify_policy_signature
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    CREDENTIAL_WEBAUTHN,
    POLICY_TAG,
    AdminCredential,
    AgentSection,
    ApproverCredential,
    AssetLimit,
    EscalationTier,
    HumanTier,
    PolicyChange,
    PolicyDocument,
    PolicyError,
    ReferenceBinding,
    SignedPolicy,
    Tiers,
    WindowRule,
    asset_key,
    unenforceable_rules,
)
from merkl.core.vectors import VECTORS_DIR, fixtures
from merkl.shared.hashing import SHA256Hash, canonical_bytes

ADMIN = fixtures.ed25519_key("test-admin")
OTHER = fixtures.ed25519_key("test-other-admin")
AGENT_KEY = fixtures.ed25519_public_hex(fixtures.ed25519_key("test-agent"))
RLUSD = IssuedCurrency(code="RLUSD", issuer="rISSUER000000000000000000000000000")


def make_document(**overrides) -> PolicyDocument:
    fields = {
        "version": "2026.01.0",
        "treasury": "rTREASURY0000000000000000000000000",
        "rail": "xrpl",
        "agents": (
            AgentSection(
                agent_id="agent-ap",
                public_key=AGENT_KEY,
                allowlist_destinations=("rSUPPLIER0000000000000000000000000",),
                allowlist_assets=(RLUSD,),
                per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
                reference_binding=ReferenceBinding(required=True, allowed_kinds=("invoice",)),
            ),
        ),
        "admin_public_key": fixtures.ed25519_public_hex(ADMIN),
    }
    fields.update(overrides)
    return PolicyDocument(**fields)


def sign(document: PolicyDocument, key=ADMIN) -> SignedPolicy:
    return SignedPolicy(
        document=document,
        signature=key.sign(document.pre_image()).hex(),
        signer_public_key=fixtures.ed25519_public_hex(key),
    )


class TestHashing:
    def test_the_hash_is_over_the_tagged_pre_image(self) -> None:
        document = make_document()
        expected = SHA256Hash.from_bytes(
            POLICY_TAG + b"\x00" + canonical_bytes(document.to_content())
        ).hex()
        assert document.policy_hash() == expected

    def test_the_hash_does_not_depend_on_construction_order(self) -> None:
        assert make_document().policy_hash() == make_document().policy_hash()

    def test_any_change_changes_the_hash(self) -> None:
        base = make_document()
        changed = make_document(version="2026.01.1")
        assert base.policy_hash() != changed.policy_hash()

    def test_the_document_round_trips_through_json(self) -> None:
        document = make_document()
        assert PolicyDocument.from_content(document.to_content()) == document

    def test_the_content_holds_no_floats(self) -> None:
        """ensure_canonical_content runs inside to_content and would have raised."""
        content = make_document().to_content()
        assert isinstance(content["risk"]["threshold"], str)
        assert isinstance(content["tiers"], dict)


class TestSignature:
    def test_a_signed_policy_verifies(self) -> None:
        assert verify_policy_signature(sign(make_document()))

    def test_a_tampered_document_does_not_verify(self) -> None:
        signed = sign(make_document())
        forged = dataclasses.replace(signed, document=make_document(version="2026.99.0"))
        assert not verify_policy_signature(forged)

    def test_a_document_cannot_nominate_its_own_admin(self) -> None:
        """The whole point of pinning: a forged policy signs itself otherwise."""
        rogue = make_document(admin_public_key=fixtures.ed25519_public_hex(OTHER))
        signed = sign(rogue, key=OTHER)
        assert verify_policy_signature(signed) is True
        assert (
            verify_policy_signature(signed, admin_public_key=fixtures.ed25519_public_hex(ADMIN))
            is False
        )

    def test_the_signature_covers_the_same_bytes_the_hash_does(self) -> None:
        document = make_document()
        assert document.pre_image().startswith(POLICY_TAG)
        assert document.policy_hash() == SHA256Hash.from_bytes(document.pre_image()).hex()


class TestAdminCredential:
    """PolicyDocument.admin (plan D16, extended): ed25519 or webauthn."""

    def test_admin_and_admin_public_key_are_mutually_exclusive(self) -> None:
        with pytest.raises(PolicyError, match="mutually exclusive"):
            make_document(
                admin_public_key=fixtures.ed25519_public_hex(ADMIN),
                admin=AdminCredential(
                    credential_type=CREDENTIAL_ED25519,
                    public_key=fixtures.ed25519_public_hex(OTHER),
                ),
            )

    def test_a_document_needs_one_admin_or_the_other(self) -> None:
        with pytest.raises(PolicyError, match="needs an admin"):
            make_document(admin_public_key=None)

    def test_the_legacy_field_synthesizes_an_ed25519_effective_admin(self) -> None:
        document = make_document()
        admin = document.effective_admin
        assert admin.credential_type == CREDENTIAL_ED25519
        assert admin.public_key == fixtures.ed25519_public_hex(ADMIN)
        assert admin.origins == ()

    def test_a_legacy_document_emits_no_admin_member(self) -> None:
        """The whole point: policy_hash over this shape must never move."""
        content = make_document().to_content()
        assert "admin" not in content
        assert content["admin_public_key"] == fixtures.ed25519_public_hex(ADMIN)

    def test_a_webauthn_admin_round_trips_and_hashes_differently(self) -> None:
        webauthn_admin = AdminCredential(
            credential_type=CREDENTIAL_WEBAUTHN,
            public_key="04" + "ab" * 64,
            origins=("https://admin.example.com",),
            rp_id="admin.example.com",
            user_verification=True,
        )
        document = make_document(admin_public_key=None, admin=webauthn_admin)
        assert document.effective_admin == webauthn_admin
        content = document.to_content()
        assert "admin_public_key" not in content
        assert content["admin"]["credential_type"] == "webauthn"
        assert PolicyDocument.from_content(content) == document
        assert document.policy_hash() != make_document().policy_hash()

    def test_a_webauthn_admin_needs_a_relying_party(self) -> None:
        with pytest.raises(PolicyError, match="rp_id"):
            AdminCredential(credential_type=CREDENTIAL_WEBAUTHN, public_key="04" + "ab" * 64)


class TestPolicyChange:
    def test_round_trips_with_credential_type(self) -> None:
        change = PolicyChange(
            old_hash="a" * 64,
            new_hash="b" * 64,
            signed_by=fixtures.ed25519_public_hex(ADMIN),
            at="2026-02-01T00:00:00Z",
            credential_type="webauthn",
        )
        assert PolicyChange.from_content(change.to_content()) == change

    def test_credential_type_defaults_to_ed25519(self) -> None:
        content = {
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
            "signed_by": fixtures.ed25519_public_hex(ADMIN),
            "at": "2026-02-01T00:00:00Z",
        }
        change = PolicyChange.from_content(content)
        assert change.credential_type == "ed25519"


class TestValidation:
    def test_unknown_members_are_rejected(self) -> None:
        content = make_document().to_content()
        content["surprise"] = "hello"
        with pytest.raises(PolicyError, match="unknown members"):
            PolicyDocument.from_content(content)

    def test_a_policy_needs_at_least_one_agent(self) -> None:
        with pytest.raises(PolicyError, match="at least one agent"):
            make_document(agents=())

    def test_duplicate_agent_ids_are_rejected(self) -> None:
        section = make_document().agents[0]
        with pytest.raises(PolicyError, match="duplicate agent ids"):
            make_document(agents=(section, section))

    def test_a_fractional_cap_is_a_string_not_a_number(self) -> None:
        with pytest.raises(ContentError):
            AssetLimit(asset=RLUSD, amount=1000.0)  # type: ignore[arg-type]

    def test_a_webauthn_approver_needs_a_relying_party(self) -> None:
        with pytest.raises(PolicyError, match="rp_id"):
            ApproverCredential(id="alice", credential_type="webauthn", public_key="04" + "ab" * 64)


class TestAssetKeys:
    def test_a_native_code_is_its_own_key(self) -> None:
        assert asset_key("XRP") == "XRP"

    def test_an_issued_currency_carries_its_issuer(self) -> None:
        assert asset_key(RLUSD) == f"RLUSD.{RLUSD.issuer}"

    def test_two_issuers_of_the_same_code_do_not_collide(self) -> None:
        other = IssuedCurrency(code="RLUSD", issuer="rSOMEONEELSE000000000000000000000")
        assert asset_key(RLUSD) != asset_key(other)


def test_the_tier_vocabulary_is_fixed_even_where_it_is_unimplemented() -> None:
    """NOTIFY and DELAY exist so a later phase does not change what a verifier reads."""
    assert [t.value for t in EscalationTier] == ["instant", "human", "notify", "delay"]


# --------------------------------------------------------------------------- #
# Rules the engine would sign but never run
# --------------------------------------------------------------------------- #

POLICY_VECTORS = json.loads((VECTORS_DIR / "policies.json").read_text())


@pytest.mark.parametrize("case", POLICY_VECTORS["document_cases"], ids=lambda c: c["name"])
def test_document_rule_vectors(case: dict) -> None:
    """The committed contract with @merkl-ai/verify: same document, same sentences."""
    content = case["signed_policy"]["document"]
    assert unenforceable_rules(content) == case["expected_findings"]
    if case["expected_findings"]:
        with pytest.raises(PolicyError) as raised:
            PolicyDocument.from_content(content)
        assert str(raised.value) == case["expected_findings"][0]
    else:
        assert PolicyDocument.from_content(content).policy_hash() == case["policy_hash"]


@pytest.mark.parametrize("case", POLICY_VECTORS["document_cases"], ids=lambda c: c["name"])
def test_a_dead_rule_is_signed_and_hashed_all_the_same(case: dict) -> None:
    """Every one of these documents has a valid admin signature over a valid hash.

    That is the finding, not an accident of the fixture: signature and hash say
    nothing about whether a rule can run, so refusing the document is the only
    place the gap can be closed.
    """
    signed = case["signed_policy"]
    pre_image = POLICY_TAG + b"\x00" + canonical_bytes(signed["document"])
    assert SHA256Hash.from_bytes(pre_image).hex() == case["policy_hash"]
    fixtures.ed25519_key("admin-vector-legacy-admin").public_key().verify(
        bytes.fromhex(signed["signature"]), pre_image
    )


class TestUnenforceableRules:
    def test_a_second_cap_for_one_asset_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="more than one per_tx_cap"):
            make_document(
                agents=(
                    AgentSection(
                        agent_id="agent-ap",
                        public_key=AGENT_KEY,
                        allowlist_assets=(RLUSD,),
                        per_tx_cap=(
                            AssetLimit(asset=RLUSD, amount="1000.00"),
                            AssetLimit(asset=RLUSD, amount="10.00"),
                        ),
                    ),
                )
            )

    def test_a_cap_for_an_asset_the_agent_may_not_move_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="not in its allowlist_assets"):
            make_document(
                agents=(
                    AgentSection(
                        agent_id="agent-ap",
                        public_key=AGENT_KEY,
                        allowlist_assets=(RLUSD,),
                        per_tx_cap=(AssetLimit(asset="XRP", amount="10.00"),),
                    ),
                )
            )

    def test_two_windows_over_the_same_asset_and_length_are_refused(self) -> None:
        with pytest.raises(PolicyError, match="more than one window"):
            make_document(
                agents=(
                    AgentSection(
                        agent_id="agent-ap",
                        public_key=AGENT_KEY,
                        allowlist_assets=(RLUSD,),
                        per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
                        windows=(
                            WindowRule(asset=RLUSD, amount="5000.00", seconds=86400),
                            WindowRule(asset=RLUSD, amount="50.00", seconds=86400),
                        ),
                    ),
                )
            )

    def test_two_windows_over_different_lengths_are_both_kept(self) -> None:
        """The engine runs every window that matches the asset, so both apply."""
        document = make_document(
            agents=(
                AgentSection(
                    agent_id="agent-ap",
                    public_key=AGENT_KEY,
                    allowlist_assets=(RLUSD,),
                    per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
                    windows=(
                        WindowRule(asset=RLUSD, amount="5000.00", seconds=86400),
                        WindowRule(asset=RLUSD, amount="500.00", seconds=3600),
                    ),
                ),
            )
        )
        assert len(document.agents[0].windows_for(RLUSD)) == 2

    def test_a_window_for_an_asset_the_agent_may_not_move_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="window for XRP"):
            make_document(
                agents=(
                    AgentSection(
                        agent_id="agent-ap",
                        public_key=AGENT_KEY,
                        allowlist_assets=(RLUSD,),
                        per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
                        windows=(WindowRule(asset="XRP", amount="5.00", seconds=60),),
                    ),
                )
            )

    def test_a_second_threshold_for_one_asset_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="more than one threshold"):
            make_document(
                tiers=Tiers(
                    human=HumanTier(
                        thresholds=(
                            AssetLimit(asset=RLUSD, amount="500.00"),
                            AssetLimit(asset=RLUSD, amount="5.00"),
                        )
                    )
                )
            )

    def test_a_threshold_for_an_asset_nobody_may_move_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="no agent in this policy may move"):
            make_document(
                tiers=Tiers(human=HumanTier(thresholds=(AssetLimit(asset="XRP", amount="5.00"),)))
            )

    def test_a_threshold_is_kept_when_any_agent_may_move_the_asset(self) -> None:
        """The tier table is document-wide: one agent's allowlist is enough."""
        document = make_document(
            agents=(
                AgentSection(
                    agent_id="agent-ap",
                    public_key=AGENT_KEY,
                    allowlist_assets=(RLUSD,),
                    per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
                ),
                AgentSection(
                    agent_id="agent-ops",
                    public_key=fixtures.ed25519_public_hex(fixtures.ed25519_key("test-agent-2")),
                    allowlist_assets=("XRP",),
                    per_tx_cap=(AssetLimit(asset="XRP", amount="5.00"),),
                ),
            ),
            tiers=Tiers(human=HumanTier(thresholds=(AssetLimit(asset="XRP", amount="1.00"),))),
        )
        assert document.tiers.human.threshold_for("XRP") is not None

    def test_the_same_code_from_two_issuers_is_two_assets(self) -> None:
        """Not a duplicate: the key carries the issuer, so both caps run."""
        other = IssuedCurrency(code="RLUSD", issuer="rSOMEONEELSE000000000000000000000")
        document = make_document(
            agents=(
                AgentSection(
                    agent_id="agent-ap",
                    public_key=AGENT_KEY,
                    allowlist_assets=(RLUSD, other),
                    per_tx_cap=(
                        AssetLimit(asset=RLUSD, amount="1000.00"),
                        AssetLimit(asset=other, amount="10.00"),
                    ),
                ),
            )
        )
        assert document.agents[0].cap_for(other) is not None


class TestNetwork:
    """`network` narrows `rail` to one chain, and is absent from a document without one."""

    def test_omitting_it_leaves_the_content_and_the_hash_untouched(self) -> None:
        document = make_document()
        assert "network" not in document.to_content()
        assert document.policy_hash() == make_document(network=None).policy_hash()

    def test_naming_one_changes_the_hash(self) -> None:
        """It is part of what the admin signs, so it cannot be added after the fact."""
        assert make_document().policy_hash() != make_document(network="xrpl-testnet").policy_hash()

    def test_testnet_and_mainnet_are_different_documents(self) -> None:
        assert (
            make_document(network="xrpl-testnet").policy_hash()
            != make_document(network="xrpl-mainnet").policy_hash()
        )

    def test_a_network_the_rail_does_not_have_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="policy.network must be one of"):
            make_document(network="xrpl-devnet")

    def test_a_rail_with_no_networks_may_not_name_one(self) -> None:
        with pytest.raises(PolicyError, match=r"must be one of \[\] for rail 'fake'"):
            make_document(rail="fake", network="xrpl-testnet")

    def test_it_survives_a_round_trip(self) -> None:
        document = make_document(network="xrpl-mainnet")
        assert PolicyDocument.from_content(document.to_content()).network == "xrpl-mainnet"

    def test_a_document_without_one_round_trips_to_none(self) -> None:
        assert PolicyDocument.from_content(make_document().to_content()).network is None


class TestSourceTag:
    def test_an_absent_source_tag_does_not_change_the_hash(self) -> None:
        assert "source_tag" not in make_document().to_content()["agents"][0]
        assert make_document().policy_hash() == make_document().policy_hash()

    def test_setting_a_source_tag_changes_the_hash(self) -> None:
        from merkl.core.policy.document import AgentSection
        from merkl.core.rail import MERKL_SOURCE_TAG

        base = make_document()
        agent = base.agents[0]
        tagged = make_document(
            agents=(
                AgentSection(
                    agent_id=agent.agent_id,
                    public_key=agent.public_key,
                    allowlist_destinations=agent.allowlist_destinations,
                    allowlist_assets=agent.allowlist_assets,
                    per_tx_cap=agent.per_tx_cap,
                    windows=agent.windows,
                    reference_binding=agent.reference_binding,
                    source_tag=99991234,
                ),
            )
        )
        assert tagged.policy_hash() != base.policy_hash()
        assert tagged.agents[0].effective_source_tag() == 99991234
        assert base.agents[0].effective_source_tag() == MERKL_SOURCE_TAG

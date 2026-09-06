"""The policy document: hashed, signed, and unable to name its own admin."""

from __future__ import annotations

import dataclasses

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
    PolicyChange,
    PolicyDocument,
    PolicyError,
    ReferenceBinding,
    SignedPolicy,
    asset_key,
)
from merkl.core.vectors import fixtures
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

"""Check 8 inside a receipt: leaf 3, the envelope, and a pinned allowlist.

``tests/core/test_attestation.py`` proves the verifier agrees with AWS. This file
proves the *wiring*: that a receipt hands leaf 3 to that verifier with the right
key and the right policy hash, and that every way of getting it wrong is reported
by name rather than passed over.

The documents here are forged by ``tests/nitro_factory.py`` and chain to a root
generated in the test. They have to be: a receipt needs an attestation that
vouches for the key in *its* envelope, and no real AWS document ever will.
Against the package's default anchor — the real AWS root — every one of them
fails at the chain check, which is a property worth having.
"""

from __future__ import annotations

import base64
import datetime

import pytest

from merkl.core.checks import CheckStatus
from merkl.core.receipt import SignerAttestation
from merkl.core.verify.attestation import AttestationTrust
from tests.core.factories import POLICY_HASH, SIGNER_KEY, make_leaves, make_receipt
from tests.nitro_factory import PRODUCTION_PCRS, fake_attestation, fake_pki

CHECK = "signer.attestation"
AT = datetime.datetime(2026, 3, 1, 12, 0, tzinfo=datetime.UTC)
PKI = fake_pki(
    valid_from=AT - datetime.timedelta(hours=1), valid_to=AT + datetime.timedelta(hours=2)
)
PINNED = {index: PRODUCTION_PCRS[index].hex() for index in (0, 1, 2, 8)}


def leaf(**overrides: object) -> SignerAttestation:
    """Leaf 3 vouching for the fixture signer key under the fixture policy."""
    document = fake_attestation(
        PKI,
        at=AT,
        public_key=bytes.fromhex(SIGNER_KEY),
        user_data=bytes.fromhex(POLICY_HASH),
        **overrides,  # type: ignore[arg-type]
    )
    return SignerAttestation(
        document=base64.b64encode(document).decode(), policy_public_key=SIGNER_KEY
    )


def trust(**overrides: object) -> AttestationTrust:
    fields: dict[str, object] = {
        "pcrs": PINNED,
        "root_pem": PKI.root_pem,
        "max_age_seconds": 300,
    }
    fields.update(overrides)
    return AttestationTrust(**fields)  # type: ignore[arg-type]


def verify(attestation: SignerAttestation | None, **kwargs: object) -> object:
    receipt = make_receipt(leaves=make_leaves(signer_attestation=attestation))
    result = receipt.verify_structure(
        attestation_trust=kwargs.pop("attestation_trust", trust()),  # type: ignore[arg-type]
        now=kwargs.pop("now", AT + datetime.timedelta(seconds=10)),  # type: ignore[arg-type]
    )
    return result.get(CHECK)


def test_an_attested_receipt_passes_check_8() -> None:
    check = verify(leaf())
    assert check is not None and check.status is CheckStatus.PASS  # type: ignore[attr-defined]


def test_the_receipt_still_verifies_as_a_whole() -> None:
    receipt = make_receipt(leaves=make_leaves(signer_attestation=leaf()))
    result = receipt.verify_structure(
        attestation_trust=trust(), now=AT + datetime.timedelta(seconds=10)
    )
    assert result.ok, [(c.name, c.detail) for c in result.failures]


def test_check_8_is_no_longer_deferred_to_a_later_phase() -> None:
    from merkl.core.receipt import DEFERRED_CHECKS

    assert CHECK not in {name for name, _ in DEFERRED_CHECKS}


@pytest.mark.parametrize(
    "kwargs,status,fragment",
    [
        ({"attestation_trust": None}, CheckStatus.NOT_IMPLEMENTED, "no PCR allowlist"),
        ({"now": None}, CheckStatus.NOT_IMPLEMENTED, "no PCR allowlist"),
    ],
)
def test_an_unpinned_verifier_says_so(
    kwargs: dict[str, object], status: CheckStatus, fragment: str
) -> None:
    check = verify(leaf(), **kwargs)
    assert check is not None
    assert check.status is status  # type: ignore[attr-defined]
    assert fragment in check.detail  # type: ignore[attr-defined]


def test_a_null_leaf_reports_an_unattested_signer() -> None:
    check = verify(None)
    assert check is not None
    assert check.status is CheckStatus.NOT_IMPLEMENTED  # type: ignore[attr-defined]
    assert "unattested signer" in check.detail  # type: ignore[attr-defined]


def test_the_real_aws_root_refuses_a_forged_document() -> None:
    """The default anchor is the published AWS root, and nothing here chains to it."""
    check = verify(leaf(), attestation_trust=AttestationTrust(pcrs=PINNED))
    assert check is not None
    assert check.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "certificate_chain" in check.detail  # type: ignore[attr-defined]


def test_a_document_vouching_for_another_key_fails() -> None:
    other = bytes(32).hex()
    document = fake_attestation(
        PKI, at=AT, public_key=bytes.fromhex(other), user_data=bytes.fromhex(POLICY_HASH)
    )
    check = verify(
        SignerAttestation(
            document=base64.b64encode(document).decode(), policy_public_key=SIGNER_KEY
        )
    )
    assert check is not None
    assert check.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "attestation.public_key" in check.detail  # type: ignore[attr-defined]


def test_a_document_from_another_policy_fails() -> None:
    document = fake_attestation(
        PKI, at=AT, public_key=bytes.fromhex(SIGNER_KEY), user_data=bytes(32)
    )
    check = verify(
        SignerAttestation(
            document=base64.b64encode(document).decode(), policy_public_key=SIGNER_KEY
        )
    )
    assert check is not None
    assert check.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "attestation.user_data" in check.detail  # type: ignore[attr-defined]


def test_leaf_3_naming_a_key_the_envelope_does_not_is_refused_before_any_crypto() -> None:
    """Cheap and first: leaf 3 has to be about the key the envelope names."""
    check = verify(
        SignerAttestation(
            document=base64.b64encode(b"ignored").decode(), policy_public_key="ab" * 32
        )
    )
    assert check is not None
    assert check.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "the envelope names" in check.detail  # type: ignore[attr-defined]


def test_a_debug_enclave_fails_check_8() -> None:
    document = fake_attestation(
        PKI,
        at=AT,
        public_key=bytes.fromhex(SIGNER_KEY),
        user_data=bytes.fromhex(POLICY_HASH),
        pcrs={index: bytes(48) for index in (0, 1, 2, 8)},
    )
    check = verify(
        SignerAttestation(
            document=base64.b64encode(document).decode(), policy_public_key=SIGNER_KEY
        ),
        attestation_trust=trust(pcrs={index: "00" * 48 for index in (0, 1, 2, 8)}),
    )
    assert check is not None
    assert check.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "debug mode" in check.detail  # type: ignore[attr-defined]


def test_a_document_that_is_not_base64_fails() -> None:
    check = verify(SignerAttestation(document="not-base64", policy_public_key=SIGNER_KEY))
    assert check is not None
    assert check.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "not base64" in check.detail  # type: ignore[attr-defined]


def test_an_unknown_format_is_not_a_pass() -> None:
    check = verify(
        SignerAttestation(
            document=base64.b64encode(b"x").decode(),
            policy_public_key=SIGNER_KEY,
            format="sgx-dcap",
        )
    )
    assert check is not None
    assert check.status is CheckStatus.NOT_IMPLEMENTED  # type: ignore[attr-defined]

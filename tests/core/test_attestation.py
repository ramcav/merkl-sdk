"""Attestation verification, against attestation documents AWS actually signed.

Every fixture here is a real COSE_Sign1 produced by a Nitro Secure Module and
signed by the AWS Nitro Attestation PKI (provenance in
``merkl/core/vectors/attestation/README.md``). None was made by Merkl, which is
the only way this test proves anything: a verifier checked against documents its
own code produced proves that the code agrees with itself.

Every one of them is expired, and that is deliberate. An NSM leaf certificate
lives about three hours. Pinning ``now`` inside a window from 2022 is only
possible because ``merkl.core`` reads no clock, so these tests are also the proof
of that rule.
"""

from __future__ import annotations

import base64
import datetime
import json
from typing import Any

import pytest

from merkl.core.canonical import ContentError
from merkl.core.checks import CheckStatus
from merkl.core.vectors.attestation import (
    ATTESTATION_DIR,
    CASES_FILE,
    DOCUMENTS_FILE,
    ROOT_PEM_FILE,
)
from merkl.core.vectors.attestation import generate as attestation_generate
from merkl.core.verify.attestation import (
    ATTESTATION_CHECKS,
    CHECK_CERT_VALIDITY,
    CHECK_CHAIN,
    CHECK_DEBUG_MODE,
    CHECK_FORMAT,
    CHECK_PCRS,
    CHECK_SIGNATURE,
    CHECK_TIMESTAMP,
    NITRO_ROOT_G1_PEM,
    NITRO_ROOT_G1_SHA256,
    AttestationError,
    AttestationTrust,
    parse_attestation,
    verify_attestation,
)

DOCUMENTS: dict[str, dict[str, Any]] = {
    entry["name"]: entry
    for entry in json.loads(DOCUMENTS_FILE.read_text(encoding="utf-8"))["documents"]
}
CASES: list[dict[str, Any]] = json.loads(CASES_FILE.read_text(encoding="utf-8"))["cases"]

PRODUCTION = DOCUMENTS["production"]
PRODUCTION_RAW = base64.b64decode(PRODUCTION["document_b64"])
PRODUCED_AT = datetime.datetime.fromtimestamp(
    PRODUCTION["observed"]["timestamp_ms"] / 1000, datetime.UTC
)
PINNED = {int(i): v for i, v in PRODUCTION["observed"]["pcrs"].items() if int(i) in (0, 1, 2, 8)}


# --------------------------------------------------------------------------- #
# The trust anchor
# --------------------------------------------------------------------------- #


def test_the_embedded_root_is_the_published_certificate() -> None:
    """The PEM in the code and the PEM in the fixtures are the same bytes.

    If they ever differ, one of them was edited, and the one in the code is the
    one every verifier uses.
    """
    assert ROOT_PEM_FILE.read_text(encoding="utf-8") == NITRO_ROOT_G1_PEM


def test_the_embedded_root_has_the_documented_fingerprint() -> None:
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    root = x509.load_pem_x509_certificate(NITRO_ROOT_G1_PEM.encode())
    der = root.public_bytes(serialization.Encoding.DER)
    assert hashlib.sha256(der).hexdigest() == NITRO_ROOT_G1_SHA256
    assert root.subject.rfc4514_string() == "CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US"


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_every_real_document_parses(name: str) -> None:
    entry = DOCUMENTS[name]
    parsed = parse_attestation(base64.b64decode(entry["document_b64"]))
    observed = entry["observed"]
    assert parsed.module_id == observed["module_id"]
    assert parsed.timestamp_ms == observed["timestamp_ms"]
    assert parsed.digest == "SHA384"
    assert parsed.pcr_hex() == observed["pcrs"]
    assert parsed.debug_mode is observed["debug_mode"]
    assert len(parsed.cabundle) + 1 == observed["chain_length"]
    assert len(parsed.signature) == 96


def test_a_debug_document_reports_debug_mode() -> None:
    parsed = parse_attestation(base64.b64decode(DOCUMENTS["debug-with-bindings"]["document_b64"]))
    assert parsed.debug_mode is True
    assert parsed.pcrs[0] == bytes(48)


def test_a_production_document_does_not() -> None:
    assert parse_attestation(PRODUCTION_RAW).debug_mode is False


@pytest.mark.parametrize(
    "raw,match",
    [
        (b"", "not CBOR"),
        (b"\x00", "four-element"),
        (b"\x84\x40\xa0\x41\x00\x40", "not a CBOR map"),
    ],
)
def test_malformed_documents_raise(raw: bytes, match: str) -> None:
    with pytest.raises(AttestationError, match=match):
        parse_attestation(raw)


def test_the_sig_structure_is_rebuilt_not_sliced() -> None:
    """RFC 9052 4.4. The bytes signed are ["Signature1", protected, b"", payload]."""
    from merkl.core.verify import cbor

    parsed = parse_attestation(PRODUCTION_RAW)
    rebuilt = cbor.loads(parsed.sig_structure())
    assert rebuilt == ["Signature1", parsed.protected, b"", parsed.payload]


# --------------------------------------------------------------------------- #
# The reference verification: a real document, fully pinned
# --------------------------------------------------------------------------- #


def test_a_real_production_document_verifies_completely() -> None:
    """The load-bearing test. Real bytes, the published AWS root, real PCRs, a
    ``now`` inside the leaf certificate's three-hour window."""
    result = verify_attestation(
        PRODUCTION_RAW,
        trust=AttestationTrust(pcrs=PINNED),
        now=PRODUCED_AT + datetime.timedelta(seconds=30),
    )
    for name in (
        CHECK_FORMAT,
        CHECK_CHAIN,
        CHECK_CERT_VALIDITY,
        CHECK_SIGNATURE,
        CHECK_TIMESTAMP,
        CHECK_PCRS,
        CHECK_DEBUG_MODE,
    ):
        check = result.get(name)
        assert check is not None and check.status is CheckStatus.PASS, (name, check)
    assert result.ok


def test_the_chain_reaches_the_root_through_four_certificates() -> None:
    chain = result_detail(CHECK_CHAIN)
    assert "certificates from the pinned AWS Nitro root" in chain


def result_detail(name: str) -> str:
    result = verify_attestation(
        PRODUCTION_RAW,
        trust=AttestationTrust(pcrs=PINNED),
        now=PRODUCED_AT + datetime.timedelta(seconds=30),
    )
    check = result.get(name)
    assert check is not None
    return check.detail


def test_certificate_validity_is_measured_at_the_document_timestamp() -> None:
    """Not at ``now``. A receipt is read years after its enclave stopped, and the
    NSM certificate that signed it expired hours later."""
    result = verify_attestation(
        PRODUCTION_RAW,
        trust=AttestationTrust(pcrs=PINNED, max_age_seconds=None),
        now=datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC),
    )
    validity = result.get(CHECK_CERT_VALIDITY)
    assert validity is not None and validity.status is CheckStatus.PASS
    assert result.ok


def test_now_must_carry_a_timezone() -> None:
    with pytest.raises(AttestationError, match="timezone-aware"):
        verify_attestation(
            PRODUCTION_RAW, trust=AttestationTrust(), now=datetime.datetime(2022, 10, 13)
        )


# --------------------------------------------------------------------------- #
# Tamper and absence
# --------------------------------------------------------------------------- #


def test_an_empty_allowlist_is_not_a_pass() -> None:
    result = verify_attestation(
        PRODUCTION_RAW,
        trust=AttestationTrust(max_age_seconds=None),
        now=PRODUCED_AT,
    )
    pcrs = result.get(CHECK_PCRS)
    assert pcrs is not None and pcrs.status is CheckStatus.NOT_IMPLEMENTED
    assert result.ok and not result.complete


def test_a_flipped_signature_byte_fails_only_the_signature() -> None:
    mutated = bytearray(PRODUCTION_RAW)
    mutated[-1] ^= 0x01
    result = verify_attestation(
        bytes(mutated),
        trust=AttestationTrust(pcrs=PINNED),
        now=PRODUCED_AT + datetime.timedelta(seconds=30),
    )
    assert [c.name for c in result.failures] == [CHECK_SIGNATURE]


def test_editing_a_pcr_breaks_the_signature_too() -> None:
    """PCRs live inside the bytes AWS signed. There is no quiet edit."""
    parsed = parse_attestation(PRODUCTION_RAW)
    at = PRODUCTION_RAW.find(parsed.pcrs[0])
    mutated = bytearray(PRODUCTION_RAW)
    mutated[at] ^= 0x01
    result = verify_attestation(
        bytes(mutated),
        trust=AttestationTrust(pcrs=PINNED),
        now=PRODUCED_AT + datetime.timedelta(seconds=30),
    )
    assert {c.name for c in result.failures} == {CHECK_PCRS, CHECK_SIGNATURE}


def test_a_document_that_does_not_reach_the_pinned_root_is_refused() -> None:
    other = (ATTESTATION_DIR / "not-the-aws-root.pem").read_text(encoding="utf-8")
    result = verify_attestation(
        PRODUCTION_RAW,
        trust=AttestationTrust(pcrs=PINNED, root_pem=other),
        now=PRODUCED_AT + datetime.timedelta(seconds=30),
    )
    chain = result.get(CHECK_CHAIN)
    assert chain is not None and chain.status is CheckStatus.FAIL
    assert "does not start at the pinned AWS Nitro root" in chain.detail


def test_a_tampered_embedded_root_is_noticed() -> None:
    """The fingerprint is checked whenever the default anchor is in use."""
    edited = NITRO_ROOT_G1_PEM.replace("MIICETCCAZagAwIBAgIRAPkx", "MIICETCCAZagAwIBAgIRAPky")
    result = verify_attestation(
        PRODUCTION_RAW, trust=AttestationTrust(root_pem=edited), now=PRODUCED_AT
    )
    chain = result.get(CHECK_CHAIN)
    assert chain is not None and chain.status is CheckStatus.FAIL


def test_a_stale_document_fails_freshness_and_nothing_else() -> None:
    result = verify_attestation(
        PRODUCTION_RAW,
        trust=AttestationTrust(pcrs=PINNED, max_age_seconds=300),
        now=PRODUCED_AT + datetime.timedelta(hours=1),
    )
    assert [c.name for c in result.failures] == [CHECK_TIMESTAMP]


def test_a_debug_enclave_is_refused_by_default() -> None:
    entry = DOCUMENTS["debug-with-bindings"]
    raw = base64.b64decode(entry["document_b64"])
    at = datetime.datetime.fromtimestamp(entry["observed"]["timestamp_ms"] / 1000, datetime.UTC)
    result = verify_attestation(
        raw, trust=AttestationTrust(pcrs={0: "00" * 48}), now=at + datetime.timedelta(seconds=5)
    )
    debug = result.get(CHECK_DEBUG_MODE)
    assert debug is not None and debug.status is CheckStatus.FAIL
    signature = result.get(CHECK_SIGNATURE)
    assert signature is not None and signature.status is CheckStatus.PASS


def test_the_receipt_bindings_hold_against_real_attested_values() -> None:
    entry = DOCUMENTS["debug-with-bindings"]
    raw = base64.b64decode(entry["document_b64"])
    at = datetime.datetime.fromtimestamp(entry["observed"]["timestamp_ms"] / 1000, datetime.UTC)
    trust = AttestationTrust(pcrs={0: "00" * 48}, require_production_mode=False)
    key = bytes.fromhex(entry["observed"]["public_key_hex"])
    user_data = bytes.fromhex(entry["observed"]["user_data_hex"])

    matched = verify_attestation(
        raw, trust=trust, now=at, expected_public_key=key, expected_user_data=user_data
    )
    assert matched.ok

    wrong = verify_attestation(
        raw, trust=trust, now=at, expected_public_key=bytes(32), expected_user_data=user_data
    )
    assert [c.name for c in wrong.failures] == ["attestation.public_key"]


def test_an_unasked_binding_is_reported_by_name() -> None:
    result = verify_attestation(
        PRODUCTION_RAW, trust=AttestationTrust(pcrs=PINNED, max_age_seconds=None), now=PRODUCED_AT
    )
    for name in ("attestation.public_key", "attestation.user_data"):
        check = result.get(name)
        assert check is not None and check.status is CheckStatus.NOT_IMPLEMENTED


def test_an_unparseable_document_still_reports_every_check_by_name() -> None:
    result = verify_attestation(b"nope", trust=AttestationTrust(pcrs=PINNED), now=PRODUCED_AT)
    assert [c.name for c in result.checks] == list(ATTESTATION_CHECKS)
    assert not result.ok


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"pcrs": {99: "00" * 48}}, "out of range"),
        ({"pcrs": {0: "AB" * 48}}, "lowercase hex"),
        ({"pcrs": {0: "00" * 20}}, "lowercase hex"),
        ({"max_age_seconds": 0}, "must be positive"),
        ({"root_pem": "not a certificate"}, None),
    ],
)
def test_a_nonsense_trust_anchor_is_refused_at_construction(
    kwargs: dict[str, Any], match: str | None
) -> None:
    if match is None:
        trust = AttestationTrust(**kwargs)
        with pytest.raises(ContentError):
            trust.root()
        return
    with pytest.raises(AttestationError, match=match):
        AttestationTrust(**kwargs)


# --------------------------------------------------------------------------- #
# The committed vectors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_committed_case_reproduces(case: dict[str, Any]) -> None:
    """The contract with ``@merkl-ai/verify``: same bytes in, same statuses out."""
    root_pem = (ATTESTATION_DIR / case["trust"]["root_pem_file"]).read_text(encoding="utf-8")
    trust = AttestationTrust(
        pcrs={int(i): v for i, v in case["trust"]["pcrs"].items()},
        root_pem=root_pem,
        max_age_seconds=case["trust"]["max_age_seconds"],
        require_production_mode=case["trust"]["require_production_mode"],
    )
    expected_key = case["expected_public_key_hex"]
    expected_user_data = case["expected_user_data_hex"]
    result = verify_attestation(
        base64.b64decode(case["document_b64"]),
        trust=trust,
        now=datetime.datetime.fromisoformat(case["now"].replace("Z", "+00:00")),
        expected_public_key=bytes.fromhex(expected_key) if expected_key else None,
        expected_user_data=bytes.fromhex(expected_user_data) if expected_user_data else None,
    )
    assert {c.name: c.status.value for c in result.checks} == case["expect"]["checks"]
    assert result.ok is case["expect"]["ok"]
    assert result.complete is case["expect"]["complete"]


def test_the_committed_vectors_are_current() -> None:
    assert attestation_generate.check(), (
        "regenerate with: python -m merkl.core.vectors.attestation.generate"
    )


def test_the_vectors_cover_every_check_passing_and_failing() -> None:
    """A vector set where some check never fails is a vector set that does not test it."""
    seen: dict[str, set[str]] = {name: set() for name in ATTESTATION_CHECKS}
    for case in CASES:
        for name, status in case["expect"]["checks"].items():
            seen[name].add(status)
    for name, statuses in seen.items():
        assert "pass" in statuses, f"no case shows {name} passing"
        assert "fail" in statuses, f"no case shows {name} failing"

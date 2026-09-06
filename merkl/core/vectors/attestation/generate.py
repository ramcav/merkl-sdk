"""Build ``cases.json`` from the real documents in ``documents.json``.

Every case names a document, a pinned ``now``, what the verifier trusted, and the
status each check must report. Tamper cases carry their own bytes so a second
implementation never has to reproduce a mutation — it reads bytes and checks
statuses, which is the whole contract.

Two of the tamper cases are worth reading twice, because they say something about
the format rather than about the code:

* ``chain-does-not-reach-the-pinned-root`` keeps the document intact and changes
  the *verifier's* anchor. The signature still verifies — a document is always
  self-consistent — and the chain check is what refuses it. That is the attack a
  pinned root exists to stop: a real COSE_Sign1 from a PKI nobody vouched for.
* ``pcr0-flipped-in-the-payload`` flips one byte of PCR0 inside the signed
  payload. Both the PCR check and the signature check fail, and they must: PCRs
  live inside the bytes AWS signed, so editing them is not something an attacker
  can do quietly. The case exists to prove the verifier notices both.

Run ``--check`` in CI: a stale ``cases.json`` means the fixtures and the verifier
have drifted apart.
"""

from __future__ import annotations

import base64
import datetime
import json
import pathlib
import sys
from typing import Any, Final

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.vectors.attestation import (
    CASES_FILE,
    DOCUMENTS_FILE,
    OTHER_ROOT_PEM_FILE,
)
from merkl.core.verify.attestation import (
    ATTESTATION_CHECKS,
    AttestationTrust,
    parse_attestation,
    verify_attestation,
)

SPEC: Final = "docs/ATTESTATION-VERIFY.md"
PINNED_PCRS: Final[tuple[int, ...]] = (0, 1, 2, 8)
"""What an operator pins: the image, the kernel and bootstrap, the application,
and the certificate a signed image was signed with."""


def _documents() -> dict[str, dict[str, Any]]:
    body = json.loads(DOCUMENTS_FILE.read_text(encoding="utf-8"))
    return {entry["name"]: entry for entry in body["documents"]}


def _raw(entry: dict[str, Any]) -> bytes:
    return base64.b64decode(entry["document_b64"])


def _at(entry: dict[str, Any], *, offset_seconds: float = 0.0) -> datetime.datetime:
    """A ``now`` relative to the moment the document was produced."""
    produced = datetime.datetime.fromtimestamp(
        entry["observed"]["timestamp_ms"] / 1000, datetime.UTC
    )
    return produced + datetime.timedelta(seconds=offset_seconds)


def _flip(raw: bytes, index: int) -> bytes:
    mutated = bytearray(raw)
    mutated[index] ^= 0x01
    return bytes(mutated)


def _flip_pcr0(raw: bytes) -> bytes:
    """Flip one byte of PCR0 where it sits inside the signed payload."""
    pcr0 = parse_attestation(raw).pcrs[0]
    at = raw.find(pcr0)
    if at < 0:  # pragma: no cover - the measurement is always in the payload
        raise AssertionError("PCR0 is not present verbatim in the document")
    return _flip(raw, at + 7)


def _move_timestamp(raw: bytes, *, forward_days: int) -> bytes:
    """Rewrite the document's own timestamp, in place, keeping the CBOR width.

    The NSM encodes the timestamp as a 64-bit unsigned integer (``0x1b`` and
    eight bytes), so a later value fits exactly where the original sat and the
    document stays the same length. Everything else is untouched.
    """
    parsed = parse_attestation(raw)
    original = b"\x1b" + parsed.timestamp_ms.to_bytes(8, "big")
    at = raw.find(original)
    if at < 0:  # pragma: no cover - the NSM always uses the 64-bit form
        raise AssertionError("the timestamp is not encoded as a 64-bit integer")
    moved = parsed.timestamp_ms + forward_days * 86_400_000
    return raw[:at] + b"\x1b" + moved.to_bytes(8, "big") + raw[at + 9 :]


def _case(
    name: str,
    description: str,
    *,
    raw: bytes,
    now: datetime.datetime,
    trust: AttestationTrust,
    expected_public_key: bytes | None = None,
    expected_user_data: bytes | None = None,
    root_file: str | None = None,
) -> JSONObject:
    """Run the verifier and record what it said. The fixture is the answer."""
    result = verify_attestation(
        raw,
        trust=trust,
        now=now,
        expected_public_key=expected_public_key,
        expected_user_data=expected_user_data,
    )
    statuses: dict[str, JSONValue] = {c.name: c.status.value for c in result.checks}
    missing = [n for n in ATTESTATION_CHECKS if n not in statuses]
    if missing:  # pragma: no cover - a check silently disappearing is a bug
        raise AssertionError(f"{name} did not report {missing}")
    return {
        "name": name,
        "description": description,
        "document_b64": base64.b64encode(raw).decode(),
        "now": now.isoformat().replace("+00:00", "Z"),
        "trust": {
            "pcrs": dict[str, JSONValue](
                {str(i): v for i, v in sorted(trust.pcrs.items())}
            ),
            "root_pem_file": root_file or "aws-nitro-root-g1.pem",
            "max_age_seconds": trust.max_age_seconds,
            "require_production_mode": trust.require_production_mode,
        },
        "expected_public_key_hex": expected_public_key.hex() if expected_public_key else None,
        "expected_user_data_hex": expected_user_data.hex() if expected_user_data else None,
        "expect": {
            "ok": result.ok,
            "complete": result.complete,
            "checks": statuses,
        },
    }


def build_cases() -> JSONObject:
    documents = _documents()
    production = documents["production"]
    bound = documents["debug-with-bindings"]
    later = documents["debug-2023"]

    production_raw = _raw(production)
    bound_raw = _raw(bound)
    later_raw = _raw(later)

    pinned = {
        int(i): production["observed"]["pcrs"][str(i)]
        for i in PINNED_PCRS
        if str(i) in production["observed"]["pcrs"]
    }
    wrong = dict(pinned) | {0: "00" * 48}
    bound_key = bytes.fromhex(bound["observed"]["public_key_hex"])
    bound_user_data = bytes.fromhex(bound["observed"]["user_data_hex"])
    other_root = OTHER_ROOT_PEM_FILE.read_text(encoding="utf-8")

    cases: list[JSONObject] = [
        _case(
            "production-enclave-fully-pinned",
            "The reference case: a production-mode document, the pinned AWS root, PCR0/1/2/8 "
            "from this very enclave, and a now inside the leaf certificate's window. Every "
            "check that has inputs passes; the two receipt bindings report not_implemented "
            "because this document carries no public_key or user_data.",
            raw=production_raw,
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "production-enclave-no-freshness-bound",
            "The same document checked years later, the way a receipt is read. max_age_seconds "
            "is None, so freshness is not asked; certificate validity is still measured against "
            "the moment the document was produced, which is why an old receipt still verifies.",
            raw=production_raw,
            now=datetime.datetime(2026, 9, 6, tzinfo=datetime.UTC),
            trust=AttestationTrust(pcrs=pinned, max_age_seconds=None),
        ),
        _case(
            "no-pcr-allowlist-is-not-a-pass",
            "Nothing pinned. The document is genuine and every cryptographic check passes, and "
            "the PCR check still reports not_implemented: a document nobody compared to an "
            "expected measurement proves only that some enclave produced it.",
            raw=production_raw,
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(max_age_seconds=None),
        ),
        _case(
            "pcr0-does-not-match-the-allowlist",
            "The document is untouched; the operator pinned a different image. This is the "
            "everyday failure: someone deployed an enclave nobody approved.",
            raw=production_raw,
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=wrong),
        ),
        _case(
            "chain-does-not-reach-the-pinned-root",
            "A real, unmodified, correctly signed document verified against a root that is not "
            "the AWS Nitro root. The signature still verifies — every document is "
            "self-consistent — and the chain check refuses it anyway.",
            raw=production_raw,
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=pinned, root_pem=other_root),
            root_file="not-the-aws-root.pem",
        ),
        _case(
            "document-is-older-than-the-freshness-bound",
            "One hour after the document was produced, with a five-minute bound. The chain and "
            "the signature are untouched; only freshness fails, because an attestation is a "
            "statement about a moment and this moment has passed.",
            raw=production_raw,
            now=_at(production, offset_seconds=3600),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "now-is-before-the-document-was-produced",
            "A verifier whose clock is behind, or a document from the future. Either way the "
            "age is negative and that is reported rather than rounded to zero.",
            raw=production_raw,
            now=_at(production, offset_seconds=-60),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "signature-byte-flipped",
            "One bit of the ES384 signature flipped. Everything structural still passes and the "
            "signature check fails, which is the only check that can notice.",
            raw=_flip(production_raw, len(production_raw) - 1),
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "pcr0-flipped-in-the-payload",
            "One byte of PCR0 edited inside the signed payload. Two checks fail together: the "
            "measurement no longer matches the allowlist, and the signature no longer covers "
            "the bytes. PCRs live inside what AWS signed, so they cannot be edited quietly.",
            raw=_flip_pcr0(production_raw),
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "timestamp-moved-past-the-certificate-window",
            "The document's own timestamp rewritten a year forward — the trick that would "
            "make a stale attestation look current. The NSM leaf certificate lives about "
            "three hours, so the chain was no longer valid at the moment now claimed, and "
            "the signature no longer covers the payload either.",
            raw=_move_timestamp(production_raw, forward_days=365),
            now=_at(production, offset_seconds=365 * 86_400 + 30),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "truncated-document",
            "The last thirty-two bytes cut off. There is no document to reason about, so the "
            "format check fails and every other check reports not_implemented by name rather "
            "than being silently dropped.",
            raw=production_raw[:-32],
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "not-cbor-at-all",
            "Arbitrary bytes where a document should be.",
            raw=b"this is not an attestation document",
            now=_at(production, offset_seconds=30),
            trust=AttestationTrust(pcrs=pinned),
        ),
        _case(
            "debug-enclave-is-refused",
            "A debug-mode enclave reports PCR0 as forty-eight zero bytes. Its document is "
            "genuine and its signature verifies; the measurements mean nothing because the "
            "image was never measured and the parent could read the enclave's memory.",
            raw=bound_raw,
            now=_at(bound, offset_seconds=30),
            trust=AttestationTrust(pcrs={0: "00" * 48}),
            expected_public_key=bound_key,
            expected_user_data=bound_user_data,
        ),
        _case(
            "debug-enclave-bindings-match",
            "The same debug document with require_production_mode off, so the two receipt "
            "bindings can be seen passing against bytes AWS actually signed: the attested "
            "public_key and user_data are exactly what the caller expected.",
            raw=bound_raw,
            now=_at(bound, offset_seconds=30),
            trust=AttestationTrust(
                pcrs={0: "00" * 48}, require_production_mode=False
            ),
            expected_public_key=bound_key,
            expected_user_data=bound_user_data,
        ),
        _case(
            "attested-key-is-not-the-receipts-key",
            "The document vouches for a key, and it is not the key the receipt was signed "
            "with. Without this check an attacker could staple any genuine attestation to any "
            "receipt.",
            raw=bound_raw,
            now=_at(bound, offset_seconds=30),
            trust=AttestationTrust(
                pcrs={0: "00" * 48}, require_production_mode=False
            ),
            expected_public_key=bytes(32),
            expected_user_data=bound_user_data,
        ),
        _case(
            "attested-user-data-is-not-the-policy-hash",
            "The enclave was running under a different policy than the receipt claims.",
            raw=bound_raw,
            now=_at(bound, offset_seconds=30),
            trust=AttestationTrust(
                pcrs={0: "00" * 48}, require_production_mode=False
            ),
            expected_public_key=bound_key,
            expected_user_data=bytes(32),
        ),
        _case(
            "second-chain-verifies-too",
            "A document from eleven months later, signed under a different set of "
            "intermediates. It is here so a verifier cannot pass by hard-coding one chain.",
            raw=later_raw,
            now=_at(later, offset_seconds=30),
            trust=AttestationTrust(
                pcrs={0: "00" * 48}, require_production_mode=False
            ),
        ),
    ]

    return {
        "description": (
            "Verification cases over real AWS Nitro attestation documents. Each case gives the "
            "document, the moment to pin, what the verifier trusted, and the status every "
            "named check must report. A second implementation passes when it reproduces every "
            "status, not when it reaches the same boolean."
        ),
        "spec": SPEC,
        "generator": "python -m merkl.core.vectors.attestation.generate",
        "checks": list(ATTESTATION_CHECKS),
        "cases": list[JSONValue](cases),
    }


def _serialize(content: JSONObject) -> str:
    return json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(path: pathlib.Path = CASES_FILE) -> pathlib.Path:
    path.write_text(_serialize(build_cases()), encoding="utf-8")
    return path


def check(path: pathlib.Path = CASES_FILE) -> bool:
    """True when the committed file matches a fresh generation."""
    return path.exists() and path.read_text(encoding="utf-8") == _serialize(build_cases())


def main(argv: list[str]) -> int:
    if "--check" in argv:
        if not check():
            print(f"stale: {CASES_FILE.name}", file=sys.stderr)
            print(
                "regenerate with: python -m merkl.core.vectors.attestation.generate",
                file=sys.stderr,
            )
            return 1
        print("attestation vectors are up to date")
        return 0
    print(f"wrote {write()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

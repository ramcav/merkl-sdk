"""A ``SignerPort`` client for the Nitro parent proxy.

It is a subclass of :class:`~merkl.adapters.signer_dev.client.DevSignerClient`
and adds no RPC method, which is the strongest thing this file can say. The
parent proxy speaks the contract in ``docs/SIGNER-RPC.md`` verbatim — it turns
each HTTP request into a vsock frame and each frame back into a response — so
swapping a dev signer for an attested one is a constructor change and nothing
else. If this class had needed to override ``propose``, phase 3 would have been a
protocol change wearing a deployment change's clothes.

What it does add is the question a caller of an *attested* signer should be
asking and would otherwise have to remember to ask: is the thing on the other end
of this socket actually an enclave I approved?

``attestation_report()`` answers it. It fetches the signer's public key and its
attestation document, and verifies the document against a PCR allowlist the
**caller** pinned, checking that the key the document vouches for is the key the
signer just claimed. ``assert_attested()`` is the same thing with a refusal at
the end, for callers who would rather not start than start unattested.

Neither is called automatically. A client that verified on every request would
either cache the answer — and then it is not really verifying — or add a network
round trip to every payment. Attestation is a thing you check when you decide to
trust a signer, and again when you want to know it is still the same one; the
receipt carries its own document for anyone checking later, and
``merkl.core.verify.attestation`` is what they run.
"""

from __future__ import annotations

import base64
import datetime
from typing import Final

from merkl.adapters.signer_dev.client import DevSignerClient
from merkl.core.checks import Check, CheckStatus, VerificationResult
from merkl.core.verify.attestation import (
    ATTESTATION_FORMATS,
    AttestationError,
    AttestationTrust,
    verify_attestation,
)
from merkl.shared.errors import MerklError

CHECK_PRESENT: Final = "signer.attested"
CHECK_KEY_AGREES: Final = "signer.attested_key_agrees"


class UnattestedSignerError(MerklError):
    """The signer on the other end is not the enclave the caller pinned."""

    error_code = "signer_error"


class NitroSignerClient(DevSignerClient):
    """The dev signer's client, pointed at the parent proxy, plus attestation.

    ``base_url`` is the parent's loopback address, or ``socket_path`` its Unix
    socket. The vsock hop is on the far side of the proxy and invisible here,
    which is the point: the SDK never learns that a hypervisor is involved.
    """

    async def attestation_report(
        self,
        *,
        trust: AttestationTrust,
        now: datetime.datetime,
        policy_hash: str | None = None,
    ) -> VerificationResult:
        """Verify the live signer's attestation against what the caller pinned.

        ``policy_hash`` is optional and checking it is the difference between
        "an approved enclave is running" and "an approved enclave is running the
        policy I think it is". Leave it out and that binding reports
        ``not_implemented`` by name rather than passing.
        """
        public_key = await self.public_key()
        document = await self.attestation()
        checks: list[Check] = []

        if document is None:
            return VerificationResult(
                (
                    Check(
                        CHECK_PRESENT,
                        CheckStatus.FAIL,
                        "the signer reports no attestation: it is a dev signer, and no "
                        "enclave vouches for its key",
                    ),
                )
            )
        if not isinstance(document, dict):
            return VerificationResult(
                (Check(CHECK_PRESENT, CheckStatus.FAIL, "the attestation is not an object"),)
            )

        document_format = str(document.get("format", ""))
        if document_format not in ATTESTATION_FORMATS:
            return VerificationResult(
                (
                    Check(
                        CHECK_PRESENT,
                        CheckStatus.FAIL,
                        f"this client knows {sorted(ATTESTATION_FORMATS)}, the signer says "
                        f"{document_format!r}",
                    ),
                )
            )
        checks.append(Check(CHECK_PRESENT, CheckStatus.PASS, f"format {document_format}"))

        attested_key = str(document.get("policy_public_key", ""))
        agrees = attested_key == public_key
        checks.append(
            Check(
                CHECK_KEY_AGREES,
                CheckStatus.PASS if agrees else CheckStatus.FAIL,
                (
                    "the attestation is about the key this signer just handed over"
                    if agrees
                    else f"the signer's key is {public_key[:16]}…, the attestation names "
                    f"{attested_key[:16]}…"
                ),
            )
        )

        try:
            raw = base64.b64decode(str(document.get("document", "")), validate=True)
        except (ValueError, TypeError):
            checks.append(
                Check(CHECK_PRESENT, CheckStatus.FAIL, "the document is not base64")
            )
            return VerificationResult(tuple(checks))

        try:
            expected_key = bytes.fromhex(public_key)
        except ValueError:
            checks.append(
                Check(CHECK_KEY_AGREES, CheckStatus.FAIL, "the signer's public key is not hex")
            )
            return VerificationResult(tuple(checks))

        try:
            result = verify_attestation(
                raw,
                trust=trust,
                now=now,
                expected_public_key=expected_key,
                expected_user_data=bytes.fromhex(policy_hash) if policy_hash else None,
            )
        except (AttestationError, ValueError) as exc:
            checks.append(Check(CHECK_PRESENT, CheckStatus.FAIL, str(exc)))
            return VerificationResult(tuple(checks))
        return VerificationResult((*checks, *result.checks))

    async def assert_attested(
        self,
        *,
        trust: AttestationTrust,
        now: datetime.datetime,
        policy_hash: str | None = None,
    ) -> VerificationResult:
        """Verify, and raise if anything was contradicted.

        Deferred checks do not raise — a caller who pinned no allowlist gets a
        result saying so, not an exception. Only a *failure* is a refusal, and
        the message names every check that failed rather than the first one.
        """
        result = await self.attestation_report(trust=trust, now=now, policy_hash=policy_hash)
        if result.failures:
            detail = "; ".join(f"{c.name}: {c.detail}" for c in result.failures)
            raise UnattestedSignerError(f"refusing to use this signer — {detail}")
        return result

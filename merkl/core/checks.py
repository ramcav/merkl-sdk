"""One vocabulary for "what did the verifier actually check?".

Extracted from :mod:`merkl.core.receipt` in phase 3, when a second verifier —
the attestation one in :mod:`merkl.core.verify.attestation` — needed to report
per-check results too. Two dataclasses named ``Check`` would have been two
answers to the same question, so there is one, here, and ``receipt`` re-exports
it for every caller that already imported it from there.

The three statuses are the whole design. ``NOT_IMPLEMENTED`` is not a pass, and
it covers two distinct honest answers: a check this phase has not written, and a
check whose *inputs are absent* from the material it was handed. A receipt with
no attestation, or a verifier handed no PCR allowlist, learns nothing about the
enclave either way — and the absence of data is never reported as agreement.
"""

from __future__ import annotations

import dataclasses
import enum

from merkl.core.canonical import JSONObject

__all__ = [
    "Check",
    "CheckStatus",
    "VerificationResult",
    "no_data",
    "outcome",
]


class CheckStatus(enum.StrEnum):
    """Outcome of one verification check.

    ``NOT_IMPLEMENTED`` is not a pass. A verifier that cannot yet run a check says
    so out loud — never a single verdict that hides which half was checked
    (plan D10).
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_IMPLEMENTED = "not_implemented"


@dataclasses.dataclass(frozen=True)
class Check:
    """One named check and what it found."""

    name: str
    status: CheckStatus
    detail: str = ""

    def to_content(self) -> JSONObject:
        return {"name": self.name, "status": self.status.value}


@dataclasses.dataclass(frozen=True)
class VerificationResult:
    """Every check, in the order the spec runs them.

    ``ok`` means nothing was contradicted. ``complete`` means every check in the
    list actually ran. Both lines are reported; neither alone is a verdict.
    """

    checks: tuple[Check, ...]

    @property
    def ok(self) -> bool:
        """True when no check failed."""
        return not self.failures

    @property
    def complete(self) -> bool:
        """True when every check ran, i.e. none is deferred to a later phase."""
        return not self.deferred

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.FAIL)

    @property
    def deferred(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.NOT_IMPLEMENTED)

    def get(self, name: str) -> Check | None:
        """The check with this name, or None."""
        for check in self.checks:
            if check.name == name:
                return check
        return None

    def to_content(self) -> JSONObject:
        """Plain JSON: the verdict lines plus every check name and status."""
        return {
            "ok": self.ok,
            "complete": self.complete,
            "checks": [c.to_content() for c in self.checks],
        }


def no_data(name: str, detail: str) -> Check:
    """A check that could not run because its inputs are not there.

    Not a pass. The spec's rule holds: a verifier says what it did not check.
    """
    return Check(name=name, status=CheckStatus.NOT_IMPLEMENTED, detail=detail)


def outcome(name: str, passed: bool, detail: str = "") -> Check:
    """A check that ran: ``PASS`` or ``FAIL``, never anything in between."""
    return Check(name=name, status=CheckStatus.PASS if passed else CheckStatus.FAIL, detail=detail)

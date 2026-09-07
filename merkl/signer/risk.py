"""Destination risk, scored by the signer and never by the agent.

The agent is the party that might be compromised, so it does not get to tell the
signer how risky its own destination is. The signer calls this itself, inside the
decision (plan section 4, ``RiskPort``).

``StaticRiskScorer`` is what a dev signer uses: an explicit blocklist scores 1,
everything else scores 0. It is deliberately not clever. A real scorer is a
network call to a screening provider, which belongs behind the same interface and
outside the pure decision path — the *score* enters the decision, the lookup does
not.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable

from merkl.core.policy.engine import RiskScore


@dataclasses.dataclass(frozen=True)
class StaticRiskScorer:
    """A blocklist. Scores 1 for anything on it, 0 for everything else."""

    blocklist: frozenset[str] = frozenset()
    source: str = "static"

    @classmethod
    def of(cls, addresses: Iterable[str], *, source: str = "static") -> StaticRiskScorer:
        return cls(blocklist=frozenset(addresses), source=source)

    def __call__(self, destination: str) -> RiskScore:
        blocked = destination in self.blocklist
        return RiskScore(value="1" if blocked else "0", source=self.source)

    async def score(self, destination: str) -> RiskScore:
        """The async :class:`~merkl.core.ports.RiskPort` face of the same table."""
        return self(destination)

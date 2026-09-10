"""The notary edge — everything that talks to merkl-api over HTTP.

Three things live here, and none of them is on the decision path:

``client.py``    ``HttpNotary``: files a receipt and its settlement capture,
                 afterwards, at the payer's own risk (plan D12).
``enrol.py``     ``EnrolClient``: the two calls ``merkl treasury init`` makes so
                 a signer the customer just created shows up in their dashboard.
``follower.py``  ``NotaryFollower``: how a self-hosted signer gets its policy and
                 its approvals without anything being pushed at it.

The direction of travel is the point. A self-hosted signer is on somebody else's
laptop behind somebody else's NAT, and Merkl has no route to it — so the signer
pulls, and everything it pulls it verifies itself: a policy against the admin
credential it has pinned, an approval against the approvers that policy names.
Nothing here is trusted, and nothing here holds a fund-moving key.
"""

from merkl.adapters.notary.client import DEFAULT_TIMEOUT_SECONDS, HttpNotary, NotaryError
from merkl.adapters.notary.enrol import (
    ENROLMENT_TOKEN_PREFIX,
    SIGNER_TOKEN_PREFIX,
    AgentRecord,
    EnrolClient,
    Enrolment,
    NotaryEnrolError,
    NotaryRecord,
)
from merkl.adapters.notary.follower import NotaryFollower

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "ENROLMENT_TOKEN_PREFIX",
    "SIGNER_TOKEN_PREFIX",
    "AgentRecord",
    "EnrolClient",
    "Enrolment",
    "HttpNotary",
    "NotaryEnrolError",
    "NotaryFollower",
    "NotaryError",
    "NotaryRecord",
]

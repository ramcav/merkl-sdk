"""``HttpNotary`` — filing a receipt, and the proof with it, over HTTP.

The notary is a witness, not an authority: nothing here is asked before a payment
is authorized, and a filing that fails leaves the payment made and the local copy
intact (plan D12). What this adapter owns is that the *whole* record reaches the
witness, which until now it did not.

``POST /v1/receipts`` takes the envelope, the seven leaves and — the part that
was missing — the settlement capture, inline, in the same call. That matters
beyond tidiness: a receipt filed without its proof is one whose ledger inclusion
nobody can establish offline, and the notary's own receipt page then says
``ledger inclusion: unchecked — no settlement proof was supplied`` about a
payment whose proof was captured, held in memory, and dropped.

``POST /v1/receipts/{id}/settlement-proof`` is the second route, for a capture
that completes after the receipt is already filed — validations collected late,
a header fetched on a retry. Same evidence, later, and it must still be able to
find the receipt it belongs to.

``docs/INTERFACES-P4.md`` section 2 is normative for both bodies.
"""

from __future__ import annotations

from typing import Any, Final

from merkl.core.canonical import JSONObject
from merkl.core.rail import SettlementProof
from merkl.core.receipt import Envelope, ReceiptLeaves
from merkl.shared.errors import MerklError

__all__ = ["HttpNotary", "NotaryError"]

DEFAULT_TIMEOUT_SECONDS: Final = 30.0


class NotaryError(MerklError):
    """The notary refused or could not be reached. Never raised at the payer."""

    error_code = "notary_error"


class HttpNotary:
    """:class:`~merkl.core.ports.NotaryPort` against a merkl-api endpoint.

    ``httpx`` is imported lazily so importing this module costs nothing to a
    caller who files receipts some other way, and an ``AsyncClient`` may be
    passed in when one already exists — the SDK's transport keeps a pooled one,
    and a second pool per builder would be a connection leak dressed as
    convenience.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        api_key: str = "",
        client: Any | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._client = client
        self._timeout = timeout

    async def file_receipt(
        self,
        envelope: Envelope,
        leaves: ReceiptLeaves,
        *,
        settlement_proof: SettlementProof | None = None,
    ) -> None:
        """File the receipt, with its capture in the same request when there is one."""
        body: JSONObject = {
            "envelope": envelope.to_content(),
            "leaves": list(leaves.contents()),
        }
        if settlement_proof is not None:
            body["settlement_proof"] = {
                "rail": settlement_proof.rail,
                "proof": settlement_proof.to_content(),
            }
        await self._post("/v1/receipts", body)

    async def file_settlement_proof(self, receipt_id: str, proof: SettlementProof) -> None:
        """Attach a capture to a receipt that is already on file."""
        await self._post(
            f"/v1/receipts/{receipt_id}/settlement-proof",
            {"rail": proof.rail, "proof": proof.to_content()},
        )

    # -- wire -------------------------------------------------------------- #

    def _headers(self) -> dict[str, str]:
        return {"X-Merkl-API-Key": self._api_key} if self._api_key else {}

    async def _post(self, path: str, body: JSONObject) -> None:
        import httpx

        url = f"{self._endpoint}{path}"
        try:
            if self._client is not None:
                response = await self._client.post(url, json=body, headers=self._headers())
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.post(url, json=body, headers=self._headers())
        except httpx.HTTPError as exc:
            raise NotaryError(
                f"the notary at {self._endpoint} could not be reached: {exc}"
            ) from exc
        if not response.is_success:
            raise NotaryError(
                f"the notary answered {response.status_code} to POST {path}: {response.text[:200]}"
            )

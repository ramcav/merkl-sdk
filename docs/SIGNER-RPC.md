# Merkl signer RPC — v1

`merkl-signer-rpc-v1`. One contract, two transports: the dev signer serves it as
JSON over HTTP on a Unix socket, and the Nitro parent proxy (phase 3) serves the
same JSON over vsock. Nothing above the transport knows which it is talking to,
which is what makes an attested signer a configuration change rather than a
rewrite.

Reference implementation: `merkl.signer.server` (server) and
`merkl.adapters.signer_dev` (clients).

## 1. Transport

`POST /` with `Content-Type: application/json`. Bodies are at most 4 MiB.

```json
{"method": "propose", "params": { … }, "id": "optional, echoed back"}
```

```json
{"protocol": "merkl-signer-rpc-v1", "result": { … }, "id": "…"}
{"protocol": "merkl-signer-rpc-v1", "error": {"code": "signer_auth_error", "message": "…"}}
```

`GET /health` returns the `health` result without a body, for a supervisor.

| Error code | HTTP | Means |
|---|---|---|
| `signer_auth_error` | 401 | the request is not authentic, has expired, or replays a nonce |
| `signer_error` | 400 | the signer cannot make sense of the request |
| `content_error`, `policy_error` | 400 | a value is not well formed |
| `state_error`, `signer_state_error` | 409 | the state cannot make that move |
| `keystore_error` | 500 | the key is unavailable |

**An error is never a decision.** A refused *payment* returns `200` with
`outcome: "deny"` and a full decision; an error means no decision was reached and
no receipt exists.

The dev signer binds a Unix socket at mode `0600` by default and refuses to bind
anything but a loopback address otherwise. Every mutating method runs under one
lock: two proposals evaluating concurrently would each see the spending window
before the other reserved against it.

## 2. Authentication

`propose` carries a `SignedRequest` (plan D15). Every other method is
unauthenticated in this phase and is expected to be reachable only through the
socket's file permissions; phase 3 authenticates them at the vsock boundary.

```json
{"method": "propose",
 "agent_id": "agent-accounts-payable",
 "nonce": "…",
 "expires_at": "2026-01-02T03:09:05Z",
 "params": { … },
 "agent_public_key": "<hex>",
 "signature": "<hex>"}
```

```
pre_image = "merkl-signer-request-v1" || NUL || method || NUL || agent_id
            || NUL || nonce || NUL || expires_at || NUL || canonical_bytes(params)
signature = Ed25519(agent_key, pre_image)
```

The signer verifies against **the key in the policy document** for `agent_id`,
never against `agent_public_key` in the request; that member exists so the
request is self-describing, not so it can authenticate itself. The nonce is
recorded in signer state and refused a second time.

## 3. Methods

### `health`

```json
{"status": "ok", "treasury": "r…", "policy_version": "2026.01.0",
 "policy_hash": "<hex>", "signer_public_key": "<hex>", "state_sequence": 41,
 "pending_escalations": 0, "attested": false,
 "warning": "UNATTESTED SIGNER — no enclave vouches for this key"}
```

### `public_key`

```json
{"public_key": "<hex, 32 raw Ed25519 bytes>", "key_type": "ed25519"}
```

Raw, not rail-formatted. XRPL's `ED` prefix and the address derived from it are
the adapter's business (`merkl.adapters.xrpl.signer_address`).

### `attestation`

```json
{"attestation": null}
```

`null` on a dev signer, and receipt leaf 3 records that absence as a fact.

### `propose`

`params.request` is the `SignedRequest`. Its own `params` are:

```json
{"instruction": { … leaf 0 … },
 "intent":      { … leaf 1 … },
 "prepared_tx": {"rail": "xrpl", "treasury": "r…", "signing_payload": "<hex>",
                 "anchor_offset": 104, "fields": { … }, "commitment": "00…00"}}
```

`fields` must carry `account`, `destination`, `amount` (the intent's own amount
object) and `memo_type`. `signing_payload` is the rail's signing pre-image with
32 zero bytes at `anchor_offset` (spec section 3.4).

Common members of every result:

```json
{"outcome": "allow" | "deny" | "escalate",
 "decision": { … receipt leaf 2 content … },
 "attestation": null,
 "signer_public_key": "<hex>",
 "policy_hash": "<hex>",
 "state_sequence": 42,
 "risk_score": "0",
 "reason": "every rule passed"}
```

`allow` adds:

```json
{"left": "<hex>", "signature": "<hex>", "signed_payload": "<hex>",
 "anchored_tx": { … }, "reservation_id": "…"}
```

`signed_payload` is the payload **after** the signer wrote LEFT into the anchor
field. The caller re-prepares the transaction with `left` and must find the two
byte-identical before submitting.

`escalate` adds `challenge` (LEFT_pre), `expires_at`, `quorum`,
`reservation_id`. `deny` adds nothing and reserves nothing.

### `approve`

```json
{"challenge": "<hex>", "assertions": [ … ], "prepared_tx": { … optional … }}
```

Assertions are in the shape of RECEIPT-SPEC section 3.3. The signer verifies each
one, counts distinct approver ids against the quorum, checks the escalation has
not expired, and **re-evaluates the policy** — minutes have passed and the window
may have filled. Approval is permission to proceed, not a decision that stands on
its own.

Result is an `allow` result, or a `deny` one when the quorum was not reached, the
challenge expired, or re-evaluation refused. A rejected escalation releases its
reservation.

### `settle` / `release`

```json
{"reservation_id": "…", "settlement_ref": "<tx hash>"}   →  {"reservation_id": "…", "state_sequence": 43}
```

`settle` attaches the transaction that carried a reservation; the amount stays
counted against the window either way, so nothing is ever counted twice.
`release` drops a reservation whose attempt provably failed.

These two are not in the plan's original method list. They are here because
reconciliation (D17) needs the signer to be able to match its reservations to the
rail's validated history, and a signer that never learns a transaction hash can
only ever report every reservation as unsettled.

### `policy_update`

```json
{"signed_policy": {"document": { … }, "signature": "<hex>", "signer_public_key": "<hex>"}}
```

Accepted only when the signature verifies against the admin key the signer has
**currently pinned** — not the key the incoming document nominates, which a
forged document could set to its own. The treasury may not change. Returns the
change entry (plan D16) for the SDK to post to the notary:

```json
{"change": {"old_hash": "<hex>", "new_hash": "<hex>", "signed_by": "<hex>", "at": "…"},
 "policy_hash": "<hex>", "policy_version": "2026.02.0"}
```

## 4. What the signer cannot check yet

The signer verifies the prepared transaction's **fields** against the intent and
writes the commitment into the payload itself, so the anchor binding is exact.
What it does not do is confirm that the payload *encodes* those fields: it has no
rail serializer, by design — `merkl.signer` depends on `merkl.core` and
`merkl.shared` alone, and adding a rail codec to the enclave image is a decision
for phase 3, not a detail.

The gap is therefore: **a malicious settlement adapter in the agent's process
could present honest `fields` alongside a payload that pays someone else.**

Three things narrow it today:

1. `merkl.signer.binding` decodes the treasury and destination addresses itself
   and requires their raw account ids to appear in the payload. A payload that
   does not even mention the destination is refused;
2. the signer requires exactly one placeholder-shaped run in the payload, so it
   knows where its commitment is going;
3. the caller re-prepares the transaction independently and compares byte for
   byte, and the ledger republishes the memo, which the receipt records as
   `observed_anchor` — so a substituted transaction is *detectable after the
   fact* from the receipt alone, even if it settled.

Closing it properly means a pure serializer for the rail's signing pre-image in
`merkl.core.rails`, letting the signer re-derive the payload from the fields and
require equality. That is the right shape and it is not built.

## 5. Phase 3 notes

The Nitro parent proxy implements this contract over vsock, with:

- `attestation` returning the CBOR attestation document (base64) instead of
  `null`, and receipt leaf 3 carrying it;
- the keystore sealed by KMS under a PCR condition rather than a passphrase
  (`merkl.signer.keystore.KeystorePort` is already the whole surface);
- state snapshots sealed with a KMS-derived key and handed to the parent for
  storage, keeping the monotonic sequence semantics of
  `merkl.signer.state.SealedStateStore`.

No method signature changes.

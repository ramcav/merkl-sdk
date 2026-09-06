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

On a Nitro signer, the leaf-3 content instead — a **fresh** document each call,
because an attestation is a statement about a moment and a verifier is entitled
to bound how old that moment is:

```json
{"attestation": {"format": "aws-nitro",
                 "document": "<base64 of the CBOR COSE_Sign1>",
                 "policy_public_key": "<hex>"}}
```

The document binds two things and both matter: `public_key` is the policy public
key, so the attestation is about *this* key rather than about some enclave from
the same image; `user_data` is the policy hash, so it says which policy was being
enforced. `docs/ATTESTATION-VERIFY.md` specifies how to check it.

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

## 4. Reading the bytes before signing them

The settlement adapter runs in the **agent's** process. That is the party this
whole design assumes may be compromised, so its account of what a payload encodes
is exactly the thing that cannot be taken on trust. A signer that compared the
adapter's reported `fields` to the intent and then signed the adapter's bytes
would bless a payment to anywhere, as long as the adapter described it honestly.

So the signer decodes the payload itself. After it writes LEFT into the anchor,
and immediately before the key moves, `merkl.signer.rails.<rail>` decodes the
exact bytes and holds them against the intent:

| Checked | Against |
|---|---|
| `TransactionType` | must be `Payment` |
| `Account` | `intent.treasury` |
| `Destination` | `intent.destination` |
| `Amount` | drops for XRP; currency, issuer and a **numeric** value comparison for issued currencies, because XRPL normalises an issued mantissa (`250.00` decodes as `250`) |
| `Memos` | exactly one, `MemoType` = `merkl/receipt-v1`, `MemoData` = LEFT |
| `Flags` | absent, `0`, or only `tfFullyCanonicalSig`. `tfPartialPayment`, `tfLimitQuality` and `tfNoRippleDirect` are refused |
| every other field | an **allowlist**: `TransactionType, Account, Destination, Amount, Fee, Sequence, LastLedgerSequence, SigningPubKey, Memos, Flags, NetworkID`. Anything else is a finding |

The allowlist is the load-bearing part. XRPL has several ways to make a Payment
deliver something other than `Amount` to `Destination` — `SendMax`, `DeliverMin`,
`Paths` and a partial-payment flag between them — and `DestinationTag` is read by
an exchange as part of the address. Intent v1 expresses none of them, so their
*presence* is the finding, and a field nobody has thought of yet is caught by
construction rather than by the next person to read the XRPL spec.

**A mismatch is a decision, not an error.** It returns `200` with
`outcome: "deny"`, and the decision carries a rule named
`rail.payload_encodes_intent` whose detail names every disagreement. The agent
asked for one payment and its adapter produced the bytes for another; that is
worth being able to prove afterwards, so it gets a receipt. The reservation is
released, so a hostile adapter cannot burn the agent's spending window either.

Codecs are **verify-only**: they decode, they never build a transaction and never
reach a network, so a codec is a pure function of bytes and can be reasoned about
— and audited — on its own.

### Where the codec comes from

The policy document names the treasury's `rail`. The signer resolves the codec at
boot and **refuses to start** if there is none: a signer that cannot read its
rail's bytes must fail at startup rather than discover it mid-payment.

Codecs load lazily, behind their own extra:

```
pip install 'merkl-sdk[signer,signer-xrpl]'
```

A separate extra from `[signer]` rather than folded into it, because a signer
serves one treasury on one rail (plan D18) — so it should carry that rail's
library and no other, and a Solana signer should not ship xrpl-py. That keeps
`merkl.signer`'s base dependent on `merkl.core` and `merkl.shared` alone, which
is what `tests/signer/test_signer_purity.py` enforces.

### What is still outside the signer

The signer now verifies that the bytes encode the intent. It does not verify that
the *rail* will accept them — a malformed fee or a stale `LastLedgerSequence`
makes the transaction fail, not misdeliver. That is a liveness problem, and it
shows up as a `FAILED` receipt rather than a wrong payment.

## 5. The Nitro transport (phase 3, shipped)

The Nitro parent proxy implements this contract over vsock. Same methods, same
request and response shapes; `merkl.adapters.signer_nitro.NitroSignerClient` is a
subclass of the dev client that adds no RPC method, and
`tests/signer/test_vsock.py` asserts the two transports answer byte-identically
for the same router. What changed:

- `attestation` returning the CBOR attestation document (base64) instead of
  `null`, and receipt leaf 3 carrying it;
- the keystore sealed by KMS under a PCR condition rather than a passphrase
  (`merkl.signer.keystore.KeystorePort` is already the whole surface);
- state snapshots sealed with a KMS-derived key and handed to the parent for
  storage, keeping the monotonic sequence semantics of
  `merkl.signer.state.SealedStateStore`;
- **the enclave image installs the rail codec extra** (`signer-xrpl` for an XRPL
  treasury). The codec is inside the enclave, not in the parent proxy: it is the
  check that makes the policy signature mean something, so it has to be measured
  by the same attestation as the key it protects;
- the policy document is baked into the image too, for the same reason: one
  handed over by the parent at boot is a policy the parent chooses.

No method signature changes.

The vsock framing is four bytes of big-endian length and then the same JSON body
(`merkl.signer.vsock`). Not HTTP: inside the enclave an HTTP parser would be code
in the trusted computing base earning nothing, with one peer and one content
type. The announced length is checked against the 4 MiB cap before anything is
allocated, because the peer is the party this design assumes may be hostile.

A second vsock port carries the *other* direction — the enclave asking the parent
for the sealed key blob, for AWS credentials, and for the rail history it
reconciles against (`nitro/parent/proxy.py`). It is a separate port and a
separate five-method dispatch table on purpose: sharing one would mean a method
meant for one direction could be reached from the other.

That history is **evidence, not instruction**. It arrives from the party this
design assumes may be compromised, is parsed into checked `Outflow` value objects
at the boundary, and goes only to `SignerEngine.reconcile`, which compares it to
state the enclave wrote itself. Rule state is never supplied by the caller
(plan D2), and nothing on that channel reaches the decision path.

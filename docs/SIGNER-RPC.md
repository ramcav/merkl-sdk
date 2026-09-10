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

`GET /health` returns the `health` result without a body, for a supervisor —
subject to the same relay credential as every other method once one is
configured (§3); it is not a special case.

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

`propose` carries a `SignedRequest` (plan D15). Every other method
authenticates differently — see §3, "Who may call what" — because a request to
`propose` names a decision to make, and everything else names an action to take
against a decision or the signer's own configuration.

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

## 3. Who may call what

`propose` authenticates itself, above: the caller signs the request with the
key the policy names for that agent, and needs no other credential. Every
other method — `health`, `public_key`, `attestation`, `approve`, `reject`,
`settle`, `release`, `policy_update` — has no signature of its own. Today that
means "reachable by anything that can reach the transport": file permissions
on a Unix socket, or nothing at all once the signer sits behind the Nitro
parent's HTTP relay.

A **relay token** bounds that. It lives in the signer's own config, never in
the policy document — the policy is public and replayable, and who may push
things at the signer is an operational fact, not a rule an intent gets
evaluated against:

```json
{"relay_tokens": [{"id": "dashboard", "token_sha256": "<hex>"}]}
```

Only the SHA-256 of each token is ever stored. `merkl signer token add <id>`
writes a fresh entry to that config and prints the bearer token **exactly
once**:

```
$ merkl signer token add dashboard
relay token 'dashboard' created. This is the only time it is shown:

  dashboard:3f9a1c…

Pass it as 'Authorization: Bearer <token>', --relay-token, or $MERKL_RELAY_TOKEN.
```

`merkl signer token revoke <id>` removes one; `merkl signer token list` prints
only ids, never tokens. The id before the colon is not secret — it is what
lets a failure name *which* credential did not verify without ever naming the
credential itself.

Once at least one relay token is configured, every method but `propose`
requires `Authorization: Bearer <id>:<secret>` matching one of them, checked in
constant time. **No relay tokens configured behaves exactly as this phase
found it** — every method reachable, bounded only by the transport — so an
existing deployment keeps working unmodified; adding a token is what switches
a signer into requiring one for everything but `propose`.

Over vsock, which has no headers, the same credential travels as a top-level
`auth` member of the request frame:

```json
{"method": "approve", "params": { … }, "auth": {"bearer": "<id>:<secret>"}}
```

The Nitro parent proxy lifts the token out of the HTTP `Authorization` header
it received and forwards it into that member unchanged (`nitro/parent/proxy.py`)
— it does not generate, store or check relay tokens itself, the same way it
does not generate, store or check anything else that matters (§6).

**This is not a fund-moving secret.** Holding a relay token lets you push
approvals, rejections and policy changes at the signer and ask about its own
state; it authorizes none of them by itself. The signer still only agrees
because the agent's own request was signed (`propose`), because the assertions
attached to an `approve`/`reject` verify against the policy's approvers, or
because a `policy_update` verifies against the pinned admin (§4, `policy_update`,
below). Losing a relay token is an availability incident — flooding,
forced escalation churn, a renamed policy over and over — not a theft. It
bounds who may push, not what pushing can accomplish.

## 4. Methods

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

### `reject`

```json
{"challenge": "<hex>", "assertions": [ … ]}
```

The other half of `approve`, and it is signed for the same reason. Somebody with
standing to approve chose not to, and that fact belongs in the record: an
escalation that simply stops being mentioned proves nothing about whether anyone
looked at it (plan D11 — *rejections are signed too*).

The signer verifies the assertions exactly as `approve` does, against the same
challenge and the same approver credentials. It then records a **`deny`**
decision whose leaf 2 carries the escalation with those assertions inside it, and
releases the reservation — a window that stays full is a denial of service the
approver did not intend.

Two cases worth stating:

* **No assertions at all** is an error, not a rejection. A refusal nobody signed
  is indistinguishable from a message anyone could have sent.
* **Assertions that do not verify** still produce a `deny`, with `detail` saying
  *no assertion verifies* rather than naming a rejector. The escalation is
  resolved either way — nothing is going to be signed for it — but the record
  does not claim a person refused when it cannot show one did.

Result is the same envelope shape as `approve`'s deny: `outcome`, `decision`
(with the `escalation` member carrying the assertions), `detail`, and
`approvals_accepted` listing the ids whose signatures verified.

**Relay contract for merkl-api.** `POST /v1/escalations/{id}/reject` currently
files the rejection in the notary's own tables. That is a record of what a
reviewer clicked, not a decision — the signer is the only policy authority
(plan D1) and the notary only relays (D11). To close the loop, the route must
forward `{challenge, assertions}` to this method and store the returned decision
beside the receipt; until it does, a rejection filed through the API leaves the
escalation pending in the signer and the reservation held until it expires.

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
{"signed_policy": {"document": { … }, "signature": "<hex or an ApprovalAssertion>",
                    "signer_public_key": "<hex>"}}
```

`signature` is either the legacy raw Ed25519 hex over the tagged pre-image, or
an `ApprovalAssertion`-shaped object (`RECEIPT-SPEC.md` section 3.3) — Ed25519
or WebAuthn — over the 32-byte `policy_hash`, with `approver_id` fixed to
`"admin"`. Both are accepted only when the signature verifies against the admin
**credential** the signer has **currently pinned** — not the key or credential
the incoming document nominates, which a forged document could set to its own.
`merkl.core.policy.approvals.verify_policy_signature` is the one function that
checks either shape; it is the same one an approver's assertion goes through.
The treasury may not change. Returns the change entry (plan D16) for the SDK to
post to the notary:

```json
{"change": {"old_hash": "<hex>", "new_hash": "<hex>", "signed_by": "<hex>",
            "credential_type": "ed25519", "at": "…"},
 "policy_hash": "<hex>", "policy_version": "2026.02.0"}
```

`signed_by` is the credential's `public_key` — Ed25519 or the WebAuthn P-256
point — never the credential's shape or origins; a reader who needs those
looks them up in the document itself. `credential_type` names *whose*
signature authorized this change (the admin the signer had pinned before the
update, i.e. `signed_by`'s kind), not the kind of admin the new document
nominates; it defaults to `ed25519` on a change entry recorded before this
field existed, which every one before this phase was. Once adopted, the
signer pins whatever admin *that* document names, ed25519 or webauthn — an
org can hand its policy
from a legacy admin key to a WebAuthn one in a single update, signed by the key
being retired.

## 5. Reading the bytes before signing them

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

## 6. The Nitro transport (phase 3, shipped)

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

No method signature changes. The one envelope-level addition, the optional
`auth` member carrying a relay bearer token (§3), is on the *request* frame,
not on any method's own params or result, and is absent entirely on a signer
with no relay tokens configured — the same `RpcRouter` answers both ways.

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

## 7. Following a notary (phase 17)

Every method above is something a caller *pushes* at the signer. That works when
somebody can reach it: an agent on the same host, a dashboard behind the Nitro
parent's relay. It does not work at all for the case this product is actually
sold into — a signer in a container on a customer's own laptop, behind their own
NAT, which Merkl has no route to and wants none.

So a self-hosted signer **pulls**. When `<home>/notary.json` exists (written by
`merkl treasury init --enrol`, mode `0600`), `merkl signer serve` starts a
follower — `merkl.adapters.notary.follower.NotaryFollower`, a daemon thread that
speaks HTTP to merkl-api and applies what it finds through the same `RpcRouter`,
under the same lock, that the socket goes through.

| Route | Direction | When |
|---|---|---|
| `GET /v1/signer/policy` | pull | every 10 s until the first policy exists, every 30 s after |
| `POST /v1/signer/heartbeat` | push | on every policy poll, carrying the hash **in force** |
| `GET /v1/signer/escalations` | pull | every 5 s while the engine holds pending escalations, else every 30 s |
| `POST /v1/signer/escalations/{challenge}/decision` | push | immediately after applying one |

All four authenticate with the **signer token** (`sgn_…`, `Authorization: Bearer`),
issued once by `POST /v1/signers/enrol` and kept in `notary.json`. It is not a
fund-moving secret and not a relay token: it identifies this signer to the
notary, and the notary uses it to decide which treasury's policy and escalations
to hand over.

**Nothing pulled is trusted.** A policy goes through `policy_update` (§4), which
verifies it against the admin credential the signer *pinned* and refuses one
naming a different treasury; with a `network` in `notary.json` it also refuses
one governing the other chain, exactly as `--rail-endpoint` does at boot. An
escalation's assertions go through `approve` or `reject` (§4), which verify each
signature against the approvers the policy names and re-evaluate the intent
before anything is signed. A notary that handed over a forged policy or a forged
approval would be refused by the code that has always refused one; a notary that
withheld a real approval would only mean the payment does not happen. That is
the whole security argument for pulling, and it is why the direction of the
connection is not a security property here.

The follower applies through `RpcRouter.dispatch_local`, which takes the lock and
skips the relay-bearer check of §3. In-process is not a relay: the follower is
the same program holding the same key, and a credential check with no attacker on
the other side of it would be ceremony. There must be exactly **one** router per
engine — `merkl signer serve` builds it and hands it to both the HTTP server and
the follower — because the lock is what stops a call arriving over the socket and
a call applied in-process from reading the same spending window.

Failures are backoffs, never exits: doubling from one second, capped at sixty,
with one line on stderr. A refused policy is logged **once per hash**, not once
per poll. An escalation this signer has never heard of — the pending set does not
survive a restart — is reported once and then skipped, rather than retried every
five seconds forever. The signer holds the key; the follower is an HTTP client,
and only one of those two is allowed to be unavailable.

Two other things follow from pulling. A policy adopted from the notary is
persisted atomically to `<home>/policy.signed.json`, so a restart with the notary
down still boots. And a signer that has *never* had a policy has no socket to
forward to, which is why `merkl.signer.forward` answers `503 signer_unavailable`
in this protocol's own error shape on a connect failure rather than dropping the
connection: "waiting for the customer to press Publish" and "the container never
started" are different facts, and a refused TCP connection cannot tell them
apart. The forwarder still parses nothing — the response is a constant, written
on connect failure, before a byte of the request is read.

The follower lives under `merkl/adapters/` and not under `merkl/signer/`.
That package depends on `merkl.core` and `merkl.shared` alone, writes to no
stream, and knows no notary; the follower is handed a `log` callable by the CLI
and an `RpcRouter` to dispatch through, and `tests/signer/test_signer_purity.py`
still holds.

# Merkl co-signer — Step 0 plan

Status: draft for approval, 2026-09-05. Supersedes the monorepo assumptions in the
original build brief; decisions below were settled in review and are not re-opened here.

Merkl extends from a notary into a mandatory co-signer for agent-initiated financial
transactions, with verifiable Merkle receipts bound to settlement. First rail: XRPL.
Sold as an AI accountability product; the rail is a detail.

## 1. Decisions (settled)

| # | Decision |
|---|----------|
| D1 | The signer is a separate process and the only policy authority. It evaluates the pinned policy itself on the canonical intent; it never accepts a decision from the caller. merkl-api may pre-evaluate for UX, non-authoritatively. |
| D2 | Rule state (daily cap, sliding window, in-flight reservations, replay nonces) lives in the signer: sealed snapshots with a monotonic sequence, reconciled against the rail's validated history on boot and periodically. Never supplied by the caller or by merkl-api. |
| D3 | Nitro signer built fully (enclave image, vsock RPC, KMS sealing, attestation). `DevSigner` implements the same RPC with `attestation() = null`, shown loudly as unattested. |
| D4 | No second chain. A receipt is a 7-leaf tree whose envelope hash is committed as one action leaf in the enclosing session (`action_type=transaction`). It inherits log inclusion, checkpoint signature and Bitcoin anchoring. No `previous_root`. No migration of existing data. |
| D5 | Split tree. Leaves 0–3 (instruction, intent, policy_decision, signer_attestation) form LEFT, the authorization commitment, which goes in the rail memo and is what the policy key signs. Leaves 4–6 (settlement, result, reasoning) form RIGHT, appended after settlement. `ROOT = H(LEFT ‖ RIGHT)`. |
| D6 | Canonicalization stays v1 (`merkl.shared.hashing.canonical_bytes`). The receipt schema forbids fractional JSON numbers: amounts are strings (drops, minor units, decimals). JCS is a possible v2 tag, not now. |
| D7 | Verification = one normative spec + one vector set + two implementations (Python `merkl.core`, JS `@merkl-ai/verify`) that must both pass every vector. verify.html template and JS move into the SDK; merkl-api renders by calling the SDK; the dashboard imports the npm package and deletes its own verifier. |
| D8 | One PyPI distribution `merkl-sdk` with subpackages `merkl.core`, `merkl.signer`, `merkl.adapters.*`, `merkl.sdk`, and extras `[xrpl] [signer] [nitro] [dev]`. Core has no I/O and no new deps. Signer, adapters and merkl-api depend on core only. |
| D9 | Layers are agnostic in code and trust, joined in evidence. A receipt verifies with the signer public key, the rail, and the local trace alone (level 1). Joining the session/log adds completeness, notary signature and Bitcoin (level 2). The join is optional and one-way. |
| D10 | Settlement verdict is two lines: transaction authorization (`verified` from the signed blob / `absent`) and ledger inclusion (`proven-offline` via inclusion proof against pinned validators / `verified-live` / `supplied-unverified` / `unchecked`). Never a single PASS that hides the level. |
| D11 | Approvals are passkey (WebAuthn) or Ed25519 signatures over the escalation challenge `LEFT_pre`. Approver public keys live in the policy. M-of-N per tier from day one. The signer verifies; merkl-api only relays. Rejections are signed too. |
| D12 | merkl-api is never on the INSTANT path. Receipts post asynchronously through the existing buffered transport. HUMAN tier uses the dashboard queue. |
| D13 | Leaf 0 = `{source: human_input | mandate | system, content_hash, signature?, ref?}`. In a Claude Code session, `ref` is the `human_input` action id and `depends_on` binds the receipt action to it. |
| D14 | DENY produces a receipt (leaves 0–2, result `denied`), no submission. Solo-submit to show `tefBAD_QUORUM` is a scenario test only. Treasury bootstrap sets `asfDisableMaster` and refuses if a RegularKey exists. |
| D15 | Agent ↔ signer requests are signed by the agent key with nonce and expiry; the agent public key is in leaf 1. |
| D16 | Policy is a signed document. Changes are signed by the admin key or an approver quorum, recorded by the signer as a change entry (old hash, new hash, who, when) that flows into the log. |
| D17 | Reconciliation: treasury outflows ↔ receipts, both directions, in the dashboard and `merkl reconcile`. |
| D18 | Topology: one signer process per treasury, many agents. Signer-list weights: any one agent key + the policy key reaches quorum; no set of agent keys alone does. State keyed by (treasury, agent). |
| D19 | Vector generator in the SDK repo; Node test job in SDK CI; `@merkl-ai/verify` published from the same release tag as PyPI. |
| D20 | Settlement-proof capture at settlement time (SHAMap path + ledger header + validator quorum from the validations stream) is a hard requirement of the XRPL adapter. |

Small decisions made in this plan (object if wrong):

- Caps are expressed per asset in the policy (`max 10000 RLUSD/tx`, `max 5000 XRP/day`). No price oracle in the decision path. A `PricePort` for USD-notional limits is an extension, not a requirement.
- Intent v1 supports two types, `payment` and `swap` (section T). Other types (trustline, escrow, card authorization) are additive on the same terms.
- Dev signer RPC: JSON over HTTP on a Unix socket or localhost. Nitro: same JSON over vsock via the parent proxy. One contract.
- Receipt ids are UUIDv7 (existing `merkl.shared.ids`).

## 2. What exists today (relevant parts)

- `merkl-sdk`: `merkl.shared` (hashing, ids, enums, errors), `merkl.sdk` (client, session, transport with retry + buffer, `@trace`/`@guardrail`), hook, integrations, CLI (`install`, `disclose`). No Merkle code. `merkl disclose` downloads verify.html from the API.
- `merkl-api`: `merkl_api.merkle` (tree, proof), `merkl_api.action.hashing` (leaf bound to `ActionRecord`), `merkl_api.checkpoint` (RFC 6962 log tree, Ed25519 signer, OTS anchor), `merkl_api.export` (bundle v1.1, `html_verifier.py` with the JS verifier as a string, PDF). 36 routes. 16 migrations, RLS on every table.
- `merkl-dashboard`: Story view, `verify.ts` (Merkle path only), Supabase auth, settings/keys/team.
- `docs/SPEC.md` in merkl-api: normative v1 format (`merkl-leaf-v1`, `merkl-binding-v1`, `merkl-entry-v1`, log tree, checkpoint, evidence, bundle).

Duplication to consolidate (brief Step 0 asks for this):

| Today | Becomes |
|-------|---------|
| `merkl_api/merkle/{tree,proof}.py` | `merkl.core.merkle`; API re-exports |
| `merkl_api/action/hashing.py` bound to `ActionRecord` | `merkl.core.leaf.action_leaf(fields)`; API wraps |
| JS verifier string in `html_verifier.py` | `merkl/core/verify/merkl-verify.js` + `verify.html` template in the SDK; API calls `merkl.core.verify.render(bundle)` |
| dashboard `src/verification/verify.ts` | deleted; imports `@merkl-ai/verify` |
| `CreateActionRequest.action_type` literal in `app/schemas.py` | built from `merkl.shared.enums.ActionType` |
| Python log-tree/checkpoint *verification* in merkl-api | `merkl.core.verify.log` (Python), used by `merkl verify`; signing stays in the API |

## 3. Target layout (`merkl-sdk` repo)

```
merkl/
  shared/        unchanged (hashing, ids, enums, errors, events)
  core/          pure, no I/O, no deps beyond shared
    merkle.py        MerkleTree, MerkleProof (moved from merkl-api)
    leaf.py          action_leaf(), receipt_leaf(), domain tags
    receipt.py       Receipt, Envelope, leaf models, build_left/right/root, selective disclosure
    intent.py        Intent v1 (payment), amount types (no floats)
    policy/          PolicyDocument, rules, engine (deterministic), decision model, approver credentials
    ports.py         SettlementPort, SignerPort, ReceiptStorePort, ApprovalPort, RiskPort, ClockPort
    verify/          verify.py (Python verifier), log.py, attestation.py, render.py, verify.html, merkl-verify.js
    vectors/         generate.py + *.json fixtures
  signer/        the process (depends on core)
    server.py        RPC: propose, approve, policy_update, public_key, attestation, health
    engine.py        authoritative evaluation, escalation registry, quorum
    state.py         sealed snapshots, reservations, nonces, reconciliation hooks
    keystore.py      DevKeystore (file, encrypted at rest) / NitroKeystore (KMS-sealed)
    auth.py          verify agent-signed requests (D15)
  adapters/
    fake/            in-memory initiating rail, deterministic, used by the scenario suite
    xrpl/            multisig Payment (XRP + issued currencies), memo=LEFT, bootstrap (asfDisableMaster), settlement proofs, account_tx reader
    signer_dev/      SignerPort client for the dev signer
    signer_nitro/    SignerPort client for the Nitro parent proxy
  sdk/           client + ReceiptBuilder (orchestrates propose → evaluate → route → co-sign → settle → attest, joins session if active)
  cli/           install, disclose (renders locally), verify, receipt show, approve, reconcile, signer serve
nitro/           enclave Dockerfile, parent proxy, KMS policy, Terraform
```

Extras: `xrpl` (xrpl-py), `signer` (server deps), `nitro` (aws-nsm, boto3), `dev` (pytest, hypothesis, ruff, mypy). Core and `merkl.sdk` keep the current three runtime deps.

## 4. Ports

```
SettlementPort (initiating family)
  prepare(intent, commitment) -> UnsignedTx          rail-specific unsigned tx with the commitment in its anchor field
  agent_sign(unsigned) -> PartialTx                    agent key
  attach_policy_signature(partial, sig) -> SignedTx
  submit(signed) -> SettlementRef                      hash, ledger index / id, observed anchor value
  settlement_proof(ref) -> SettlementProof | None      captured at settlement time (D20)
  history(treasury, since) -> [Outflow]                validated outflows, for state (D2) and reconciliation (D17)
  anchor_capability() -> immutable | mutable | none

SignerPort
  public_key() -> bytes
  attestation() -> AttestationDoc | None
  propose(SignedRequest) -> Decision | Escalation      D1, D15
  approve(challenge, ApprovalAssertion) -> Decision    D11
  sign_tx(canonical_tx_bytes, commitment) -> Signature only after its own ALLOW

ReceiptStorePort   put(receipt), get(id), list(treasury, agent, since)
ApprovalPort       enqueue(escalation), collect(challenge) -> [ApprovalAssertion]
RiskPort           score(destination) -> RiskScore     called by the signer, never by the agent
ClockPort          now() -> Timestamp                  injected everywhere in core and signer
```

The authorizing family (card networks) is a future port; adding it touches orchestration, not core.

## 5. Receipt format (`merkl-receipt-v1`)

Leaf hash: `SHA-256("merkl-receipt-leaf-v1" ‖ NUL ‖ leaf_name ‖ NUL ‖ canonical_bytes(content))`. Absent content is the literal `null`.

| # | leaf_name | content (all strings/ints, no floats) |
|---|-----------|----------------------------------------|
| 0 | instruction | source, content_hash, signature?, ref? |
| 1 | intent | type, rail, treasury, destination, amount{value, currency}, reference?, policy_version, agent_public_key, nonce, expires_at |
| 2 | policy_decision | policy_hash, rules[{name, outcome, detail}], outcome, tier, escalation?{challenge, expires_at, quorum, approvals[]} |
| 3 | signer_attestation | Nitro attestation document (CBOR, base64) with the policy public key, or null |
| 4 | settlement | rail, tx_hash, signed_tx_blob, ledger_index, close_time, observed_anchor, settlement_proof_ref |
| 5 | result | outcome hash (engine result, balance deltas) |
| 6 | reasoning | content_hash of the model trace; testimony |

Tree: Merkl's existing padding (repeat last leaf) gives eight leaves, two halves. LEFT over 0–3 is the authorization commitment; RIGHT over 4–6(+6). Envelope: `receipt_id, version, root, left, leaf_hashes[8], rail, treasury, agent_id, policy_hash, signer_public_key, session_locator?{session_id, leaf_index}`. The envelope's canonical hash is the session action's `input_hash`.

Verification order (spec §, also the vector cases): leaves → LEFT → policy signature (over tx blob on XRPL, over LEFT elsewhere) → attestation → intent vs settled fields (step 3b) → memo = LEFT → signed blob → inclusion proof → RIGHT → ROOT → envelope → session/log (level 2).

## 6. Signer process

- Boot: load policy document, verify its signature against the pinned admin key, compute `policy_hash`; unseal key (dev: encrypted file; Nitro: KMS with PCR condition); load sealed state; reconcile against rail history.
- `propose`: verify agent signature, nonce, expiry (D15) → run policy → reserve against windows → return decision leaf content + attestation + (ALLOW) signature over the prepared tx, or (ESCALATE) challenge, or (DENY) decision only.
- `approve`: verify each assertion (WebAuthn envelope or Ed25519), quorum, expiry → re-evaluate → final decision + signature.
- `policy_update`: accept only a signed document; write change entry (D16).
- State snapshot after every mutation, monotonic sequence, handed to the parent for storage.

## 7. XRPL adapter scope

Payment in XRP and issued currencies (RLUSD). Amounts as drops or decimal strings. Memo `MemoType=merkl/receipt-v1`, `MemoData=LEFT` hex. Multisig fee scaling. Bootstrap script: SignerListSet per D18, then `asfDisableMaster`, then verify no RegularKey. Settlement proof capture from the validations stream at submit time. `account_tx` reader for state and reconciliation. Testnet first, mainnet config identical.

## 8. Verification entry points

- `merkl verify <receipt|bundle>`: Python, offline, structured verdict.
- `verify.html`: rendered locally by the SDK (`merkl disclose`) or by merkl-api; same JS; verdict in plain language per check, with the levels and states of D9/D10.
- Dashboard: imports `@merkl-ai/verify`; receipt rows in the Story expand into the seven leaves and the verdict.
- Pinned roots the verifier needs: policy public key(s), Merkl checkpoint key, AWS Nitro root + PCR allowlist, XRPL validator keys (UNL). Distributed the same way the checkpoint key is today.

## 9. merkl-api changes

Tables (each with RLS and a downgrade): `receipts` (envelope JSON, root, session/action locator, treasury, agent, outcome), `escalations` + `approvals` (challenge, quorum, assertions), `policies` + `policy_changes`, `approver_credentials`, `settlement_proofs`. Routes: `POST/GET /v1/receipts`, `GET /v1/escalations` (queue), `POST /v1/escalations/{id}/approve|reject` (relay), `GET/POST /v1/policies`, `GET /v1/treasuries/{id}/reconcile`. Bundle v1.2 includes receipts and settlement proofs. `html_verifier.py` delegates to the SDK. `merkl_api.merkle` becomes a re-export.

## 10. Dashboard changes

Receipt view inside the Story; approvals queue with WebAuthn (app-level `navigator.credentials`, independent of Supabase MFA); passkey registration in settings; policy view (hash, version, approvers, change history); reconciliation view; `@merkl-ai/verify` replaces `verify.ts`. Palette and tokens unchanged.

## 11. What stays untouched

`merkl-leaf-v1`, `merkl-binding-v1`, `merkl-entry-v1`, the log tree, checkpoints, OTS anchoring, the evidence log format, the Claude Code hook, every existing table and route. Existing bundles keep verifying.

## 12. Phases, branches, deliverables

| Phase | Repo / branch | Ships |
|-------|---------------|-------|
| 1 | `merkl-sdk` `phase-1/receipt-core` | `merkl.core.{merkle, leaf, receipt, intent}`, `docs/RECEIPT-SPEC.md`, vector generator + fixtures (roots, proofs, tampered leaves, split-tree cases), tests. merkl-api switches to `merkl.core.merkle` (path override in dev, PyPI on release). |
| 2 | `merkl-sdk` `phase-2/policy-signer-xrpl` | policy engine, ports, `merkl.signer` (dev keystore), `adapters.fake`, `adapters.xrpl` incl. bootstrap and settlement proofs, `ReceiptBuilder`, agent-signed requests, scenario suite green on fake and XRPL testnet. |
| 3 | `merkl-sdk` `phase-3/nitro-signer` | enclave image, parent proxy, KMS sealing, attestation in leaf 3, Terraform, attestation verification in Python and JS. |
| 4 | `merkl-sdk` `phase-4/verification`; `merkl-api` `phase-4/receipts`; `merkl-dashboard` `phase-4/receipts` | Python + JS verifiers, verify.html moved, `@merkl-ai/verify` published, CLI (`verify`, `receipt show`, `disclose --leaves`, `approve`, `reconcile`); API tables/routes/bundle v1.2; dashboard receipt view, approvals with passkeys, policy and reconciliation views. |
| 5 | all, `phase-5/scenarios-docs` | five scenarios (benign, injection drain, over-threshold + M-of-N approval, structuring, reference mismatch) on both rails; README with architecture, trust model, receipt spec, how to add a rail; landing rewrite (separate brief). |

Each phase ends with a report: what shipped, what is stubbed, which vectors exist, any core/adapter boundary bent and why. verify.html must verify at the end of every phase.

## T. Trading (`merkl-sdk` `phase-14/trading`)

The agent may trade, and the policy it cannot see or change bounds every trade.
The decisions are in `docs/RECEIPT-SPEC.md` §3.1 (`swap`) and §3 (leaf 5's
`delivered`/`spent`); what follows is only what a reader of this plan needs.

- **A trade is a cross-currency Payment to self.** `Destination == Account`,
  `Amount` = the buy side (exact), `SendMax` = the sell ceiling, no `Paths`, no
  `DeliverMin`, no `tfPartialPayment`. The ledger delivers exactly `Amount` for
  at most `SendMax` or the transaction fails, so the agent's limit price is
  enforced by the chain and the policy has only to bound size. Not
  `OfferCreate`: a resting order has no settlement moment.
- **The sold side is the outflow.** No new arithmetic. `per_tx_cap`, `windows`
  and `tiers.human.thresholds` read `sell.max_amount`; both currencies must be
  in `allowlist_assets`; `allowlist_destinations` does not apply, because the
  destination is the treasury. Rule state reserves the ceiling and accounts the
  settled trade by what actually left.
- **`may_swap` is a separate grant.** A new agent-section boolean, false when
  absent and omitted from the hashed content when false, so no `policy_hash`
  signed before this phase changed. A trade by an agent without it is `DENY`
  with `may_swap: agent may not trade`. A `may_swap` agent must allowlist at
  least two assets or the grant is unenforceable (§ "rules a document may not
  carry").
- **Trust lines are set at init, not through the signer.** `merkl treasury init
  --trust CODE.issuer` sets them before the SignerList is installed and the
  master key disabled — afterwards a `TrustSet` would need the quorum the
  bootstrap is only about to install. **The `trustline` intent type stays
  deferred**: an agent cannot open a line, and the assets it may hold are
  therefore an operator's decision made once, at setup, with the master key.
- **Mainnet is possible and deliberately awkward.** `merkl treasury init
  --xrpl-mainnet` has no faucet (wallets come from the operator's own 0600 seed
  file), prints the network's own reserve arithmetic before submitting anything,
  requires a typed confirmation, and records `policy.network` as `xrpl-mainnet`.

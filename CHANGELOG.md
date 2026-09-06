# Changelog

All notable changes to `merkl-sdk`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut by pushing a `v<version>` tag; see
`.github/workflows/release.yml`.

## [Unreleased]

### Added

- **`merkl.core.policy` — the signed policy and the deterministic engine.**
  `PolicyDocument` v1 is hashed and signed over one pre-image under
  `merkl-policy-v1`, so a signature can never be valid for a document with a
  different hash, and a policy update is checked against the admin key the signer
  has *pinned* rather than the key the incoming document nominates.
  `evaluate(intent, policy, state, risk, now)` is a pure function whose output
  serialises byte-for-byte as receipt leaf 2. A denial is a decision with rules
  and a receipt, not an exception. Rule state is an immutable ledger with a
  monotonic sequence: reservations count against a sliding window from the moment
  they exist, settling relabels rather than re-counts, and `reconcile()` compares
  rail history to signer state in both directions.
- **Approval assertions are pinned** (`RECEIPT-SPEC.md` §3.3): WebAuthn passkeys
  and Ed25519 keys, every binary member as hex of the exact bytes, quorum over
  distinct approver ids. `LEFT_pre` is pinned too (§3.2) — LEFT with leaf 2's
  escalation omitted and its outcome set back to `escalate` — so a reader holding
  only the finished receipt can recompute the challenge the approvers signed.
- **Four deferred verification checks now run.** `policy.signature`,
  `intent.matches_settled_fields`, `settlement.anchor_equals_left` and
  `settlement.signed_blob` execute whenever the receipt carries their inputs and
  report `not_implemented` by name when it does not. The settlement leaf gains an
  optional `policy_signature` carrying the exact bytes the policy key signed,
  which is what makes check 7 possible offline; adding an optional member keeps
  the frozen tag. A forger who rebuilds the whole tree consistently still cannot
  produce that signature — three new tamper vectors are receipts where every
  structural check passes and the receipt proves nothing.
- **`merkl.signer` — the co-signer process.** Ed25519 keystore encrypted at rest
  behind a three-method port so a Nitro keystore drops in; agent-signed requests
  with nonce and expiry (`merkl-signer-request-v1`) verified against the key in
  the policy, never the key in the request; sealed, sequenced state that refuses
  to roll back; JSON-RPC over a Unix socket, documented in `docs/SIGNER-RPC.md`
  as the same contract phase 3 speaks over vsock.
- **The anchor placeholder** (`RECEIPT-SPEC.md` §3.4) resolves the ordering
  problem in the split tree. LEFT covers the policy decision, so it cannot exist
  before the signer decides — yet the transaction has to carry it. The adapter
  prepares 32 zero bytes, the signer checks they are untouched, writes LEFT over
  them itself and signs the result, and the adapter reproduces the same bytes
  independently. The signer never parses a rail's binary format to know that the
  memo it authorized is the memo that settles.
- **`merkl.adapters`** — `fake` (a deterministic in-memory rail that enforces
  2-of-2 quorum and refuses a lone signature with `BAD_QUORUM`), `xrpl`
  (multisigned Payments anchored by memo, treasury bootstrap that installs the
  signer list before disabling the master key and then reads the account back,
  settlement-proof capture from the validations stream), and `signer_dev`
  (SignerPort clients over a socket and in-process).
- **`ReceiptBuilder`** (`merkl/sdk/receipts.py`) — propose → route → co-sign →
  settle → attest. Re-prepares the transaction with the real commitment and
  requires it to equal the bytes the signer signed before submitting; releases
  the reservation when a rail refuses; commits the envelope hash as one
  `transaction` action in the enclosing session, optionally and one-way.
- **`merkl signer serve`, `merkl treasury init --xrpl-testnet`,
  `merkl treasury verify`.** Extras `[xrpl]` and `[signer]`.
- **Scenario suite**: five scenarios (benign payment, prompt-injection drain,
  over-threshold with 2-of-3 approval mixing a passkey and a key, structuring
  across a sliding window, reference mismatch) green against the in-memory rail
  and against XRPL testnet (`MERKL_XRPL_TESTNET=1`, skipped otherwise).
- **New vector file** `approvals.json`: WebAuthn and Ed25519 assertions, valid
  and invalid, plus quorum counting. The three vector receipts now carry real
  Ed25519 policy signatures, anchors equal to their own LEFT and transaction
  hashes that derive from their blobs.

### Changed

- `Settlement` gains optional `policy_signature`; `DEFERRED_CHECKS` drops the
  four checks this phase implemented and keeps `signer.attestation` (phase 3),
  `settlement.ledger_inclusion` (phase 4) and `session.log_join` (phase 4).
  Committed vectors were regenerated for both reasons.
- `merkl.core` now imports `cryptography` — a declared runtime dependency
  already — to *verify* signatures. It still makes none: no private key enters
  the pure core.

- **`merkl.core` — the pure core of Merkl's proof formats.** No HTTP, no
  database, no filesystem, no clock, and no dependency beyond the standard
  library and `merkl.shared`. It holds the Merkle tree and inclusion proofs
  (moved out of merkl-api with byte-identical semantics, plus subtree roots so
  the halves of a receipt tree are addressable), `merkl-leaf-v1` as a function of
  plain fields rather than a server record, and the new co-signer receipt:
  `merkl-receipt-leaf-v1`, Intent v1, the seven-leaf split tree, the envelope,
  selective disclosure and structural verification.
- **`docs/RECEIPT-SPEC.md`** — normative, every byte. Leaf encodings, leaf order,
  the 7-to-8 padding and the LEFT/RIGHT split, the envelope's canonical form, the
  disclosure format, and the verification order with each check marked
  implemented or deferred to a named phase.
- **Test vectors** in `merkl/core/vectors/`: Merkle trees, action leaves, receipt
  leaves, three complete receipts (allowed, denied, escalated-then-approved) and
  22 tamper cases, each naming the exact checks a conforming verifier must fail.
  Plain JSON with lowercase hex and no floats, so a second implementation in
  another language can load the same files. Regenerate with
  `python -m merkl.core.vectors.generate`.

Nothing existing changed: `merkl.shared`, `merkl.sdk`, the hook, the CLI and the
integrations are untouched, and the frozen `merkl-leaf-v1` encoding is pinned
byte-for-byte against merkl-api's own implementation by a committed fixture.

## [0.1.1] - 2026-09-04

### Fixed

- **Claude Code hook lost whole sessions when two notaries were configured.**
  Hook state was keyed on the Claude session id alone, so a machine running the
  hook against both a local dev server and production had the two processes
  share one state file, race to open a session, and then post every later action
  to a session id the other backend had never issued. The 404 failed a bare
  `resp.is_success` check and the action was dropped with no signal — one
  affected workspace recorded 481 `human_input` leaves against 10 `tool_call`s.
  State is now scoped per `(conversation, endpoint, API key)`.
- Hook state is written atomically. Tool calls in one assistant turn run
  concurrently, and a truncated read left the other process with a blank state,
  which opened a duplicate session.
- A session id the notary does not recognise now self-heals: the hook reopens a
  session and retries once, with dependency edges cleared — they pointed at
  leaves in a session that no longer existed.
- Session goal is taken from the `UserPromptSubmit` payload. The session is
  opened before Claude Code flushes the prompt to the transcript, so reading the
  transcript at that moment found nothing and sessions were recorded under the
  placeholder goal `"Claude Code session"`.

### Added

- `MERKL_DEBUG=1` logs rejected posts to stderr. Silence is what let the above
  go unnoticed.
- Hook state files older than seven days are cleaned up. `reset_for_resume()`
  deliberately keeps them past `SessionEnd`, so they accumulated indefinitely.

## [0.1.0] - 2026-09-03

Initial release. Python SDK, Claude Code hook, and `merkl` CLI.

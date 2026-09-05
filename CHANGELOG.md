# Changelog

All notable changes to `merkl-sdk`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut by pushing a `v<version>` tag; see
`.github/workflows/release.yml`.

## [Unreleased]

### Added

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

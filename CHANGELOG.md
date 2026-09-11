# Changelog

All notable changes to `merkl-sdk`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut by pushing a `v<version>` tag; see
`.github/workflows/release.yml`.

## [Unreleased]

## [0.3.0] - 2026-09-10

### Added — phase 17, the five-minute setup

- **`$MERKL_HOME`, and a home that holds everything.** Every command's `--home`
  now defaults to `$MERKL_HOME`, else `~/.merkl/signer`. `treasury init` writes
  the seed file, each agent's Ed25519 request key, the relay tokens, the notary
  record and the policy under it — nothing outside it and the agent bundle. The
  image sets it to the volume, so the printed `docker run` lines carry no
  `--home` and `signer serve` needs no `--policy`.
- **`merkl treasury init` is the whole setup, in the order the customer sees.**
  It makes the treasury, its agents and one request key each; enrols with the
  notary *before a single transaction*, so the page they left open can show them
  an address to fund; on mainnet prints the minimum the network itself says the
  account needs and polls until it is there; asks for the sentence; installs the
  trust lines, the signer list and `asfDisableMaster`; reads the account back;
  reports ready; and leaves an agent bundle. `--enrol TOKEN --notary URL`,
  `--confirm SENTENCE`, `--agent-dir PATH`, `--bundle-to-notary` are new; the
  operator's `--wallet-file` flow is unchanged and pinned by a test.
- **Mainnet no longer needs an existing seed file.** With none, fresh keys are
  generated locally and the address is printed to fund — an XRPL account exists
  the moment somebody pays into it. An existing file is still read, never
  written over.
- **The agent bundle.** `trader.toml`, `agent-ed25519.pem`, `wallet.json`,
  `relay-token.txt` and `notary-api-key.txt`, the last four at `0600`, written to
  `--agent-dir` (default `/agent` in the image, else `<home>/agents/<id>/bundle`)
  or sent to the notary for a signer Merkl runs. The config is
  `examples/trader/config.example.toml` filled in line by line, comments intact;
  every path in it is relative, so the folder can be moved or downloaded. The
  treasury's own seed is never in one.
- **`merkl signer serve` follows the notary.** With a `notary.json` in `<home>`
  it waits for the first published policy (every 10 s), picks up changes (every
  30 s), pulls the approvals people gave in the dashboard (every 5 s while it
  holds pending escalations, else 30 s) and heartbeats with the hash actually in
  force. Everything pulled is verified here — a policy against the pinned admin,
  an approval against the policy's approvers — so the notary is a postbox and
  never an authority. `docs/SIGNER-RPC.md` §7 is normative.
- **`merkl signer bootstrap`** — `treasury init` non-interactively (mainnet
  requires `--confirm`, exit 5) and then `serve`, in one process. What a managed
  container runs.
- **`merkl treasury enrol --enrol TOKEN --notary URL`** — re-sends both notary
  calls from what is on disk. The one failure this setup can have that leaves
  nothing to undo now has a one-line fix, and `init` exits 7 and prints it
  rather than pretending the treasury is not there.
- **`merkl signer token add <id> --env`** prints the two finished lines
  (`MERKL_SIGNER_TOKEN=`, `SIGNER_RELAY_TOKENS=`) instead of the bare token.
- **`api_key_file` in the trading agent's config**, beside `api_key_env`. Both
  work; the file wins, because everything else in a bundle is already a file.

### Fixed

- **An approved escalation can be submitted by the process that resumes it.**
  `ReceiptBuilder.resume()` prepared the transaction again, and a rail autofills
  the sequence, fee and last-ledger from the ledger *now* — minutes after the
  policy key signed, often in a process that never prepared this payment — so the
  bytes no longer matched and the payment was refused with `the anchored
  transaction differs from the bytes the policy key signed`. Inside one process
  `execute` got away with it only because adapters memoise their autofill.
  `ReceiptOutcome` now carries `prepared_tx` while a decision is pending, and
  `resume(prepared_tx=…)` rebuilds the anchored transaction from it through the
  new `SettlementPort.anchored_from_content` (XRPL and fake adapters) instead of
  preparing afresh. The comparison against `signed_payload` is untouched and is
  still the last word: a tampered record is refused, and so is one from another
  payment. `examples/trader` persists `prepared_tx` in its pending record, so an
  agent restarted mid-escalation can still finish it.
- **A transaction lives as long as the intent it carries.** The XRPL adapter set
  `LastLedgerSequence` from xrpl-py's default of twenty ledgers — about seventy
  seconds — which is right for a payment submitted immediately and useless for
  one waiting on a person. It is now derived from the intent's own `expires_at`:
  `ceil(seconds_remaining / 3.5) + 4` ledgers, floored at twenty, in the pure
  `merkl.adapters.xrpl.last_ledger_for`.
- **An escalated receipt now reaches the notary with its open challenge.**
  `ReceiptBuilder` built the `pending_escalation` block *after* filing, so
  `POST /v1/receipts` never carried it: the receipt landed, the escalation row
  was never opened, and the dashboard's Approvals page said "nothing is waiting
  on a person" for a payment the signer had escalated. The block is built first
  and passed through to `HttpNotary`, which sends it as `docs/INTERFACES-P4.md`
  sec 2 describes. Passed only when there is one, so a notary implementation
  written against the older `NotaryPort` signature keeps filing settled and
  denied receipts unchanged.

### Changed

- **The signer image**: `MERKL_HOME` and `MERKL_AGENT_DIR` set, `/agent` created
  writable, `CMD` reduced to `["signer", "serve"]`. The entrypoint supervises the
  forwarder for `signer bootstrap` as well as `signer serve`, and after any other
  subcommand hands `/agent`'s contents back to whoever owns the directory — so a
  bind-mounted `./merkl-agent` is readable on the host without sudo.
- **`merkl.signer.forward` answers `503 signer_unavailable`** — a constant, in
  this protocol's own error shape, written on connect failure before a byte of
  the request is read — instead of dropping the connection. A signer waiting for
  its first policy and a container that never started are different facts, and a
  refused TCP connection cannot tell them apart.
- **`RpcRouter.dispatch_local`**: in-process dispatch that takes the same lock
  and skips the relay-bearer check. In-process is not a relay. `build_server` and
  `serve` accept the router so there is exactly one per engine — two would let a
  call over the socket and a call applied in-process read the same window.
- **`merkl.adapters.notary` is a package** (`client`, `enrol`, `follower`).
  `from merkl.adapters.notary import HttpNotary` is unchanged.
- **`bootstrap_treasury` split** into `create_wallets` and `install_signer_list`,
  because something now happens in between: the enrolment call, and on mainnet
  the wait for money. The one-call form stays for callers with nothing to do
  there.

### Added — phase 14, the agent may trade

- **Intent v1 gains `type: "swap"`.** A trade sells at most `sell.max_amount`
  and buys exactly `buy.amount`, settling to the treasury itself. On XRPL that
  is a cross-currency Payment to self — `Amount` is the buy side, `SendMax` the
  sell ceiling, no `Paths`, no `DeliverMin`, no `tfPartialPayment` — so the
  ledger delivers exactly what was asked for at most the ceiling or the
  transaction fails, and the agent's limit price is enforced by the chain.
  Additive: a payment intent is unchanged to the byte.
- **The sold side is the outflow.** `per_tx_cap`, `windows` and
  `tiers.human.thresholds` read `sell.max_amount`, both currencies must be on
  the agent's `allowlist_assets`, and `allowlist_destinations` does not apply.
  No new arithmetic — a trade is capped, windowed and escalated by exactly what
  bounds a payment.
- **`may_swap`**, a new agent-section member. False when absent and omitted from
  the hashed content when false, so every `policy_hash` signed before this
  release is unchanged. A trade by an agent without it is denied with
  `may_swap: agent may not trade`. A `may_swap` agent must allowlist at least
  two assets, or the grant is one of the rules a document may not carry.
- **Leaf 5 gains `delivered` and `spent`** — what the rail's own metadata said
  arrived and left, never the intent's numbers copied across. Check 9 holds a
  trade to both: `delivered` must equal the buy side exactly, `spent` must stay
  inside the ceiling. Either absent is reported by name as unchecked.
- **The card reads a trade.** `Bought`, `Sold … (limit …)` and `Rate`, the rate
  to six significant digits by integer arithmetic in both implementations. A
  refused trade reads `Asked to buy X for up to Y`.
- **`merkl treasury init --trust CODE.issuer`** sets trust lines before the
  signer list is installed and the master key disabled, and `--xrpl-mainnet`
  runs the bootstrap against mainnet: no faucet, wallets from the operator's own
  0600 seed file, the network's own reserve arithmetic printed, a typed
  confirmation, and `policy.network` recorded as `xrpl-mainnet`.
- **`history()` reads a trade as a trade**: the outflow is what was spent, and
  the delivered amount comes back on `Outflow.inflow_value`/`inflow_asset`.
- **A sixth demo scenario**: the agent trades inside its cap, is capped when it
  sizes up, and is refused in an asset it may not hold.

## [0.2.1] - 2026-09-10

### Fixed

- **The signer image no longer crash-loops on first boot.** Its command asked
  `merkl signer serve` for `--host 0.0.0.0`, which `merkl.signer.server` refuses
  — "use a Unix socket, or bind loopback and put your own proxy in front of it"
  — so `ghcr.io/ramcav/merkl-signer:0.2.0` died the moment it started. The guard
  is right and is unchanged. The image now runs the proxy it names: the signer
  binds a Unix socket, and `merkl.signer.forward` (new, stdlib asyncio, no new
  dependency) listens on `$MERKL_SIGNER_LISTEN` — `0.0.0.0:8787` by default —
  and relays to it byte for byte, parsing nothing and refusing nothing. What
  faces the network holds no key; authentication stays in the signer, where it
  is audited. `docker run -p 127.0.0.1:8787:8787` and a compose service reached
  as `signer:8787` both work. The two processes are supervised as one pair: if
  either exits, the container exits with that code, and every other subcommand
  (`treasury init`, `signer token`, `policy show`) still passes straight through
  the entrypoint. A `docker stop` exits `0` rather than reporting the signal.
- **A refused relay token is no longer echoed back to the caller.** The
  rejection took the bearer's id as everything before the first `:` — so a
  bearer with no `:` in it, a bare secret, came back whole in the error message,
  into the caller's terminal and its logs. A wrong-but-real credential pasted
  into the wrong signer was leaked by the signer itself. The message now names a
  token id only when this signer already holds one under that name, and says
  nothing at all about the bytes presented otherwise.

### Added

- `@merkl-ai/verify` exports `./package.json`, so a consumer can read the
  version of the verifier it has installed.

## [0.2.0] - 2026-09-07

### Added — phase 11

- **The receipt is a document.** `ReceiptCard` (`merkl.core.verify.card` and
  `receiptCard()` in `@merkl-ai/verify`) is the one structure `verify.html`,
  `merkl receipt show` and `merkl verify` render: status first (SETTLED /
  REFUSED / …), five body lines (Paid or Asked, To, From, By, On, Ref),
  provenance (Because, Allowed by, Approved by, Signed by), a VERIFIED stamp
  with level, and the seven leaves folded under Details. Vectors in
  `cards.json`.
- **XRPL agent conventions.** Every co-signed Payment carries `SourceTag`
  (default `20260907`, overridable per agent, hash-neutral when omitted) and
  a second memo (`MemoType` `agent`) with `{action, agent_id, session_id,
  task_id}`. The signer codec requires exactly those two memos, in that
  order. `merkl treasury init` still escalates every payment until a
  threshold is written.


### Added — phase 10

- **`ReceiptBuilder` files the settlement capture with the receipt.** The rail
  adapter captured a `SettlementProof` at submit time and the flow dropped it.
  Leaf 4 commits only a `settlement_proof_ref` — sixteen characters of
  transaction hash — so the ledger header, the transaction and the validators'
  signatures a reader needs to establish inclusion *offline* existed nowhere
  but in memory, and every receipt this SDK produced read `ledger inclusion:
  unchecked — no settlement proof was supplied`. Two new ports in
  `merkl.core.ports`: `NotaryPort` (`file_receipt`, with the proof inline, and
  `file_settlement_proof` for a capture completed afterwards) and
  `SettlementProofStorePort` (`put_settlement_proof`), the latter its own port
  rather than a fourth argument to `ReceiptStorePort.put` so a store written
  against the older shape keeps working — the builder probes for the method and
  never assumes it. `merkl.adapters.notary.HttpNotary` implements the first
  against merkl-api (`POST /v1/receipts` with `settlement_proof`, falling back
  to `POST /v1/receipts/{id}/settlement-proof`);
  `merkl.sdk.receipt_store.LocalReceiptStore` implements both over
  `~/.merkl/receipts`, beside the evidence log and in the shape `merkl disclose`
  and `merkl receipt show` already read, so an offline disclosure reaches
  `proven-offline` with no notary in the picture at all. A notary that is down
  never fails a settled payment: `ReceiptOutcome.notary_error` carries the
  failure rather than raising it (plan D12).

- **`ReceiptVerdict.not_checked`** — every check that did not run, each with the
  reason the check gives itself, plus `not_checked_line` and `verdict_line`
  rendering them. Both pages previously reduced this to one generic clause
  ("some checks are not implemented in this browser or unconfigured"), which is
  true of every incomplete verdict and tells a reader nothing about which fact
  is still open on the one in front of them. `@merkl-ai/verify` exports
  `notCheckedOf`, `notCheckedLine` and `CHECK_LABELS`, and `verdicts.json`
  records all three members for both implementations.

### Changed — phase 10

- **`level_detail` is one sentence that names its own level**
  (`LEVEL_DETAIL_RECEIPT` / `LEVEL_DETAIL_SESSION`, exported from both
  implementations). `verify.html` and `merkl verify` used to prefix "Level 2."
  to a string that already began "level 2:".

- **A session bundle's action rows are located by the leaf their proof names**,
  not by their position in `actions[]` (`merkl.core.verify.log.leaf_index_of`,
  `leafIndexOf` in JS). A full export lists every action in leaf order so
  nothing changes for one; a bundle *scoped* to a single receipt carries one row
  that may be leaf 5 of twelve, and reading its position joined the receipt to
  whatever was listed first. This is what lets a receipt page reach level 2
  without shipping the whole session (`merkl-api/docs/SPEC.md` §9).

- **An unsealed session says so** rather than reading as a bare level 1: when a
  bundle's session is not sealed, `session.log_join` reports `not_implemented`
  with "session … is not sealed yet; level 2 becomes available after sealing".

### Fixed — phase 10

- **A session with no root yet reads as incomplete, not contradicted.** An
  unsealed session states `root_hash: null`, and `str(None)` is the four
  characters `"None"` — truthy, so `verify_log_bundle` held every inclusion
  proof against it, found that none landed there, and failed
  `log.session_root`. A receipt filed before its session sealed therefore read
  as `SOMETHING WAS CONTRADICTED`, the loudest verdict the format has, about a
  session that had simply not been sealed yet. The JS half already coalesced
  the null correctly, so the two implementations disagreed and no vector had a
  null root to catch it; `verdicts.json`'s `receipt-page-session-open` now
  carries one.

- **`@merkl-ai/verify`'s terminal entry point** (`cli.mjs`) prints the level
  once, prints leaf 6's note under the testimony sentence, and names each
  unchecked check with its reason — the same three corrections as `merkl
  verify`, which it is supposed to agree with line for line.

### Changed — phase 10 (continued)

- **The plain summary carries leaf 6's `note` as its own member**
  (`summary.testimony_note`), rendered under the testimony sentence in a quieter
  style rather than run into it — one is the verifier speaking about what a
  committed hash establishes, the other is the agent speaking about itself. An
  unattested signer's line now adds "expected for a dev signer; a Nitro signer
  attests", because leaf 3 being null is the normal state of a dev deployment
  and reads as an alarm without it.

### Added — phase 9

- **`PolicyDocument.network`** — `xrpl-testnet` or `xrpl-mainnet`, optional,
  and **omitted from the content when unset**, so every `policy_hash` signed
  before this field existed is byte-identical and every admin signature over
  one still verifies. `rail` names a settlement family; `network` names one
  ledger in it, and the allowed values live beside `rail` in
  `merkl.core.rail.NETWORKS_BY_RAIL`. The same `rXXX` on testnet and on mainnet
  are unrelated accounts, so "xrpl" alone never said where the money goes.
  `merkl signer serve --rail-endpoint <url>` (or `$MERKL_RAIL_ENDPOINT`)
  refuses to start when the endpoint's host names a different chain than the
  policy — the signer makes no call, it reads the string
  (`merkl.signer.rails.network_of_endpoint`); an unrecognised host, such as a
  private rippled, is not an opinion and does not block. The XRPL codec refuses
  a payload whose `NetworkID` names another chain, and documents why that check
  is weak: mainnet is network 0 and testnet is network 1, and rippled rejects a
  `NetworkID` below 1024, so neither chain's Payments carry the field and its
  absence proves nothing. `merkl policy show` and `merkl signer serve` both
  print the network. `docs/INTERFACES-P4.md` §2 has the table merkl-api and
  merkl-dashboard build against.

- **`merkl.adapters.xrpl.history(..., ledger_index_min=)`** — bounds the
  `account_tx` read below instead of asking a full-history node for a treasury's
  whole life. Optional and unbounded by default, so an existing caller reads
  exactly what it read before; the notary passes the ledger of its earliest
  settled receipt (`docs/INTERFACES-P4.md` §7).

### Changed — phase 9

- **A policy document may no longer carry a rule the engine would never run.**
  The engine reads `per_tx_cap` and `tiers.human.thresholds` first-match-per-
  asset and `windows` all-matches-per-asset, but `to_content()` serialised
  duplicates verbatim — so a second, tighter cap was hashed into `policy_hash`,
  signed by the admin, read by a human as protection, and never enforced.
  `PolicyDocument` construction now refuses: more than one cap per asset per
  agent, more than one window per (asset, seconds) per agent, more than one
  human threshold per asset, any cap or window for an asset outside that
  agent's `allowlist_assets`, and any threshold for an asset no agent may move.
  Two windows over the same asset with *different* lengths are still both live.
  The error names the rule, the agent and the asset.
  `merkl.core.policy.unenforceable_rules(content)` is the checker, over the
  document's content so the constructor and both verifiers judge the same
  bytes; `@merkl-ai/verify` exports `unenforceableRules` and its
  `policyDocumentCheck` reports the same sentence as a `policy.document`
  failure, before the signature and before the hash, because a valid admin
  signature over a matching hash says nothing about whether a rule can run.
  Eight `document_cases` in `merkl/core/vectors/policies.json` pin the
  sentences for both implementations; the nine existing signature cases are
  untouched byte for byte.

### Fixed — phase 9

- **`merkl signer serve` against a keystore created with an explicit
  passphrase** wrote a stray `passphrase` file beside a key it could not open
  and then failed with "the keystore passphrase is wrong, or the key file is
  damaged" — a message about the wrong thing. `DevKeystore` now generates a
  passphrase file only when it is generating the key too, and otherwise raises
  naming what is missing; `serve` resolves the passphrase from
  `$MERKL_SIGNER_PASSPHRASE` or a terminal prompt, never by writing one, and
  exits 5 with the precise message. A failure to decrypt now names *which*
  passphrase was tried, and points at a stray file when that is what was tried —
  the one case this fix cannot undo is a file an older signer already wrote, and
  the old message sent people looking at the key file instead.

### Added — phase 6

- **Relay bearer authentication on the signer RPC.** Every method but
  `propose` — `health`, `public_key`, `attestation`, `approve`, `reject`,
  `settle`, `release`, `policy_update` — now accepts an optional relay
  credential: `merkl signer token add|revoke|list` writes SHA-256 digests
  only to the signer's config and prints a fresh token exactly once. Once at
  least one is configured, every non-`propose` method requires
  `Authorization: Bearer <id>:<secret>`, checked in constant time; with none
  configured a signer behaves exactly as it did before this phase. Wired
  through both transports — the HTTP `Authorization` header for the dev
  signer, and a vsock `auth` frame member the Nitro parent proxy forwards
  unchanged from the header it received (`merkl.signer.relay_auth`,
  `docs/SIGNER-RPC.md` §3, "Who may call what"). Not a fund-moving secret: it
  bounds who may push at the signer, not what a push can accomplish.
- **Policy documents may be signed by a WebAuthn admin, not only Ed25519.**
  `PolicyDocument.admin` (`{credential_type, public_key, origins?, rp_id?,
  user_verification?}`) sits beside the legacy `admin_public_key` field —
  mutually exclusive, and the legacy field still emits exactly the bytes it
  always did, so `policy_hash` for every document signed before this phase is
  byte-identical (`merkl/core/vectors/policies.json` proves it: regenerating
  touches only `manifest.json`). `SignedPolicy.signature` may now be an
  `ApprovalAssertion`-shaped object — Ed25519 or WebAuthn — over the 32-byte
  `policy_hash`, with `approver_id` fixed to `"admin"`, verified by
  `merkl.core.policy.approvals.verify_policy_signature`: one function for
  both admins and approvers, no second WebAuthn parser. `merkl policy sign
  <document.json> --key <ed25519>` is the non-browser path; `merkl policy
  show` renders a document — rules, tiers, approvers, admin — in words.
  `verifyPolicySignature` is the `@merkl-ai/verify` mirror
  (`docs/INTERFACES-P4.md` §6, "Policy signing for the dashboard", has the
  exact WebAuthn challenge and the POST body the API relays to
  `policy_update`). `PolicyChange` gains `credential_type`, naming which kind
  of admin authorized the change; it defaults to `ed25519` for change entries
  recorded before this field existed, which every one before this phase was.
- **`merkl.adapters.xrpl.history(treasury, since, *, json_rpc_url)`** — a
  module-level, read-only, wallet-free counterpart to
  `XrplSettlementAdapter.history`, for the notary's reconciliation (plan D17),
  which must never hold a signing key. Builds its own throwaway
  `AsyncJsonRpcClient` and reads `account_tx` through the same
  `_outflows_from_response` parser the wallet-holding method uses — one
  parser, not two copies of it. `docs/INTERFACES-P4.md` §7, "Reconciliation:
  reading rail history", documents the attribute-checked fallback the API
  uses and that this reads public ledger data only.
- **XRPL offline ledger inclusion is real: `proven-offline` means what it
  says.** `merkl.core.verify.xrpl` (Python) and its `@merkl-ai/verify` mirror (a
  hand-written, zero-dependency secp256k1 ECDSA verifier included — Web
  Crypto has no secp256k1) build and fold the real transaction SHAMap (16-ary
  radix trie, `MIN\0`/`SND\0` prefixes), verify `STValidation` signatures
  against the raw blob the `validations` stream publishes, and verify
  manifests (master key signs ephemeral key). A validation counts as one
  pinned master key's agreement only when its manifest verifies and names the
  key that actually signed. The XRPL adapter now captures a real `tx_path`
  from the ledger's full binary transaction set at settlement time (was
  always `missing` before this phase) and the manifest in effect for each
  validator that signed, both self-checked before publishing. `merkl xrpl
  pin-unl <url|file>` turns a published validator list (`vl.ripple.com`,
  `vl.xrplf.org`, testnet's own) into the pinned master-key set a verifier
  trusts without re-fetching it — auditing the publisher's manifest chain,
  the list's own signature, and every validator's manifest inside it.
  `merkl demo --xrpl-testnet` pins the real testnet UNL and reaches
  `proven-offline` on real settled transactions; `docs/RECEIPT-SPEC.md` §7.2
  has every byte, and `merkl/core/vectors/xrpl/` carries real testnet
  fixtures — a ledger, two validators' validations and manifests, the
  testnet UNL — with tamper cases for both implementations.

### Fixed — integration run (phase 7)

- Receipt envelopes now carry `session_locator` when a session is joined, so a
  posted receipt links back to its session and action.
- `ReceiptBuilder.resume()` finishes a payment whose escalation was approved or
  rejected out of band (through the notary relay).
- `ReceiptOutcome.pending_escalation` exposes challenge, expiry and quorum of a
  still-escalating decision so a caller can hand it to a notary.
- `SignerEngine.approve()` no longer double-counts the escalating payment's own
  reservation against its window; a payment sized at the window's edge was
  always denied on approval.


### Added — phase 5

- **`merkl demo`** — runs the five scenarios end to end and writes each as a
  self-contained `verify.html`, checked by both `merkl verify` and the new
  `@merkl-ai/verify` CLI over the same file before either is written to disk. The
  fake rail always runs; `--xrpl-testnet` (or `MERKL_XRPL_TESTNET=1`) also runs
  the same five stories against the real network, reusing the treasury cached
  under `~/.merkl` (the same wallet files `merkl treasury init` and the pytest
  suite use) so a second run does not re-drain the faucet, and prints a
  transaction hash for every payment that actually settles.
- **`merkl.demo`** — the rig, the five scenarios and the page-writer, as a
  shipped package: a real signer, a real encrypted keystore, real approvals,
  and a swappable `Environment` (`FakeEnvironment`, `XrplEnvironment`) so the
  same five stories run unmodified against either rail. A scenario's claim
  about itself raises `ScenarioError` rather than asserting, so it cannot
  silently disappear under `python -O`.
- **`@merkl-ai/verify`'s CLI** (`merkl/core/verify/js/cli.mjs`, reachable as
  `npx @merkl-ai/verify` or the `merkl-verify` bin once installed) — the same
  checks `merkl verify` runs, over a receipt, a bundle, or a rendered
  `verify.html`, in the other implementation. A scenario page that only
  `merkl verify` had checked would have been checked once; checked by both, it
  has been checked by two programs that share no code.
- **README rewritten** for the co-signer: an ASCII architecture diagram
  (`merkl.sdk` → `merkl.signer` / `merkl.adapters` → `merkl.core`), the trust
  model in plain words (who holds what, what a receipt needs to verify, what
  Merkl never has, what the customer's enclave attests), a pointer to
  `docs/RECEIPT-SPEC.md`, how to add a rail with `merkl.adapters.fake` as the
  worked example, how to run the scenarios, and how to deploy the signer (dev,
  Nitro). Sold as an AI accountability product; XRPL gets one sentence.

Ran the XRPL path for real: bootstrap reused the treasury cached from an
earlier phase, and four of the five scenarios settled with real transaction
hashes recorded (the fifth, the prompt-injection drain, is a denial and
settles nothing — that is what it is testing). Both verifiers agreed on every
page, including the ones built from real testnet transactions.

### Fixed — phase 5

- **`merkl demo --no-node` always exited non-zero, even when nothing was
  wrong.** `PageReport.agreed` requires two verifier readings by design — it
  answers "did both agree" — but with `--no-node` only the Python reading ever
  existed, so it was always `False`. `demo_command` now falls back to the
  single reading's own verdict when the JavaScript verifier was not asked to
  run, rather than reporting disagreement between a verifier and nothing.

### Added

- **Verification is now two implementations of one spec (plan D7).**
  `merkl.core.verify.receipt.verify_receipt` and `@merkl-ai/verify`'s
  `verifyReceipt` compute the same bytes, report the same check names with the
  same statuses, and reach the same verdict from the same material — down to the
  plain-language summary a reader sees. `merkl/core/vectors/verdicts.json`
  records each verdict beside the exact settlement proof, validator set, policy
  document and session bundle it was reached from, and both suites assert
  against it. A divergence is a bug in one of them, never a difference.
- **One verdict, never one boolean.** The settlement result is two lines (plan
  D10): *transaction authorization* (`verified` / `absent` / `contradicted`) and
  *ledger inclusion* (`proven-offline` / `verified-live` / `supplied-unverified`
  / `unchecked`). Above them sits the level (plan D9): level 1 is the receipt
  against the signer key and the rail; level 2 additionally joins the session
  log. And above that, five sentences — what the agent was told, which rule
  allowed it, who approved, what settled, when — because a receipt whose meaning
  only survives as hex has not been verified by anybody who matters.
- **Three checks the format defined and nothing ran.**
  `policy.escalation_challenge` recomputes `LEFT_pre` from the finished receipt,
  so a reader can see the approvers signed *this* payment.
  `policy.approval_quorum` counts distinct approvers the policy names.
  `policy.document` looks the policy up **by hash** — a policy replaced since
  cannot be shown in place of the one that decided — and verifies its admin
  signature when the caller pins the key.
- **`merkl.core.verify.settlement` — what a settlement capture actually proves.**
  Three separate checks, because collapsing them is how a verifier claims more
  than it holds: is the proof about this transaction, does the header hash to the
  ledger hash it claims (XRPL's `LWR\0` preimage, recomputed), and did a quorum
  of validators the *verifier* pinned sign that hash. `settlement.ledger_inclusion`
  needs one more link — a path folding the transaction into the header's
  transaction root — which XRPL captures still lack and name in their own
  `missing` list.
- **`merkl.core.verify.log` — sessions, the transparency log and evidence, in
  Python.** Action leaves, session inclusion, the `merkl-entry-v1` chain, RFC 6962
  log inclusion, the checkpoint body and its Ed25519 signature, the continuation
  binding, and disclosed evidence records. These existed only in JavaScript,
  inside a page merkl-api rendered — one implementation of a normative format,
  living in the wrong repository.
- **`verify.html` and the JavaScript verifier move into the SDK**, rendered by
  `merkl.core.verify.render.render_verify_html(bundle)` — the function merkl-api
  calls, taking a session bundle, a receipt-only bundle or a disclosure. The page
  leads with sentences and keeps every hash behind an expander, shows an
  unattested signer loudly rather than as a missing field, labels reasoning as
  testimony, names every check it could not run, and keeps the evidence
  drop-zone. It is one self-contained file that opens from a USB stick with no
  network.
- **`@merkl-ai/verify`** — the same algorithms in JavaScript, no dependencies, Web
  Crypto only: canonicalization ported escape for escape, the frozen leaf
  encodings, the receipt tree, WebAuthn and Ed25519 approvals, a CBOR reader
  restricted to the attestation profile, an X.509 reader for the four fields a
  chain check needs, AWS Nitro attestation, settlement proofs and the session
  log. 172 tests under `node --test`, no bundler, published from the same tag as
  the PyPI distribution (plan D19).
- **CLI.** `merkl verify <receipt|bundle|verify.html>` — the rendered page an
  auditor was emailed is itself a valid input, so disagreeing with it is
  something you can check. `merkl receipt show` reads the seven leaves out loud.
  `merkl disclose --leaves` ships a selective disclosure whose withheld leaves
  are hashes proving only that they exist unedited, and renders the page locally
  so a disclosure survives the notary being down. `merkl approve` / `merkl
  reject` sign an escalation with a local Ed25519 key. `merkl reconcile` matches
  outflows to receipts in both directions — the direction that matters finds
  money leaving with no co-signed authorization behind it.
- **Signer RPC `reject(challenge, assertions)`** (plan D11). Verified like
  `approve`, records a DENY whose leaf 2 carries the signed refusals, releases
  the reservation. An escalation that simply stops being mentioned proves nothing
  about whether anybody looked at it.
- **`docs/INTERFACES-P4.md`** — the contract merkl-api and merkl-dashboard build
  against: the renderer's name and signature, the bundle v1.2 members the
  verifier reads, the `@merkl-ai/verify` API, the fixtures, and which files in
  merkl-api become deletable.
- **New fixtures.** `verdicts.json` (4), `bundles/` (three real merkl-api exports
  plus 9 mutations), and a fourth receipt settled on the fake rail so
  `proven-offline` is a state both implementations reach rather than a branch
  nobody runs. `py.typed`, so merkl-api's mypy stops seeing this package as
  untyped.

### Fixed

- **The rendered session verifier had been throwing since summaries were
  removed.** merkl-api's template referenced `#actions-tbody`, `#root-hash`,
  `#total-count` and `#verified-count` from its JavaScript but stopped declaring
  any of them in its HTML, so every session page failed at `tbody.appendChild`
  and showed "Error" in the badge. The SDK template declares the table.

### Changed

- `DEFERRED_CHECKS` is empty of phase markers: `settlement.ledger_inclusion` and
  `session.log_join` are implemented, and `verify_receipt_structure` now reports
  them as needing material a receipt cannot carry, naming the function that takes
  it. Its own behaviour is unchanged.
- The fake rail captures a transaction-set root, a path to it and signed
  validations, so its settlement proofs have an empty `missing` list. XRPL still
  names `shamap_path`. `SettlementProof` gains `tx_path`.
- The receipt vectors' `policy_hash` is now a real `PolicyDocument`'s hash rather
  than a digest of a sentence, so `policy.document` and `policy.approval_quorum`
  can be exercised at all. Committed fixtures were regenerated.

### Added — phases 1-3 of this cycle

- **`merkl.core.verify.attestation` — AWS Nitro attestation documents, verified
  offline.** Parses the NSM's COSE_Sign1, walks the certificate chain to the AWS
  Nitro Attestation PKI root embedded in the package (SHA-256
  `641a0321…`, published as a zip whose digest is `8cf60e2b…`), checks the ES384
  signature over a *rebuilt* `Sig_structure`, and reports nine named checks:
  format, chain, certificate validity, signature, freshness, PCR allowlist, debug
  mode, and the two bindings to the receipt. Certificate validity is measured at
  the document's own timestamp rather than at `now` — an NSM leaf certificate
  lives about three hours, and a receipt is read years later. `now` is an
  argument everywhere, so verification is reproducible and `merkl.core` still
  reads no clock.
- **`merkl.core.verify.cbor` — the CBOR profile it needs, stdlib only.**
  Definite lengths, shortest-form heads, no floats, no tags but COSE's, no
  duplicate map keys, bounded depth and element counts. `cbor2` would have been a
  dependency for the auditor, the JS verifier and the enclave image alike, in
  order to accept shapes an attestation document may not contain. The
  deterministic writer is not optional: verifying a COSE_Sign1 means re-encoding
  the `Sig_structure` and checking the signature over *those* bytes.
- **Check 8 runs.** `verify_receipt_structure` takes `attestation_trust` and
  `now`, and holds leaf 3 against the envelope: the attested key must be
  `signer_public_key` and the attested `user_data` must be `policy_hash`. Without
  both, a genuine attestation from any enclave could be stapled to any receipt.
  The allowlist and the moment are arguments, never values read from the receipt.
  A null leaf 3 reports that the receipt *proves* it came from an unattested
  signer, which is a fact rather than a gap.
- **Attestation vectors: three documents AWS actually signed.** From
  `evervault/attestation-doc-validation` (Apache-2.0, commit `10cc232f`), with
  provenance, in `merkl/core/vectors/attestation/`. Seventeen cases including
  tamper cases where the chain does not reach the pinned root, a PCR is edited
  inside the signed payload, the timestamp is moved past the certificate window,
  and a debug-mode enclave is refused. Every document is expired, which is the
  point: only a verifier that takes `now` as an argument can check them at all.
- **`NitroKeystore` and `merkl.signer.attestation`.** The policy key is generated
  inside the enclave from NSM entropy mixed with the process CSPRNG, sealed
  through a two-method `SealingPort` and handed to the parent as a ciphertext;
  later boots open it only if the enclave measures the same. `attestation()`
  asks the NSM for a fresh document on every call, binding the policy public key
  and the current policy hash — read through a callable, so a `policy_update`
  reaches the next attestation on its own. The NSM client is one `ioctl` on
  `/dev/nsm` with CBOR on both sides, so no compiled dependency enters the image
  whose every byte is measured into PCR0.
- **`merkl.signer.vsock` — the same RPC, over the only wire an enclave has.**
  Four bytes of length and then the same JSON. `server.handle_request` is now
  transport-independent and both transports go through it; a test asserts they
  answer byte-identically for the same router.
- **`merkl.adapters.nitro` — KMS with the attestation as the credential.**
  `kms:Decrypt` carrying the enclave's attestation as `Recipient` returns a CMS
  envelope wrapped to an ephemeral key that exists only inside the enclave, so
  the parent proxies the HTTPS and reads nothing. `cryptography` does not do CMS,
  so `cms.py` walks exactly that structure and refuses every other — more than
  one recipient, PKCS#1 v1.5 key transport, `AuthEnvelopedData`, non-minimal or
  indefinite DER lengths. Tested against envelopes `openssl cms` produced. Two
  KMS backends, `kmstool_enclave_cli` and botocore, behind the `[nitro]` extra.
- **`merkl.adapters.signer_nitro`.** A subclass of `DevSignerClient` that adds no
  RPC method — the parent proxy speaks the same contract, so an attested signer
  is a constructor change. It adds `attestation_report()` and `assert_attested()`
  for the question only an attested signer can answer.
- **`nitro/` — the deployment.** Enclave image (installing the rail codec extra,
  because the codec is what makes the policy signature mean something and must be
  measured with the key it protects), parent proxy, and Terraform whose KMS key
  policy conditions `kms:Decrypt` on `kms:RecipientAttestation:PCR0/1/2/8` while
  leaving `kms:Encrypt` unconditioned — that condition key is not evaluated for
  `Encrypt`, and conditioning it would deny the first boot the ability to seal
  the key it just generated. `nitro/README.md` carries the runbook, the threat
  notes, and a table of exactly which artifacts were executed and which were only
  written.
- **`docs/ATTESTATION-VERIFY.md`** — normative for check 8 and for the phase-4
  JavaScript verifier, specified byte by byte.


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
- **The signer reads the bytes before signing them.** `merkl.signer.rails`
  decodes the exact payload — after the anchor write — and holds it against the
  intent: transaction type, account, destination, amount (drops for XRP, numeric
  for issued currencies, since XRPL normalises the mantissa), exactly one memo
  whose data is LEFT, and an **allowlist** of fields so `SendMax`, `DeliverMin`,
  `Paths`, `DestinationTag`, `tfPartialPayment` and anything unforeseen are
  findings by construction. The settlement adapter runs in the agent's process,
  so its account of what its bytes encode was the one thing still taken on trust.
  A mismatch is a DENY decision with a `rail.payload_encodes_intent` rule and a
  receipt, and the reservation is released. The codec is resolved at boot from
  the policy's `rail` and the signer refuses to start without one; it loads
  lazily behind the `signer-xrpl` extra so the signer's base stays on
  `merkl.core` and `merkl.shared` alone.
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

### Changed — phases 1-3 of this cycle

- `Check`, `CheckStatus` and `VerificationResult` moved to `merkl.core.checks`,
  shared by both verifiers. `merkl.core.receipt` re-exports them unchanged.
- `signer.attestation` left `DEFERRED_CHECKS`. Two remain, both phase 4.
- `merkl.signer.server.handle_request` is public and transport-independent.
- `Settlement` gains optional `policy_signature`; `DEFERRED_CHECKS` drops the
  four checks phase 2 implemented, and phase 3 removed a fifth. Two remain:
  `settlement.ledger_inclusion` and `session.log_join`, both phase 4. Committed
  vectors were regenerated for both reasons.
- `PolicyDocument` gains a required `rail` member: a policy that does not say
  which ledger it governs cannot tell the signer which codec to load.
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

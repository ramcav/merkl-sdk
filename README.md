# merkl-sdk

Merkl makes AI agents accountable. It records what an agent did and fingerprints
every action so the record can't be quietly edited later. And when an agent is
trusted to move money, Merkl adds a second key: nothing settles unless a policy
the customer wrote and pinned agrees with what the agent is asking for. Either
way, the result is a receipt anyone can check in a browser, offline, without
asking Merkl and without an account.

Homepage: [merkl.ai](https://merkl.ai) · Dashboard: [app.merkl.ai](https://app.merkl.ai)

## Install (Claude Code)

```bash
pip install merkl-sdk
merkl install --claude-code --global
```

The installer asks for an API key (`mk_...` from [app.merkl.ai](https://app.merkl.ai)) and wires Claude Code. Restart Claude Code or run `/hooks`. After that, every session records automatically.

**Prefer to have your agent do it?** Point it at `INSTALL.md` — it drives the install and only asks you for the API key.

## How it works

<img alt="Recording flow: the agent's actions and prompts are hashed locally; raw payloads stay in the local evidence log; only hashes and metadata reach the Merkl API, where leaves form a Merkle tree at seal, the root is appended to the append-only log, and the log state is Ed25519-signed as a checkpoint." src="docs/recording.png">

The hook computes a SHA-256 hash of each action on your machine and sends only the hash to the Merkl API. A hash works like a fingerprint: it identifies the data exactly, but you cannot reconstruct the data from it.

When a session ends, its hashes are combined into a Merkle tree and the result is added to a log that can only grow. Merkl signs that log. If anyone changed or deleted an old entry (including us), the hashes would stop lining up and any auditor who checks would see it.

On a timer, the signed log's fingerprint is submitted to [OpenTimestamps](https://opentimestamps.org), which commits it into the Bitcoin blockchain. Once that lands, the timestamp is anchored to Bitcoin: not even Merkl can backdate what happened, and anyone can check it against the chain with the standard `ots` tool — without trusting Merkl or the calendar.

## What leaves your machine

Merkl's servers see three things: tool names, timestamps and status, and hashes. The raw data goes into a local file that is never uploaded:

```
~/.merkl/evidence/<session>.jsonl
```

Plaintext previews are off unless you opt in.

- `MERKL_INCLUDE_PREVIEWS=1` sends short plaintext previews along with the hashes
- `MERKL_EVIDENCE_DIR=off` turns off local evidence capture
- `MERKL_AGENT_ID` and `MERKL_ENDPOINT` set the agent's label and the server (default `https://api.merkl.ai`)

## When you actually need it

Say a customer claims your agent refunded the wrong amount. You look up the action and run:

```bash
merkl disclose <action_id>
# → disclosure-<id>/
#     verify.html      the verification page, with the proofs baked in
#     bundle.json      the same data, for `merkl verify` or your own tooling
#     evidence.jsonl   the raw record of that one action, nothing else
#     README.txt       what this is and how to check it
```

Send them the folder. They open `verify.html` in any browser. It works offline, needs no account and installs nothing. They drop the evidence file on the page, and it recomputes the hashes and compares them against what was recorded when the action ran. If the record was edited afterwards, even by one character, the numbers won't match and the page says so.

<img alt="Verification flow: the operator runs merkl disclose and emails verify.html plus one evidence record; the auditor opens it offline with no account, drops the evidence file, and the record is re-hashed and compared to the committed Merkle leaf. A match verifies via Merkle proof, log inclusion and signature; a mismatch means the payload was altered." src="docs/verification.png">

The fingerprint was recorded when the action ran, and the dispute comes later. You cannot go back and doctor a record to fit your story. Neither can we. You disclose only what you choose; the other actions in the session stay as hashes.

## When an agent moves money

Recording is a fingerprint after the fact. A payment needs something stronger:
nobody, including the agent's own developer, should be able to point it at an
account the policy never approved. So a payment isn't authorized by the agent's
key alone. It needs a second signature from a **policy signer** — a separate
process that holds a key of its own, evaluates a policy document the customer
wrote and signed, and only signs if the payment agrees with it. The agent can
propose anything a prompt injection or a bug tells it to. It cannot make the
second key sign.

### Who holds what

| | |
|---|---|
| The agent's key | Signs its half of the transaction. Compromising it gets you one signature out of two. |
| The policy key | The only other signature that can complete a payment. Runs inside a signer process the customer runs — nowhere Merkl operates. |
| Merkl (the company) | Never holds a fund-moving key, and is never asked to authorize one. Merkl's servers relay approval requests; they do not decide them. |
| The customer's enclave (optional) | On AWS Nitro, the policy key is generated *inside* the enclave, sealed to it, and never leaves in the clear. The enclave attests — with a signature from AWS hardware — that this exact key lives inside an enclave enforcing this exact policy. Anyone can check that attestation offline, years later, trusting nothing but AWS's published root. |

The dev signer (no enclave, for testing) makes the opposite fact loud instead of
hiding it: its receipts carry a `null` attestation, and every verifier shows
*"unattested signer"* rather than leaving the field blank.

### What verification needs

A receipt is a small Merkle tree of seven facts — what the agent was told, what
it asked for, what the policy decided, who attested to the signer, what
settled, what the result was, and the model's own account of its reasoning
(labelled testimony, never proof). `docs/RECEIPT-SPEC.md` specifies every byte.

Checking one needs no trusted party:

- **Level 1** — the receipt verifies against the signer's own public key and the
  rail it settled on. Nobody has to trust Merkl's servers, a notary, or
  anything else.
- **Level 2** — the receipt also joins the append-only log described above,
  which adds a notary signature and a Bitcoin anchor.

Level 1 is not a lesser proof. It is a different, fully-answered question. A
verdict is never a single yes: for a settled payment it reports two lines —
did the policy key sign the bytes that actually settled, and is that
transaction in a ledger anyone can check — because collapsing them would hide
which half was established.

"In a ledger anyone can check" means `proven-offline`: on XRPL, the transaction
SHAMap path from the transaction to the ledger header's own `transaction_hash`
(rebuilt from the ledger's full binary transaction set, folded back by the
verifier from the transaction's own bytes — never trusted as a bare hash), and
a quorum of validators the *verifier* pinned in advance whose signatures the
verifier checks itself, against the manifest that authorized the key that
actually signed. `merkl xrpl pin-unl <url>` turns a published validator list
(`vl.ripple.com`, `vl.xrplf.org`, testnet's own) into that pinned set, auditing
the whole chain — the publisher's manifest, the list's own signature, every
validator's manifest inside it — and printing exactly what it trusted and what
it skipped.

Approvals, when a policy sends a payment to a human tier, are passkey
(WebAuthn) or Ed25519 signatures over the exact payment, M of N, checked by the
signer — never by Merkl. A rejection is signed too, for the same reason a
denial gets a receipt: a refusal nobody recorded proves that nobody looked.

### The shape of it

```
                     the agent's process (assumed compromised)
+----------------------------------------------------------------------------------+
|                             merkl.sdk.ReceiptBuilder                             |
|                                                                                  |
|             propose -> (approve, if escalated) -> co-sign -> submit              |
|                       -> attest -> the seven-leaf receipt                        |
+----------------------------------------------------------------------------------+
               SignerPort |                            | SettlementPort
                    v                                           v

+--------------------------------------+    +--------------------------------------+
|             merkl.signer             |    |            merkl.adapters            |
|      the only policy authority       |    |     fake . xrpl -- one per rail      |
|                                      |    |                                      |
|    keystore: dev file / Nitro KMS    |    |   builds the unsigned tx, collects   |
|    sealed rule state -- windows,     |    |   the agent's signature, hands the   |
|        caps, nonces; reconciled      |    |    bytes to the signer, submits,     |
|     against the rail's own history   |    |       reads back what settled        |
|   evaluate(intent, policy, state)    |    |                                      |
|   reads the bytes before it signs    |    |                                      |
+--------------------------------------+    +--------------------------------------+

              | import only                               | import only           --> the ledger (fake / XRPL)
                    v                                           v

+----------------------------------------------------------------------------------+
|                                    merkl.core                                    |
|               pure: no I/O, no clock, no rail client, no new deps                |
|                                                                                  |
|            Intent . PolicyDocument . evaluate() . the 7-leaf receipt             |
|           ports.py (Protocols only) . verify/ (Python + JS, one spec)            |
+----------------------------------------------------------------------------------+
```

Every arrow into `merkl.core` points inward. The core declares what it needs as
Protocols (`merkl.core.ports`); the signer and the adapters implement them. The
signer never imports an adapter and never imports `merkl.sdk`; nothing in
`merkl.core` does I/O, reads a clock, or has heard of XRPL.

The first rail is XRPL, because it lets an agent hold a wallet and move money
without a bank in the loop — that's what makes "an agent that transacts" a real
scenario worth defending rather than a hypothetical.

### Run the five scenarios

```bash
merkl demo                     # fake rail, ./merkl-demo/fake/*.html
merkl demo --xrpl-testnet      # also XRPL testnet (funds from the faucet once,
                                # then reuses the treasury cached under ~/.merkl)
```

Five stories, each ending in a receipt: an ordinary invoice that settles; a
prompt injection that asks the agent to drain the treasury and gets refused
before the second key is ever asked to sign; a payment over the human
threshold that needs two of three approvers; small payments structured to
duck under a cap, caught by a sliding window; and a payment for the right
supplier but the wrong invoice, refused, followed by the right one, which
settles. Every page is a self-contained `verify.html` that `merkl verify` and
`npx @merkl/verify` both check — two implementations that share no code,
agreeing on the same bytes. `merkl/demo/scenarios.py` is the source; run
`pytest tests/demo/ tests/scenarios/` to see the same claims as tests.

### Add a rail

A rail is one adapter. Nothing in `merkl.core` or `merkl.signer` changes.
`merkl.adapters.fake` (`merkl/adapters/fake/rail.py`) is the worked example: a
deterministic in-memory ledger that still enforces the real 2-of-2 quorum and
refuses a lone signature the way XRPL does (`BAD_QUORUM`, after `tefBAD_QUORUM`),
so a scenario proves something about the signer rather than about a rail Merkl
wrote to agree with itself. Implement `merkl.core.ports.SettlementPort`:

```python
class SettlementPort(Protocol):
    async def prepare(self, intent, commitment) -> UnsignedTx: ...
    async def agent_sign(self, unsigned) -> PartialTx: ...
    async def attach_policy_signature(self, partial, sig) -> SignedTx: ...
    async def submit(self, signed) -> SettlementRef: ...
    async def settlement_proof(self, ref) -> SettlementProof | None: ...
    async def history(self, treasury, since) -> list[Outflow]: ...
    def anchor_capability(self) -> AnchorCapability: ...
```

Two things a rail adapter must get right, because the signer depends on them:

- `prepare` is called twice — once with a 32-zero-byte placeholder where the
  anchor goes, once with the real commitment — and the two calls must produce
  byte-identical bytes apart from that field. That equality is how the signer
  proves, after the fact, that the transaction it signed is the transaction
  that settled (`docs/RECEIPT-SPEC.md` §3.4).
- The signer decodes the payload itself before signing it — it does not trust
  the adapter's account of what the bytes mean, because the adapter runs in the
  agent's own process. Add a rail and you also add a **verify-only** codec at
  `merkl/signer/rails/<rail>.py`: an allowlist of fields, not a blocklist of
  dangerous ones (`docs/SIGNER-RPC.md` §5). The signer refuses to boot for a
  rail with no codec, rather than discover the gap mid-payment.

### Deploy the signer

**Dev**, for local testing — no attestation, and every receipt says so:

```bash
merkl treasury init --xrpl-testnet     # fund and lock down a testnet treasury
merkl signer serve --policy policy.json --socket /tmp/merkl-signer.sock
```

**Nitro**, for production — the key is generated inside an AWS Nitro Enclave in
*the customer's own account*, sealed to it, and never leaves in the clear.
Merkl never holds it; nobody does, except the running enclave. `nitro/README.md`
has the full build, the PCR allowlist and its two enforcement points, the
runbook (first boot, a code change, a policy change, a restart), and the threat
notes: exactly what a hostile parent process can and cannot do to it.

## Verify

Anyone can check a Merkl record without asking us, without an account and without
a network. There are three ways in, and they are the same checks:

```bash
merkl verify disclosure-abc123/verify.html    # the page an auditor was emailed
merkl verify bundle.json --all                # every check, and what it compared
merkl receipt show <id> --leaves              # one receipt, read out loud
merkl xrpl pin-unl https://vl.ripple.com -o pinned.json   # audit a validator list once
```

```js
import { verifyReceipt } from '@merkl/verify';   // no dependencies, Web Crypto only
```

Two implementations, one spec, one set of published test vectors: `merkl.core.verify`
in Python and `@merkl/verify` in JavaScript both run against
`merkl/core/vectors/`, so if they ever disagreed one of them would be wrong — and
you can check that too. `docs/RECEIPT-SPEC.md` specifies every byte.

**A verdict is never one boolean.** Two lines are reported, and both matter:
`ok` means nothing was contradicted; `complete` means every check actually ran. A
check the verifier had no material for — no policy document, no settlement proof,
no PCR allowlist — is reported by name as *not checked*, never as a pass. For a
co-signed payment the settlement result is two more lines, because collapsing
them would hide which half was established:

| Line | Question |
|---|---|
| Transaction authorization | did the policy key sign the bytes that settled |
| Ledger inclusion | is that transaction in a ledger anyone can check, and how strongly |

And an unattested signer — a receipt whose leaf 3 is `null`, meaning nothing
proves which machine held the policy key — is shown loudly rather than left out.

**Nothing verified here trusts us.** Trust anchors are arguments: the PCR
allowlist, the validator key set, the policy document, the admin key. No receipt
gets to nominate what it should be judged against, the AWS Nitro root is embedded
rather than fetched, and `now` is passed in rather than read, so a verification
is reproducible years later.

## Python SDK

```python
from merkl.sdk import MerklClient

client = MerklClient(endpoint="https://api.merkl.ai", agent_id="my-agent", api_key="mk_...")
async with client.session(goal="Process refunds", allowed_tools=["query_db"]) as session:
    await session.record_action(tool_name="query_db", input_data="SELECT ...", output_data={...})
# the session seals on exit and its root is added to the log
```

Set `include_previews=True` on the client if you want truncated plaintext in the dashboard. Adapters for LangChain, OpenAI, CrewAI and Google ADK live in `merkl.integrations.*`. They work; Claude Code is the supported launch path.

Co-signed payments go through `ReceiptBuilder` (`merkl/sdk/receipts.py`), which
joins the enclosing session as one `transaction` action so a payment's receipt
inherits the same log inclusion as everything else: propose, escalate if the
policy asks, co-sign, submit, attest, and hand back a receipt with a `.verify()`
you can call before you even look at the dashboard.

## A note on the crypto

SHA-256, Merkle trees (RFC 6962), Ed25519, Bitcoin timestamping via OpenTimestamps. For co-signed payments: WebAuthn (passkeys) and Ed25519 for approvals, AWS Nitro attestation (COSE_Sign1, ES384) for the enclave signer, XRPL multisignatures for settlement. No proprietary math. Sessions resumed after a seal chain to their predecessor.

## Development

```bash
pip install -e ".[dev]"
pytest
```

# merkl-sdk

Merkl gives your AI agent a paper trail that holds up. It records everything the agent does, fingerprints each action with a hash, and stores those fingerprints where nobody can quietly edit them afterwards. The actual data (commands, file contents, prompts) never leaves your computer. If anyone later asks "did the agent really do this?", you can prove the answer in a browser.

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

## Verify

Anyone can check a Merkl record without asking us, without an account and without
a network. There are three ways in, and they are the same checks:

```bash
merkl verify disclosure-abc123/verify.html    # the page an auditor was emailed
merkl verify bundle.json --all                # every check, and what it compared
merkl receipt show <id> --leaves              # one receipt, read out loud
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

## A note on the crypto

SHA-256, Merkle trees (RFC 6962), Ed25519, Bitcoin timestamping via OpenTimestamps. No proprietary math. Sessions resumed after a seal chain to their predecessor.

## Development

```bash
pip install -e ".[dev]"
pytest
```

# A trading agent that pays its own bills

A small program that wakes up every fifteen minutes, looks at the XRP/RLUSD book
on the XRP Ledger, decides at most one thing, and writes down what it did. It
trades through a Merkl policy it cannot read, it pays its own compute bill out
of the treasury it trades, and every decision it makes — including the ones it
was refused — becomes a public receipt.

It is about three hundred lines you can read in one sitting. It is not a
framework, it has no plugin system, and there is nothing to subclass. If you want
a different agent, replace `decide.py`.

```
trader.py            the loop and the wiring
market.py            what the ledger says
decide.py            what the model says — the part you replace
ledger.py            the agent's own books: state, the compute bill, the journal
config.py            one TOML file, validated once
config.example.toml  a worked example, commented
```

## The idea

Give an agent real money and real freedom, and put a rule it cannot argue with
between it and the ledger.

The policy lives in a co-signer the agent does not control. The agent is told
which policy *version* its intents must name, and **nothing about what that
policy says** — no cap, no window, no threshold, no destination list. It finds
out what it may do the way anyone finds out a rule: it proposes something, it is
refused in words, and the refusal is handed back to it on the next cycle. Every
one of those refusals is a receipt too, so an outsider can check that the agent
was bounded rather than take somebody's word for it.

That is why `config.py` has no section for the rules and never will. An agent
that could read its own limits would be an agent whose story about staying inside
them is worth nothing.

## Install

```bash
pip install 'merkl-sdk[xrpl]' anthropic
```

`anthropic` is not a Merkl dependency — it is this example's, and only
`decide.py` imports it, lazily. Swap the decision function and you do not need
it at all.

## What you need before you start

1. **A treasury.** `merkl treasury init --xrpl-mainnet --trust RLUSD.<issuer>`
   writes the multisigned account and a wallet file. Fund it with the hundred
   dollars you are prepared to lose.
2. **A policy, signed by you, running in a co-signer.** `merkl policy sign` and
   `merkl signer serve`. It must grant the agent `may_swap`, allow both assets,
   and allow the operator address you want the compute bill paid to. Everything
   else — the cap, the window, the human threshold — is yours to choose and the
   agent's to discover.
3. **An agent key.** `openssl genpkey -algorithm ed25519 -out agent-ed25519.pem
   && chmod 600 agent-ed25519.pem`, with the public half named in the policy's
   agent section. On its own it moves nothing: it authenticates the agent to the
   co-signer, and the co-signer holds the key that actually signs.
4. **A notary key.** `MERKL_API_KEY` for api.merkl.ai, so the receipts are
   witnessed somewhere other than your laptop.
5. **A model key.** `ANTHROPIC_API_KEY`.

Copy `config.example.toml`, edit it, and read the comments — they say which
values are secrets and how each one is referenced rather than inlined.

Or skip all five: `merkl treasury init` writes this file for you, already filled
in, beside the key, the wallet and the tokens it generated. It lands in
`./merkl-agent/` (or wherever `--agent-dir` says) with every path in it relative,
so the folder can be moved. What it cannot fill in is `treasury.policy_version` —
that is decided when you publish the policy — so it says
`"<set this after you publish>"` and the signer will refuse every intent until
you replace it. `[notary].api_key_file` names the `0600` file it wrote;
`api_key_env` still works, and the file wins when both are set.

## Run it

```bash
python -m examples.trader --config trader.toml            # the loop
python -m examples.trader --config trader.toml --once     # one cycle, then exit
python -m examples.trader --config trader.toml --dry-run  # decide and journal, propose nothing
```

It is a plain process. Put it under whatever already restarts things on your
machine — systemd, a supervisor, a `while true` — and do not give it a scheduler
of its own.

## What one cycle does

1. **Finish what was in flight.** If the process died between proposing
   something and writing it down, the receipt id and nonce are on disk. The agent
   looks the receipt up and journals what happened. It never re-sends. A trading
   agent that retries on restart is a trading agent that double-trades on a bad
   afternoon.
2. **Resolve an escalation**, if a proposal is sitting with a human. Nothing new
   is decided while somebody is still thinking about the last thing — an agent
   that carried on regardless would be an agent whose escalations mean nothing.
3. **Read the market**: the book both ways off the ledger over JSON-RPC, the
   treasury's balances, and one external reference price with its source named.
   The reference is allowed to be down; the cycle still runs.
4. **Pay the compute bill**, if it is due. That is the cycle's one action.
5. **Otherwise ask the model**, and act on at most one thing it says.
6. **Journal, and sleep.**

The cap of one action per cycle is not a rule the model is asked to respect. The
tool loop in `decide.py` stops the instant a proposal is made, so a model that
called `propose_swap` three times would still get exactly one proposal made.

## What the model sees

Four tools and nothing else:

| tool | what it does |
|---|---|
| `get_market()` | the book, the balances, the reference price |
| `read_receipts(limit)` | its own recent proposals, decisions and refusals |
| `propose_swap(sell_asset, sell_max_amount, buy_asset, buy_amount, reasoning)` | ends the cycle |
| `propose_payment(destination, amount, asset, reasoning)` | ends the cycle |

The system prompt is the `SYSTEM` constant at the top of `decide.py`. It states
the job — stay in business, pay the bill, grow the treasury — says that doing
nothing is a real action, says that the policy exists and cannot be read, and
says that every proposal becomes a public receipt. It states no number from the
policy, and a test asserts that it never will.

Amounts are decimal strings everywhere, from the JSON-RPC parse to the intent.
`0.1 + 0.2` is a bug in a payments system, and no float is ever built.

## The compute bill

The agent counts its own tokens from what the API reported, prices them at the
rate in `[model]`, and once a week proposes to pay the operator for them out of
the treasury, converted at the price it can see. If that payment is refused, or
the treasury cannot cover it, the agent writes **out of business** to the journal
and exits non-zero.

This is the honest half of the story. The agent is not free, it knows what it
costs, and it stops rather than quietly running on somebody else's money. Runway
— days of compute the treasury can still pay for at the current burn — is on the
first line of every journal entry.

## The journal

`journal.md` gets two lines a cycle:

```
2026-09-10T00:08:45Z — 97.99991 XRP + 200 TST — runway unknown
Bought 100 TST for at most 2 XRP. Settled. receipt b97b9f53858e3d6b6050c242cc1fd86b
```

`journal.jsonl` gets the same facts as data. Neither is evidence and neither
pretends to be — the receipt is the evidence, in `receipts/` and at the notary.
The journal is the part a human reads over coffee.

## Replacing the decision function

`decide.decide()` takes a `ModelPort` — one method, `create(**request)` — and
returns a `Decision`: a swap, a payment, or a considered nothing, plus the
reasoning that becomes the receipt's leaf 6 and the token counts that become the
bill. Write a moving average, a human at a prompt, a different provider; as long
as it returns a `Decision`, the rest of the program does not change and does not
care.

## Tests

```bash
pytest tests/examples/test_trader.py
```

Everything below the model is real there: a real signer with a real encrypted
keystore and real sealed window state, real receipts on disk, against the
in-memory rail. Two things are stubbed — the model (a scripted list of replies)
and the XRPL node (`httpx.MockTransport`, so `market.py`'s own JSON-RPC parsing
is exercised rather than skipped).

```bash
ruff check examples/trader tests/examples
mypy --strict -p examples.trader
```

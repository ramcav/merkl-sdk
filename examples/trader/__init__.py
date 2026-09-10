"""A reference trading agent: it trades, it pays its own bills, it receipts both.

Five modules, and you can read all of them in one sitting:

``trader.py``  the loop and the wiring
``market.py``  what the ledger says
``decide.py``  what the model says — the part you are meant to replace
``ledger.py``  the agent's own books: state, the compute bill, the journal
``config.py``  one TOML file, validated once

Nothing here is a framework. See ``README.md``.
"""

"""``merkl.adapters`` — the edge, where the pure core meets real systems.

Every module here implements a Protocol from :mod:`merkl.core.ports` and imports
``merkl.core`` and ``merkl.shared`` only. Nothing in ``merkl.core`` imports
anything here, and nothing here imports ``merkl.sdk``: the dependency runs one
way, which is what lets the same core be verified in a browser, evaluated in an
enclave and orchestrated in an agent process.

* ``fake`` — a deterministic in-memory rail that still enforces 2-of-2 quorum.
* ``xrpl`` — XRPL multisigned Payments, memo-anchored, with settlement proofs.
* ``signer_dev`` — a :class:`~merkl.core.ports.SignerPort` client for the dev
  signer's RPC.
"""

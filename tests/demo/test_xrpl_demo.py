"""The demo's five scenarios, against XRPL testnet. Opt-in, and slow on purpose.

```
MERKL_XRPL_TESTNET=1 .venv/bin/python -m pytest tests/demo/test_xrpl_demo.py -v -s
```

Skipped by default with a reason, same as ``tests/scenarios/test_xrpl_testnet.py``:
a suite that needs the network is a suite that fails on a train. This one checks
the piece that module does not — that ``merkl.demo.pages.write_pages`` renders a
page for a *real* settled transaction and the Python verifier reports nothing
contradicted over it, tx hash included in the failure message if it ever isn't.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ENABLED = os.environ.get("MERKL_XRPL_TESTNET") == "1"

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not ENABLED,
        reason="XRPL testnet is opt-in: set MERKL_XRPL_TESTNET=1 (it funds accounts "
        "from the faucet the first time and submits real transactions)",
    ),
]


async def test_the_five_scenarios_settle_on_testnet_and_both_verifiers_pass(
    tmp_path: Path,
) -> None:
    from merkl.demo.pages import write_pages
    from merkl.demo.scenarios import run_all
    from merkl.demo.xrpl_env import build_xrpl_environment

    env = await build_xrpl_environment(tmp_path / "rig")
    results = await run_all(env)
    reports = write_pages(results, tmp_path / "out", rail="xrpl")

    tx_hashes = [
        outcome.settlement.tx_hash
        for report in reports
        for outcome in report.result.outcomes
        if outcome.settlement is not None
    ]
    assert tx_hashes, "at least one scenario must actually settle on testnet"

    for report in reports:
        for reading in report.readings:
            assert reading.ran, f"{reading.verifier} did not run: {reading.detail}"
            assert reading.ok, (
                f"{reading.verifier} contradicted {report.page.name}: {reading.detail}"
                f" (tx hashes this run: {tx_hashes})"
            )

    print("\nXRPL testnet transactions (demo):")
    for report in reports:
        for outcome in report.result.outcomes:
            if outcome.settlement is not None:
                print(f"  {report.result.name:<28} {outcome.settlement.tx_hash}")

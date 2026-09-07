"""``merkl demo`` — run the five scenarios end to end, write pages to open.

Runs the same signer, the same policy engine and the same seven-leaf receipt
the SDK uses in production against a rail, and writes each scenario as a
self-contained ``verify.html`` that both the Python and the JavaScript
verifier have already checked. That is the whole point of a demo: not "trust
me", but "open this file and check it yourself".

```
merkl demo                     # fake rail only, ./merkl-demo/fake/
merkl demo --xrpl-testnet      # also XRPL testnet: funds from the faucet the
                                # first time, reuses the cached treasury after
MERKL_XRPL_TESTNET=1 merkl demo   # same, via the env var the pytest suite uses
```

The fake rail always runs — it is free, offline, and deterministic. XRPL
testnet is opt-in because it touches a real network and, the first time, a real
faucet.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

from merkl.demo.pages import PageReport, summary_lines, write_pages
from merkl.demo.scenarios import FakeEnvironment, ScenarioError, run_all

DEFAULT_OUT: Path = Path("merkl-demo")


def _run_fake(out: Path, *, node: bool) -> list[PageReport]:
    with tempfile.TemporaryDirectory(prefix="merkl-demo-fake-") as tmp:
        env = FakeEnvironment(home=Path(tmp))
        results = asyncio.run(run_all(env))
        return write_pages(results, out / "fake", rail="fake", node=node)


def _pin_testnet_unl() -> tuple[dict[str, str], int]:
    """The real testnet UNL, audited once, the way a reader would in advance.

    Falls back to an empty pin (``settlement.validator_quorum`` reports
    ``not_implemented`` rather than a wrong pass) if the network or the list
    itself is unavailable — a demo should show what a real capture proves,
    never fabricate a pin it could not actually audit.
    """
    import httpx

    from merkl.adapters.xrpl import TESTNET_UNL_URL
    from merkl.core.verify.xrpl import CryptoError, pin_validator_list

    try:
        response = httpx.get(TESTNET_UNL_URL, timeout=15.0)
        response.raise_for_status()
        reading = pin_validator_list(response.json())
    except (httpx.HTTPError, ValueError, CryptoError) as exc:
        print(
            f"warning: could not pin the testnet UNL ({exc}); quorum will be unchecked",
            file=sys.stderr,
        )
        return {}, 0
    return {m: m for m in reading.masters}, reading.quorum()


def _run_xrpl(out: Path, *, node: bool) -> tuple[list[PageReport], tuple[str, ...]]:
    from merkl.demo.xrpl_env import build_xrpl_environment

    validators, quorum = _pin_testnet_unl()
    with tempfile.TemporaryDirectory(prefix="merkl-demo-xrpl-") as tmp:
        env = asyncio.run(build_xrpl_environment(Path(tmp)))
        results = asyncio.run(run_all(env))
        reports = write_pages(
            results,
            out / "xrpl-testnet",
            rail="xrpl",
            node=node,
            quorum=quorum,
            validator_trust=validators or None,
        )
    return reports, env.bootstrap_txs


def _pages_ok(reports: list[PageReport], *, node: bool) -> bool:
    """Whether every page verified — on both implementations, or on the one that ran.

    ``PageReport.agreed`` requires two readings by design: it is the property that
    matters when both verifiers ran. With ``--no-node`` there is only one reading,
    and judging pages by ``agreed`` would report failure on every run regardless of
    what the Python verifier actually found — silence about the missing half of
    the check is a worse answer than "one verifier says this page holds".
    """
    if node:
        return all(r.agreed for r in reports)
    return all(r.readings[0].ok for r in reports)


def _settlement_tx_hashes(reports: list[PageReport]) -> list[str]:
    """One line per settled payment, so a testnet run leaves tx hashes in the log."""
    lines = []
    for report in reports:
        for outcome in report.result.outcomes:
            if outcome.settlement is not None:
                lines.append(f"    {report.result.name:<28} {outcome.settlement.tx_hash}")
    return lines


def demo_command(*, out: Path | None = None, xrpl: bool = False, node: bool = True) -> int:
    out = out or DEFAULT_OUT
    if node and shutil.which("node") is None:
        print(
            "node is not on PATH — the JavaScript verifier will report as not run",
            file=sys.stderr,
        )

    print(f"running the five scenarios on the fake rail -> {out / 'fake'}")
    try:
        fake_reports = _run_fake(out, node=node)
    except ScenarioError as exc:
        print(f"a scenario did not produce the outcome it claims to: {exc}", file=sys.stderr)
        return 1
    for line in summary_lines(fake_reports):
        print(f"  {line}")
    ok = _pages_ok(fake_reports, node=node)

    if xrpl or os.environ.get("MERKL_XRPL_TESTNET") == "1":
        print(f"\nrunning the five scenarios on XRPL testnet -> {out / 'xrpl-testnet'}")
        try:
            xrpl_reports, bootstrap_txs = _run_xrpl(out, node=node)
        except ImportError:
            print(
                "the xrpl extras are not installed: "
                "pip install 'merkl-sdk[xrpl,signer,signer-xrpl]'",
                file=sys.stderr,
            )
            return 2
        except ScenarioError as exc:
            print(f"a scenario did not produce the outcome it claims to: {exc}", file=sys.stderr)
            return 1
        for tx in bootstrap_txs:
            print(f"  bootstrap tx  {tx}")
        for line in summary_lines(xrpl_reports):
            print(f"  {line}")
        print("  settled transactions:")
        for line in _settlement_tx_hashes(xrpl_reports):
            print(line)
        ok = ok and _pages_ok(xrpl_reports, node=node)

    print()
    print(f"pages written to {out.resolve()}")
    print("open index.html, or check any page yourself, two ways:")
    print(f"  merkl verify {out / 'fake' / '1-benign-payment.html'} --all")
    print(f"  npx @merkl-ai/verify {out / 'fake' / '1-benign-payment.html'} --all")
    if not ok:
        print(
            "\nat least one page did not verify cleanly on both implementations",
            file=sys.stderr,
        )
    return 0 if ok else 1

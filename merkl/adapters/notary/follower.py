"""``NotaryFollower`` — how a signer on somebody else's laptop stays current.

A self-hosted signer is behind a NAT Merkl cannot route to, so nothing is ever
pushed at it. It pulls: its policy, and the approvals people gave in the
dashboard. That is not a workaround for the network topology, it is the thing
that makes the topology safe — an approval reaching this process is an
*assertion*, verified here against the approvers the policy names, and a policy
reaching it is verified here against the admin credential the signer pinned. The
notary is a postbox. It could hand over a forged approval and the signer would
refuse it; it could withhold a real one and the payment simply would not happen.

Four things happen on a schedule:

* **the first policy.** Until one exists the signer has nothing to serve, so it
  polls every 10 s and boots on the first answer, persisting it to
  ``<home>/policy.signed.json`` so a restart with no notary still works.
* **policy changes.** Every 30 s afterwards. A changed hash goes through the
  engine's ``policy_update``, which checks it against the *pinned* admin and
  refuses a document that names a different treasury; only then is it persisted.
  A refused policy is logged once per hash, not once per poll — a notary stuck
  on a bad document must not turn the signer's log into the reason nobody reads
  the log.
* **escalations.** Every 5 s while the engine holds pending ones, else 30 s.
  Each set of assertions goes through the same ``approve``/``reject`` the RPC
  uses, under the router's own lock, and the result is POSTed back.
* **the heartbeat**, on every policy poll, carrying the hash actually in force.
  That is how the dashboard can say "the policy is live" rather than "the policy
  was published", which are different facts about different machines.

It runs on a daemon thread and never raises out of it. A notary that is down, a
DNS failure, a 500 — each is a backoff (doubling, capped at 60 s) and a line on
stderr, never a signer that stops answering. The signer is the thing holding the
key; the follower is a client of an HTTP API, and one of those two is allowed to
be unavailable.

It lives here rather than under ``merkl/signer/`` on purpose. That package
writes to no stream and knows no notary (``tests/signer/test_signer_purity.py``),
and it stays that way: the follower is handed a ``log`` to call and an
``RpcRouter`` to dispatch through, and the signer never learns it exists.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from merkl.adapters.notary.client import DEFAULT_TIMEOUT_SECONDS, NotaryError
from merkl.adapters.notary.enrol import NotaryRecord
from merkl.core.canonical import JSONObject
from merkl.core.policy.document import PolicyError, SignedPolicy
from merkl.shared.errors import MerklError
from merkl.signer.server import RpcRouter

POLICY_PATH: Final = "/v1/signer/policy"
HEARTBEAT_PATH: Final = "/v1/signer/heartbeat"
ESCALATIONS_PATH: Final = "/v1/signer/escalations"

FIRST_POLICY_SECONDS: Final = 10.0
POLICY_SECONDS: Final = 30.0
ESCALATIONS_BUSY_SECONDS: Final = 5.0
ESCALATIONS_IDLE_SECONDS: Final = 30.0
MAX_BACKOFF_SECONDS: Final = 60.0
TICK_SECONDS: Final = 1.0

OUTCOME_APPROVE: Final = "approve"
OUTCOME_REJECT: Final = "reject"


def _assertion_of(entry: Any) -> JSONObject:
    """One assertion, without the notary's own ``outcome`` annotation.

    ``outcome`` says which button the approver pressed; it is the notary's word
    for how to read a signature, never part of the signed material, and
    ``ApprovalAssertion`` refuses members it does not know.
    """
    return {key: value for key, value in dict(entry).items() if key != "outcome"}


class NotaryFollower:
    """One signer following one notary. Constructed by the CLI, never by the signer."""

    def __init__(
        self,
        record: NotaryRecord,
        *,
        home: Path,
        log: Callable[[str], None],
        transport: Any | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        first_policy_seconds: float = FIRST_POLICY_SECONDS,
        policy_seconds: float = POLICY_SECONDS,
        escalations_busy_seconds: float = ESCALATIONS_BUSY_SECONDS,
        escalations_idle_seconds: float = ESCALATIONS_IDLE_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._record = record
        self._home = Path(home)
        self._log = log
        self._transport = transport
        self._timeout = timeout
        self._first_policy_seconds = first_policy_seconds
        self._policy_seconds = policy_seconds
        self._busy_seconds = escalations_busy_seconds
        self._idle_seconds = escalations_idle_seconds
        self._sleep = sleep
        self._clock = clock

        self._router: RpcRouter | None = None
        self._client: Any | None = None
        self._policy_hash: str | None = None
        self._policy_version: str | None = None
        self._refused: set[str] = set()
        self._unknown: set[str] = set()
        self._backoff: dict[str, float] = {"policy": 0.0, "escalations": 0.0}
        self._due: dict[str, float] = {"policy": 0.0, "escalations": 0.0}

    # -- what the CLI drives ----------------------------------------------- #

    @property
    def policy_file(self) -> Path:
        return self._home / "policy.signed.json"

    @property
    def treasury_url(self) -> str:
        return self._record.treasury_url

    def await_first_policy(self, stop: Callable[[], bool] | None = None) -> SignedPolicy | None:
        """Poll until the notary has a policy for this treasury, then persist it.

        Returns ``None`` only when ``stop`` asked it to give up. Every failure
        in here is a backoff and a line, because the customer is on the
        dashboard signing the policy right now and a signer that exited would
        have to be started again by hand.
        """
        said = False
        while stop is None or not stop():
            try:
                policy = self.fetch_policy()
            except (NotaryError, PolicyError) as exc:
                self._log(f"  notary       {exc}")
                policy = None
                self._sleep(self._penalise("policy"))
                continue
            self._backoff["policy"] = 0.0
            if policy is not None:
                self.adopt(policy)
                return policy
            if not said:
                self._log(
                    f"  policy       none published yet — waiting for one at {self._record.url}"
                )
                said = True
            self._heartbeat()
            self._sleep(self._first_policy_seconds)
        return None

    def attach(self, router: RpcRouter) -> None:
        """Point the follower at the running signer. Nothing is applied before this."""
        self._router = router

    def start(self) -> threading.Thread:
        """Run the schedule on a daemon thread that never takes the signer down."""
        thread = threading.Thread(target=self._run, name="merkl-notary-follower", daemon=True)
        thread.start()
        return thread

    def run_forever(self, stop: Callable[[], bool] | None = None) -> None:
        while stop is None or not stop():
            self.tick()
            self._sleep(TICK_SECONDS)

    def tick(self) -> None:
        """Do whatever is due. Called on the thread, and directly by the suite."""
        now = self._clock()
        if now >= self._due["policy"]:
            ok = self._guard("policy", self.poll_policy)
            self._schedule("policy", self._policy_seconds if ok else None)
        if now >= self._due["escalations"]:
            ok = self._guard("escalations", self.poll_escalations)
            self._schedule("escalations", self._escalation_interval() if ok else None)

    # -- the three calls ---------------------------------------------------- #

    def fetch_policy(self) -> SignedPolicy | None:
        """``GET /v1/signer/policy`` — the active policy of this signer's treasury."""
        answer = self._request("GET", POLICY_PATH)
        payload = answer.get("policy")
        if not payload:
            return None
        document = payload.get("signed_document") if isinstance(payload, dict) else None
        if document is None:
            raise NotaryError("the notary's policy answer carries no signed_document")
        return SignedPolicy.from_content(document)

    def poll_policy(self) -> None:
        """Fetch, heartbeat, and adopt a changed hash through the engine."""
        policy = self.fetch_policy()
        self._heartbeat()
        if policy is None or policy.policy_hash == self._policy_hash:
            return
        if policy.policy_hash in self._refused:
            return
        router = self._router
        if router is None:  # pragma: no cover - attach() happens before start()
            return
        network = self._record.network
        if network is not None and policy.document.network not in (None, network):
            self._refuse(
                policy.policy_hash,
                f"it governs {policy.document.network}, and this signer was enrolled on {network}",
            )
            return
        try:
            router.dispatch_local("policy_update", {"signed_policy": policy.to_content()})
        except (MerklError, ValueError) as exc:
            self._refuse(policy.policy_hash, str(exc))
            return
        self.adopt(policy)
        self._log(
            f"  policy       {policy.document.version} in force  "
            f"{policy.policy_hash[:16]}… (from the notary)"
        )

    def poll_escalations(self) -> int:
        """``GET /v1/signer/escalations``, apply each, POST the result back."""
        router = self._router
        if router is None:  # pragma: no cover - attach() happens before start()
            return 0
        answer = self._request("GET", ESCALATIONS_PATH)
        raw = answer.get("escalations")
        entries = raw if isinstance(raw, list) else []
        handled = 0
        for entry in entries:
            if self._apply(router, entry):
                handled += 1
        return handled

    def adopt(self, policy: SignedPolicy) -> None:
        """Remember a policy and write it to ``<home>/policy.signed.json``, atomically.

        Atomically because a signer that is restarted while this is half-written
        is a signer that will not boot, and the notary may be unreachable at
        exactly that moment. The file is the fallback, so it is never a partial
        one.
        """
        self._policy_hash = policy.policy_hash
        self._policy_version = policy.document.version
        path = self.policy_file
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(policy.to_content(), indent=2) + "\n")
        os.replace(tmp, path)

    # -- internals ---------------------------------------------------------- #

    def _apply(self, router: RpcRouter, entry: Any) -> bool:
        """One escalation: decide it the way the RPC would, then report the result.

        A rejection wins over an approval in the same set. Somebody with
        standing looked at this and said no; the fact that somebody else said
        yes does not turn that into a payment, and both signatures reach the
        receipt either way (``engine.reject`` carries every assertion into
        leaf 2).
        """
        challenge = entry.get("challenge")
        if not isinstance(challenge, str) or not challenge:
            return False
        if challenge in self._unknown:
            return False
        assertions = list(entry.get("assertions") or [])
        rejects = [a for a in assertions if dict(a).get("outcome") == OUTCOME_REJECT]
        chosen = rejects or [a for a in assertions if dict(a).get("outcome") == OUTCOME_APPROVE]
        if not chosen:
            return False
        method = "reject" if rejects else "approve"
        params: JSONObject = {
            "challenge": challenge,
            "assertions": [_assertion_of(a) for a in chosen],
        }
        try:
            result = router.dispatch_local(method, params)
        except MerklError as exc:
            self._unknown.add(challenge)
            self._log(f"  escalation   {challenge[:16]}… cannot be decided here: {exc}")
            return False
        self._request(
            "POST",
            f"{ESCALATIONS_PATH}/{challenge}/decision",
            {"result": result},
        )
        self._log(f"  escalation   {challenge[:16]}… {method}d, decision filed")
        return True

    def _escalation_interval(self) -> float:
        return self._busy_seconds if self._pending() else self._idle_seconds

    def _pending(self) -> int:
        router = self._router
        if router is None:  # pragma: no cover - attach() happens before start()
            return 0
        try:
            health = router.dispatch_local("health", {})
        except MerklError:  # pragma: no cover - health does not fail
            return 0
        count = health.get("pending_escalations")
        return count if isinstance(count, int) else 0

    def _heartbeat(self) -> None:
        self._request(
            "POST",
            HEARTBEAT_PATH,
            {"policy_hash": self._policy_hash, "policy_version": self._policy_version},
        )

    def _refuse(self, policy_hash: str, why: str) -> None:
        """Say once why a published policy is not being served, then stop saying it."""
        self._refused.add(policy_hash)
        self._log(f"  policy       refused {policy_hash[:16]}…: {why}")

    def _guard(self, name: str, work: Callable[[], Any]) -> bool:
        """Run one scheduled job. An exception is a line and a backoff, never a raise."""
        try:
            work()
        except Exception as exc:  # noqa: BLE001 - the follower never takes the signer down
            self._log(f"  notary       {name} poll failed: {exc}")
            return False
        self._backoff[name] = 0.0
        return True

    def _schedule(self, name: str, interval: float | None) -> None:
        self._due[name] = self._clock() + (
            interval if interval is not None else self._penalise(name)
        )

    def _penalise(self, name: str) -> float:
        """Double this job's backoff, capped. One second the first time."""
        current = self._backoff[name]
        nxt = min(MAX_BACKOFF_SECONDS, current * 2 if current else 1.0)
        self._backoff[name] = nxt
        return nxt

    def _http(self) -> Any:
        import httpx

        if self._client is None:
            self._client = httpx.Client(
                base_url=self._record.url.rstrip("/"),
                timeout=self._timeout,
                transport=self._transport,
                headers={"Authorization": f"Bearer {self._record.signer_token}"},
            )
        return self._client

    def _request(self, method: str, path: str, body: JSONObject | None = None) -> JSONObject:
        import httpx

        try:
            response = self._http().request(method, path, json=body)
        except httpx.HTTPError as exc:
            raise NotaryError(f"{method} {path} failed: {exc}") from exc
        if not response.is_success:
            raise NotaryError(f"{method} {path} answered {response.status_code}")
        if response.status_code == 204 or not response.content:
            return {}
        try:
            answer = response.json()
        except ValueError as exc:
            raise NotaryError(f"{method} {path} did not answer JSON") from exc
        return answer if isinstance(answer, dict) else {}

    def close(self) -> None:  # pragma: no cover - the process is ending anyway
        if self._client is not None:
            self._client.close()
            self._client = None

    def _run(self) -> None:
        try:
            self.run_forever()
        except BaseException as exc:  # noqa: BLE001 - a dead thread must still say why
            self._log(f"  notary       the follower stopped: {exc}")


__all__ = [
    "ESCALATIONS_BUSY_SECONDS",
    "ESCALATIONS_IDLE_SECONDS",
    "ESCALATIONS_PATH",
    "FIRST_POLICY_SECONDS",
    "HEARTBEAT_PATH",
    "MAX_BACKOFF_SECONDS",
    "POLICY_PATH",
    "POLICY_SECONDS",
    "NotaryFollower",
]

"""``NotaryFollower`` — a real signer, a fake notary, and nothing pushed at either.

The engine here is the real :class:`~merkl.signer.engine.SignerEngine` behind the
real :class:`~merkl.signer.server.RpcRouter`, on the in-memory rail. The notary
is an ``httpx.MockTransport`` that answers the three routes of
``P17-CONTRACT.md`` and records what it was told. What is being checked is the
loop between them: a policy published in the dashboard reaches a signer nobody
can route to, an approval a person gave in a browser becomes a signature over
the challenge, and the decision comes back to the notary.

Time never passes here. The follower's clock and its sleep are both injected, so
a schedule that says "every 30 seconds" is a test that runs in milliseconds.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from merkl.adapters.notary import NotaryFollower, NotaryRecord
from merkl.core.canonical import shift_instant
from merkl.core.policy.document import SignedPolicy
from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.receipt import PolicyOutcome
from merkl.demo.rig import (
    ADMIN,
    AGENT,
    AGENT_ID,
    Rig,
    approvals_for,
    build_policy,
    build_rig,
    sign_policy,
)
from merkl.signer.auth import sign_request
from merkl.signer.server import RpcRouter

SIGNER_TOKEN = "sgn_" + "b" * 43


class FakeNotary:
    """The three routes a follower pulls on, plus what it pushed back."""

    def __init__(self, policy: SignedPolicy | None = None) -> None:
        self.policy = policy
        self.escalations: list[dict[str, Any]] = []
        self.heartbeats: list[dict[str, Any]] = []
        self.decisions: list[tuple[str, dict[str, Any]]] = []
        self.failures = 0
        self.calls = 0

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def publish(self, policy: SignedPolicy) -> None:
        self.policy = policy

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.failures:
            self.failures -= 1
            return httpx.Response(503, json={"detail": "the notary is restarting"})
        path = request.url.path
        if path == "/v1/signer/policy":
            if self.policy is None:
                return httpx.Response(200, json={"policy": None})
            return httpx.Response(
                200,
                json={
                    "policy": {
                        "signed_document": self.policy.to_content(),
                        "policy_hash": self.policy.policy_hash,
                        "version": self.policy.document.version,
                    }
                },
            )
        if path == "/v1/signer/heartbeat":
            self.heartbeats.append(json.loads(request.content))
            return httpx.Response(204)
        if path == "/v1/signer/escalations":
            return httpx.Response(200, json={"escalations": self.escalations})
        if path.endswith("/decision"):
            challenge = path.split("/")[-2]
            self.decisions.append((challenge, json.loads(request.content)))
            return httpx.Response(200, json={"status": "settled"})
        return httpx.Response(404, json={"detail": path})  # pragma: no cover


def record(url: str = "https://api.merkl.ai", network: str | None = None) -> NotaryRecord:
    return NotaryRecord(
        url=url,
        signer_id="sig_01",
        signer_token=SIGNER_TOKEN,
        org_slug="acme",
        treasury_url="https://app.merkl.ai/acme/treasuries/rTREASURY",
        network=network,
    )


def follower(
    notary: FakeNotary, home: Path, *, network: str | None = None, log: list[str] | None = None
) -> NotaryFollower:
    lines = log if log is not None else []
    return NotaryFollower(
        record(network=network),
        home=home,
        log=lines.append,
        transport=notary.transport,
        sleep=lambda _seconds: None,
        clock=lambda: 0.0,
    )


async def pending_challenge(rig: Rig) -> str:
    intent = rig.intent(value="900.00")
    unsigned = await rig.rail.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
    request = sign_request(
        method="propose",
        agent_id=AGENT_ID,
        nonce="n-" + rig.clock.now(),
        expires_at=shift_instant(rig.clock.now(), 300),
        params={
            "instruction": rig.instruction("pay the quarterly retainer").to_content(),
            "intent": intent.to_content(),
            "prepared_tx": unsigned.to_content(),
        },
        agent_public_key=AGENT.public_key,
        sign=AGENT.sign,
    )
    decision = rig.engine.propose(request.to_content())
    assert decision["outcome"] == PolicyOutcome.ESCALATE.value
    return str(decision["challenge"])


def annotated(challenge: str, at: str, outcome: str = "approve") -> dict[str, Any]:
    """An escalation exactly as ``GET /v1/signer/escalations`` describes one."""
    return {
        "challenge": challenge,
        "expires_at": shift_instant(at, 3600),
        "quorum": 2,
        "assertions": [
            {**a.to_content(), "outcome": outcome} for a in approvals_for(challenge, at=at)
        ],
    }


class TestTheFirstPolicy:
    def test_it_waits_until_one_is_published_and_then_persists_it(self, tmp_path: Path) -> None:
        notary = FakeNotary()
        published = sign_policy(build_policy())
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)

        polls = {"n": 0}

        def stop() -> bool:
            polls["n"] += 1
            if polls["n"] == 3:
                notary.publish(published)
            return False

        policy = following.await_first_policy(stop=stop)

        assert policy is not None
        assert policy.policy_hash == published.policy_hash
        on_disk = SignedPolicy.from_content(json.loads(following.policy_file.read_text()))
        assert on_disk.policy_hash == published.policy_hash
        assert any("none published yet" in line for line in lines)

    def test_it_says_it_is_waiting_once_rather_than_every_ten_seconds(
        self, tmp_path: Path
    ) -> None:
        notary = FakeNotary()
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)
        rounds = {"n": 0}

        def stop() -> bool:
            rounds["n"] += 1
            return rounds["n"] > 5

        following.await_first_policy(stop=stop)
        assert sum("none published yet" in line for line in lines) == 1

    def test_a_notary_that_is_down_is_a_backoff_and_not_an_exit(self, tmp_path: Path) -> None:
        notary = FakeNotary(sign_policy(build_policy()))
        notary.failures = 2
        following = follower(notary, tmp_path)
        assert following.await_first_policy() is not None

    def test_it_heartbeats_while_it_waits(self, tmp_path: Path) -> None:
        notary = FakeNotary()
        following = follower(notary, tmp_path)
        rounds = {"n": 0}

        def stop() -> bool:
            rounds["n"] += 1
            return rounds["n"] > 2

        following.await_first_policy(stop=stop)
        assert notary.heartbeats, "the dashboard learns the signer is alive before it is serving"
        assert notary.heartbeats[0] == {"policy_hash": None, "policy_version": None}


class TestPolicyChanges:
    def test_a_new_hash_goes_through_policy_update_and_is_persisted(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)
        following.attach(RpcRouter(rig.engine))
        following.poll_policy()

        replacement = sign_policy(build_policy(per_tx_cap="2000.00"))
        assert replacement.policy_hash != rig.signed_policy.policy_hash
        notary.publish(replacement)

        following.poll_policy()

        assert rig.engine.policy_hash == replacement.policy_hash, "the engine adopted it"
        on_disk = SignedPolicy.from_content(json.loads(following.policy_file.read_text()))
        assert on_disk.policy_hash == replacement.policy_hash
        assert any("in force" in line for line in lines)

    def test_the_heartbeat_carries_the_hash_actually_in_force(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        following = follower(notary, tmp_path)
        following.attach(RpcRouter(rig.engine))

        following.poll_policy()
        following.poll_policy()

        assert notary.heartbeats[-1] == {
            "policy_hash": rig.signed_policy.policy_hash,
            "policy_version": rig.signed_policy.document.version,
        }

    def test_a_policy_for_another_treasury_is_refused_once_and_not_every_poll(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)
        following.attach(RpcRouter(rig.engine))
        following.poll_policy()

        notary.publish(sign_policy(build_policy(treasury="rSOMEONEELSE000000000000000000000")))
        for _ in range(4):
            following.poll_policy()

        assert rig.engine.policy_hash == rig.signed_policy.policy_hash, "it kept serving its own"
        assert sum("refused" in line for line in lines) == 1

    def test_a_policy_for_the_other_chain_never_reaches_the_engine(self, tmp_path: Path) -> None:
        """Enrolled on testnet, handed a mainnet policy: the same refusal ``serve`` makes."""
        on_testnet = dataclasses.replace(
            build_policy(rail="xrpl"), network="xrpl-testnet", version="2026.01.1"
        )
        rig = build_rig(tmp_path / "signer", policy=on_testnet)
        notary = FakeNotary(rig.signed_policy)
        lines: list[str] = []
        following = follower(notary, tmp_path, network="xrpl-testnet", log=lines)
        following.attach(RpcRouter(rig.engine))

        elsewhere = dataclasses.replace(
            build_policy(rail="xrpl"), network="xrpl-mainnet", version="2026.01.2"
        )
        notary.publish(sign_policy(elsewhere))
        following.poll_policy()

        assert rig.engine.policy_hash == rig.signed_policy.policy_hash
        assert any("xrpl-mainnet" in line and "xrpl-testnet" in line for line in lines)

    def test_a_policy_signed_by_a_stranger_is_refused(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)
        following.attach(RpcRouter(rig.engine))
        following.poll_policy()

        document = build_policy(per_tx_cap="9999.00")
        forged = SignedPolicy(
            document=document,
            signature=AGENT.sign(document.pre_image()),
            signer_public_key=ADMIN.public_key,
        )
        notary.publish(forged)
        following.poll_policy()

        assert rig.engine.policy_hash == rig.signed_policy.policy_hash
        assert any("refused" in line for line in lines)


@pytest.mark.asyncio
class TestEscalations:
    async def test_an_approved_escalation_is_applied_and_the_decision_posted(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path / "signer")
        challenge = await pending_challenge(rig)
        notary = FakeNotary(rig.signed_policy)
        notary.escalations = [annotated(challenge, rig.clock.now())]
        following = follower(notary, tmp_path)
        following.attach(RpcRouter(rig.engine))

        assert following.poll_escalations() == 1

        posted_challenge, body = notary.decisions[0]
        assert posted_challenge == challenge
        assert body["result"]["outcome"] == PolicyOutcome.ALLOW.value
        assert body["result"]["signature"], "the key moved, in-process, with no bearer presented"
        assert rig.engine.health()["pending_escalations"] == 0

    async def test_a_rejection_wins_over_an_approval_in_the_same_set(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        challenge = await pending_challenge(rig)
        entry = annotated(challenge, rig.clock.now())
        entry["assertions"][0]["outcome"] = "reject"
        notary = FakeNotary(rig.signed_policy)
        notary.escalations = [entry]
        following = follower(notary, tmp_path)
        following.attach(RpcRouter(rig.engine))

        following.poll_escalations()

        _, body = notary.decisions[0]
        assert body["result"]["outcome"] == PolicyOutcome.DENY.value
        assert "rejected by" in body["result"]["detail"]

    async def test_an_escalation_this_signer_never_saw_is_reported_once_and_skipped(
        self, tmp_path: Path
    ) -> None:
        """A restart loses the pending set. It must not turn into a poll-rate log."""
        rig = build_rig(tmp_path / "signer")
        lines: list[str] = []
        notary = FakeNotary(rig.signed_policy)
        notary.escalations = [annotated("ab" * 32, rig.clock.now())]
        following = follower(notary, tmp_path, log=lines)
        following.attach(RpcRouter(rig.engine))

        for _ in range(3):
            assert following.poll_escalations() == 0

        assert notary.decisions == []
        assert sum("cannot be decided here" in line for line in lines) == 1

    async def test_the_poll_speeds_up_while_something_is_pending(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        following = follower(notary, tmp_path)
        following.attach(RpcRouter(rig.engine))

        assert following._escalation_interval() == 30.0
        await pending_challenge(rig)
        assert following._escalation_interval() == 5.0

    async def test_an_escalation_with_no_verified_assertions_is_left_alone(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path / "signer")
        challenge = await pending_challenge(rig)
        entry = annotated(challenge, rig.clock.now())
        entry["assertions"] = []
        notary = FakeNotary(rig.signed_policy)
        notary.escalations = [entry]
        following = follower(notary, tmp_path)
        following.attach(RpcRouter(rig.engine))

        assert following.poll_escalations() == 0
        assert rig.engine.health()["pending_escalations"] == 1, "it is still waiting for people"


class TestTheSchedule:
    def test_a_failing_poll_backs_off_and_the_loop_survives_it(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)
        following.attach(RpcRouter(rig.engine))
        notary.failures = 10

        for _ in range(3):
            following.tick()

        assert any("poll failed" in line for line in lines)
        notary.failures = 0
        following._due["policy"] = 0.0
        following.poll_policy()
        assert notary.heartbeats, "and it recovers as soon as the notary answers"

    def test_the_backoff_doubles_and_is_capped_at_a_minute(self, tmp_path: Path) -> None:
        notary = FakeNotary()
        following = follower(notary, tmp_path)
        seen = [following._penalise("policy") for _ in range(8)]
        assert seen[:4] == [1.0, 2.0, 4.0, 8.0]
        assert max(seen) == 60.0

    def test_the_thread_is_a_daemon_and_never_raises_out(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path / "signer")
        notary = FakeNotary(rig.signed_policy)
        lines: list[str] = []
        following = follower(notary, tmp_path, log=lines)
        following.attach(RpcRouter(rig.engine))
        stop = {"n": 0}

        def counting_stop() -> bool:
            stop["n"] += 1
            return stop["n"] > 2

        following.run_forever(stop=counting_stop)
        assert notary.calls > 0

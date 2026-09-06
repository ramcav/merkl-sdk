"""Policy document v1 — the rules, signed, hashed and pinned.

A policy is a *document*, not configuration. It is canonicalized, hashed under
its own domain tag, and signed by an admin key (plan D16). The signer verifies
that signature at boot, computes ``policy_hash``, and every decision it makes
names that hash — so anyone holding the document can re-run the same rules on the
same intent and reach the same verdict.

```
policy_pre_image = "merkl-policy-v1" || NUL || canonical_bytes(document)
policy_hash      = SHA-256(policy_pre_image)          lowercase hex
signature        = Ed25519(admin_key, policy_pre_image)
```

Signing the pre-image rather than the hash means the bytes that are signed and
the bytes that are hashed are the same bytes, so a signature can never be valid
for a document with a different hash.

No floats, at any depth: caps, thresholds and risk scores are decimal strings and
window lengths are whole seconds.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Mapping
from decimal import Decimal
from typing import Any, Final

from merkl.core.canonical import (
    ContentError,
    JSONObject,
    decimal_string,
    drop_none,
    ensure_canonical_content,
    parse_decimal,
    token,
)
from merkl.core.crypto import tagged
from merkl.core.intent import CurrencyRef, currency_content, currency_from_content
from merkl.shared.hashing import SHA256Hash, canonical_bytes

POLICY_TAG: Final = b"merkl-policy-v1"
"""Domain tag of a policy document. Hashed and signed over the same pre-image."""

POLICY_VERSION_TAG: Final = "merkl-policy-v1"

CREDENTIAL_WEBAUTHN: Final = "webauthn"
CREDENTIAL_ED25519: Final = "ed25519"
CREDENTIAL_TYPES: Final = (CREDENTIAL_WEBAUTHN, CREDENTIAL_ED25519)


class PolicyError(ContentError):
    """Raised when a policy document, or part of one, is not well formed."""

    error_code = "policy_error"


class EscalationTier(enum.StrEnum):
    """How far an intent has to travel before it can settle.

    ``INSTANT`` and ``HUMAN`` are implemented. ``NOTIFY`` and ``DELAY`` are named
    here because the tier vocabulary is part of the receipt format and adding a
    value later would change what an old verifier can read; they carry no
    behaviour in this phase and the engine never returns them.
    """

    INSTANT = "instant"
    HUMAN = "human"
    NOTIFY = "notify"
    DELAY = "delay"


IMPLEMENTED_TIERS: Final = (EscalationTier.INSTANT, EscalationTier.HUMAN)


def asset_key(currency: CurrencyRef) -> str:
    """A stable string key for one asset, used to match rules and window state.

    Native codes are ``[A-Z0-9]{1,20}`` so they never contain ``.``; an issued
    currency is ``code.issuer``. Two different assets can never collide.
    """
    content = currency_content(currency)
    if isinstance(content, str):
        return content
    if not isinstance(content, dict):  # pragma: no cover - currency_content guarantees this
        raise PolicyError(f"currency must be a code or an object, got {type(content).__name__}")
    return f"{content['code']}.{content['issuer']}"


def _members(data: Any, allowed: set[str], owner: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise PolicyError(f"{owner} must be an object, got {type(data).__name__}")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError(f"{owner} has unknown members: {unknown}")
    return data


def _required(data: Mapping[str, Any], key: str, owner: str) -> Any:
    if key not in data:
        raise PolicyError(f"{owner} requires {key}")
    return data[key]


def _positive_int(value: Any, field: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{field} must be an integer, got {type(value).__name__}")
    if value < minimum:
        raise PolicyError(f"{field} must be >= {minimum}, got {value}")
    return value


def _strings(values: Any, field: str, *, max_length: int = 256) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise PolicyError(f"{field} must be an array")
    return tuple(token(v, f"{field}[]", max_length=max_length) for v in values)


# --------------------------------------------------------------------------- #
# Rule pieces
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AssetLimit:
    """One asset and one amount: a per-transaction cap or an escalation threshold."""

    asset: CurrencyRef
    amount: str

    def __post_init__(self) -> None:
        currency_content(self.asset)
        decimal_string(self.amount, "asset_limit.amount", positive=False)

    @property
    def key(self) -> str:
        return asset_key(self.asset)

    @property
    def value(self) -> Decimal:
        return parse_decimal(self.amount, "asset_limit.amount")

    def to_content(self) -> JSONObject:
        return {"asset": currency_content(self.asset), "amount": self.amount}

    @classmethod
    def from_content(cls, data: Any) -> AssetLimit:
        obj = _members(data, {"asset", "amount"}, "asset_limit")
        return cls(
            asset=currency_from_content(_required(obj, "asset", "asset_limit")),
            amount=_required(obj, "amount", "asset_limit"),
        )


@dataclasses.dataclass(frozen=True)
class WindowRule:
    """A rolling limit: at most ``amount`` of ``asset`` in any ``seconds`` window.

    Not a calendar day. A structuring attack that spreads payments either side of
    midnight walks straight through a daily bucket; a window that slides with the
    clock has no seam to aim at.
    """

    asset: CurrencyRef
    amount: str
    seconds: int

    def __post_init__(self) -> None:
        currency_content(self.asset)
        decimal_string(self.amount, "window.amount", positive=False)
        _positive_int(self.seconds, "window.seconds")

    @property
    def key(self) -> str:
        return asset_key(self.asset)

    @property
    def value(self) -> Decimal:
        return parse_decimal(self.amount, "window.amount")

    def to_content(self) -> JSONObject:
        return {
            "asset": currency_content(self.asset),
            "amount": self.amount,
            "seconds": self.seconds,
        }

    @classmethod
    def from_content(cls, data: Any) -> WindowRule:
        obj = _members(data, {"asset", "amount", "seconds"}, "window")
        return cls(
            asset=currency_from_content(_required(obj, "asset", "window")),
            amount=_required(obj, "amount", "window"),
            seconds=_required(obj, "seconds", "window"),
        )


@dataclasses.dataclass(frozen=True)
class ReferenceBinding:
    """What a payment must be *for*.

    An agent that can pay an allowed supplier an allowed amount can still be
    talked into paying the same supplier twice, or paying for something nobody
    ordered. Binding the payment to an invoice — by kind, by id, or by the hash of
    the document itself — is what makes that detectable, and the hash set is the
    only one of the three an attacker cannot guess.
    """

    required: bool = False
    allowed_kinds: tuple[str, ...] = ()
    allowlist: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.required, bool):
            raise PolicyError("reference_binding.required must be a boolean")
        for kind in self.allowed_kinds:
            token(kind, "reference_binding.allowed_kinds[]", max_length=64)
        for ref_id in self.allowlist:
            token(ref_id, "reference_binding.allowlist[]", max_length=256)
        for digest in self.hashes:
            token(digest, "reference_binding.hashes[]", max_length=128)

    def to_content(self) -> JSONObject:
        return {
            "required": self.required,
            "allowed_kinds": list(self.allowed_kinds),
            "allowlist": list(self.allowlist),
            "hashes": list(self.hashes),
        }

    @classmethod
    def from_content(cls, data: Any) -> ReferenceBinding:
        obj = _members(
            data, {"required", "allowed_kinds", "allowlist", "hashes"}, "reference_binding"
        )
        return cls(
            required=bool(obj.get("required", False)),
            allowed_kinds=_strings(
                obj.get("allowed_kinds", []), "reference_binding.allowed_kinds"
            ),
            allowlist=_strings(obj.get("allowlist", []), "reference_binding.allowlist"),
            hashes=_strings(obj.get("hashes", []), "reference_binding.hashes", max_length=128),
        )


# --------------------------------------------------------------------------- #
# Agents, tiers, approvers
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AgentSection:
    """One agent's authority over one treasury.

    ``public_key`` is the Ed25519 key that signs the agent's requests to the
    signer (plan D15) and appears in leaf 1 of every receipt it produces. The
    signer looks it up here rather than believing the key in the request.
    """

    agent_id: str
    public_key: str
    allowlist_destinations: tuple[str, ...] = ()
    allowlist_assets: tuple[CurrencyRef, ...] = ()
    per_tx_cap: tuple[AssetLimit, ...] = ()
    windows: tuple[WindowRule, ...] = ()
    reference_binding: ReferenceBinding = dataclasses.field(default_factory=ReferenceBinding)

    def __post_init__(self) -> None:
        token(self.agent_id, "agent.agent_id", max_length=128)
        token(self.public_key, "agent.public_key", max_length=256)
        for destination in self.allowlist_destinations:
            token(destination, "agent.allowlist_destinations[]", max_length=128)
        for currency in self.allowlist_assets:
            currency_content(currency)

    def allows_asset(self, currency: CurrencyRef) -> bool:
        wanted = asset_key(currency)
        return any(asset_key(a) == wanted for a in self.allowlist_assets)

    def cap_for(self, currency: CurrencyRef) -> AssetLimit | None:
        wanted = asset_key(currency)
        for limit in self.per_tx_cap:
            if limit.key == wanted:
                return limit
        return None

    def windows_for(self, currency: CurrencyRef) -> tuple[WindowRule, ...]:
        wanted = asset_key(currency)
        return tuple(w for w in self.windows if w.key == wanted)

    def to_content(self) -> JSONObject:
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "allowlist_destinations": list(self.allowlist_destinations),
            "allowlist_assets": [currency_content(a) for a in self.allowlist_assets],
            "per_tx_cap": [limit.to_content() for limit in self.per_tx_cap],
            "windows": [window.to_content() for window in self.windows],
            "reference_binding": self.reference_binding.to_content(),
        }

    @classmethod
    def from_content(cls, data: Any) -> AgentSection:
        obj = _members(
            data,
            {
                "agent_id",
                "public_key",
                "allowlist_destinations",
                "allowlist_assets",
                "per_tx_cap",
                "windows",
                "reference_binding",
            },
            "agent",
        )
        assets = obj.get("allowlist_assets", [])
        if not isinstance(assets, list):
            raise PolicyError("agent.allowlist_assets must be an array")
        caps = obj.get("per_tx_cap", [])
        windows = obj.get("windows", [])
        if not isinstance(caps, list) or not isinstance(windows, list):
            raise PolicyError("agent.per_tx_cap and agent.windows must be arrays")
        return cls(
            agent_id=_required(obj, "agent_id", "agent"),
            public_key=_required(obj, "public_key", "agent"),
            allowlist_destinations=_strings(
                obj.get("allowlist_destinations", []),
                "agent.allowlist_destinations",
                max_length=128,
            ),
            allowlist_assets=tuple(currency_from_content(a) for a in assets),
            per_tx_cap=tuple(AssetLimit.from_content(c) for c in caps),
            windows=tuple(WindowRule.from_content(w) for w in windows),
            reference_binding=ReferenceBinding.from_content(obj.get("reference_binding", {})),
        )


@dataclasses.dataclass(frozen=True)
class HumanTier:
    """The human-approval tier: above this, people sign (plan D11).

    ``quorum`` is M of the approvers in the document; ``expires_seconds`` is how
    long the challenge stays open. An expired escalation is a denial, never a
    quiet allow.
    """

    thresholds: tuple[AssetLimit, ...] = ()
    quorum: int = 1
    expires_seconds: int = 3600

    def __post_init__(self) -> None:
        _positive_int(self.quorum, "tiers.human.quorum")
        _positive_int(self.expires_seconds, "tiers.human.expires_seconds")

    def threshold_for(self, currency: CurrencyRef) -> AssetLimit | None:
        wanted = asset_key(currency)
        for limit in self.thresholds:
            if limit.key == wanted:
                return limit
        return None

    def to_content(self) -> JSONObject:
        return {
            "thresholds": [limit.to_content() for limit in self.thresholds],
            "quorum": self.quorum,
            "expires_seconds": self.expires_seconds,
        }

    @classmethod
    def from_content(cls, data: Any) -> HumanTier:
        obj = _members(data, {"thresholds", "quorum", "expires_seconds"}, "tiers.human")
        thresholds = obj.get("thresholds", [])
        if not isinstance(thresholds, list):
            raise PolicyError("tiers.human.thresholds must be an array")
        return cls(
            thresholds=tuple(AssetLimit.from_content(t) for t in thresholds),
            quorum=obj.get("quorum", 1),
            expires_seconds=obj.get("expires_seconds", 3600),
        )


@dataclasses.dataclass(frozen=True)
class Tiers:
    """The tier table. ``instant`` has no members and exists to be named."""

    human: HumanTier = dataclasses.field(default_factory=HumanTier)

    def to_content(self) -> JSONObject:
        return {"instant": {}, "human": self.human.to_content()}

    @classmethod
    def from_content(cls, data: Any) -> Tiers:
        obj = _members(data, {"instant", "human"}, "tiers")
        instant_section = obj.get("instant", {})
        if instant_section not in ({}, None):
            raise PolicyError("tiers.instant has no members in v1")
        return cls(human=HumanTier.from_content(obj.get("human", {})))


def _effective_rp_id(rp_id: str | None, origins: Iterable[str]) -> str | None:
    """The relying-party id an authenticator hashed, explicit or derived from an origin.

    Shared by :class:`ApproverCredential` and :class:`AdminCredential` — same
    WebAuthn binding, same derivation, one function.
    """
    if rp_id is not None:
        return rp_id
    for origin in origins:
        host = origin.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host:
            return host
    return None


def _validate_credential_shape(
    *,
    credential_type: str,
    public_key: str,
    origins: tuple[str, ...],
    rp_id: str | None,
    user_verification: bool,
    owner: str,
) -> None:
    """The validation an approver and an admin credential share."""
    if credential_type not in CREDENTIAL_TYPES:
        raise PolicyError(
            f"{owner}.credential_type must be one of {list(CREDENTIAL_TYPES)}, "
            f"got {credential_type!r}"
        )
    token(public_key, f"{owner}.public_key", max_length=256)
    for origin in origins:
        token(origin, f"{owner}.origins[]", max_length=256)
    if rp_id is not None:
        token(rp_id, f"{owner}.rp_id", max_length=256)
    if not isinstance(user_verification, bool):
        raise PolicyError(f"{owner}.user_verification must be a boolean")


@dataclasses.dataclass(frozen=True)
class ApproverCredential:
    """One person who may approve an escalation, and the key they approve with.

    A WebAuthn approver's ``public_key`` is the uncompressed SEC1 P-256 point in
    hex; an Ed25519 approver's is the raw 32-byte key in hex. ``origins`` and
    ``rp_id`` are the WebAuthn ceremony's binding to a site: without them a
    signature harvested by a phishing page would count, which is the whole reason
    passkeys carry an origin at all.
    """

    id: str
    credential_type: str
    public_key: str
    origins: tuple[str, ...] = ()
    rp_id: str | None = None
    user_verification: bool = False

    def __post_init__(self) -> None:
        token(self.id, "approver.id", max_length=128)
        _validate_credential_shape(
            credential_type=self.credential_type,
            public_key=self.public_key,
            origins=self.origins,
            rp_id=self.rp_id,
            user_verification=self.user_verification,
            owner="approver",
        )
        if self.credential_type == CREDENTIAL_WEBAUTHN and not self.effective_rp_id:
            raise PolicyError(
                "a webauthn approver needs rp_id or at least one origin to derive it from"
            )

    @property
    def effective_rp_id(self) -> str | None:
        """The relying-party id the authenticator hashed, explicit or from the origin."""
        return _effective_rp_id(self.rp_id, self.origins)

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "id": self.id,
                "credential_type": self.credential_type,
                "public_key": self.public_key,
                "origins": list(self.origins),
                "rp_id": self.rp_id,
                "user_verification": self.user_verification,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> ApproverCredential:
        obj = _members(
            data,
            {"id", "credential_type", "public_key", "origins", "rp_id", "user_verification"},
            "approver",
        )
        return cls(
            id=_required(obj, "id", "approver"),
            credential_type=_required(obj, "credential_type", "approver"),
            public_key=_required(obj, "public_key", "approver"),
            origins=_strings(obj.get("origins", []), "approver.origins"),
            rp_id=obj.get("rp_id"),
            user_verification=bool(obj.get("user_verification", False)),
        )


@dataclasses.dataclass(frozen=True)
class AdminCredential:
    """The admin's signing credential (plan D16, extended): Ed25519 or WebAuthn.

    Same shape as :class:`ApproverCredential`, minus ``id`` — there is one admin,
    not a roster. Deliberately: verifying an admin's signature over a policy and
    verifying an approver's assertion over an escalation are the same function,
    ``merkl.core.policy.approvals.verify_policy_signature`` reusing
    ``verify_assertion`` — no second WebAuthn parser for the admin role. The
    challenge an admin signs is the 32-byte ``policy_hash``, not the legacy
    pre-image and not an escalation's ``LEFT_pre``.

    ``PolicyDocument.admin_public_key`` is the older, narrower shape: an Ed25519
    key with no origin binding, signed the legacy way (see
    :meth:`PolicyDocument.pre_image`). A document carries exactly one of
    ``admin_public_key`` or ``admin`` — see :attr:`PolicyDocument.effective_admin`.
    """

    credential_type: str
    public_key: str
    origins: tuple[str, ...] = ()
    rp_id: str | None = None
    user_verification: bool = False

    def __post_init__(self) -> None:
        _validate_credential_shape(
            credential_type=self.credential_type,
            public_key=self.public_key,
            origins=self.origins,
            rp_id=self.rp_id,
            user_verification=self.user_verification,
            owner="admin",
        )
        if self.credential_type == CREDENTIAL_WEBAUTHN and not self.effective_rp_id:
            raise PolicyError(
                "a webauthn admin needs rp_id or at least one origin to derive it from"
            )

    @property
    def effective_rp_id(self) -> str | None:
        return _effective_rp_id(self.rp_id, self.origins)

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "credential_type": self.credential_type,
                "public_key": self.public_key,
                "origins": list(self.origins),
                "rp_id": self.rp_id,
                "user_verification": self.user_verification,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> AdminCredential:
        obj = _members(
            data,
            {"credential_type", "public_key", "origins", "rp_id", "user_verification"},
            "admin",
        )
        return cls(
            credential_type=_required(obj, "credential_type", "admin"),
            public_key=_required(obj, "public_key", "admin"),
            origins=_strings(obj.get("origins", []), "admin.origins"),
            rp_id=obj.get("rp_id"),
            user_verification=bool(obj.get("user_verification", False)),
        )


@dataclasses.dataclass(frozen=True)
class RiskRule:
    """The destination-risk threshold. A score at or above it is a denial."""

    threshold: str = "1"

    def __post_init__(self) -> None:
        decimal_string(self.threshold, "risk.threshold", positive=False)

    @property
    def value(self) -> Decimal:
        return parse_decimal(self.threshold, "risk.threshold")

    def to_content(self) -> JSONObject:
        return {"threshold": self.threshold}

    @classmethod
    def from_content(cls, data: Any) -> RiskRule:
        obj = _members(data, {"threshold"}, "risk")
        return cls(threshold=obj.get("threshold", "1"))


# --------------------------------------------------------------------------- #
# The document
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class PolicyDocument:
    """Everything the signer needs to decide, and nothing it needs to keep secret.

    A policy document is public: publishing it lets anyone re-run a decision.
    What it must never contain is state — spend history and reservations live in
    the signer (plan D2), because a document that carried its own counters could
    be replayed to reset them.

    ``rail`` names the settlement family this treasury lives on. The signer
    resolves its payload codec from it at boot and refuses to start without one,
    so a policy cannot put a signer in the position of signing bytes it cannot
    read. A policy update may not change it (that would be a different treasury).
    """

    version: str
    treasury: str
    rail: str
    agents: tuple[AgentSection, ...]
    admin_public_key: str | None = None
    admin: AdminCredential | None = None
    tiers: Tiers = dataclasses.field(default_factory=Tiers)
    approvers: tuple[ApproverCredential, ...] = ()
    risk: RiskRule = dataclasses.field(default_factory=RiskRule)
    format: str = POLICY_VERSION_TAG

    def __post_init__(self) -> None:
        token(self.version, "policy.version", max_length=64)
        token(self.treasury, "policy.treasury", max_length=128)
        token(self.rail, "policy.rail", max_length=64)
        if self.admin_public_key is not None and self.admin is not None:
            raise PolicyError(
                "policy.admin_public_key and policy.admin are mutually exclusive; a document "
                "names exactly one admin credential"
            )
        if self.admin_public_key is None and self.admin is None:
            raise PolicyError(
                "a policy document needs an admin: admin_public_key (legacy ed25519) or admin"
            )
        if self.admin_public_key is not None:
            token(self.admin_public_key, "policy.admin_public_key", max_length=256)
        if self.format != POLICY_VERSION_TAG:
            raise PolicyError(
                f"policy.format must be {POLICY_VERSION_TAG!r}, got {self.format!r}"
            )
        if not self.agents:
            raise PolicyError("a policy document names at least one agent")
        ids = [a.agent_id for a in self.agents]
        if len(set(ids)) != len(ids):
            raise PolicyError(f"duplicate agent ids in policy: {sorted(ids)}")
        approver_ids = [a.id for a in self.approvers]
        if len(set(approver_ids)) != len(approver_ids):
            raise PolicyError(f"duplicate approver ids in policy: {sorted(approver_ids)}")
        if self.tiers.human.quorum > max(len(self.approvers), 1) and self.tiers.human.thresholds:
            raise PolicyError(
                f"quorum {self.tiers.human.quorum} exceeds the {len(self.approvers)} "
                "approvers the document names"
            )

    def agent(self, agent_id: str) -> AgentSection | None:
        """The section for one agent, or None when the policy does not know it."""
        for section in self.agents:
            if section.agent_id == agent_id:
                return section
        return None

    def approver(self, approver_id: str) -> ApproverCredential | None:
        for credential in self.approvers:
            if credential.id == approver_id:
                return credential
        return None

    @property
    def effective_admin(self) -> AdminCredential:
        """The admin credential, normalized to one shape regardless of which field is set.

        The legacy ``admin_public_key`` synthesizes an Ed25519 :class:`AdminCredential`
        with no origin binding — exactly what it always meant, just expressed in
        the newer shape so verification has one code path (D16).
        """
        if self.admin is not None:
            return self.admin
        if self.admin_public_key is None:  # pragma: no cover - __post_init__ guarantees one
            raise PolicyError("policy document has neither admin_public_key nor admin")
        return AdminCredential(
            credential_type=CREDENTIAL_ED25519, public_key=self.admin_public_key
        )

    def to_content(self) -> JSONObject:
        content: JSONObject = {
            "format": self.format,
            "version": self.version,
            "treasury": self.treasury,
            "rail": self.rail,
            "agents": [agent.to_content() for agent in self.agents],
            "tiers": self.tiers.to_content(),
            "approvers": [approver.to_content() for approver in self.approvers],
            "risk": self.risk.to_content(),
        }
        # The legacy field, when set, is emitted exactly as it always was — no
        # "admin" member alongside it — so `policy_hash()` over a legacy
        # document is byte-identical to every document signed before this
        # phase (the committed vectors prove it). A document using the newer
        # `admin` credential carries that member instead, never both.
        if self.admin_public_key is not None:
            content["admin_public_key"] = self.admin_public_key
        else:
            assert self.admin is not None  # __post_init__ guarantees exactly one is set
            content["admin"] = self.admin.to_content()
        ensure_canonical_content(content, path="policy")
        return content

    @classmethod
    def from_content(cls, data: Any) -> PolicyDocument:
        obj = _members(
            data,
            {
                "format",
                "version",
                "treasury",
                "rail",
                "agents",
                "tiers",
                "approvers",
                "admin_public_key",
                "admin",
                "risk",
            },
            "policy",
        )
        agents = _required(obj, "agents", "policy")
        approvers = obj.get("approvers", [])
        if not isinstance(agents, list) or not isinstance(approvers, list):
            raise PolicyError("policy.agents and policy.approvers must be arrays")
        admin_content = obj.get("admin")
        return cls(
            format=obj.get("format", POLICY_VERSION_TAG),
            version=_required(obj, "version", "policy"),
            treasury=_required(obj, "treasury", "policy"),
            rail=_required(obj, "rail", "policy"),
            agents=tuple(AgentSection.from_content(a) for a in agents),
            tiers=Tiers.from_content(obj.get("tiers", {})),
            approvers=tuple(ApproverCredential.from_content(a) for a in approvers),
            admin_public_key=obj.get("admin_public_key"),
            admin=(
                AdminCredential.from_content(admin_content) if admin_content is not None else None
            ),
            risk=RiskRule.from_content(obj.get("risk", {})),
        )

    def pre_image(self) -> bytes:
        """``"merkl-policy-v1" || NUL || canonical_bytes(document)`` — hashed and signed."""
        return tagged(POLICY_TAG, canonical_bytes(self.to_content()))

    def policy_hash(self) -> str:
        """The digest every decision names. Lowercase hex."""
        return SHA256Hash.from_bytes(self.pre_image()).hex()


@dataclasses.dataclass(frozen=True)
class SignedPolicy:
    """A policy document and the admin signature that put it into force (D16).

    ``signature`` is either the legacy raw Ed25519 hex over
    :meth:`PolicyDocument.pre_image`, or an ``ApprovalAssertion``-shaped object
    (Ed25519 or WebAuthn) over the 32-byte :meth:`PolicyDocument.policy_hash`.
    It stays unparsed here — ``ApprovalAssertion`` lives in
    ``merkl.core.policy.approvals``, which imports *this* module, and parsing it
    here would be a cycle. ``merkl.core.policy.approvals.verify_policy_signature``
    is where both shapes are actually checked.
    """

    document: PolicyDocument
    signature: str | JSONObject
    signer_public_key: str

    def __post_init__(self) -> None:
        if isinstance(self.signature, str):
            token(self.signature, "signed_policy.signature", max_length=256)
        elif isinstance(self.signature, dict):
            ensure_canonical_content(self.signature, path="signed_policy.signature")
        else:
            raise PolicyError(
                "signed_policy.signature must be a hex string or an assertion object, got "
                f"{type(self.signature).__name__}"
            )
        token(self.signer_public_key, "signed_policy.signer_public_key", max_length=256)

    @property
    def policy_hash(self) -> str:
        return self.document.policy_hash()

    def to_content(self) -> JSONObject:
        return {
            "document": self.document.to_content(),
            "signature": self.signature,
            "signer_public_key": self.signer_public_key,
        }

    @classmethod
    def from_content(cls, data: Any) -> SignedPolicy:
        obj = _members(data, {"document", "signature", "signer_public_key"}, "signed_policy")
        return cls(
            document=PolicyDocument.from_content(_required(obj, "document", "signed_policy")),
            signature=_required(obj, "signature", "signed_policy"),
            signer_public_key=_required(obj, "signer_public_key", "signed_policy"),
        )


@dataclasses.dataclass(frozen=True)
class PolicyChange:
    """The record a signer writes when a policy is replaced (plan D16).

    ``signed_by`` is the credential that authorized the change — the admin the
    signer had pinned *before* the update, not whatever the new document
    nominates. ``credential_type`` names its kind (``ed25519`` or
    ``webauthn``), added alongside it in plan D16's extension so a reader can
    tell which verification path produced this change without re-deriving it
    from the document. Defaults to ``ed25519`` for change entries recorded
    before that field existed — every one of them was.
    """

    old_hash: str
    new_hash: str
    signed_by: str
    at: str
    credential_type: str = CREDENTIAL_ED25519

    def to_content(self) -> JSONObject:
        return {
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "signed_by": self.signed_by,
            "at": self.at,
            "credential_type": self.credential_type,
        }

    @classmethod
    def from_content(cls, data: Any) -> PolicyChange:
        obj = _members(
            data,
            {"old_hash", "new_hash", "signed_by", "at", "credential_type"},
            "policy_change",
        )
        return cls(
            old_hash=_required(obj, "old_hash", "policy_change"),
            new_hash=_required(obj, "new_hash", "policy_change"),
            signed_by=_required(obj, "signed_by", "policy_change"),
            at=_required(obj, "at", "policy_change"),
            credential_type=obj.get("credential_type", CREDENTIAL_ED25519),
        )


def policy_from_json(data: Any) -> PolicyDocument:
    """Parse a policy document from already-decoded JSON."""
    return PolicyDocument.from_content(data)


def currencies(values: Iterable[Any]) -> tuple[CurrencyRef, ...]:
    """Parse a list of currency contents (helper for callers building documents)."""
    return tuple(currency_from_content(v) for v in values)

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Classification(str, Enum):
    SAFE = "SAFE"
    SENSITIVE = "SENSITIVE"
    CRITICAL = "CRITICAL"
    BLOCKED = "BLOCKED"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REQUIRE_STRONG_APPROVAL = "REQUIRE_STRONG_APPROVAL"


class TrustLevel(str, Enum):
    USER_DIRECT = "USER_DIRECT"
    AGENT_INTERNAL = "AGENT_INTERNAL"
    EXTERNAL_CONTENT = "EXTERNAL_CONTENT"
    UNKNOWN = "UNKNOWN"


class OriginType(str, Enum):
    USER_DIRECT = "USER_DIRECT"
    LOCAL_UI = "LOCAL_UI"
    AGENT_INTERNAL = "AGENT_INTERNAL"
    EXTERNAL_CONTENT = "EXTERNAL_CONTENT"
    EXTERNAL_API = "EXTERNAL_API"
    UNKNOWN = "UNKNOWN"


class Channel(str, Enum):
    CLI = "cli"
    DESKTOP_APP = "desktop_app"
    BROWSER = "browser"
    EMAIL = "email"
    WEBPAGE = "webpage"
    API = "api"
    MCP = "mcp"
    UNKNOWN = "unknown"


class AuthenticationMethod(str, Enum):
    NONE = "none"
    LOCAL_SESSION = "local_session"
    PASSPHRASE = "passphrase"
    TOKEN = "token"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    USED = "USED"


@dataclass(frozen=True)
class Provenance:
    origin_type: OriginType = OriginType.UNKNOWN
    channel: Channel = Channel.UNKNOWN
    authenticated: bool = False
    authentication_method: AuthenticationMethod = AuthenticationMethod.UNKNOWN
    session_id: str = ""
    request_id: str = ""
    parent_request_id: str = ""
    delegation_chain: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Provenance":
        if not data:
            return cls()
        delegation_chain = data.get("delegation_chain", [])
        if not isinstance(delegation_chain, list):
            raise ValueError("provenance.delegation_chain must be a list")
        return cls(
            origin_type=OriginType(
                str(data.get("origin_type", OriginType.UNKNOWN.value))
            ),
            channel=Channel(str(data.get("channel", Channel.UNKNOWN.value))),
            authenticated=bool(data.get("authenticated", False)),
            authentication_method=AuthenticationMethod(
                str(
                    data.get(
                        "authentication_method", AuthenticationMethod.UNKNOWN.value
                    )
                )
            ),
            session_id=str(data.get("session_id", "")),
            request_id=str(data.get("request_id", "")),
            parent_request_id=str(data.get("parent_request_id", "")),
            delegation_chain=[str(item) for item in delegation_chain],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin_type": self.origin_type.value,
            "channel": self.channel.value,
            "authenticated": self.authenticated,
            "authentication_method": self.authentication_method.value,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "parent_request_id": self.parent_request_id,
            "delegation_chain": self.delegation_chain,
        }


@dataclass(frozen=True)
class ActionRequest:
    actor: str
    source: str
    tool: str
    action: str
    target: str
    payload_summary: str
    risk_hints: list[str] = field(default_factory=list)
    # Fail closed: a request constructed without an explicit trust level is
    # treated as UNKNOWN (untrusted), not USER_DIRECT. Callers that speak for
    # the operator must set source_trust=TrustLevel.USER_DIRECT explicitly.
    source_trust: TrustLevel = TrustLevel.UNKNOWN
    provenance: Provenance = field(default_factory=Provenance)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionRequest":
        required = ["actor", "source", "tool", "action", "target", "payload_summary"]
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"missing required request fields: {', '.join(missing)}")
        risk_hints = data.get("risk_hints", [])
        if not isinstance(risk_hints, list) or not all(
            isinstance(item, str) for item in risk_hints
        ):
            raise ValueError("risk_hints must be a list of strings")
        provenance_data = data.get("provenance")
        provenance = Provenance.from_dict(provenance_data)
        if "source_trust" in data:
            source_trust = TrustLevel(str(data["source_trust"]))
            # Cap an explicit claim at what source/origin_type evidence supports.
            source_trust, inconsistency = reconcile_trust(
                source_trust, str(data["source"]), provenance.origin_type
            )
            if inconsistency is not None:
                risk_hints = [*risk_hints, inconsistency]
        elif provenance_data:
            source_trust = _trust_from_provenance(provenance)
        else:
            # Fail closed: no explicit trust and no provenance => untrusted.
            source_trust = TrustLevel.UNKNOWN
        return cls(
            actor=str(data["actor"]),
            source=str(data["source"]),
            tool=str(data["tool"]),
            action=str(data["action"]),
            target=str(data["target"]),
            payload_summary=str(data["payload_summary"]),
            risk_hints=risk_hints,
            source_trust=source_trust,
            provenance=provenance,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["source_trust"] = self.source_trust.value
        data["provenance"] = self.provenance.to_dict()
        return data


def _trust_from_provenance(provenance: Provenance) -> TrustLevel:
    if provenance.origin_type == OriginType.USER_DIRECT:
        return TrustLevel.USER_DIRECT
    if provenance.origin_type == OriginType.AGENT_INTERNAL:
        return TrustLevel.AGENT_INTERNAL
    if provenance.origin_type in {OriginType.EXTERNAL_CONTENT, OriginType.EXTERNAL_API}:
        return TrustLevel.EXTERNAL_CONTENT
    return TrustLevel.UNKNOWN


# Risk-hint prefix recorded when reconcile_trust() downgrades an inflated claim.
INCONSISTENT_PROVENANCE_HINT = "inconsistent_provenance"

# Higher rank == more trusted. Used only to compare claimed vs. evidenced trust.
_TRUST_RANK = {
    TrustLevel.UNKNOWN: 0,
    TrustLevel.EXTERNAL_CONTENT: 1,
    TrustLevel.AGENT_INTERNAL: 2,
    TrustLevel.USER_DIRECT: 3,
}

# Source-string tokens that positively indicate untrusted external origin. Kept
# in sync with the inference tokens in agent_sudo/adapters/common.py.
_EXTERNAL_SOURCE_TOKENS = {"web", "email", "document", "external", "slack", "browser"}


def _evidenced_trust(source: str, origin_type: OriginType) -> TrustLevel | None:
    """The most restrictive trust level the (source, origin_type) signals support.

    Returns None when no signal has an opinion (e.g. unknown source + UNKNOWN
    origin) — those cases are left to the fail-closed default, not treated as a
    contradiction. Only positive indicators contribute an opinion.
    """
    evidence: list[TrustLevel] = []
    if origin_type in {OriginType.EXTERNAL_CONTENT, OriginType.EXTERNAL_API}:
        evidence.append(TrustLevel.EXTERNAL_CONTENT)
    elif origin_type == OriginType.AGENT_INTERNAL:
        evidence.append(TrustLevel.AGENT_INTERNAL)
    elif origin_type == OriginType.USER_DIRECT:
        evidence.append(TrustLevel.USER_DIRECT)
    normalized = source.lower()
    if normalized in {"user", "human", "user_direct"}:
        evidence.append(TrustLevel.USER_DIRECT)
    elif any(token in normalized for token in _EXTERNAL_SOURCE_TOKENS):
        evidence.append(TrustLevel.EXTERNAL_CONTENT)
    if not evidence:
        return None
    return min(evidence, key=lambda level: _TRUST_RANK[level])


def reconcile_trust(
    claimed: TrustLevel, source: str, origin_type: OriginType
) -> tuple[TrustLevel, str | None]:
    """Cap an explicitly-claimed trust level at what the evidence supports.

    Fail closed against contradictory provenance: if `claimed` is more trusted
    than the floor implied by `source`/`origin_type`, downgrade it to that floor
    and return an explaining reason. Downgrade only — a caller may always claim
    a *lower* trust than the evidence (self-restriction). Neutral/absent signals
    contribute no opinion and never trigger a downgrade. A claim that is
    internally consistent with its evidence is returned unchanged (a fully
    consistent forgery is a documented limitation, not detectable here).
    """
    ceiling = _evidenced_trust(source, origin_type)
    if ceiling is None or _TRUST_RANK[claimed] <= _TRUST_RANK[ceiling]:
        return claimed, None
    reason = (
        f"{INCONSISTENT_PROVENANCE_HINT}: source_trust={claimed.value} exceeds "
        f"evidence (source={source!r}, origin_type={origin_type.value}); "
        f"downgraded to {ceiling.value}"
    )
    return ceiling, reason


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    method: str
    reason: str
    pending: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "method": self.method,
            "reason": self.reason,
            "pending": self.pending,
        }


@dataclass(frozen=True)
class GatewayResult:
    request: ActionRequest
    classification: Classification
    decision: Decision
    approval_method: str
    reason: str
    dry_run: bool = False
    approval_attempts: list[dict[str, Any]] = field(default_factory=list)
    approval_request_id: str = ""
    approval_command: str = ""
    approval_expires_at: str = ""
    approval_expires_in_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "classification": self.classification.value,
            "decision": self.decision.value,
            "approval_method": self.approval_method,
            "approval_attempts": self.approval_attempts,
            "reason": self.reason,
            "dry_run": self.dry_run,
            "approval_request_id": self.approval_request_id,
            "approval_command": self.approval_command,
            "approval_expires_at": self.approval_expires_at,
            "approval_expires_in_seconds": self.approval_expires_in_seconds,
        }


@dataclass(frozen=True)
class DelegationToken:
    token_id: str
    actor: str
    allowed_actions: list[str]
    allowed_paths: list[str]
    denied_actions: list[str]
    expires_at: str
    max_uses: int
    created_at: str
    reason: str
    uses: int = 0
    revoked: bool = False
    critical: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationToken":
        return cls(
            token_id=str(data["token_id"]),
            actor=str(data["actor"]),
            allowed_actions=[str(item) for item in data.get("allowed_actions", [])],
            allowed_paths=[str(item) for item in data.get("allowed_paths", [])],
            denied_actions=[str(item) for item in data.get("denied_actions", [])],
            expires_at=str(data["expires_at"]),
            max_uses=int(data["max_uses"]),
            created_at=str(data["created_at"]),
            reason=str(data.get("reason", "")),
            uses=int(data.get("uses", 0)),
            revoked=bool(data.get("revoked", False)),
            critical=bool(data.get("critical", False)),
        )

    @classmethod
    def create(
        cls,
        *,
        token_id: str,
        actor: str,
        allowed_actions: list[str],
        allowed_paths: list[str],
        denied_actions: list[str],
        expires_at: datetime,
        max_uses: int,
        created_at: datetime,
        reason: str,
        critical: bool = False,
    ) -> "DelegationToken":
        return cls(
            token_id=token_id,
            actor=actor,
            allowed_actions=allowed_actions,
            allowed_paths=allowed_paths,
            denied_actions=denied_actions,
            expires_at=expires_at.isoformat().replace("+00:00", "Z"),
            max_uses=max_uses,
            created_at=created_at.isoformat().replace("+00:00", "Z"),
            reason=reason,
            critical=critical,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalRequest:
    approval_request_id: str
    action_request: ActionRequest
    classification: Classification
    decision: Decision
    required_approval_method: str
    created_at: str
    expires_at: str
    status: ApprovalStatus
    reason: str
    # Run-context of the process that requested this approval (issue #109):
    # which agent-sudo copy, client, workspace, pid. Optional and additive so
    # older records (and external producers) deserialize unchanged.
    run_context: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovalRequest":
        run_context = data.get("run_context")
        return cls(
            approval_request_id=str(data["approval_request_id"]),
            action_request=ActionRequest.from_dict(data["action_request"]),
            classification=Classification(str(data["classification"])),
            decision=Decision(str(data["decision"])),
            required_approval_method=str(data["required_approval_method"]),
            created_at=str(data["created_at"]),
            expires_at=str(data["expires_at"]),
            status=ApprovalStatus(str(data["status"])),
            reason=str(data.get("reason", "")),
            run_context=run_context if isinstance(run_context, dict) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "approval_request_id": self.approval_request_id,
            "action_request": self.action_request.to_dict(),
            "classification": self.classification.value,
            "decision": self.decision.value,
            "required_approval_method": self.required_approval_method,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "reason": self.reason,
        }
        if self.run_context is not None:
            data["run_context"] = self.run_context
        return data

"""One-shot evaluation: the full Agent_Sudo value demonstration in one command.

`agent-sudo eval` runs the blocked -> delegated -> allowed-once -> denied ->
audit-verified ladder in-process through the real engine (the same
`MCPGateway`/`PermissionGateway` the MCP server uses), writing to an isolated
temp directory. It replaces the hand-pasted Python snippets in the 5-minute
evaluation path.

Additive only: no policy, delegation-model, provenance, or default-path changes.
"""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stderr
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_sudo import __version_label__
from agent_sudo.audit import AuditLogger, verify_audit_log
from agent_sudo.delegations import DelegationStore
from agent_sudo.mcp_gateway import MCPGateway
from agent_sudo.models import Decision
from agent_sudo.pending_approvals import PendingApprovalStore
from agent_sudo.policy import load_default_policy

# Exit codes
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

_ACTOR = "codex"
_CALL: dict[str, Any] = {
    "name": "run_shell_command",
    "arguments": {"command": "pwd"},
    "actor": _ACTOR,
}


@dataclass
class StepResult:
    n: int
    name: str  # machine-readable
    label: str  # human-readable
    passed: bool
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalReport:
    steps: list[StepResult]
    audit_log: Path
    token_id: str | None = None

    @property
    def passed(self) -> bool:
        return bool(self.steps) and all(s.passed for s in self.steps)


def _build_gateway(
    audit_path: Path, pending_path: Path, store: DelegationStore
) -> MCPGateway:
    # Imported here to avoid an import cycle (gateway lazily imports this module).
    from agent_sudo.gateway import PermissionGateway

    audit_logger = AuditLogger(audit_path)
    # A non-interactive pending-approval store mirrors the MCP server: an
    # unapproved critical action becomes a silent pending request (no passphrase
    # prompt, no stray "approval system not initialized" output during eval).
    pending = PendingApprovalStore(
        pending_path, audit_logger=audit_logger, notify=False
    )
    # Mock no-TTY to ensure we get a pending request rather than instant denial.
    from agent_sudo.approvals import ApprovalProvider

    approvals = ApprovalProvider(stdin_is_tty=lambda: False)

    gateway = PermissionGateway(
        load_default_policy(),
        approvals=approvals,
        audit_logger=audit_logger,
        delegation_store=store,
        pending_approval_store=pending,
    )
    return MCPGateway(gateway)


def _dispatch(gateway: MCPGateway):
    """Dispatch the standard eval call, suppressing the engine's informational
    'approval system not initialized' stderr notice (eval intentionally has no
    passphrase configured). Exceptions still propagate."""
    with redirect_stderr(io.StringIO()):
        return gateway.dispatch(dict(_CALL))


def run_eval(*, output_dir: Path | str | None = None) -> EvalReport:
    """Run the five-step ladder and return a structured report.

    Writes the audit log and delegation store under a persisted temp directory
    (so the printed path survives for inspection) unless ``output_dir`` is given.
    Never reads or mutates the user's default ``~/.agent-sudo`` paths.
    """
    if output_dir is not None:
        base = Path(output_dir)
    else:
        base = Path(tempfile.mkdtemp(prefix="agent-sudo-eval-"))
    base.mkdir(parents=True, exist_ok=True)
    audit_path = base / "audit.jsonl"
    deleg_path = base / "delegations.json"
    pending_path = base / "pending_approvals.json"

    store = DelegationStore(deleg_path)
    gateway = _build_gateway(audit_path, pending_path, store)
    steps: list[StepResult] = []

    # [1/5] An unsafe (critical) request is blocked with no delegation/approval.
    r1 = _dispatch(gateway)
    steps.append(
        StepResult(
            1,
            "blocked_unsafe_request",
            "Blocked unsafe request",
            r1.gateway_result.decision == Decision.REQUIRE_STRONG_APPROVAL
            and not r1.executed,
            {"decision": r1.gateway_result.decision.value, "executed": r1.executed},
        )
    )

    # [2/5] Create a one-use, scoped delegation for exactly that action+target.
    token = store.create(
        actor=_ACTOR,
        allowed_actions=["run_shell_command"],
        allowed_paths=["pwd"],
        ttl_seconds=300,
        max_uses=1,
        critical=True,
        reason="agent-sudo eval",
    )
    steps.append(
        StepResult(
            2,
            "created_delegation",
            "Created delegation",
            token is not None,
            {"token_id": token.token_id},
        )
    )

    # [3/5] The same request is now allowed exactly once, via the delegation.
    r3 = _dispatch(gateway)
    steps.append(
        StepResult(
            3,
            "delegated_request_allowed",
            "Delegated request allowed",
            r3.gateway_result.decision == Decision.ALLOW
            and r3.gateway_result.approval_method == "DELEGATION"
            and r3.executed,
            {
                "decision": r3.gateway_result.decision.value,
                "method": r3.gateway_result.approval_method,
                "executed": r3.executed,
            },
        )
    )

    # [4/5] The next attempt is denied: the one-use token is exhausted.
    r4 = _dispatch(gateway)
    uses = next(
        (t.uses for t in store.list() if t.token_id == token.token_id),
        None,
    )
    steps.append(
        StepResult(
            4,
            "token_exhausted_denied",
            "Token exhausted, denied again",
            r4.gateway_result.decision == Decision.DENY and uses == 1,
            {"decision": r4.gateway_result.decision.value, "uses": uses},
        )
    )

    # [5/5] The tamper-evident audit chain verifies.
    ok, message = verify_audit_log(audit_path)
    steps.append(
        StepResult(
            5,
            "audit_chain_verified",
            "Audit chain verified",
            ok,
            {"message": message},
        )
    )

    return EvalReport(steps=steps, audit_log=audit_path, token_id=token.token_id)


_DOT_WIDTH = 36


def format_report(report: EvalReport) -> str:
    """Human-readable evaluation output."""
    lines = ["Agent_Sudo Evaluation", ""]
    for step in report.steps:
        status = "PASS" if step.passed else "FAIL"
        prefix = f"[{step.n}/5] {step.label} "
        dots = "." * max(1, _DOT_WIDTH - len(prefix))
        line = f"{prefix}{dots} {status}"
        if not step.passed:
            line += f"  ({_failure_hint(step)})"
        lines.append(line)
    lines.append("")
    lines.append(f"Result: {'PASS' if report.passed else 'FAIL'}")
    lines.append(f"Audit log: {report.audit_log}")
    if report.passed:
        lines.append(f"Next: agent-sudo audit list {report.audit_log}")
        lines += ["", _WHAT_YOU_SAW]
    return "\n".join(lines)


_WHAT_YOU_SAW = (
    "What you just saw:\n"
    "  A critical action was blocked by default; a scoped, one-use delegation\n"
    "  let exactly one matching call through; the next call was denied once the\n"
    "  token was exhausted; and every decision was written to a hash-chained\n"
    "  audit log that verified clean. That is authorization + delegation +\n"
    "  tamper-evident audit, end to end."
)


def _failure_hint(step: StepResult) -> str:
    d = step.detail
    if "decision" in d:
        return f"got decision={d.get('decision')} executed={d.get('executed')}"
    if "message" in d:
        return str(d.get("message"))
    return "unexpected result"


def format_report_json(report: EvalReport) -> str:
    return json.dumps(
        {
            "result": "pass" if report.passed else "fail",
            "steps": [
                {
                    "n": s.n,
                    "name": s.name,
                    "status": "pass" if s.passed else "fail",
                    **s.detail,
                }
                for s in report.steps
            ],
            "audit_log": str(report.audit_log),
            "version": __version_label__,
        },
        indent=2,
    )

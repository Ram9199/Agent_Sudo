from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

from agent_sudo import __version_label__
from agent_sudo.approvals import ApprovalProvider, init_approval_config, CONFIG_PATH
from agent_sudo.audit import (
    AuditLogger,
    audit_entries_since,
    filter_entries,
    format_audit_log,
    format_audit_review,
    parse_since_window,
    read_audit_entries,
    verify_audit_log,
)
from agent_sudo.classifier import ActionClassifier
from agent_sudo.delegations import (
    DelegationStore,
    DELEGATIONS_PATH_ENV,
    default_delegations_path,
    delegation_status,
    is_broad_delegation,
)
from agent_sudo.doctor import doctor_exit_code, format_doctor_checks, run_doctor
from agent_sudo.models import (
    INCONSISTENT_PROVENANCE_HINT,
    ActionRequest,
    ApprovalStatus,
    Classification,
    Decision,
    GatewayResult,
    OriginType,
    TrustLevel,
)
from agent_sudo.pending_approvals import (
    PENDING_APPROVALS_PATH,
    PendingApprovalStore,
    approval_command,
    format_pending_approvals,
    resolve_approval_identifier,
    expires_in_seconds,
)
from agent_sudo.policy import Policy, load_default_policy, load_policy


class PermissionGateway:
    def __init__(
        self,
        policy: Policy,
        approvals: ApprovalProvider | None = None,
        audit_logger: AuditLogger | None = None,
        delegation_store: DelegationStore | None = None,
        pending_approval_store: PendingApprovalStore | None = None,
    ):
        self.policy = policy
        self.classifier = ActionClassifier(policy)
        self.approvals = approvals or ApprovalProvider()
        self.audit_logger = audit_logger
        self.delegation_store = delegation_store
        self.pending_approval_store = pending_approval_store

    def evaluate(
        self, request: ActionRequest, *, dry_run: bool = False
    ) -> GatewayResult:
        classification = self.classifier.classify(request)
        policy_result = self.policy.decision_for(classification)
        decision = policy_result.decision
        approval_method = "none"
        reason = policy_result.reason
        # Surface a provenance-consistency downgrade in the decision/audit reason.
        inconsistency = next(
            (
                hint
                for hint in request.risk_hints
                if hint.startswith(INCONSISTENT_PROVENANCE_HINT)
            ),
            None,
        )
        if inconsistency is not None:
            reason = f"{reason}; {inconsistency}"
        approval_attempts: list[dict[str, object]] = []
        approval_request_id = ""
        approval_command_text = ""
        approval_expires_at = ""
        approval_expires_in_seconds: int | None = None

        if dry_run and decision in {
            Decision.REQUIRE_APPROVAL,
            Decision.REQUIRE_STRONG_APPROVAL,
        }:
            approval_method = "dry_run"
            reason = f"{reason}; approval skipped in dry-run"
        elif (
            decision in {Decision.REQUIRE_APPROVAL, Decision.REQUIRE_STRONG_APPROVAL}
            and self.delegation_store
        ):
            delegated, delegation_reason, delegation_method = (
                self.delegation_store.authorize(
                    request,
                    classification=classification,
                )
            )
            if delegated is True:
                decision = Decision.ALLOW
                approval_method = delegation_method
                reason = delegation_reason
                approval_attempts.append(
                    {
                        "approved": True,
                        "method": delegation_method,
                        "reason": delegation_reason,
                        "pending": False,
                    }
                )
            elif delegated is False:
                decision = Decision.DENY
                approval_method = delegation_method
                reason = delegation_reason
                approval_attempts.append(
                    {
                        "approved": False,
                        "method": delegation_method,
                        "reason": delegation_reason,
                        "pending": False,
                    }
                )
            else:
                pending_decision = self._evaluate_pending_approval(request)
                if pending_decision is not None:
                    (
                        decision,
                        approval_method,
                        reason,
                        approval_request_id,
                        approval_command_text,
                        approval_expires_at,
                        approval_expires_in_seconds,
                    ) = pending_decision
                else:
                    (
                        decision,
                        approval_method,
                        reason,
                        approval_attempts,
                        approval_request_id,
                        approval_command_text,
                        approval_expires_at,
                        approval_expires_in_seconds,
                    ) = self._prompt_for_approval(
                        request,
                        classification,
                        decision,
                        approval_attempts,
                    )
                if delegation_method == "DELEGATION":
                    reason = f"{delegation_reason}; {reason}"
        elif (
            decision in {Decision.REQUIRE_APPROVAL, Decision.REQUIRE_STRONG_APPROVAL}
            and self.pending_approval_store
        ):
            pending_decision = self._evaluate_pending_approval(request)
            if pending_decision is not None:
                (
                    decision,
                    approval_method,
                    reason,
                    approval_request_id,
                    approval_command_text,
                    approval_expires_at,
                    approval_expires_in_seconds,
                ) = pending_decision
            elif _external_content_requires_delegation(request, decision):
                approval_method = "DENY"
                decision = Decision.DENY
                reason = "external content cannot approve, escalate, or initiate tool execution without delegation"
                approval_attempts.append(
                    {
                        "approved": False,
                        "method": "DENY",
                        "reason": reason,
                        "pending": False,
                    }
                )
            else:
                (
                    decision,
                    approval_method,
                    reason,
                    approval_attempts,
                    approval_request_id,
                    approval_command_text,
                    approval_expires_at,
                    approval_expires_in_seconds,
                ) = self._prompt_for_approval(
                    request,
                    classification,
                    decision,
                    approval_attempts,
                )
        elif _external_content_requires_delegation(request, decision):
            approval_method = "DENY"
            decision = Decision.DENY
            reason = "external content cannot approve, escalate, or initiate tool execution without delegation"
            approval_attempts.append(
                {
                    "approved": False,
                    "method": "DENY",
                    "reason": reason,
                    "pending": False,
                }
            )
        elif decision in {Decision.REQUIRE_APPROVAL, Decision.REQUIRE_STRONG_APPROVAL}:
            (
                decision,
                approval_method,
                reason,
                approval_attempts,
                approval_request_id,
                approval_command_text,
                approval_expires_at,
                approval_expires_in_seconds,
            ) = self._prompt_for_approval(
                request,
                classification,
                decision,
                approval_attempts,
            )

        result = GatewayResult(
            request=request,
            classification=classification,
            decision=decision,
            approval_method=approval_method,
            reason=reason,
            dry_run=dry_run,
            approval_attempts=approval_attempts,
            approval_request_id=approval_request_id,
            approval_command=approval_command_text,
            approval_expires_at=approval_expires_at,
            approval_expires_in_seconds=approval_expires_in_seconds,
        )
        if self.audit_logger is not None:
            self.audit_logger.record(result)
        return result

    def _prompt_for_approval(
        self,
        request: ActionRequest,
        classification: Classification,
        decision: Decision,
        approval_attempts: list[dict[str, object]],
    ) -> tuple[Decision, str, str, list[dict[str, object]], str, str, str, int | None]:
        if decision == Decision.REQUIRE_APPROVAL:
            approval = self.approvals.approve_sensitive(request)
            approval_method = approval.method
            approval_attempts.append(approval.to_dict())
            if approval.pending:
                approval_id, command, reason, expires_at, expires_in = (
                    self._create_pending_approval(
                        request,
                        classification,
                        decision,
                        approval_method,
                        approval.reason,
                    )
                )
                decision = Decision.REQUIRE_APPROVAL
                return (
                    decision,
                    approval_method,
                    reason,
                    approval_attempts,
                    approval_id,
                    command,
                    expires_at,
                    expires_in,
                )
            else:
                decision = Decision.ALLOW if approval.approved else Decision.DENY
            reason = approval.reason
            return (
                decision,
                approval_method,
                reason,
                approval_attempts,
                "",
                "",
                "",
                None,
            )
        if decision == Decision.REQUIRE_STRONG_APPROVAL:
            approval = self.approvals.approve_critical(request)
            approval_method = approval.method
            approval_attempts.append(approval.to_dict())
            if approval.pending:
                approval_id, command, reason, expires_at, expires_in = (
                    self._create_pending_approval(
                        request,
                        classification,
                        decision,
                        approval_method,
                        approval.reason,
                    )
                )
                decision = Decision.REQUIRE_STRONG_APPROVAL
                return (
                    decision,
                    approval_method,
                    reason,
                    approval_attempts,
                    approval_id,
                    command,
                    expires_at,
                    expires_in,
                )
            else:
                decision = Decision.ALLOW if approval.approved else Decision.DENY
            reason = approval.reason
            return (
                decision,
                approval_method,
                reason,
                approval_attempts,
                "",
                "",
                "",
                None,
            )
        return (
            decision,
            "none",
            "approval not required",
            approval_attempts,
            "",
            "",
            "",
            None,
        )

    def _evaluate_pending_approval(
        self,
        request: ActionRequest,
    ) -> tuple[Decision, str, str, str, str, str, int | None] | None:
        if self.pending_approval_store is None:
            return None
        approval = self.pending_approval_store.find_matching(request)
        if approval is None:
            return None
        if approval.status == ApprovalStatus.APPROVED:
            used = self.pending_approval_store.consume_matching(request)
            if used is not None:
                return (
                    Decision.ALLOW,
                    "PENDING_APPROVAL",
                    f"approved by pending approval {used.approval_request_id}",
                    used.approval_request_id,
                    "",
                    "",
                    None,
                )
        command = approval_command(approval.approval_request_id)
        if approval.status == ApprovalStatus.PENDING:
            return (
                approval.decision,
                approval.required_approval_method,
                approval.reason,
                approval.approval_request_id,
                command,
                approval.expires_at,
                expires_in_seconds(approval),
            )
        return (
            Decision.DENY,
            "PENDING_APPROVAL",
            f"approval request is {approval.status.value}",
            approval.approval_request_id,
            "",
            "",
            None,
        )

    def _create_pending_approval(
        self,
        request: ActionRequest,
        classification: Classification,
        decision: Decision,
        required_approval_method: str,
        reason: str,
    ) -> tuple[str, str, str, str, int | None]:
        config_path = (
            self.approvals.config_path
            if hasattr(self.approvals, "config_path")
            else CONFIG_PATH
        )
        if not config_path.exists():
            sys.stderr.write(
                "approval system not initialized\n\n"
                "Run:\n"
                "agent-sudo init-approval\n\n"
                "to create a local approval passphrase.\n"
            )
        if self.pending_approval_store is None:
            return "", "", reason, "", None
        approval = self.pending_approval_store.create(
            action_request=request,
            classification=classification,
            decision=decision,
            required_approval_method=required_approval_method,
            reason=reason,
        )
        command = approval_command(approval.approval_request_id)
        return (
            approval.approval_request_id,
            command,
            f"{reason}; pending approval created: {approval.approval_request_id}; run `{command}`",
            approval.expires_at,
            expires_in_seconds(approval),
        )


def _external_content_requires_delegation(
    request: ActionRequest, decision: Decision
) -> bool:
    if decision not in {Decision.REQUIRE_APPROVAL, Decision.REQUIRE_STRONG_APPROVAL}:
        return False
    return (
        request.source_trust == TrustLevel.EXTERNAL_CONTENT
        or request.provenance.origin_type == OriginType.EXTERNAL_CONTENT
    )


class RequestInputError(Exception):
    """A request / tool-call input file is missing or not valid JSON.

    Raised by the input loaders so the CLI can print a friendly one-line error
    and a payload example instead of dumping a raw traceback (and the user's
    path) for the common mistake of passing an inline string or a bad path.
    """


_REQUEST_EXAMPLE = (
    '{"actor": "agent", "source": "user", "tool": "shell", '
    '"action": "run_shell_command", "target": "ls", '
    '"payload_summary": "list files"}'
)
_TOOL_CALL_EXAMPLE = '{"name": "run_shell_command", "arguments": {"command": "ls"}}'
_REQUEST_FILE_HELP = (
    "Path to a JSON file containing the request (an object, or a list of "
    f"objects). Not an inline string. Example contents: {_REQUEST_EXAMPLE}"
)
_TOOL_CALL_FILE_HELP = (
    "Path to a JSON file containing the native tool call. Not an inline "
    f"string. Example contents: {_TOOL_CALL_EXAMPLE}"
)


def _read_json_input(path: Path, *, kind: str, example: str) -> object:
    """Read and parse a JSON input file, raising :class:`RequestInputError`.

    ``kind`` names the input in messages (e.g. ``"request"``); ``example`` is a
    minimal valid payload shown to the user when the file is missing or invalid.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RequestInputError(
            f"{kind} file not found: {path}\n"
            f"This argument is a path to a JSON file, not an inline {kind}.\n"
            f"Example {kind} file contents:\n  {example}"
        ) from exc
    except OSError as exc:
        raise RequestInputError(f"could not read {kind} file {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RequestInputError(
            f"{kind} file is not valid JSON: {path} ({exc})\n"
            f"Example {kind} file contents:\n  {example}"
        ) from exc


def load_requests(path: Path) -> list[ActionRequest]:
    raw = _read_json_input(path, kind="request", example=_REQUEST_EXAMPLE)
    items = raw if isinstance(raw, list) else [raw]
    if not isinstance(items, list):
        raise ValueError("request file must contain a JSON object or list")
    return [ActionRequest.from_dict(item) for item in items]


def _resolve_default_audit_log_path() -> Path:
    local_path = Path(".agent-sudo/mcp-audit.jsonl")
    if local_path.exists():
        return local_path
    return Path("~/.agent-sudo/mcp-audit.jsonl").expanduser()


class _VersionAction(argparse.Action):
    """Print version + provenance (which copy of agent-sudo is running)."""

    def __init__(self, option_strings, dest, **kwargs):
        kwargs.setdefault("nargs", 0)
        kwargs.setdefault("help", "show version and which install is running")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        from agent_sudo.self_identity import (
            describe_running_install,
            format_version_block,
        )

        identity = describe_running_install()
        print(format_version_block(identity, version_label=__version_label__))
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-sudo")
    parser.add_argument("--version", action=_VersionAction)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check", help="Classify requests and show policy decisions"
    )
    check_parser.add_argument("request_file", type=Path, help=_REQUEST_FILE_HELP)
    check_parser.add_argument("--policy", type=Path, help="Path to policy YAML")

    run_parser = subparsers.add_parser(
        "run", help="Evaluate requests with approvals and audit logging"
    )
    run_parser.add_argument("request_file", type=Path, help=_REQUEST_FILE_HELP)
    run_parser.add_argument("--policy", type=Path, help="Path to policy YAML")
    run_parser.add_argument(
        "--dry-run", action="store_true", help="Skip approval prompts"
    )
    run_parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path(".agent-sudo/audit.jsonl"),
        help="Audit JSONL path",
    )
    run_parser.add_argument(
        "--notify",
        action="store_true",
        help="Enable desktop notifications for pending approvals",
    )
    run_parser.add_argument(
        "--open-approval-terminal",
        action="store_true",
        help="Automatically open Terminal.app for pending approvals",
    )

    hermes_parser = subparsers.add_parser(
        "hermes-check", help="Normalize and check an agent native tool call"
    )
    hermes_parser.add_argument("tool_call_file", type=Path, help=_TOOL_CALL_FILE_HELP)
    hermes_parser.add_argument("--policy", type=Path, help="Path to policy YAML")

    codex_parser = subparsers.add_parser(
        "codex-check", help="Normalize and check a Codex native tool call"
    )
    codex_parser.add_argument("tool_call_file", type=Path, help=_TOOL_CALL_FILE_HELP)
    codex_parser.add_argument("--policy", type=Path, help="Path to policy YAML")

    generic_check_parser = subparsers.add_parser(
        "generic-check", help="Normalize and check a universal tool call"
    )
    generic_check_parser.add_argument(
        "tool_call_file", type=Path, help=_TOOL_CALL_FILE_HELP
    )
    generic_check_parser.add_argument("--policy", type=Path, help="Path to policy YAML")

    generic_run_parser = subparsers.add_parser(
        "generic-run", help="Evaluate a universal tool call"
    )
    generic_run_parser.add_argument(
        "tool_call_file", type=Path, help=_TOOL_CALL_FILE_HELP
    )
    generic_run_parser.add_argument("--policy", type=Path, help="Path to policy YAML")
    generic_run_parser.add_argument("--dry-run", action="store_true")
    generic_run_parser.add_argument(
        "--audit-log", type=Path, default=Path(".agent-sudo/audit.jsonl")
    )
    generic_run_parser.add_argument(
        "--notify",
        action="store_true",
        help="Enable desktop notifications for pending approvals",
    )
    generic_run_parser.add_argument(
        "--open-approval-terminal",
        action="store_true",
        help="Automatically open Terminal.app for pending approvals",
    )

    verify_parser = subparsers.add_parser(
        "verify-audit", help="Verify audit JSONL hash chain"
    )
    verify_parser.add_argument(
        "audit_log",
        type=Path,
        nargs="?",
        default=None,
        help="Path to audit JSONL (default: ~/.agent-sudo/mcp-audit.jsonl)",
    )

    audit_parser = subparsers.add_parser(
        "audit", help="Inspect the local audit log in human-readable form"
    )
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_list = audit_subparsers.add_parser(
        "list", help="Show recent audit decisions as a readable table"
    )
    audit_list.add_argument(
        "audit_log",
        type=Path,
        nargs="?",
        default=None,
        help="Path to audit JSONL (default: ~/.agent-sudo/mcp-audit.jsonl)",
    )
    audit_list.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Show only the most recent N records (default: 20; use 0 for all)",
    )
    audit_list.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON records instead of a table",
    )
    audit_list.add_argument(
        "--since",
        help="Only records within a window (examples: 30m, 24h, 7d)",
    )
    audit_list.add_argument(
        "--decision",
        choices=["ALLOW", "DENY", "REQUIRE_APPROVAL", "REQUIRE_STRONG_APPROVAL"],
        help="Keep only records with this decision",
    )
    audit_list.add_argument(
        "--origin",
        choices=[
            "USER_DIRECT",
            "LOCAL_UI",
            "AGENT_INTERNAL",
            "EXTERNAL_CONTENT",
            "EXTERNAL_API",
            "UNKNOWN",
        ],
        help="Keep only records whose provenance origin matches",
    )
    audit_list.add_argument(
        "--actor", help="Keep only records whose actor contains this substring"
    )
    audit_list.add_argument(
        "--tool", help="Keep only records whose tool contains this substring"
    )
    audit_list.add_argument(
        "--target", help="Keep only records whose target contains this substring"
    )
    audit_list.add_argument(
        "--non-allow",
        action="store_true",
        help="Exclude ALLOW decisions (show denials, approvals, escalations)",
    )
    audit_review = audit_subparsers.add_parser(
        "review",
        help="Review the recent audit window with verification and non-ALLOW rows",
    )
    audit_review.add_argument(
        "audit_log",
        type=Path,
        nargs="?",
        default=None,
        help="Path to audit JSONL (default: ~/.agent-sudo/mcp-audit.jsonl)",
    )
    audit_review.add_argument(
        "--since",
        default="24h",
        help="Window to review (default: 24h; examples: 30m, 24h, 7d)",
    )
    audit_trace = audit_subparsers.add_parser(
        "trace",
        help="Trace one delegation token's lifecycle across the audit log",
    )
    audit_trace.add_argument(
        "token_id", help="Delegation token id (full or unique prefix)"
    )
    audit_trace.add_argument(
        "audit_log",
        type=Path,
        nargs="?",
        default=None,
        help="Path to audit JSONL (default: ~/.agent-sudo/mcp-audit.jsonl)",
    )
    audit_trace.add_argument(
        "--delegations-file",
        type=Path,
        default=None,
        help=(
            "Path to delegations.json (default: alongside the audit log, "
            "else ~/.agent-sudo/delegations.json)"
        ),
    )
    audit_trace.add_argument(
        "--json",
        action="store_true",
        help="Output the trace as JSON instead of a table",
    )

    init_parser = subparsers.add_parser(
        "init-approval",
        help="Initialize or reset local approval passphrase hash",
        description=(
            "Initialize or reset the local agent-sudo passphrase hash. "
            "If a passphrase already exists, resetting it will: "
            "(1) revoke all existing delegation tokens, "
            "(2) cancel all active pending or approved requests, "
            "(3) preserve existing audit logs, and "
            "(4) log a chained 'passphrase_reset' event to the audit log. "
            "The old passphrase is one-way hashed only and cannot be recovered."
        ),
    )
    init_parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    init_parser.add_argument(
        "--pending-approvals-file", type=Path, default=PENDING_APPROVALS_PATH
    )
    init_parser.add_argument(
        "--delegations-file", type=Path, default=default_delegations_path()
    )
    init_parser.add_argument(
        "--audit-log", type=Path, default=Path(".agent-sudo/audit.jsonl")
    )
    init_parser.add_argument("--force", action="store_true")
    subparsers.add_parser("doctor", help="Check local agent-sudo readiness")
    inventory_parser = subparsers.add_parser(
        "inventory",
        help=(
            "Read-only report of Agent_Sudo installs, MCP client configs, "
            "and version drift"
        ),
    )
    inventory_parser.add_argument(
        "--json", action="store_true", help="Emit the report as JSON"
    )
    topology_parser = subparsers.add_parser(
        "topology",
        help=(
            "Read-only view of which Agent_Sudo instances guard you (CLI, MCP "
            "clients, audit logs) and what is not routed through Agent_Sudo"
        ),
    )
    topology_parser.add_argument(
        "--json", action="store_true", help="Emit the topology as JSON"
    )
    verify_routing_parser = subparsers.add_parser(
        "verify-routing",
        help="Report observed evidence of whether actions flow through Agent_Sudo",
    )
    verify_routing_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on a provable misconfiguration (for scripted checks)",
    )
    subparsers.add_parser(
        "demo", help="Run a built-in interactive demo of Agent_Sudo gateway decisions"
    )

    eval_parser = subparsers.add_parser(
        "eval",
        help=(
            "Run the full blocked -> delegated -> allowed-once -> denied -> "
            "verified evaluation in one command"
        ),
    )
    eval_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Write eval artifacts here instead of a temp dir",
    )
    eval_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a table",
    )

    approvals_parser = subparsers.add_parser(
        "approvals", help="Manage pending approval requests"
    )
    approvals_subparsers = approvals_parser.add_subparsers(
        dest="approvals_command", required=True
    )
    approvals_list = approvals_subparsers.add_parser(
        "list", help="List pending approval requests"
    )
    approvals_list.add_argument(
        "--pending-approvals-file", type=Path, default=PENDING_APPROVALS_PATH
    )

    pending_parser = subparsers.add_parser(
        "pending", help="List active pending approval requests"
    )
    pending_parser.add_argument(
        "--pending-approvals-file", type=Path, default=PENDING_APPROVALS_PATH
    )

    approve_parser = subparsers.add_parser(
        "approve", help="Approve a pending approval request"
    )
    approve_parser.add_argument("approval_request_id")
    approve_parser.add_argument(
        "--pending-approvals-file", type=Path, default=PENDING_APPROVALS_PATH
    )
    approve_parser.add_argument("--audit-log", type=Path)
    approve_parser.add_argument("--approval-config", type=Path)

    deny_parser = subparsers.add_parser("deny", help="Deny a pending approval request")
    deny_parser.add_argument("approval_request_id")
    deny_parser.add_argument(
        "--pending-approvals-file", type=Path, default=PENDING_APPROVALS_PATH
    )
    deny_parser.add_argument("--audit-log", type=Path)

    helper_parser = subparsers.add_parser(
        "approval-helper", help="Guided terminal approval helper for pending requests"
    )
    helper_parser.add_argument(
        "--pending-approvals-file", type=Path, default=PENDING_APPROVALS_PATH
    )
    helper_parser.add_argument("--approval-config", type=Path, default=CONFIG_PATH)
    helper_parser.add_argument("--audit-log", type=Path)
    helper_parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously poll and watch for new requests",
    )
    helper_parser.add_argument(
        "--auto-opened",
        action="store_true",
        help="Minimal display mode with auto-close logic for auto-opened terminals",
    )

    setup_parser = subparsers.add_parser(
        "setup",
        help=(
            "Print dry-run setup instructions for an agent runtime "
            "(run with no target for an interactive picker)"
        ),
    )
    setup_parser.add_argument(
        "agent",
        nargs="?",
        default=None,
        choices=["hermes", "codex", "claude-code", "claude-desktop", "openclaw"],
        help="Target runtime; omit to choose interactively",
    )

    delegate_parser = subparsers.add_parser(
        "delegate", help="Manage scoped delegation tokens"
    )
    delegate_subparsers = delegate_parser.add_subparsers(
        dest="delegate_command", required=True
    )

    delegate_create = delegate_subparsers.add_parser(
        "create", help="Create a scoped delegation token"
    )
    delegate_create.add_argument("--actor", required=True)
    delegate_create.add_argument(
        "--allow-action", action="append", required=True, dest="allowed_actions"
    )
    delegate_create.add_argument(
        "--allow-path", action="append", required=True, dest="allowed_paths"
    )
    delegate_create.add_argument(
        "--deny-action", action="append", default=[], dest="denied_actions"
    )
    delegate_create.add_argument("--ttl-seconds", type=int, default=7200)
    delegate_create.add_argument("--max-uses", type=int, default=1)
    delegate_create.add_argument("--reason", default="")
    delegate_create.add_argument("--critical", action="store_true")
    delegate_create.add_argument("--delegations-file", type=Path)

    delegate_list = delegate_subparsers.add_parser(
        "list", help="List delegation tokens"
    )
    delegate_list.add_argument("--delegations-file", type=Path)

    delegate_revoke = delegate_subparsers.add_parser(
        "revoke", help="Revoke a delegation token"
    )
    delegate_revoke.add_argument("token_id")
    delegate_revoke.add_argument("--delegations-file", type=Path)

    upgrade_parser = subparsers.add_parser(
        "upgrade-local", help="Safe local upgrade of agent-sudo"
    )
    upgrade_parser.add_argument(
        "--check",
        action="store_true",
        help="Check for available upgrades without updating",
    )
    upgrade_parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow upgrading even with user changes; generated artifacts are cleaned automatically without this flag",
    )

    context_parser = subparsers.add_parser(
        "context", help="Detect and return the runtime workspace context as JSON"
    )
    context_parser.add_argument("--workspace", help="Path to configured workspace root")

    workspace_parser = subparsers.add_parser(
        "workspace", help="Manage the persisted Agent_Sudo workspace"
    )
    workspace_subparsers = workspace_parser.add_subparsers(
        dest="workspace_command", required=True
    )
    workspace_set = workspace_subparsers.add_parser(
        "set", help="Persist the workspace used by MCP clients"
    )
    workspace_set.add_argument("path", help="Workspace directory to persist")
    workspace_set.add_argument("--config", type=Path, help=argparse.SUPPRESS)
    workspace_set.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help=(
            "Audit JSONL path for the workspace_changed event "
            "(default: the standard local/home audit log)"
        ),
    )
    workspace_show = workspace_subparsers.add_parser(
        "show", help="Show the persisted workspace"
    )
    workspace_show.add_argument("--config", type=Path, help=argparse.SUPPRESS)

    return parser


def run_built_in_demo() -> int:
    import tempfile

    from agent_sudo import branding

    branding.print_wordmark()
    print("=" * 60)
    print("                AGENT_SUDO INTERACTIVE DEMO                 ")
    print("=" * 60)
    print("Agent_Sudo is a local permission gateway for AI agents.")
    print("This demo evaluates three simulated tool calls using the default policy.\n")

    policy = load_default_policy()

    # Write to a stable, inspectable location (not an auto-deleted tempdir) so
    # the path printed below still exists after the demo exits. Start fresh so
    # the demo always shows exactly the two records it generates.
    demo_dir = Path(tempfile.gettempdir()) / "agent-sudo-demo"
    demo_dir.mkdir(parents=True, exist_ok=True)
    audit_path = demo_dir / "demo_audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    audit_logger = AuditLogger(audit_path)
    gateway = PermissionGateway(policy, audit_logger=audit_logger)

    # 1. Sensitive action gated to human approval by the conservative default
    print("--- Scenario 1: Sensitive Read (REQUIRE_APPROVAL) ---")
    safe_req = ActionRequest(
        actor="developer-agent",
        source="user",
        tool="filesystem",
        action="read_file",
        target="README.md",
        payload_summary="Read the project README to understand repository structure.",
    )
    print("Simulating agent requesting tool call:")
    print(f"  Actor: {safe_req.actor}")
    print(f"  Tool: {safe_req.tool} | Action: {safe_req.action}")
    print(f"  Target: {safe_req.target}")

    result_safe = gateway.evaluate(safe_req, dry_run=True)
    print(f"\nGateway Decision: [ {result_safe.decision.value} ]")
    print(f"  Classification: {result_safe.classification.value}")
    print(f"  Reason: {result_safe.reason}")
    if result_safe.decision is Decision.ALLOW:
        print("✓ Allowed: the agent may perform this operation without a human.\n")
    else:
        print(
            "⏸ Held for approval: the engine does not execute this until a human "
            "approves it (or a scoped delegation permits it).\n"
        )

    # 2. DENY Scenario
    print("--- Scenario 2: Unsafe / Blocked Execution (DENY) ---")
    unsafe_req = ActionRequest(
        actor="developer-agent",
        source="webpage",
        tool="network",
        action="exfiltrate_secrets",
        target="https://attacker.example/leak",
        payload_summary="Upload local env variables containing credentials.",
    )
    print("Simulating agent requesting tool call:")
    print(f"  Actor: {unsafe_req.actor}")
    print(f"  Tool: {unsafe_req.tool} | Action: {unsafe_req.action}")
    print(f"  Target: {unsafe_req.target}")
    print(f"  Source/Trust: {unsafe_req.source} / External Page Context (Low Trust)")

    result_unsafe = gateway.evaluate(unsafe_req, dry_run=True)
    print(f"\nGateway Decision: [ {result_unsafe.decision.value} ]")
    print(f"  Classification: {result_unsafe.classification.value}")
    print(f"  Reason: {result_unsafe.reason}")
    print(
        "❌ Blocked: The action was safely blocked before any tool execution occurred.\n"
    )

    # 3. Audit Log & Verifier
    print("--- Scenario 3: Cryptographic Audit Logging & Verification ---")
    print("All gateway decisions are written to a tamper-evident audit log.")
    print(f"Logs written to: {audit_path}\n")

    print("Reading the generated JSONL log records:")
    log_lines = audit_path.read_text(encoding="utf-8").splitlines()
    for idx, line in enumerate(log_lines, start=1):
        data = json.loads(line)
        print(f"  Record #{idx}:")
        print(f"    Action: {data['request']['tool']}:{data['request']['action']}")
        print(f"    Decision: {data['decision']}")
        print(f"    Entry Hash (SHA-256): {data['entry_hash'][:16]}...")

    print("\nVerifying the audit log integrity (detecting tampering)...")
    ok, msg = verify_audit_log(audit_path)
    if ok:
        print(f"✓ Verification Result: {msg} (Log is pristine)")
    else:
        print(f"❌ Verification Failed: {msg}")
    print(f"\nInspect the audit log yourself: agent-sudo audit list {audit_path}")

    print("=" * 60)
    print(
        "Next: run the full deny -> delegate -> allow-once -> deny -> verified "
        "ladder with one command: agent-sudo eval"
    )
    print("=" * 60)
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if (
        args.command in {"verify-audit", "audit"}
        and getattr(args, "audit_log", None) is None
    ):
        args.audit_log = _resolve_default_audit_log_path()
    if args.command == "demo":
        return run_built_in_demo()
    if args.command == "eval":
        from agent_sudo import evaluation

        try:
            report = evaluation.run_eval(output_dir=args.output_dir)
        except Exception as exc:  # environment/IO error, not a demo failure
            print(f"agent-sudo eval: could not run evaluation: {exc}", file=sys.stderr)
            return evaluation.EXIT_ERROR
        if getattr(args, "json", False):
            print(evaluation.format_report_json(report))
        else:
            print(evaluation.format_report(report))
        return evaluation.EXIT_PASS if report.passed else evaluation.EXIT_FAIL
    if args.command == "verify-audit":
        ok, message = verify_audit_log(args.audit_log)
        print(message)
        return 0 if ok else 1
    if args.command == "audit":
        if not args.audit_log.exists():
            sys.stderr.write(
                f"no audit log found at {args.audit_log}\n\n"
                "Agent_Sudo records decisions once an agent runs through the "
                "gateway. Common locations:\n"
                "  .agent-sudo/mcp-audit.jsonl   (Claude Desktop / MCP server)\n"
                "  .agent-sudo/audit.jsonl       (agent-sudo run / generic-run)\n"
                "Pass the path explicitly: agent-sudo audit list <path>\n"
            )
            return 1
        if args.audit_command == "list":
            entries = read_audit_entries(args.audit_log)
            if args.since:
                try:
                    entries = audit_entries_since(
                        entries, parse_since_window(args.since)
                    )
                except ValueError as exc:
                    print(str(exc), file=sys.stderr)
                    return 1
            entries = filter_entries(
                entries,
                decision=args.decision,
                origin=args.origin,
                actor=args.actor,
                tool=args.tool,
                target=args.target,
                non_allow=args.non_allow,
            )
            limit = None if args.limit <= 0 else args.limit
            if args.json:
                selected = entries if limit is None else entries[-limit:]
                print(json.dumps(selected, indent=2, sort_keys=True))
            else:
                print(format_audit_log(entries, limit=limit))
            return 0
        if args.audit_command == "review":
            ok, message = verify_audit_log(args.audit_log)
            if not ok:
                print(message, file=sys.stderr)
                return 1
            try:
                since = parse_since_window(args.since)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 1
            entries = audit_entries_since(read_audit_entries(args.audit_log), since)
            print(message)
            print(format_audit_review(entries, since_label=args.since))
            return 0
        if args.audit_command == "trace":
            from agent_sudo.audit_trace import run_trace

            return run_trace(
                args.token_id,
                args.audit_log,
                args.delegations_file,
                as_json=args.json,
            )
    if args.command == "init-approval":
        try:
            init_approval_config(
                config_path=args.config,
                pending_approvals_path=args.pending_approvals_file,
                delegations_path=args.delegations_file,
                audit_log_path=args.audit_log,
                force=args.force,
            )
        except ValueError as exc:
            print(f"init-approval failed: {exc}", file=sys.stderr)
            return 1
        print("approval config initialized")
        return 0
    if args.command == "doctor":
        from agent_sudo import branding

        branding.print_wordmark()
        checks = run_doctor()
        print(format_doctor_checks(checks))
        return doctor_exit_code(checks)
    if args.command == "inventory":
        import json as json_module

        from agent_sudo.inventory import build_inventory, format_inventory

        report = build_inventory()
        if args.json:
            print(json_module.dumps(report.to_dict(), indent=2))
        else:
            from agent_sudo import branding

            branding.print_wordmark()
            print(format_inventory(report))
        return 0
    if args.command == "topology":
        import json as json_module

        from agent_sudo.topology import build_topology, format_topology

        topology = build_topology()
        if args.json:
            print(json_module.dumps(topology.to_dict(), indent=2))
        else:
            from agent_sudo import branding

            branding.print_wordmark()
            print(format_topology(topology))
        return 0
    if args.command == "verify-routing":
        from agent_sudo.routing_check import (
            format_routing_report,
            routing_exit_code,
            run_routing_check,
        )

        signals = run_routing_check()
        print(format_routing_report(signals))
        return routing_exit_code(signals, strict=getattr(args, "strict", False))
    if args.command == "setup":
        from agent_sudo import branding, setup_guides

        target = args.agent
        if target is None:
            # No target named. Offer an interactive picker on a real TTY;
            # otherwise (CI/pipes) print guidance to stderr and exit non-zero
            # so scripts fail loudly instead of hanging on input.
            if sys.stdin.isatty():
                branding.print_wordmark()
                target = setup_guides.prompt_for_target()
                if target is None:
                    print("No target selected.", file=sys.stderr)
                    return 1
            else:
                print(setup_guides.no_target_guidance(), file=sys.stderr)
                return 2
        print(setup_guides.render_setup(target))
        return 0
    if args.command == "approvals":
        store = PendingApprovalStore(args.pending_approvals_file)
        if args.approvals_command == "list":
            print(
                json.dumps(
                    [approval.to_dict() for approval in store.list()],
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
    if args.command == "pending":
        store = PendingApprovalStore(args.pending_approvals_file)
        print(format_pending_approvals(store.list()))
        return 0
    if args.command == "approve":
        config_path = args.approval_config or CONFIG_PATH
        if not config_path.exists():
            sys.stderr.write(
                "approval system not initialized\n\n"
                "Run:\n"
                "agent-sudo init-approval\n\n"
                "to create a local approval passphrase.\n"
            )
            return 1
        audit_logger = AuditLogger(args.audit_log) if args.audit_log else None
        store = PendingApprovalStore(
            args.pending_approvals_file, audit_logger=audit_logger
        )
        approval_id = resolve_approval_identifier(
            args.approval_request_id, store.list()
        )
        if approval_id is None:
            print(
                f"approval request not found: {args.approval_request_id}",
                file=sys.stderr,
            )
            return 1
        provider_kwargs = {"config_path": config_path}
        approval, result = store.approve(
            approval_id,
            approval_provider=ApprovalProvider(**provider_kwargs),
        )
        if approval is None:
            print(result.reason, file=sys.stderr)
            return 1
        if not result.approved:
            print(f"Error: {result.reason}", file=sys.stderr)
            return 1
        print(json.dumps(approval.to_dict(), sort_keys=True))
        return 0
    if args.command == "deny":
        audit_logger = AuditLogger(args.audit_log) if args.audit_log else None
        store = PendingApprovalStore(
            args.pending_approvals_file, audit_logger=audit_logger
        )
        approval = store.deny(args.approval_request_id)
        if approval is None:
            print(
                f"approval request not found: {args.approval_request_id}",
                file=sys.stderr,
            )
            return 1
        print(json.dumps(approval.to_dict(), sort_keys=True))
        return 0
    if args.command == "delegate":
        store = (
            DelegationStore(args.delegations_file)
            if args.delegations_file
            else DelegationStore()
        )
        if args.delegate_command == "create":
            token = store.create(
                actor=args.actor,
                allowed_actions=args.allowed_actions,
                allowed_paths=args.allowed_paths,
                denied_actions=args.denied_actions,
                ttl_seconds=args.ttl_seconds,
                max_uses=args.max_uses,
                reason=args.reason,
                critical=args.critical,
            )
            print(json.dumps(token.to_dict(), sort_keys=True))
            print(f"delegations file: {store.path}", file=sys.stderr)
            if args.delegations_file is None and not os.environ.get(
                DELEGATIONS_PATH_ENV
            ):
                print(
                    "warning: using default delegation store "
                    f"{store.path}; integrations may use another store. "
                    f"Set {DELEGATIONS_PATH_ENV} or pass --delegations-file "
                    "to match the runtime store.",
                    file=sys.stderr,
                )
            return 0
        if args.delegate_command == "list":
            # Enrich the displayed output with derived, observability-only fields
            # (status + broad). These are not persisted and do not affect
            # authorization; the stored token shape is unchanged.
            enriched = []
            for token in store.list():
                row = token.to_dict()
                row["status"] = delegation_status(token)
                row["broad"] = is_broad_delegation(token)
                enriched.append(row)
            print(json.dumps(enriched, indent=2, sort_keys=True))
            return 0
        if args.delegate_command == "revoke":
            token = store.revoke(args.token_id)
            if token is None:
                print(f"delegation token not found: {args.token_id}", file=sys.stderr)
                return 1
            print(json.dumps(token.to_dict(), sort_keys=True))
            return 0

    if args.command == "upgrade-local":
        from agent_sudo.upgrade import handle_upgrade

        return handle_upgrade(check_only=args.check, allow_dirty=args.allow_dirty)

    if args.command == "context":
        from agent_sudo.context import detect_runtime_context

        ctx = detect_runtime_context(workspace=args.workspace)
        print(json.dumps(ctx.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "workspace":
        from agent_sudo.context import get_config_workspace, save_config_workspace

        if args.workspace_command == "set":
            audit_log_path = args.audit_log or _resolve_default_audit_log_path()
            try:
                workspace = save_config_workspace(
                    args.path,
                    config_path=args.config,
                    audit_log_path=audit_log_path,
                )
            except ValueError as exc:
                print(f"workspace set failed: {exc}", file=sys.stderr)
                return 1
            print(f"workspace set to {workspace}")
            return 0
        if args.workspace_command == "show":
            workspace = get_config_workspace(config_path=args.config)
            if workspace is None:
                print("no workspace configured", file=sys.stderr)
                return 1
            print(workspace)
            return 0

    if args.command == "approval-helper":
        from agent_sudo.helper import run_approval_helper

        return run_approval_helper(
            pending_approvals_path=args.pending_approvals_file,
            config_path=args.approval_config,
            audit_log_path=args.audit_log,
            watch=args.watch,
            auto_opened=args.auto_opened,
        )

    policy = load_policy(args.policy) if args.policy else load_default_policy()
    if args.command == "hermes-check":
        from agent_sudo.adapters.hermes import from_hermes_tool_call

        request = from_hermes_tool_call(_cli_load_tool_call(args.tool_call_file))
        result = PermissionGateway(policy).evaluate(request, dry_run=True)
        _print_result(result)
        return 0

    if args.command == "codex-check":
        from agent_sudo.adapters.codex import from_codex_tool_call

        request = from_codex_tool_call(_cli_load_tool_call(args.tool_call_file))
        result = PermissionGateway(policy).evaluate(request, dry_run=True)
        _print_result(result)
        return 0

    if args.command == "generic-check":
        from agent_sudo.adapters.generic import from_generic_tool_call

        request = from_generic_tool_call(_cli_load_tool_call(args.tool_call_file))
        result = PermissionGateway(policy).evaluate(request, dry_run=True)
        _print_result(result)
        return 0

    if args.command == "generic-run":
        from agent_sudo.adapters.generic import from_generic_tool_call
        from agent_sudo.executors import SafeToolExecutor, ShellCommandExecutor

        request = from_generic_tool_call(_cli_load_tool_call(args.tool_call_file))
        audit_logger = None if args.dry_run else AuditLogger(args.audit_log)
        pending_store = (
            None
            if args.dry_run
            else PendingApprovalStore(
                notify=getattr(args, "notify", False),
                open_approval_terminal=getattr(args, "open_approval_terminal", None),
            )
        )
        gateway = PermissionGateway(
            policy, audit_logger=audit_logger, pending_approval_store=pending_store
        )
        executor = SafeToolExecutor(gateway, ShellCommandExecutor())
        execution = (
            executor.dry_run(request) if args.dry_run else executor.execute(request)
        )
        _print_execution_result(execution)
        return (
            0
            if args.dry_run or execution.gateway_result.decision != Decision.DENY
            else 2
        )

    requests = _cli_load_requests(args.request_file)

    if args.command == "check":
        gateway = PermissionGateway(policy)
        for result in (gateway.evaluate(request, dry_run=True) for request in requests):
            _print_result(result)
        return _exit_code_for(results=None)

    audit_logger = None if args.dry_run else AuditLogger(args.audit_log)
    pending_store = (
        None
        if args.dry_run
        else PendingApprovalStore(
            notify=getattr(args, "notify", False),
            open_approval_terminal=getattr(args, "open_approval_terminal", None),
        )
    )
    gateway = PermissionGateway(
        policy, audit_logger=audit_logger, pending_approval_store=pending_store
    )
    results = [gateway.evaluate(request, dry_run=args.dry_run) for request in requests]
    for result in results:
        _print_result(result)
    return _exit_code_for(results, dry_run=args.dry_run)


def _print_result(result: GatewayResult) -> None:
    print(
        json.dumps(
            {
                "actor": result.request.actor,
                "action": result.request.action,
                "target": result.request.target,
                "classification": result.classification.value,
                "decision": result.decision.value,
                "approval_method": result.approval_method,
                "approval_attempts": result.approval_attempts,
                "reason": result.reason,
                "dry_run": result.dry_run,
            },
            sort_keys=True,
        )
    )


def _print_execution_result(result: object) -> None:
    print(
        json.dumps(
            {
                "action": result.request.action,
                "actor": result.request.actor,
                "target": result.request.target,
                "classification": result.gateway_result.classification.value,
                "decision": result.gateway_result.decision.value,
                "executed": result.executed,
                "exit_code": result.exit_code,
                "reason": result.reason,
                "dry_run": result.gateway_result.dry_run,
            },
            sort_keys=True,
        )
    )


def load_tool_call(path: Path) -> dict[str, object]:
    raw = _read_json_input(path, kind="tool call", example=_TOOL_CALL_EXAMPLE)
    if not isinstance(raw, dict):
        raise ValueError("tool call file must contain a JSON object")
    return raw


def _cli_load_requests(path: Path) -> list[ActionRequest]:
    """CLI wrapper: report a friendly error and exit 2 on bad input."""
    try:
        return load_requests(path)
    except RequestInputError as exc:
        print(f"agent-sudo: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _cli_load_tool_call(path: Path) -> dict[str, object]:
    """CLI wrapper: report a friendly error and exit 2 on bad input."""
    try:
        return load_tool_call(path)
    except RequestInputError as exc:
        print(f"agent-sudo: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _exit_code_for(
    results: list[GatewayResult] | None, *, dry_run: bool = False
) -> int:
    if not results:
        return 0
    if dry_run:
        return 0
    return 2 if any(result.decision == Decision.DENY for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable

from agent_sudo import __version_label__
from agent_sudo.audit import AuditLogger
from agent_sudo.delegations import DelegationStore
from agent_sudo.gateway import PermissionGateway
from agent_sudo.mcp_gateway import MCPGateway
from agent_sudo.mcp_validation import tool_call_from_jsonrpc
from agent_sudo.models import ActionRequest, ApprovalStatus, Decision
from agent_sudo.pending_approvals import PENDING_APPROVALS_PATH, PendingApprovalStore
from agent_sudo.policy import load_default_policy, load_policy


SERVER_NAME = "agent-sudo-mcp"
PROTOCOL_VERSION = "2025-03-26"

# Default block-and-wait window when --interactive-approvals is enabled. Kept
# conservatively below the pending-approval TTL ceiling (600s) and below the
# tightest measured client tool-call timeout (Codex, 120s) so the held call
# resolves in-band on clients that tolerate the wait. See issue #73 (Phase 1A/1B).
DEFAULT_APPROVAL_WAIT_SECONDS = 60.0
_APPROVAL_POLL_INTERVAL_SECONDS = 1.0

_APPROVAL_REQUIRED = frozenset(
    {Decision.REQUIRE_APPROVAL, Decision.REQUIRE_STRONG_APPROVAL}
)
_TERMINAL_STATUSES = frozenset(
    {ApprovalStatus.DENIED, ApprovalStatus.EXPIRED, ApprovalStatus.USED}
)


TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read a local file through agent-sudo policy enforcement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": (
            "DEMO/REFERENCE executor: classifies and gates the write through "
            "agent-sudo, then writes inside the configured workspace (defaults "
            "to /tmp/agent-sudo-demo if no workspace is configured). It does "
            "not write to arbitrary paths outside the workspace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write."},
                "content": {"type": "string", "description": "UTF-8 text content."},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "run_shell_command",
        "description": (
            "DEMO/REFERENCE executor: classifies and gates the command through "
            "agent-sudo, then executes only a narrow allowlist. It is not a "
            "general shell. To gate real commands, embed the agent-sudo "
            "authorization engine in your agent (see README)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Command line to evaluate.",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "get_runtime_context",
        "description": "Get current working directory, git repository root, active branch, and workspace status details.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


class AgentSudoMCPServer:
    def __init__(
        self,
        gateway: PermissionGateway,
        *,
        workspace: str | None = None,
        interactive_approvals: bool = False,
        approval_wait_seconds: float = DEFAULT_APPROVAL_WAIT_SECONDS,
        poll_interval_seconds: float = _APPROVAL_POLL_INTERVAL_SECONDS,
        sleep_func: Callable[[float], None] = time.sleep,
        monotonic_func: Callable[[], float] = time.monotonic,
    ):
        self.gateway = gateway
        write_root = Path(workspace) if workspace else Path("/tmp/agent-sudo-demo")
        self.mcp_gateway = MCPGateway(
            gateway, write_root=write_root, workspace=workspace
        )
        self.interactive_approvals = interactive_approvals
        self.approval_wait_seconds = max(0.0, approval_wait_seconds)
        # A ticket becomes EXPIRED at its TTL and the block-and-wait loop returns
        # the moment it does, so waiting longer than the TTL is impossible. Clamp
        # (and warn) instead of silently capping, so the operator knows to raise
        # --approval-ttl-seconds. The TTL itself is never extended here.
        store = getattr(gateway, "pending_approval_store", None)
        ttl = getattr(store, "ttl_seconds", None)
        if ttl is not None and self.approval_wait_seconds > ttl:
            print(
                f"--approval-wait-seconds {int(self.approval_wait_seconds)} exceeds "
                f"pending TTL {int(ttl)}s; will wait at most {int(ttl)}s. "
                "Raise --approval-ttl-seconds to wait longer.",
                file=sys.stderr,
            )
            self.approval_wait_seconds = float(ttl)
        self.poll_interval_seconds = max(0.0, poll_interval_seconds)
        self._sleep = sleep_func
        self._monotonic = monotonic_func

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        if method == "notifications/initialized":
            return None
        request_id = message.get("id")
        try:
            if method == "initialize":
                self._capture_client(message)
                return _response(request_id, self._initialize_result())
            if method == "tools/list":
                return _response(request_id, {"tools": TOOLS})
            if method == "tools/call":
                return _response(request_id, self._call_tool(message))
            return _error(request_id, -32601, f"method not found: {method}")
        except Exception as exc:
            return _error(request_id, -32603, str(exc))

    @staticmethod
    def _capture_client(message: dict[str, Any]) -> None:
        # The MCP client announces itself via initialize params.clientInfo.name;
        # record it so approval prompts/notifications/audit name the real caller
        # (issue #109). Best-effort: a missing name leaves the "unknown" default.
        try:
            name = message["params"]["clientInfo"]["name"]
        except (KeyError, TypeError):
            return
        from agent_sudo.run_context import set_client

        set_client(str(name))

    def _initialize_result(self) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": __version_label__},
        }

    def _call_tool(self, message: dict[str, Any]) -> dict[str, Any]:
        tool_call = tool_call_from_jsonrpc(message)
        execution = self.mcp_gateway.dispatch(tool_call)

        # Phase 1B: block-and-wait. When interactive approvals are enabled and
        # the call was held for approval, keep the tools/call open, poll the
        # existing pending-approval store, and on approval re-dispatch the same
        # tool_call so the existing consume path returns ALLOW and the real
        # result. No delegation, no scope derivation: this only waits on the
        # one pending approval already created for this exact request.
        interactive_wait: dict[str, Any] | None = None
        if (
            self.interactive_approvals
            and execution.gateway_result.decision in _APPROVAL_REQUIRED
            and execution.gateway_result.approval_request_id
        ):
            outcome = self._wait_for_decision(
                execution.gateway_result.approval_request_id
            )
            interactive_wait = {
                "enabled": True,
                "outcome": outcome,
                "waited_seconds_budget": self.approval_wait_seconds,
            }
            if outcome == "approved":
                execution = self.mcp_gateway.dispatch(tool_call)

        approval_required = execution.gateway_result.decision in _APPROVAL_REQUIRED
        transcript = {
            "status": "approval_required"
            if approval_required
            else ("executed" if execution.executed else "blocked"),
            "incoming_mcp_request": message,
            "normalized_action_request": execution.request.to_dict(),
            "classification": execution.gateway_result.classification.value,
            "risk": execution.gateway_result.classification.value,
            "approval_decision": execution.gateway_result.decision.value,
            "approval_method": execution.gateway_result.approval_method,
            "approval_request_id": execution.gateway_result.approval_request_id,
            "approval_id": execution.gateway_result.approval_request_id,
            "approval_command": execution.gateway_result.approval_command,
            "expires_at": execution.gateway_result.approval_expires_at,
            "expires_in_seconds": execution.gateway_result.approval_expires_in_seconds,
            "action_summary": _action_summary(execution.request),
            "execution_result": {
                "executed": execution.executed,
                "exit_code": execution.exit_code,
                "stdout": execution.stdout,
                "stderr": execution.stderr,
                "reason": execution.reason,
            },
        }
        if interactive_wait is not None:
            transcript["interactive_wait"] = interactive_wait
        is_error = (
            execution.gateway_result.decision != Decision.ALLOW
            or not execution.executed
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": _tool_text(
                        execution.executed,
                        execution.stdout,
                        execution.stderr,
                        execution.reason,
                    ),
                }
            ],
            "structuredContent": transcript,
            "isError": is_error,
        }

    def _wait_for_decision(self, approval_request_id: str) -> str:
        """Block until the pending approval resolves or the wait window elapses.

        Returns one of: "approved", "denied", "expired", "used", "gone",
        "unavailable", "timeout". Polls the existing store; the approval may be
        granted via any channel (terminal helper, desktop prompt, or another
        process running `agent-sudo approve`).
        """
        store = self.gateway.pending_approval_store
        if store is None:
            return "unavailable"
        deadline = self._monotonic() + self.approval_wait_seconds
        while True:
            approval = self._lookup(store, approval_request_id)
            if approval is None:
                return "gone"
            if approval.status == ApprovalStatus.APPROVED:
                return "approved"
            if approval.status in _TERMINAL_STATUSES:
                return approval.status.value
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return "timeout"
            self._sleep(min(self.poll_interval_seconds, remaining))

    @staticmethod
    def _lookup(store: PendingApprovalStore, approval_request_id: str):
        for approval in store.list():
            if approval.approval_request_id == approval_request_id:
                return approval
        return None


def build_server(
    *,
    policy_path: Path | None = None,
    audit_log: Path | None = None,
    delegations_file: Path | None = None,
    pending_approvals_file: Path | None = None,
    approval_ttl_seconds: int | None = None,
    workspace: str | None = None,
    notify: bool | None = None,
    open_approval_terminal: bool | None = None,
    interactive_approvals: bool = False,
    approval_wait_seconds: float = DEFAULT_APPROVAL_WAIT_SECONDS,
) -> AgentSudoMCPServer:
    # Record the active workspace for run-context stamping (issue #109).
    from agent_sudo.run_context import set_workspace

    set_workspace(workspace)

    policy = load_policy(policy_path) if policy_path else load_default_policy()
    audit_logger = AuditLogger(audit_log or Path(".agent-sudo/mcp-audit.jsonl"))
    delegation_store = DelegationStore(delegations_file) if delegations_file else None
    pending_store = PendingApprovalStore(
        pending_approvals_file or PENDING_APPROVALS_PATH,
        audit_logger=audit_logger,
        ttl_seconds=approval_ttl_seconds,
        notify=notify,
        open_approval_terminal=open_approval_terminal,
    )
    gateway = PermissionGateway(
        policy,
        audit_logger=audit_logger,
        delegation_store=delegation_store,
        pending_approval_store=pending_store,
    )
    return AgentSudoMCPServer(
        gateway,
        workspace=workspace,
        interactive_approvals=interactive_approvals,
        approval_wait_seconds=approval_wait_seconds,
    )


def serve(
    *,
    input_stream: BinaryIO | None = None,
    output_stream: BinaryIO | None = None,
    server: AgentSudoMCPServer | None = None,
) -> int:
    actual_input = input_stream or sys.stdin.buffer
    actual_output = output_stream or sys.stdout.buffer
    actual_server = server or build_server()
    while True:
        message = read_message(actual_input)
        if message is None:
            return 0
        response = actual_server.handle(message)
        if response is not None:
            write_message(actual_output, response)


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    while True:
        line = stream.readline()
        if line == b"":
            return None
        decoded = line.decode("utf-8").strip()
        if not decoded:
            continue
        parsed = json.loads(decoded)
        if not isinstance(parsed, dict):
            raise ValueError("MCP message must be a JSON object")
        return parsed


def write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    stream.write(body + b"\n")
    stream.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SERVER_NAME,
        description=(
            "Agent_Sudo MCP server (stdio). Launched by your MCP client, not "
            "run by hand. To try the engine first, run: agent-sudo eval"
        ),
        epilog=(
            "Quickstart: pipx install agent-sudo-mcp && agent-sudo eval. "
            "Generate a client config with: agent-sudo setup. "
            "Use absolute paths for --audit-log / --delegations-file / "
            "--pending-approvals-file: the client may launch this server from "
            "any directory."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"{SERVER_NAME} {__version_label__}"
    )
    parser.add_argument("--policy", type=Path, help="Path to policy YAML")
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path(".agent-sudo/mcp-audit.jsonl"),
        help=(
            "Path to the JSONL audit log to append decisions to "
            "(default: .agent-sudo/mcp-audit.jsonl, relative to the launch "
            "directory). Use an absolute path so the log is findable."
        ),
    )
    parser.add_argument(
        "--delegations-file",
        type=Path,
        help=(
            "Path to the delegation-token store. Required to honor "
            "`agent-sudo delegate create` tokens; without it the server runs "
            "with no delegation store and tokens are silently ignored."
        ),
    )
    parser.add_argument(
        "--pending-approvals-file",
        type=Path,
        default=PENDING_APPROVALS_PATH,
        help=(
            "Path to the pending-approvals store that `agent-sudo pending` / "
            "`agent-sudo approve` read and write "
            f"(default: {PENDING_APPROVALS_PATH})."
        ),
    )
    parser.add_argument(
        "--approval-ttl-seconds",
        type=int,
        help="Pending approval TTL, clamped to 30-600 seconds",
    )
    parser.add_argument("--workspace", help="Path to configured workspace root")
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Enable desktop notifications for pending approvals",
    )
    parser.add_argument(
        "--open-approval-terminal",
        action="store_true",
        help="Automatically open Terminal.app for pending approvals",
    )
    parser.add_argument(
        "--interactive-approvals",
        action="store_true",
        help=(
            "Hold a blocked tool call open and wait for approval, then resume "
            "and return the real result in the same call (block-and-wait). "
            "Default off. Pair with --open-approval-terminal or --notify so the "
            "approval prompt appears."
        ),
    )
    parser.add_argument(
        "--approval-wait-seconds",
        type=float,
        default=DEFAULT_APPROVAL_WAIT_SECONDS,
        help=(
            "Max seconds to hold a call open waiting for approval when "
            f"--interactive-approvals is set (default {int(DEFAULT_APPROVAL_WAIT_SECONDS)}). "
            "Keep below the client's tool-call timeout."
        ),
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    server = build_server(
        policy_path=args.policy,
        audit_log=args.audit_log,
        delegations_file=args.delegations_file,
        pending_approvals_file=args.pending_approvals_file,
        approval_ttl_seconds=args.approval_ttl_seconds,
        workspace=args.workspace,
        notify=args.notify,
        open_approval_terminal=args.open_approval_terminal,
        interactive_approvals=args.interactive_approvals,
        approval_wait_seconds=args.approval_wait_seconds,
    )
    return serve(server=server)


def _response(request_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _tool_text(executed: bool, stdout: str, stderr: str, reason: str) -> str:
    if executed:
        return stdout if stdout else reason
    if stderr:
        return f"{reason}: {stderr}"
    return reason


def _action_summary(request: ActionRequest) -> str:
    return f"{request.action} by {request.actor} on {request.target}"


if __name__ == "__main__":
    raise SystemExit(main())

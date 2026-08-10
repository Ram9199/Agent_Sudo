from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from agent_sudo.adapters.mcp import from_mcp_tool_call
from agent_sudo.executors import ExecutionResult
from agent_sudo.gateway import PermissionGateway
from agent_sudo.models import ActionRequest, Decision, GatewayResult


DEMO_WRITE_ROOT = Path("/tmp/agent-sudo-demo")
DEMO_SHELL_COMMANDS = {"pwd", "ls", "cat"}


class MCPGateway:
    def __init__(
        self,
        gateway: PermissionGateway,
        *,
        write_root: Path = DEMO_WRITE_ROOT,
        workspace: str | None = None,
    ):
        self.gateway = gateway
        self.write_root = write_root
        self.workspace = workspace

    def dispatch(
        self, tool_call: dict[str, Any], *, dry_run: bool = False
    ) -> ExecutionResult:
        request = from_mcp_tool_call(tool_call)
        gateway_result = self.gateway.evaluate(request, dry_run=dry_run)
        if dry_run:
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason="dry-run: gateway evaluated MCP tool call without executing tool",
            )
        if gateway_result.decision != Decision.ALLOW:
            reason = gateway_result.reason
            if request.action == "write_file":
                reason = _format_blocked_write_reason(
                    target=request.target,
                    gateway_reason=gateway_result.reason,
                    write_root=self.write_root,
                    is_path_block=False,
                )
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason=reason,
            )
        return self._execute_demo_tool(request, gateway_result, tool_call)

    def _execute_demo_tool(
        self,
        request: ActionRequest,
        gateway_result: GatewayResult,
        tool_call: dict[str, Any],
    ) -> ExecutionResult:
        if request.action == "read_file":
            return self._read_file(request, gateway_result)
        if request.action == "write_file":
            return self._write_file(request, gateway_result, tool_call)
        if request.action == "run_shell_command":
            return self._run_shell_command(request, gateway_result)
        if request.action == "get_runtime_context":
            return self._get_runtime_context(request, gateway_result)
        return ExecutionResult(
            request=request,
            gateway_result=gateway_result,
            executed=False,
            exit_code=None,
            reason=f"demo MCP gateway does not implement action {request.action!r}",
        )

    def _get_runtime_context(
        self, request: ActionRequest, gateway_result: GatewayResult
    ) -> ExecutionResult:
        from agent_sudo.context import detect_runtime_context

        try:
            ctx = detect_runtime_context(workspace=self.workspace)
            stdout_content = json.dumps(ctx.to_dict(), sort_keys=True)
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=True,
                exit_code=0,
                stdout=stdout_content,
                reason="executed",
            )
        except Exception as exc:
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=1,
                stderr=str(exc),
                reason=f"failed to get runtime context: {exc}",
            )

    def _read_file(
        self, request: ActionRequest, gateway_result: GatewayResult
    ) -> ExecutionResult:
        try:
            content = Path(request.target).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            return ExecutionResult(
                request,
                gateway_result,
                False,
                None,
                stderr=str(exc),
                reason="read failed",
            )
        return ExecutionResult(
            request, gateway_result, True, 0, stdout=content, reason="executed"
        )

    def _write_file(
        self,
        request: ActionRequest,
        gateway_result: GatewayResult,
        tool_call: dict[str, Any],
    ) -> ExecutionResult:
        target = Path(request.target).expanduser()
        try:
            resolved_root = self.write_root.resolve()
            resolved_target = target.resolve()
        except OSError as exc:
            return ExecutionResult(
                request,
                gateway_result,
                False,
                None,
                stderr=str(exc),
                reason="invalid path",
            )

        # Boundary checks
        workspace_git = (resolved_root / ".git").resolve()
        workspace_agent_sudo = (resolved_root / ".agent-sudo").resolve()
        home_agent_sudo = Path("~/.agent-sudo").expanduser().resolve()

        if resolved_target == workspace_git or workspace_git in resolved_target.parents:
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason="Action was blocked by policy: write_file. Reason: Write is not permitted inside .git directory.",
            )

        if (
            resolved_target == workspace_agent_sudo
            or workspace_agent_sudo in resolved_target.parents
        ):
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason="Action was blocked by policy: write_file. Reason: Write is not permitted inside workspace .agent-sudo directory.",
            )

        if (
            resolved_target == home_agent_sudo
            or home_agent_sudo in resolved_target.parents
        ):
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason="Action was blocked by policy: write_file. Reason: Write is not permitted inside ~/.agent-sudo/ directory.",
            )

        blocked_files = [Path("~/.agent-sudo/config.json").expanduser().resolve()]
        if getattr(self.gateway, "audit_logger", None) and getattr(
            self.gateway.audit_logger, "path", None
        ):
            blocked_files.append(self.gateway.audit_logger.path.resolve())
        if getattr(self.gateway, "delegation_store", None) and getattr(
            self.gateway.delegation_store, "path", None
        ):
            blocked_files.append(self.gateway.delegation_store.path.resolve())
        if getattr(self.gateway, "pending_approval_store", None) and getattr(
            self.gateway.pending_approval_store, "path", None
        ):
            blocked_files.append(self.gateway.pending_approval_store.path.resolve())

        for bf in blocked_files:
            if resolved_target == bf or bf in resolved_target.parents:
                return ExecutionResult(
                    request=request,
                    gateway_result=gateway_result,
                    executed=False,
                    exit_code=None,
                    reason=f"Action was blocked by policy: write_file. Reason: Write is not permitted to protected path: {bf}",
                )
        if (
            resolved_target != resolved_root
            and resolved_root not in resolved_target.parents
        ):
            reason = _format_blocked_write_reason(
                target=request.target,
                gateway_reason=None,
                write_root=resolved_root,
                is_path_block=True,
            )
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason=reason,
            )
        content = _content_from_tool_call(tool_call)
        try:
            resolved_target.parent.mkdir(parents=True, exist_ok=True)
            resolved_target.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ExecutionResult(
                request,
                gateway_result,
                False,
                None,
                stderr=str(exc),
                reason="write failed",
            )
        return ExecutionResult(
            request,
            gateway_result,
            True,
            0,
            stdout=str(resolved_target),
            reason="executed",
        )

    def _run_shell_command(
        self, request: ActionRequest, gateway_result: GatewayResult
    ) -> ExecutionResult:
        try:
            argv = shlex.split(request.target)
        except ValueError as exc:
            return ExecutionResult(
                request,
                gateway_result,
                False,
                None,
                stderr=str(exc),
                reason="invalid shell syntax",
            )
        if not _demo_shell_allowed(argv):
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                reason="shell command is outside the MCP demo allowlist",
            )
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, check=False
            )
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=True,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                reason="executed",
            )
        except OSError as exc:
            return ExecutionResult(
                request=request,
                gateway_result=gateway_result,
                executed=False,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                reason="host failed to run command",
            )


def dispatch_mcp_tool_call(
    tool_call: dict[str, Any],
    gateway: PermissionGateway,
    *,
    dry_run: bool = False,
    workspace: str | None = None,
) -> ExecutionResult:
    return MCPGateway(gateway, workspace=workspace).dispatch(tool_call, dry_run=dry_run)


def _content_from_tool_call(tool_call: dict[str, Any]) -> str:
    params = (
        tool_call.get("parameters")
        or tool_call.get("params")
        or tool_call.get("arguments")
        or tool_call
    )
    if not isinstance(params, dict):
        return ""
    value = params.get("content")
    return str(value) if value is not None else ""


def _demo_shell_allowed(argv: list[str]) -> bool:
    if not argv:
        return False
    if argv[0] in DEMO_SHELL_COMMANDS:
        return True
    return argv[:3] == ["python3", "-m", "unittest"]


def _format_blocked_write_reason(
    target: str,
    gateway_reason: str | None,
    write_root: Path,
    is_path_block: bool,
) -> str:
    # A request is in demo mode if the target path contains 'agent-sudo-demo'
    is_demo = "agent-sudo-demo" in str(target)

    lines = [
        "Action was blocked by policy: write_file",
        f"Target path: {target}",
    ]

    if gateway_reason:
        lines.append(f"Reason: {gateway_reason}")
    elif is_path_block:
        if is_demo:
            lines.append(
                f"Reason: Write was attempted outside the allowed demo directory ({write_root})."
            )
        else:
            lines.append("Reason: Write was attempted outside the allowed directory.")

    if is_path_block:
        if is_demo:
            lines.append(
                "What user can do next: To run the demo, write only inside the allowed demo directory "
                f"({write_root}). To gate writes to arbitrary workspace paths, integrate the agent-sudo "
                "authorization engine directly into your agent's native file-writing tools."
            )
        else:
            lines.append(
                "What user can do next: The default write_file tool in the agent-sudo MCP server is a reference "
                "executor restricted to its configured root directory. To gate writes to arbitrary workspace paths, "
                "integrate the agent-sudo authorization engine directly into your agent's native file-writing tools."
            )
    else:
        # Policy restriction failure (e.g. CLI approval / delegation required)
        lines.append(
            "What user can do next: Run this action in an interactive environment to approve, or grant a "
            "delegation token for this action. To gate writes to arbitrary workspace paths, integrate the "
            "agent-sudo authorization engine directly into your agent's native file-writing tools."
        )

    return "\n".join(lines)

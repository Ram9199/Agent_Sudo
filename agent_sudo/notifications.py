from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from agent_sudo.models import ApprovalRequest


def send_approval_notification(approval: ApprovalRequest) -> bool:
    """
    Sends a macOS native desktop notification for a pending approval request.
    This function is optional, secure, and non-blocking.
    """
    if sys.platform != "darwin":
        return False

    request = approval.action_request
    action = request.action
    classification = approval.classification.value

    # Secure target summary formulation to avoid leaking secrets
    target_str = request.target.strip() if request.target else ""
    if action == "run_shell_command":
        # Extract command binary/name only, never show full args
        safe_target = target_str.split()[0] if target_str else "command"
    elif action in ("write_file", "read_file", "edit_file", "delete_file"):
        # Extract filename only, never show full path
        try:
            safe_target = Path(target_str).name
        except Exception:
            safe_target = "file"
    else:
        # Fall back to payload summary or truncated target
        safe_target = request.payload_summary or target_str

    if not safe_target:
        safe_target = "action"

    # Truncate target if too long
    if len(safe_target) > 50:
        safe_target = safe_target[:47] + "..."

    title = "Agent_Sudo approval required"
    # Identify which copy of Agent_Sudo is asking (issue #109) so a stale or
    # unexpected install can't prompt anonymously.
    from agent_sudo.run_context import format_notification_stamp

    stamp = format_notification_stamp(approval.run_context)
    stamp_line = f"\n{stamp}" if stamp else ""
    body = (
        f"{classification} action requested: {action} on {safe_target}"
        f"{stamp_line}\nRun: agent-sudo pending"
    )

    # Truncate body to ensure safety
    if len(body) > 200:
        body = body[:197] + "..."

    # Escape double quotes and backslashes for AppleScript syntax compatibility
    escaped_title = title.replace("\\", "\\\\").replace('"', '\\"')
    escaped_body = body.replace("\\", "\\\\").replace('"', '\\"')

    applescript = f'display notification "{escaped_body}" with title "{escaped_title}"'

    try:
        # Execute osascript using shell=False to prevent shell injection vulnerabilities
        res = subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def open_approval_terminal_window(pending_approvals_file: Path | None = None) -> bool:
    """
    Opens a macOS Terminal.app window running agent-sudo approval-helper.
    This function is secure, non-blocking, and handles AppleScript execution safely.
    """
    if sys.platform != "darwin":
        return False

    cmd_parts = [
        sys.executable,
        "-m",
        "agent_sudo.gateway",
        "approval-helper",
        "--auto-opened",
    ]
    if pending_approvals_file:
        cmd_parts.extend(
            ["--pending-approvals-file", str(pending_approvals_file.resolve())]
        )

    import shlex

    shell_cmd = " ".join(shlex.quote(part) for part in cmd_parts)

    # Escape for AppleScript double-quotes
    escaped_shell_cmd = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')

    # AppleScript command: clear screen first, then exec to replace shell and auto-close
    applescript = (
        f'tell application "Terminal"\n'
        f'    do script "clear; exec {escaped_shell_cmd}"\n'
        f"    activate\n"
        f"end tell"
    )

    try:
        res = subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False

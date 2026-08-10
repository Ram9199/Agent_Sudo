from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable

from agent_sudo.models import ApprovalRequest, ApprovalStatus
from agent_sudo.approvals import CONFIG_PATH, ApprovalProvider
from agent_sudo.run_context import format_stamp
from agent_sudo.pending_approvals import (
    PENDING_APPROVALS_PATH,
    PendingApprovalStore,
    format_pending_approvals,
)


def get_safe_target_summary(app: ApprovalRequest) -> str:
    request = app.action_request
    action = request.action
    target_str = request.target.strip() if request.target else ""
    if action == "run_shell_command":
        cmd_part = target_str.split()[0] if target_str else "command"
        try:
            safe_target = Path(cmd_part).name
        except Exception:
            safe_target = cmd_part
    elif action in ("write_file", "read_file", "edit_file", "delete_file"):
        try:
            safe_target = Path(target_str).name
        except Exception:
            safe_target = "file"
    else:
        safe_target = request.payload_summary or target_str

    if not safe_target:
        safe_target = "action"
    if len(safe_target) > 60:
        safe_target = safe_target[:57] + "..."
    return safe_target


def run_approval_helper(
    pending_approvals_path: Path = PENDING_APPROVALS_PATH,
    config_path: Path = CONFIG_PATH,
    audit_log_path: Path | None = None,
    watch: bool = False,
    input_func: Callable[[str], str] = input,
    auto_opened: bool = False,
) -> int:
    """
    Checks for the approval configuration and runs the interactive guided approval terminal loop.
    """
    # 1. Check if the passphrase config exists
    if not config_path.exists():
        sys.stderr.write(
            "No approval passphrase configuration found.\n\n"
            "To set up a secure passphrase for approving critical actions, run:\n"
            "    agent-sudo init-approval\n\n"
            "Important:\n"
            "- The passphrase cannot be recovered.\n"
            "- Resetting the passphrase in the future will revoke all active delegation tokens and cancel any active pending approvals.\n"
        )
        if auto_opened:
            try:
                input_func("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
        return 1

    try:
        from agent_sudo.audit import AuditLogger

        audit_logger = AuditLogger(audit_log_path) if audit_log_path else None
        store = PendingApprovalStore(pending_approvals_path, audit_logger=audit_logger)

        initial_pending = [
            a for a in store.list() if a.status == ApprovalStatus.PENDING
        ]
        allow_autoclose = len(initial_pending) == 1
        autoclose_triggered = False
        autoclose_message = ""

        def process_pending(processed_ids: set[str]) -> bool:
            nonlocal autoclose_triggered, autoclose_message
            approvals = [a for a in store.list() if a.status == ApprovalStatus.PENDING]
            unprocessed = [
                a for a in approvals if a.approval_request_id not in processed_ids
            ]
            if not approvals:
                return False

            if unprocessed:
                if auto_opened:
                    # Clear terminal screen
                    print("\033[H\033[J", end="")
                    print("Agent_Sudo approval required\n")

                    for idx, app in enumerate(approvals, start=1):
                        if app.approval_request_id in processed_ids:
                            continue

                        safe_target = get_safe_target_summary(app)
                        from datetime import datetime, timezone
                        from agent_sudo.pending_approvals import _parse_time

                        try:
                            expires_at = _parse_time(app.expires_at)
                            now = datetime.now(timezone.utc)
                            rem = max(0, int((expires_at - now).total_seconds()))
                        except Exception:
                            rem = 120

                        print(f"Request #{idx}:")
                        print(f"  Risk:      {app.classification.value}")
                        print(f"  Action:    {app.action_request.action}")
                        print(f"  Actor:     {app.action_request.actor}")
                        print(f"  Target:    {safe_target}")
                        stamp = format_stamp(app.run_context)
                        if stamp:
                            print(f"  From:      {stamp}")
                        print(f"  Expires in ~{rem}s — approve before then.")
                        print()
                else:
                    print("\nActive pending approvals:")
                    print(format_pending_approvals(approvals))
                    print("\nTo approve from the CLI, run:")
                    print("    agent-sudo approve <index_or_uuid>\n")

                for idx, app in enumerate(approvals, start=1):
                    if app.approval_request_id in processed_ids:
                        continue

                    action_desc = f"{app.action_request.action} by {app.action_request.actor} on {get_safe_target_summary(app)}"
                    if len(action_desc) > 80:
                        action_desc = action_desc[:77] + "..."

                    prompt_text = f"Approve request #{idx} ({action_desc})? [y/N] "
                    try:
                        answer = input_func(prompt_text).strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        print("\nSkipped.")
                        processed_ids.add(app.approval_request_id)
                        continue

                    if answer in {"y", "yes"}:
                        provider = ApprovalProvider(config_path=config_path)
                        try:
                            approval, result = store.approve(
                                app.approval_request_id, approval_provider=provider
                            )
                            if approval and result.approved:
                                print(f"Request #{idx} approved successfully.")
                                # Check auto-close logic
                                remaining = [
                                    a
                                    for a in store.list()
                                    if a.status == ApprovalStatus.PENDING
                                ]
                                if (
                                    auto_opened
                                    and allow_autoclose
                                    and not remaining
                                    and not watch
                                ):
                                    autoclose_triggered = True
                                    autoclose_message = (
                                        "Approved. Closing in 3 seconds..."
                                    )
                            else:
                                print(f"Approval failed: {result.reason}")
                        except Exception as e:
                            print(f"Error executing approval: {e}")
                    elif answer in {"n", "no"}:
                        try:
                            store.deny(app.approval_request_id)
                            print(f"Request #{idx} denied.")
                            # Check auto-close logic
                            remaining = [
                                a
                                for a in store.list()
                                if a.status == ApprovalStatus.PENDING
                            ]
                            if (
                                auto_opened
                                and allow_autoclose
                                and not remaining
                                and not watch
                            ):
                                autoclose_triggered = True
                                autoclose_message = "Denied. Closing in 3 seconds..."
                        except Exception as e:
                            print(f"Error executing deny: {e}")
                    else:
                        print(f"Request #{idx} skipped (remains pending).")

                    processed_ids.add(app.approval_request_id)
                return True
            return False

        if not watch:
            processed_ids: set[str] = set()
            has_pending = process_pending(processed_ids)

            if not has_pending:
                print("No active pending approvals.")
                if auto_opened:
                    try:
                        input_func("\nPress Enter to exit...")
                    except (KeyboardInterrupt, EOFError):
                        pass
                return 0

            if auto_opened:
                if autoclose_triggered:
                    print(f"\n{autoclose_message}")
                    time.sleep(3.0)
                    return 0
                else:
                    try:
                        input_func("\nPress Enter to exit...")
                    except (KeyboardInterrupt, EOFError):
                        pass
            return 0
        else:
            print("Watching for pending approvals... (Press Ctrl+C to stop)")
            processed_ids = set()
            has_printed_empty = False
            while True:
                has_pending = process_pending(processed_ids)
                if not has_pending:
                    # check if queue is completely empty and we haven't printed the notice
                    approvals = [
                        a for a in store.list() if a.status == ApprovalStatus.PENDING
                    ]
                    if not approvals and not has_printed_empty:
                        print("No active pending approvals.")
                        has_printed_empty = True
                else:
                    has_printed_empty = False

                # Clean up processed_ids for expired/removed approvals to prevent leak
                current_ids = {
                    a.approval_request_id for a in store.list(update_expired=False)
                }
                processed_ids = processed_ids.intersection(current_ids)

                time.sleep(1.0)
    except KeyboardInterrupt:
        if watch:
            print("\nStopped watching.")
        else:
            print("\nInterrupted.")
        return 0
    except Exception:
        import traceback

        traceback.print_exc()
        if auto_opened:
            try:
                input_func("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
        return 1

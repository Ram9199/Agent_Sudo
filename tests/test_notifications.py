from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agent_sudo.models import ActionRequest, Classification, Decision
from agent_sudo.pending_approvals import PendingApprovalStore


class NativeNotificationTests(unittest.TestCase):
    def _sample_action_request(
        self,
        action="run_shell_command",
        target="pwd",
        payload_summary="Show current directory",
    ) -> ActionRequest:
        return ActionRequest(
            actor="mcp-client",
            source="user",
            tool="shell",
            action=action,
            target=target,
            payload_summary=payload_summary,
        )

    @patch("sys.platform", "darwin")
    @patch("subprocess.run")
    def test_notification_called_when_enabled(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending.json", notify=True)
            store.create(
                action_request=self._sample_action_request(),
                classification=Classification.CRITICAL,
                decision=Decision.REQUIRE_STRONG_APPROVAL,
                required_approval_method="PASSPHRASE_CONFIRM",
                reason="Shell execution is critical",
            )

        # Verify notification was sent
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        command_list = args[0]
        self.assertEqual(command_list[0], "osascript")
        self.assertEqual(command_list[1], "-e")
        self.assertIn(
            "CRITICAL action requested: run_shell_command on pwd", command_list[2]
        )
        self.assertIn("Agent_Sudo approval required", command_list[2])
        self.assertEqual(kwargs.get("shell"), None)  # default is False

    @patch("sys.platform", "darwin")
    @patch("subprocess.run")
    def test_notification_not_called_when_disabled(self, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending.json", notify=False)
            store.create(
                action_request=self._sample_action_request(),
                classification=Classification.CRITICAL,
                decision=Decision.REQUIRE_STRONG_APPROVAL,
                required_approval_method="PASSPHRASE_CONFIRM",
                reason="Shell execution is critical",
            )
        mock_run.assert_not_called()

    @patch("sys.platform", "darwin")
    @patch("subprocess.run")
    def test_notification_failure_does_not_break_approval_creation(
        self, mock_run
    ) -> None:
        mock_run.side_effect = Exception("osascript process execution crashed")
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending.json", notify=True)
            # This should not raise an exception or block approval creation
            approval = store.create(
                action_request=self._sample_action_request(),
                classification=Classification.CRITICAL,
                decision=Decision.REQUIRE_STRONG_APPROVAL,
                required_approval_method="PASSPHRASE_CONFIRM",
                reason="Shell execution is critical",
            )
            approvals = store.list()

        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0].approval_request_id, approval.approval_request_id)

    @patch("sys.platform", "darwin")
    @patch("subprocess.run")
    def test_notification_content_is_truncated_and_sanitized(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)

        # Test 1: shell command with long sensitive parameters is truncated to command name only
        req_shell = self._sample_action_request(
            action="run_shell_command",
            target="cat /etc/passwd /secret/token.json --pass=123",
            payload_summary="long command",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending1.json", notify=True)
            store.create(
                action_request=req_shell,
                classification=Classification.CRITICAL,
                decision=Decision.REQUIRE_STRONG_APPROVAL,
                required_approval_method="PASSPHRASE_CONFIRM",
                reason="shell critical",
            )
        args1, _ = mock_run.call_args
        self.assertIn(
            "CRITICAL action requested: run_shell_command on cat", args1[0][2]
        )
        self.assertNotIn("/etc/passwd", args1[0][2])
        self.assertNotIn("123", args1[0][2])

        # Test 2: file write action is truncated to base filename, not absolute path
        mock_run.reset_mock()
        req_file = self._sample_action_request(
            action="write_file",
            target="/Users/username/secret_workspace/my_private_file.txt",
            payload_summary="write private file",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending2.json", notify=True)
            store.create(
                action_request=req_file,
                classification=Classification.SENSITIVE,
                decision=Decision.REQUIRE_APPROVAL,
                required_approval_method="CLI_CONFIRM",
                reason="file sensitive",
            )
        args2, _ = mock_run.call_args
        self.assertIn(
            "SENSITIVE action requested: write_file on my_private_file.txt", args2[0][2]
        )
        self.assertNotIn("/Users/username/secret_workspace", args2[0][2])

        # Test 3: escaping of double quotes in AppleScript execution string
        mock_run.reset_mock()
        req_quotes = self._sample_action_request(
            action="generic_action",
            target='foo "bar" \\ baz',
            payload_summary="description with quotes",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending3.json", notify=True)
            store.create(
                action_request=req_quotes,
                classification=Classification.SENSITIVE,
                decision=Decision.REQUIRE_APPROVAL,
                required_approval_method="CLI_CONFIRM",
                reason="sensitive quotes",
            )
        args3, _ = mock_run.call_args
        body = args3[0][2]
        # The action/target head and the trailing Run hint are unchanged; the
        # run-context stamp line (issue #109) is inserted between them. Assert
        # the stable parts plus the stamp presence, without pinning the
        # environment-dependent version/install_type the stamp reports.
        self.assertIn(
            'display notification "SENSITIVE action requested: generic_action on description with quotes',
            body,
        )
        self.assertIn("\nvia agent-sudo ", body)
        self.assertIn(
            '\nRun: agent-sudo pending" with title "Agent_Sudo approval required"',
            body,
        )

    @patch("sys.platform", "darwin")
    @patch("subprocess.run")
    def test_default_env_var_enables_notification(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        with patch.dict("os.environ", {"AGENT_SUDO_NOTIFY": "1"}):
            with tempfile.TemporaryDirectory() as tmpdir:
                store = PendingApprovalStore(Path(tmpdir) / "pending.json")
                store.create(
                    action_request=self._sample_action_request(),
                    classification=Classification.CRITICAL,
                    decision=Decision.REQUIRE_STRONG_APPROVAL,
                    required_approval_method="PASSPHRASE_CONFIRM",
                    reason="critical action",
                )
        mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()

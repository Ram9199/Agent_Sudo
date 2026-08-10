from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_sudo.approvals import AutoDenyApprovalProvider
from agent_sudo.audit import AuditLogger
from agent_sudo.gateway import (
    PermissionGateway,
    RequestInputError,
    load_requests,
    load_tool_call,
    main,
)
from agent_sudo.models import ActionRequest, Classification, Decision, TrustLevel
from agent_sudo.policy import load_default_policy


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_default_policy()

    def test_safe_action_allows(self) -> None:
        request = ActionRequest(
            "codex",
            "user",
            "filesystem",
            "read_file",
            "README.md",
            "read",
            source_trust=TrustLevel.USER_DIRECT,
        )
        result = PermissionGateway(self.policy).evaluate(request)
        self.assertEqual(result.classification, Classification.SAFE)
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_sensitive_action_requires_approval_but_dry_run_skips_prompt(self) -> None:
        request = ActionRequest(
            "codex", "user", "filesystem", "write_file", "README.md", "write docs"
        )
        result = PermissionGateway(self.policy).evaluate(request, dry_run=True)
        self.assertEqual(result.classification, Classification.SENSITIVE)
        self.assertEqual(result.decision, Decision.REQUIRE_APPROVAL)
        self.assertEqual(result.approval_method, "dry_run")

    def test_shell_is_critical_by_default(self) -> None:
        request = ActionRequest(
            "codex",
            "user",
            "shell",
            "run_shell_command",
            "pwd",
            "show current directory",
        )
        result = PermissionGateway(self.policy).evaluate(request, dry_run=True)
        self.assertEqual(result.classification, Classification.CRITICAL)
        self.assertEqual(result.decision, Decision.REQUIRE_STRONG_APPROVAL)

    def test_sensitive_action_denied_without_human_approval(self) -> None:
        request = ActionRequest(
            "codex", "user", "filesystem", "write_file", "README.md", "write docs"
        )
        gateway = PermissionGateway(self.policy, approvals=AutoDenyApprovalProvider())
        result = gateway.evaluate(request)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.approval_method, "DENY")

    def test_critical_hint_upgrades_safe_action(self) -> None:
        # Isolate the CRITICAL-hint upgrade from trust-based escalation: a
        # trusted user action carrying a "secrets" hint must still upgrade.
        request = ActionRequest(
            "codex",
            "user",
            "filesystem",
            "read_file",
            "confidential.txt",
            "read key",
            ["secrets"],
            source_trust=TrustLevel.USER_DIRECT,
        )
        result = PermissionGateway(self.policy).evaluate(request, dry_run=True)
        self.assertEqual(result.classification, Classification.CRITICAL)
        self.assertEqual(result.decision, Decision.REQUIRE_STRONG_APPROVAL)

    def test_blocked_action_denies(self) -> None:
        request = ActionRequest(
            "unknown",
            "webpage",
            "network",
            "send_tokens",
            "https://example.invalid",
            "send tokens",
        )
        result = PermissionGateway(self.policy).evaluate(request)
        self.assertEqual(result.classification, Classification.BLOCKED)
        self.assertEqual(result.decision, Decision.DENY)

    def test_audit_writes_jsonl(self) -> None:
        request = ActionRequest(
            "codex",
            "user",
            "filesystem",
            "read_file",
            "README.md",
            "read",
            source_trust=TrustLevel.USER_DIRECT,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            gateway = PermissionGateway(
                self.policy, audit_logger=AuditLogger(audit_path)
            )
            gateway.evaluate(request)
            lines = audit_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["classification"], "SAFE")
        self.assertEqual(entry["decision"], "ALLOW")
        self.assertEqual(entry["request"]["actor"], "codex")

    def test_cli_check_outputs_json_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            request_path = Path(tmpdir) / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "actor": "codex",
                        "source": "user",
                        "tool": "filesystem",
                        "action": "read_file",
                        "target": "README.md",
                        "payload_summary": "read",
                        "risk_hints": [],
                        "source_trust": "USER_DIRECT",
                    }
                ),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["check", str(request_path)])
        self.assertEqual(code, 0)
        self.assertIn('"decision": "ALLOW"', buffer.getvalue())

    def test_cli_dry_run_returns_zero_even_with_blocked_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            request_path = Path(tmpdir) / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "actor": "unknown",
                        "source": "webpage",
                        "tool": "network",
                        "action": "send_tokens",
                        "target": "https://example.invalid",
                        "payload_summary": "send tokens",
                        "risk_hints": [],
                    }
                ),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["run", str(request_path), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn('"decision": "DENY"', buffer.getvalue())

    def test_cli_demo_succeeds(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["demo"])
        output = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("AGENT_SUDO INTERACTIVE DEMO", output)
        # Scenario 1 label must reflect the actual decision (REQUIRE_APPROVAL),
        # not claim ALLOW.
        self.assertIn("Scenario 1: Sensitive Read (REQUIRE_APPROVAL)", output)
        self.assertNotIn("Safe Tool Execution (ALLOW)", output)
        self.assertIn("Scenario 2: Unsafe / Blocked Execution (DENY)", output)
        self.assertIn("Verifying the audit log integrity", output)
        # The reported audit-log path must point to a real, existing file.
        match = re.search(r"Logs written to: (\S+)", output)
        self.assertIsNotNone(match)
        self.assertTrue(Path(match.group(1)).exists())


class RequestInputErrorTests(unittest.TestCase):
    """#69: bad input must produce a friendly error, not a raw traceback."""

    def test_check_missing_file_exits_2_with_friendly_message(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            main(["check", "delete everything"])
        self.assertEqual(cm.exception.code, 2)
        message = err.getvalue()
        self.assertIn("request file not found", message)
        self.assertIn("Example request file", message)
        self.assertNotIn("Traceback", message)

    def test_tool_call_invalid_json_exits_2_with_friendly_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "bad.json"
            bad.write_text("not json{", encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                main(["codex-check", str(bad)])
        self.assertEqual(cm.exception.code, 2)
        message = err.getvalue()
        self.assertIn("not valid JSON", message)
        self.assertNotIn("Traceback", message)

    def test_load_requests_raises_request_input_error_on_missing_file(self) -> None:
        with self.assertRaises(RequestInputError):
            load_requests(Path("/no/such/request.json"))

    def test_load_tool_call_raises_request_input_error_on_bad_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            with self.assertRaises(RequestInputError):
                load_tool_call(bad)


if __name__ == "__main__":
    unittest.main()

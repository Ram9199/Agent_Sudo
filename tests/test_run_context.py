"""Tests for the run-context stamp on prompts, notifications, audit (issue #109)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_sudo import run_context
from agent_sudo.audit import AuditLogger, read_audit_entries
from agent_sudo.models import (
    ActionRequest,
    ApprovalRequest,
    ApprovalStatus,
    Classification,
    Decision,
)
from agent_sudo.pending_approvals import PendingApprovalStore


class RunContextCurrentTests(unittest.TestCase):
    def setUp(self):
        run_context.reset_for_tests()

    def tearDown(self):
        run_context.reset_for_tests()

    def test_has_minimum_fields(self):
        ctx = run_context.current()
        self.assertEqual(
            set(ctx),
            {"version", "install_type", "client", "workspace", "pid"},
        )
        self.assertEqual(ctx["pid"], os.getpid())

    def test_client_defaults_then_reflects_set_client(self):
        # default is non-empty (cli or unknown depending on how tests launch)
        self.assertTrue(run_context.current()["client"])
        run_context.set_client("antigravity")
        self.assertEqual(run_context.current()["client"], "antigravity")

    def test_set_workspace_reflected(self):
        run_context.set_workspace("/work/space")
        self.assertEqual(run_context.current()["workspace"], "/work/space")

    def test_default_client_mapping(self):
        self.assertEqual(run_context._default_client("console-script"), "cli")
        self.assertEqual(run_context._default_client("python -m"), "cli")
        self.assertEqual(run_context._default_client("embedded"), "unknown")


class FormatStampTests(unittest.TestCase):
    def test_empty_for_none(self):
        self.assertEqual(run_context.format_stamp(None), "")
        self.assertEqual(run_context.format_notification_stamp(None), "")

    def test_full_stamp(self):
        ctx = {
            "version": "0.5.6",
            "install_type": "editable",
            "client": "antigravity",
            "workspace": "/w",
            "pid": 42,
        }
        stamp = run_context.format_stamp(ctx)
        self.assertIn("agent-sudo 0.5.6 (editable)", stamp)
        self.assertIn("client=antigravity", stamp)
        self.assertIn("ws=/w", stamp)
        self.assertIn("pid=42", stamp)

    def test_unknown_client_omitted(self):
        ctx = {"version": "0.5.6", "install_type": "editable", "client": "unknown"}
        self.assertNotIn("client=", run_context.format_stamp(ctx))

    def test_notification_stamp_is_compact(self):
        ctx = {"version": "0.5.6", "install_type": "pinned-wheel"}
        self.assertEqual(
            run_context.format_notification_stamp(ctx),
            "via agent-sudo 0.5.6 (pinned-wheel)",
        )


class ApprovalRecordRoundTripTests(unittest.TestCase):
    def _request(self) -> ActionRequest:
        return ActionRequest(
            actor="agent",
            source="user",
            tool="t",
            action="write_file",
            target="/x",
            payload_summary="write x",
        )

    def test_run_context_survives_to_from_dict(self):
        ctx = {"version": "0.5.6", "install_type": "editable", "pid": 1}
        approval = ApprovalRequest(
            approval_request_id="id",
            action_request=self._request(),
            classification=Classification.SENSITIVE,
            decision=Decision.REQUIRE_APPROVAL,
            required_approval_method="CLI_CONFIRM",
            created_at="t0",
            expires_at="t1",
            status=ApprovalStatus.PENDING,
            reason="r",
            run_context=ctx,
        )
        restored = ApprovalRequest.from_dict(approval.to_dict())
        self.assertEqual(restored.run_context, ctx)

    def test_legacy_record_without_run_context(self):
        approval = ApprovalRequest(
            approval_request_id="id",
            action_request=self._request(),
            classification=Classification.SENSITIVE,
            decision=Decision.REQUIRE_APPROVAL,
            required_approval_method="CLI_CONFIRM",
            created_at="t0",
            expires_at="t1",
            status=ApprovalStatus.PENDING,
            reason="r",
        )
        data = approval.to_dict()
        self.assertNotIn("run_context", data)  # omitted when absent
        self.assertIsNone(ApprovalRequest.from_dict(data).run_context)


class StampingIntegrationTests(unittest.TestCase):
    def setUp(self):
        run_context.reset_for_tests()

    def tearDown(self):
        run_context.reset_for_tests()

    def test_audit_entry_is_stamped(self):
        run_context.set_client("claude-desktop")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            AuditLogger(path).record_event("test_event", {"foo": "bar"})
            entries = read_audit_entries(path)
        self.assertEqual(len(entries), 1)
        ctx = entries[0]["run_context"]
        self.assertEqual(ctx["client"], "claude-desktop")
        self.assertEqual(ctx["pid"], os.getpid())

    def test_create_attaches_run_context_to_record(self):
        run_context.set_client("antigravity")
        req = ActionRequest(
            actor="agent",
            source="user",
            tool="t",
            action="write_file",
            target="/x",
            payload_summary="write x",
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = PendingApprovalStore(Path(tmp) / "pending.json")
            approval = store.create(
                action_request=req,
                classification=Classification.SENSITIVE,
                decision=Decision.REQUIRE_APPROVAL,
                required_approval_method="CLI_CONFIRM",
                reason="r",
            )
            on_disk = json.loads((Path(tmp) / "pending.json").read_text())
        self.assertEqual(approval.run_context["client"], "antigravity")
        self.assertEqual(on_disk[0]["run_context"]["client"], "antigravity")


if __name__ == "__main__":
    unittest.main()

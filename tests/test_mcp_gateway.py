from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_sudo.approvals import ApprovalProvider
from agent_sudo.delegations import DelegationStore
from agent_sudo.gateway import PermissionGateway
from agent_sudo.mcp_gateway import MCPGateway, dispatch_mcp_tool_call
from agent_sudo.models import ActionRequest, ApprovalResult, Decision
from agent_sudo.policy import load_default_policy


class ApproveAllProvider(ApprovalProvider):
    def approve_sensitive(self, request: ActionRequest) -> ApprovalResult:
        return ApprovalResult(True, "test_yes", "approved")

    def approve_critical(self, request: ActionRequest) -> ApprovalResult:
        return ApprovalResult(True, "test_passphrase", "approved")


class MCPGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_default_policy()
        # Hermetic isolation: these tests must not depend on the developer's
        # ambient ~/.agent-sudo/config.json workspace (or AGENT_SUDO_WORKSPACE).
        # When a configured workspace points at the repo root, a target inside
        # it routes down the path-restriction branch instead of the policy
        # BLOCKED branch the assertions expect (issue #84). Clear both so
        # behavior matches a clean CI runner regardless of local state.
        workspace_patcher = mock.patch(
            "agent_sudo.context._load_config_workspace", return_value=None
        )
        workspace_patcher.start()
        self.addCleanup(workspace_patcher.stop)
        env_patcher = mock.patch.dict(os.environ, {}, clear=False)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("AGENT_SUDO_WORKSPACE", None)

    def test_safe_delegated_shell_executes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = DelegationStore(Path(tmpdir) / "delegations.json")
            store.create(
                actor="mcp-client",
                allowed_actions=["run_shell_command"],
                allowed_paths=["pwd"],
                max_uses=1,
                reason="demo shell",
                critical=True,
            )
            gateway = PermissionGateway(self.policy, delegation_store=store)
            result = dispatch_mcp_tool_call(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "shell",
                    "action": "run_shell_command",
                    "target": "pwd",
                    "payload_summary": "show current directory",
                },
                gateway,
            )

        self.assertTrue(result.executed)
        self.assertEqual(result.gateway_result.decision, Decision.ALLOW)
        self.assertEqual(result.gateway_result.approval_method, "DELEGATION")

    def test_shell_spawn_failure_reports_not_executed(self) -> None:
        # PR #90 review fix: when the host fails to *spawn* the process
        # (subprocess.run raises OSError), nothing executed — the result must
        # report executed=False with no exit code, not executed=True.
        with tempfile.TemporaryDirectory() as tmpdir:
            store = DelegationStore(Path(tmpdir) / "delegations.json")
            store.create(
                actor="mcp-client",
                allowed_actions=["run_shell_command"],
                allowed_paths=["pwd"],
                max_uses=1,
                reason="spawn-failure test",
                critical=True,
            )
            gateway = PermissionGateway(self.policy, delegation_store=store)
            with mock.patch(
                "agent_sudo.mcp_gateway.subprocess.run",
                side_effect=OSError("exec format error"),
            ):
                result = dispatch_mcp_tool_call(
                    {
                        "actor": "mcp-client",
                        "source": "user",
                        "tool": "shell",
                        "action": "run_shell_command",
                        "target": "pwd",
                        "payload_summary": "show current directory",
                    },
                    gateway,
                )

        self.assertFalse(result.executed)
        self.assertIsNone(result.exit_code)
        self.assertIn("host failed to run command", result.reason)
        self.assertIn("exec format error", result.stderr)

    def test_write_inside_demo_path_executes_with_approval(self) -> None:
        target = Path("/tmp/agent-sudo-demo/unit-test-notes.txt")
        if target.exists():
            target.unlink()
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        mcp_gateway = MCPGateway(gateway)
        result = mcp_gateway.dispatch(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "filesystem",
                "action": "write_file",
                "target": str(target),
                "parameters": {"path": str(target), "content": "demo\n"},
                "payload_summary": "write demo file",
            }
        )

        self.assertTrue(result.executed)
        self.assertEqual(target.read_text(encoding="utf-8"), "demo\n")
        target.unlink()

    def test_write_outside_root_blocked_non_demo_mode(self) -> None:
        target = Path("/Volumes/Storage/Agent_Sudo/tmp_dogfood.txt")
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        mcp_gateway = MCPGateway(gateway)
        result = mcp_gateway.dispatch(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "filesystem",
                "action": "write_file",
                "target": str(target),
                "parameters": {"path": str(target), "content": "dogfood\n"},
                "payload_summary": "write dogfood file",
            }
        )
        self.assertFalse(result.executed)
        self.assertNotIn("agent-sudo-demo", result.reason)
        self.assertIn("Action was blocked by policy: write_file", result.reason)
        self.assertIn(f"Target path: {target}", result.reason)
        self.assertIn("Reason: BLOCKED actions are denied by policy", result.reason)
        self.assertIn(
            "Run this action in an interactive environment to approve, or grant a delegation token for this action.",
            result.reason,
        )
        self.assertIn(
            "integrate the agent-sudo authorization engine directly into your agent's native file-writing tools.",
            result.reason,
        )

    def test_write_outside_root_blocked_demo_mode(self) -> None:
        target = Path("/tmp/agent-sudo-demo/../outside-demo.txt")
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        mcp_gateway = MCPGateway(gateway)
        result = mcp_gateway.dispatch(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "filesystem",
                "action": "write_file",
                "target": str(target),
                "parameters": {"path": str(target), "content": "demo\n"},
                "payload_summary": "write demo file",
            }
        )
        self.assertFalse(result.executed)
        self.assertIn("agent-sudo-demo", result.reason)
        self.assertIn("Action was blocked by policy: write_file", result.reason)
        self.assertIn(f"Target path: {target}", result.reason)
        self.assertIn(
            "Reason: Write was attempted outside the allowed demo directory",
            result.reason,
        )
        self.assertIn(
            "To run the demo, write only inside the allowed demo directory",
            result.reason,
        )

    def test_write_path_block_relative_path(self) -> None:
        target = "outside.txt"
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        mcp_gateway = MCPGateway(gateway)
        result = mcp_gateway.dispatch(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "filesystem",
                "action": "write_file",
                "target": target,
                "parameters": {"path": target, "content": "relative\n"},
                "payload_summary": "write relative file",
            }
        )
        self.assertFalse(result.executed)
        self.assertNotIn("agent-sudo-demo", result.reason)
        self.assertIn("Action was blocked by policy: write_file", result.reason)
        self.assertIn(f"Target path: {target}", result.reason)
        self.assertIn(
            "Reason: Write was attempted outside the allowed directory.", result.reason
        )
        self.assertIn(
            "The default write_file tool in the agent-sudo MCP server is a reference executor restricted to its configured root directory.",
            result.reason,
        )

    def test_write_blocked_by_policy(self) -> None:
        target = Path("/tmp/agent-sudo-demo/notes.txt")
        gateway = PermissionGateway(self.policy)
        mcp_gateway = MCPGateway(gateway)
        result = mcp_gateway.dispatch(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "filesystem",
                "action": "write_file",
                "target": str(target),
                "parameters": {"path": str(target), "content": "notes\n"},
                "payload_summary": "write notes file",
            }
        )
        self.assertFalse(result.executed)
        self.assertIn("Action was blocked by policy: write_file", result.reason)
        self.assertIn(f"Target path: {target}", result.reason)
        self.assertIn("Reason: approval requires an interactive TTY", result.reason)
        self.assertIn(
            "Run this action in an interactive environment to approve, or grant a delegation token for this action.",
            result.reason,
        )

    def test_mcp_gateway_denies_blocked_action(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        result = dispatch_mcp_tool_call(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "network",
                "action": "exfiltrate_secrets",
                "target": "https://example.invalid/upload",
                "payload_summary": "send secrets",
            },
            gateway,
        )

        self.assertFalse(result.executed)
        self.assertEqual(result.gateway_result.decision, Decision.DENY)

    def test_mcp_gateway_executes_allowed_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "readme.txt"
            path.write_text("hello\n", encoding="utf-8")
            gateway = PermissionGateway(self.policy)
            result = dispatch_mcp_tool_call(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "read_file",
                    "target": str(path),
                    "payload_summary": "read demo file",
                },
                gateway,
            )

        self.assertTrue(result.executed)
        self.assertEqual(result.stdout, "hello\n")

    def test_mcp_gateway_dry_run_does_not_execute(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        result = dispatch_mcp_tool_call(
            {
                "actor": "mcp-client",
                "source": "user",
                "tool": "shell",
                "action": "run_shell_command",
                "target": "pwd",
                "payload_summary": "show current directory",
            },
            gateway,
            dry_run=True,
        )

        self.assertFalse(result.executed)
        self.assertEqual(
            result.gateway_result.decision, Decision.REQUIRE_STRONG_APPROVAL
        )

    def test_server_workspace_initialization(self) -> None:
        from agent_sudo.mcp_server import AgentSudoMCPServer

        gateway = PermissionGateway(self.policy)
        server_with_ws = AgentSudoMCPServer(gateway, workspace="/foo/bar")
        self.assertEqual(server_with_ws.mcp_gateway.write_root, Path("/foo/bar"))

        server_no_ws = AgentSudoMCPServer(gateway)
        self.assertEqual(
            server_no_ws.mcp_gateway.write_root, Path("/tmp/agent-sudo-demo")
        )

    def test_write_file_inside_workspace_succeeds(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace_path = Path(tmpdir)
            mcp_gateway = MCPGateway(
                gateway, write_root=workspace_path, workspace=str(workspace_path)
            )
            target = workspace_path / "test.txt"
            result = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(target),
                    "parameters": {"path": str(target), "content": "hello workspace\n"},
                    "payload_summary": "write test file",
                }
            )
            self.assertTrue(result.executed)
            self.assertEqual(target.read_text(encoding="utf-8"), "hello workspace\n")

    def test_write_file_outside_workspace_blocked(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace_path = Path(tmpdir) / "workspace"
            workspace_path.mkdir()
            outside_path = Path(tmpdir) / "outside.txt"

            mcp_gateway = MCPGateway(
                gateway, write_root=workspace_path, workspace=str(workspace_path)
            )
            result = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(outside_path),
                    "parameters": {"path": str(outside_path), "content": "outside\n"},
                    "payload_summary": "write outside file",
                }
            )
            self.assertFalse(result.executed)
            self.assertIn(
                "Write was attempted outside the allowed directory", result.reason
            )

    def test_path_traversal_outside_workspace_blocked(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace_path = Path(tmpdir) / "workspace"
            workspace_path.mkdir()
            target_traversal = workspace_path / "../outside.txt"

            mcp_gateway = MCPGateway(
                gateway, write_root=workspace_path, workspace=str(workspace_path)
            )
            result = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(target_traversal),
                    "parameters": {
                        "path": str(target_traversal),
                        "content": "traversal\n",
                    },
                    "payload_summary": "write traversal file",
                }
            )
            self.assertFalse(result.executed)
            self.assertIn(
                "Write was attempted outside the allowed directory", result.reason
            )

    def test_symlink_escape_outside_workspace_blocked(self) -> None:
        import os

        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace_path = Path(tmpdir) / "workspace"
            workspace_path.mkdir()
            outside_file = Path(tmpdir) / "outside.txt"
            outside_file.write_text("outside data", encoding="utf-8")

            # create a symlink inside workspace pointing to outside_file
            link_path = workspace_path / "link_to_outside.txt"
            try:
                os.symlink(outside_file, link_path)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks not supported on this platform")

            mcp_gateway = MCPGateway(
                gateway, write_root=workspace_path, workspace=str(workspace_path)
            )
            result = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(link_path),
                    "parameters": {
                        "path": str(link_path),
                        "content": "escape attempt\n",
                    },
                    "payload_summary": "write symlink escape file",
                }
            )
            self.assertFalse(result.executed)
            self.assertIn(
                "Write was attempted outside the allowed directory", result.reason
            )

    def test_write_to_git_dir_blocked(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace_path = Path(tmpdir)
            git_config = workspace_path / ".git" / "config"

            mcp_gateway = MCPGateway(
                gateway, write_root=workspace_path, workspace=str(workspace_path)
            )
            result = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(git_config),
                    "parameters": {
                        "path": str(git_config),
                        "content": "corrupted git\n",
                    },
                    "payload_summary": "write git config",
                }
            )
            self.assertFalse(result.executed)
            self.assertIn("Write is not permitted inside .git directory", result.reason)

    def test_write_to_agent_sudo_state_dir_blocked(self) -> None:
        gateway = PermissionGateway(self.policy, approvals=ApproveAllProvider())
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace_path = Path(tmpdir)

            # 1. Block workspace/.agent-sudo/
            workspace_state = workspace_path / ".agent-sudo" / "config.json"
            mcp_gateway = MCPGateway(
                gateway, write_root=workspace_path, workspace=str(workspace_path)
            )
            result_workspace_state = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(workspace_state),
                    "parameters": {"path": str(workspace_state), "content": "config\n"},
                    "payload_summary": "write workspace agent-sudo config",
                }
            )
            self.assertFalse(result_workspace_state.executed)
            self.assertIn(
                "Write is not permitted inside workspace .agent-sudo directory",
                result_workspace_state.reason,
            )

            # 2. Block ~/.agent-sudo/
            home_state = Path("~/.agent-sudo/config.json").expanduser()
            result_home_state = mcp_gateway.dispatch(
                {
                    "actor": "mcp-client",
                    "source": "user",
                    "tool": "filesystem",
                    "action": "write_file",
                    "target": str(home_state),
                    "parameters": {"path": str(home_state), "content": "config\n"},
                    "payload_summary": "write home agent-sudo config",
                }
            )
            self.assertFalse(result_home_state.executed)
            self.assertIn(
                "Write is not permitted inside ~/.agent-sudo/ directory",
                result_home_state.reason,
            )


if __name__ == "__main__":
    unittest.main()

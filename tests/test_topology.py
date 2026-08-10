"""Tests for the read-only topology view (issue #112)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_sudo.inventory import (
    ConfigRecord,
    InstallRecord,
    InventoryReport,
    _audit_log_from_args,
)
from agent_sudo.topology import build_topology, format_topology


def _report() -> InventoryReport:
    installs = [
        InstallRecord(
            root="/home/.pyenv/shims",
            executable="/home/.pyenv/shims/agent-sudo",
            version="",
            path_rank=6,
            statuses=["ACTIVE", "PYENV-SHIM"],
        ),
        InstallRecord(
            root="/home/.pyenv/versions/3.11.14",
            executable="/home/.pyenv/versions/3.11.14/bin/agent-sudo",
            version="0.5.6",
            editable_source="/repo/Agent_Sudo",
            path_rank=0,
            statuses=["ACTIVE", "EDITABLE"],
        ),
        InstallRecord(
            root="/home/Developer/Agent_Sudo/.venv",
            executable="/home/Developer/Agent_Sudo/.venv/bin/agent-sudo-mcp",
            version="0.5.6",
            editable_source="/home/Developer/Agent_Sudo",
            path_rank=None,
            statuses=["ACTIVE", "EDITABLE"],
        ),
    ]
    configs = [
        ConfigRecord(
            client="claude-desktop",
            config_path="/home/Library/Claude/config.json",
            server_name="agent-sudo",
            command="/home/.pyenv/versions/3.11.14/bin/agent-sudo-mcp",
            command_exists=True,
            install_root="/home/.pyenv/versions/3.11.14",
            version="0.5.6",
            audit_log="/home/.agent-sudo/mcp-audit.jsonl",
            statuses=["ACTIVE"],
        ),
        ConfigRecord(
            client="gemini",
            config_path="/home/.gemini/config/mcp_config.json",
            server_name="agent-sudo",
            command="/home/Developer/Agent_Sudo/.venv/bin/agent-sudo-mcp",
            command_exists=True,
            install_root="/home/Developer/Agent_Sudo/.venv",
            version="0.5.6",
            audit_log="/home/.agent-sudo/antigravity-mcp-audit.jsonl",
            statuses=["ACTIVE"],
        ),
        ConfigRecord(
            client="antigravity",
            config_path="/home/.gemini/antigravity/mcp_config.json",
            server_name="agent-sudo",
            command="/home/Developer/Agent_Sudo/.venv/bin/agent-sudo-mcp",
            command_exists=True,
            install_root="/home/Developer/Agent_Sudo/.venv",
            version="0.5.6",
            audit_log="/home/.agent-sudo/antigravity-mcp-audit.jsonl",
            statuses=["ACTIVE"],
        ),
    ]
    return InventoryReport(
        installs=installs, configs=configs, warnings=[], newest_version="0.5.6"
    )


class AuditLogExtractionTests(unittest.TestCase):
    def test_space_separated(self):
        self.assertEqual(
            _audit_log_from_args(["--notify", "--audit-log", "/a/x.jsonl"]),
            "/a/x.jsonl",
        )

    def test_equals_form(self):
        self.assertEqual(_audit_log_from_args(["--audit-log=/a/x.jsonl"]), "/a/x.jsonl")

    def test_absent(self):
        self.assertEqual(_audit_log_from_args(["--notify"]), "")

    def test_flag_without_value(self):
        self.assertEqual(_audit_log_from_args(["--audit-log"]), "")


class TopologyStructureTests(unittest.TestCase):
    def test_shim_collapses_into_resolved_install(self):
        topo = build_topology(report=_report(), unrouted_tools=[])
        # The shim is NOT a separate CLI row; it collapses into the resolved
        # pyenv-version install, which is marked via_shim.
        self.assertEqual(len(topo.cli_surfaces), 1)
        surface = topo.cli_surfaces[0]
        self.assertEqual(surface.install_root, "/home/.pyenv/versions/3.11.14")
        self.assertFalse(surface.is_shim)
        self.assertTrue(surface.via_shim)
        self.assertEqual(surface.version, "0.5.6")
        # no standalone shim entry, no misleading duplicate
        self.assertFalse(any(s.is_shim for s in topo.cli_surfaces))
        self.assertEqual(
            len({s.install_root for s in topo.cli_surfaces}), len(topo.cli_surfaces)
        )
        # the non-PATH install (Developer .venv) is not a CLI surface
        roots = {s.install_root for s in topo.cli_surfaces}
        self.assertNotIn("/home/Developer/Agent_Sudo/.venv", roots)

    def test_shim_only_on_path_is_shown_as_shim(self):
        # When nothing but a shim resolves on PATH, show the shim itself (there
        # is no resolved version install to collapse into).
        report = InventoryReport(
            installs=[
                InstallRecord(
                    root="/home/.pyenv/shims",
                    executable="/home/.pyenv/shims/agent-sudo",
                    version="",
                    path_rank=0,
                    statuses=["ACTIVE", "PYENV-SHIM"],
                )
            ],
            configs=[],
            warnings=[],
            newest_version="",
        )
        topo = build_topology(report=report, unrouted_tools=[])
        self.assertEqual(len(topo.cli_surfaces), 1)
        self.assertTrue(topo.cli_surfaces[0].is_shim)

    def test_mcp_clients_carry_audit_and_editable_source(self):
        topo = build_topology(report=_report(), unrouted_tools=[])
        by = {c.client: c for c in topo.mcp_clients}
        self.assertEqual(
            by["claude-desktop"].audit_log, "/home/.agent-sudo/mcp-audit.jsonl"
        )
        self.assertEqual(by["claude-desktop"].editable_source, "/repo/Agent_Sudo")
        self.assertEqual(by["gemini"].editable_source, "/home/Developer/Agent_Sudo")

    def test_audit_destinations_group_clients(self):
        topo = build_topology(report=_report(), unrouted_tools=[])
        dest = topo.audit_destinations
        self.assertEqual(dest["/home/.agent-sudo/mcp-audit.jsonl"], ["claude-desktop"])
        self.assertEqual(
            sorted(dest["/home/.agent-sudo/antigravity-mcp-audit.jsonl"]),
            ["antigravity", "gemini"],
        )


class NotRoutedTests(unittest.TestCase):
    def test_detects_present_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            present = Path(tmp) / "smithery_home"
            present.mkdir()
            tools = [{"name": "smithery", "binaries": [], "paths": [str(present)]}]
            topo = build_topology(report=_report(), unrouted_tools=tools)
        self.assertEqual(len(topo.not_routed), 1)
        self.assertEqual(topo.not_routed[0].name, "smithery")
        self.assertTrue(topo.not_routed[0].found)

    def test_absent_tool_not_reported(self):
        tools = [
            {"name": "ghosttool", "binaries": [], "paths": ["/nope/does/not/exist"]}
        ]
        topo = build_topology(report=_report(), unrouted_tools=tools)
        self.assertEqual(topo.not_routed, [])

    def test_routed_client_name_excluded(self):
        # a tool whose name IS a routed client must not be flagged as unrouted
        with tempfile.TemporaryDirectory() as tmp:
            present = Path(tmp) / "x"
            present.mkdir()
            tools = [{"name": "gemini", "binaries": [], "paths": [str(present)]}]
            topo = build_topology(report=_report(), unrouted_tools=tools)
        self.assertEqual(topo.not_routed, [])


class FormatTopologyTests(unittest.TestCase):
    def test_sections_and_key_facts_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            present = Path(tmp) / "smithery"
            present.mkdir()
            tools = [{"name": "smithery", "binaries": [], "paths": [str(present)]}]
            text = format_topology(
                build_topology(report=_report(), unrouted_tools=tools)
            )
        for header in (
            "1. CLI surfaces",
            "2. MCP clients",
            "3. Audit destinations",
            "4. Not routed through Agent_Sudo",
        ):
            self.assertIn(header, text)
        self.assertIn("claude-desktop", text)
        self.assertIn("smithery", text)
        self.assertIn("NOT configured to route through Agent_Sudo", text)
        self.assertIn("agent-sudo inventory", text)

    def test_empty_not_routed_states_none(self):
        text = format_topology(build_topology(report=_report(), unrouted_tools=[]))
        self.assertIn("(no known unrouted MCP tooling detected)", text)


if __name__ == "__main__":
    unittest.main()

"""Tests for the read-only install/config inventory (issue #101)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_sudo.inventory import (
    InventoryReport,
    _mcp_entries_from_toml_fallback,
    build_inventory,
    format_inventory,
)


def _make_install(root: Path, version: str, *, editable_from: str = "") -> Path:
    """Create a fake venv install: bin/agent-sudo* + dist-info METADATA."""
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ("agent-sudo", "agent-sudo-mcp"):
        exe = bin_dir / name
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o755)
    dist_info = (
        root
        / "lib"
        / "python3.11"
        / "site-packages"
        / f"agent_sudo_mcp-{version}.dist-info"
    )
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: agent-sudo-mcp\nVersion: {version}\n",
        encoding="utf-8",
    )
    if editable_from:
        (dist_info / "direct_url.json").write_text(
            json.dumps(
                {"url": f"file://{editable_from}", "dir_info": {"editable": True}}
            ),
            encoding="utf-8",
        )
    return bin_dir / "agent-sudo-mcp"


def _snapshot(home: Path) -> set[str]:
    return {str(p) for p in home.rglob("*")}


class InventoryDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def _build(self, *, path_env: str = "", platform: str = "linux") -> InventoryReport:
        return build_inventory(
            home=self.home,
            path_env=path_env,
            platform=platform,
            environ={},
            include_running=False,
        )

    def test_empty_home_reports_nothing(self) -> None:
        report = self._build()
        self.assertEqual(report.installs, [])
        self.assertEqual(report.configs, [])
        self.assertEqual(report.newest_version, "")

    def test_pipx_install_discovered_with_version(self) -> None:
        venv = self.home / ".local" / "pipx" / "venvs" / "agent-sudo-mcp"
        _make_install(venv, "0.5.6")
        report = self._build()
        self.assertEqual(len(report.installs), 1)
        install = report.installs[0]
        self.assertEqual(install.version, "0.5.6")
        self.assertTrue(any(v.startswith("pipx:") for v in install.discovered_via))

    def test_pyenv_install_discovered(self) -> None:
        _make_install(self.home / ".pyenv" / "versions" / "3.11.14", "0.5.5")
        report = self._build()
        self.assertEqual(len(report.installs), 1)
        self.assertEqual(report.installs[0].version, "0.5.5")
        self.assertTrue(
            any(v.startswith("pyenv:") for v in report.installs[0].discovered_via)
        )

    def test_path_scan_and_shadowing(self) -> None:
        first = self.home / "venv-a"
        second = self.home / "venv-b"
        _make_install(first, "0.5.6")
        _make_install(second, "0.5.6")
        path_env = os.pathsep.join([str(first / "bin"), str(second / "bin")])
        report = self._build(path_env=path_env)
        self.assertEqual(len(report.installs), 2)
        ranks = {i.root: i.path_rank for i in report.installs}
        self.assertEqual(ranks[str(first)], 0)
        self.assertEqual(ranks[str(second)], 1)
        shadowed = [i for i in report.installs if "PATH-SHADOWED" in i.statuses]
        self.assertEqual([i.root for i in shadowed], [str(second)])

    def test_editable_install_detected(self) -> None:
        venv = self.home / "venv-dev"
        _make_install(venv, "0.5.6", editable_from="/somewhere/Agent_Sudo")
        report = self._build(path_env=str(venv / "bin"))
        install = report.installs[0]
        self.assertTrue(install.editable)
        self.assertEqual(install.editable_source, "/somewhere/Agent_Sudo")
        self.assertIn("EDITABLE", install.statuses)

    def test_pyenv_shim_not_reported_as_unknown_install(self) -> None:
        shims = self.home / ".pyenv" / "shims"
        shims.mkdir(parents=True)
        shim = shims / "agent-sudo"
        shim.write_text("#!/bin/sh\n", encoding="utf-8")
        shim.chmod(0o755)
        report = self._build(path_env=str(shims))
        self.assertEqual(len(report.installs), 1)
        install = report.installs[0]
        self.assertIn("PYENV-SHIM", install.statuses)
        self.assertNotIn("UNKNOWN", install.statuses)
        self.assertNotIn("DUPLICATE INSTALL", install.statuses)
        self.assertEqual(report.warnings, [])


class InventoryConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def _build(self, *, platform: str = "linux") -> InventoryReport:
        return build_inventory(
            home=self.home,
            path_env="",
            platform=platform,
            environ={},
            include_running=False,
        )

    def _write_json_config(self, path: Path, command: str, args: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"mcpServers": {"agent-sudo": {"command": command, "args": args}}}
            ),
            encoding="utf-8",
        )

    def test_claude_desktop_config_resolves_install(self) -> None:
        venv = self.home / "venv"
        exe = _make_install(venv, "0.5.6")
        self._write_json_config(
            self.home / ".config" / "Claude" / "claude_desktop_config.json",
            str(exe),
            ["--audit-log", "/abs/audit.jsonl"],
        )
        report = self._build()
        self.assertEqual(len(report.configs), 1)
        config = report.configs[0]
        self.assertEqual(config.client, "claude-desktop")
        self.assertEqual(config.install_root, str(venv))
        self.assertEqual(config.version, "0.5.6")
        self.assertIn("ACTIVE", config.statuses)
        self.assertEqual(config.recommendation, "up to date")

    def test_claude_desktop_macos_path(self) -> None:
        venv = self.home / "venv"
        exe = _make_install(venv, "0.5.6")
        self._write_json_config(
            self.home
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json",
            str(exe),
            [],
        )
        report = self._build(platform="darwin")
        self.assertEqual([c.client for c in report.configs], ["claude-desktop"])

    def test_gemini_and_antigravity_configs(self) -> None:
        venv = self.home / "venv"
        exe = _make_install(venv, "0.5.6")
        self._write_json_config(self.home / ".gemini" / "settings.json", str(exe), [])
        self._write_json_config(
            self.home / ".gemini" / "antigravity" / "mcp_config.json", str(exe), []
        )
        report = self._build()
        self.assertEqual(
            sorted(c.client for c in report.configs), ["antigravity", "gemini"]
        )

    def test_codex_toml_config_parsed_and_comments_ignored(self) -> None:
        venv = self.home / "venv"
        exe = _make_install(venv, "0.5.6")
        config = self.home / ".codex" / "config.toml"
        config.parent.mkdir(parents=True)
        config.write_text(
            "\n".join(
                [
                    "# [mcp_servers.agent-sudo-old]",
                    '# command = "/old/bin/agent-sudo-mcp"',
                    "[mcp_servers.other-server]",
                    'command = "/usr/bin/other-tool"',
                    "[mcp_servers.agent-sudo]",
                    f'command = "{exe}"',
                    'args = ["--audit-log", "/abs/audit.jsonl"]',
                ]
            ),
            encoding="utf-8",
        )
        report = self._build()
        self.assertEqual(len(report.configs), 1)
        config_record = report.configs[0]
        self.assertEqual(config_record.client, "codex")
        self.assertEqual(config_record.server_name, "agent-sudo")
        self.assertEqual(config_record.command, str(exe))

    def test_non_agent_sudo_servers_ignored(self) -> None:
        self._write_json_config(
            self.home / ".gemini" / "settings.json", "/usr/bin/some-other-mcp", []
        )
        report = self._build()
        self.assertEqual(report.configs, [])

    def test_missing_command_reported_unknown(self) -> None:
        self._write_json_config(
            self.home / ".gemini" / "settings.json",
            str(self.home / "gone" / "bin" / "agent-sudo-mcp"),
            [],
        )
        report = self._build()
        config = report.configs[0]
        self.assertFalse(config.command_exists)
        self.assertIn("UNKNOWN", config.statuses)
        self.assertIn("does not exist", config.recommendation)

    def test_malformed_config_is_warning_not_crash(self) -> None:
        path = self.home / ".gemini" / "settings.json"
        path.parent.mkdir(parents=True)
        path.write_text("{not valid json", encoding="utf-8")
        report = self._build()
        self.assertEqual(report.configs, [])
        self.assertTrue(any("could not parse" in w for w in report.warnings))

    def test_python_module_invocation_detected(self) -> None:
        venv = self.home / "venv"
        _make_install(venv, "0.5.6")
        python = venv / "bin" / "python3"
        python.write_text("#!/bin/sh\n", encoding="utf-8")
        python.chmod(0o755)
        self._write_json_config(
            self.home / ".gemini" / "settings.json",
            str(python),
            ["-m", "agent_sudo.mcp_server"],
        )
        report = self._build()
        self.assertEqual(len(report.configs), 1)
        self.assertEqual(report.configs[0].install_root, str(venv))


class InventoryClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def _build(self) -> InventoryReport:
        return build_inventory(
            home=self.home,
            path_env="",
            platform="linux",
            environ={},
            include_running=False,
        )

    def test_version_drift_and_stale(self) -> None:
        newest = self.home / ".local" / "pipx" / "venvs" / "agent-sudo-mcp"
        exe = _make_install(newest, "0.5.6")
        _make_install(self.home / ".pyenv" / "versions" / "3.10.2", "0.5.4")
        config_path = self.home / ".gemini" / "settings.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            json.dumps({"mcpServers": {"agent-sudo": {"command": str(exe)}}}),
            encoding="utf-8",
        )
        report = self._build()
        self.assertEqual(report.newest_version, "0.5.6")
        by_version = {i.version: i for i in report.installs}
        old = by_version["0.5.4"]
        self.assertIn("VERSION DRIFT", old.statuses)
        self.assertIn("STALE", old.statuses)
        self.assertIn("DUPLICATE INSTALL", old.statuses)
        new = by_version["0.5.6"]
        self.assertIn("ACTIVE", new.statuses)
        self.assertNotIn("STALE", new.statuses)

    def test_config_drift_recommendation(self) -> None:
        old_venv = self.home / "old-venv"
        old_exe = _make_install(old_venv, "0.5.4")
        _make_install(
            self.home / ".local" / "pipx" / "venvs" / "agent-sudo-mcp", "0.5.6"
        )
        config_path = self.home / ".gemini" / "settings.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            json.dumps({"mcpServers": {"agent-sudo": {"command": str(old_exe)}}}),
            encoding="utf-8",
        )
        report = self._build()
        config = report.configs[0]
        self.assertIn("VERSION DRIFT", config.statuses)
        self.assertIn("0.5.4", config.recommendation)
        self.assertIn("0.5.6", config.recommendation)

    def test_unknown_version_install(self) -> None:
        broken = self.home / "broken-venv"
        bin_dir = broken / "bin"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "agent-sudo"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o755)
        report = build_inventory(
            home=self.home,
            path_env=str(bin_dir),
            platform="linux",
            environ={},
            include_running=False,
        )
        install = report.installs[0]
        self.assertIn("UNKNOWN", install.statuses)
        self.assertTrue(
            any("could not determine version" in w for w in report.warnings)
        )


class InventoryReadOnlyAndOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def test_build_inventory_writes_nothing(self) -> None:
        venv = self.home / ".local" / "pipx" / "venvs" / "agent-sudo-mcp"
        exe = _make_install(venv, "0.5.6")
        config_path = self.home / ".gemini" / "settings.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            json.dumps({"mcpServers": {"agent-sudo": {"command": str(exe)}}}),
            encoding="utf-8",
        )
        before = {str(p) for p in self.home.rglob("*")}
        build_inventory(
            home=self.home,
            path_env="",
            platform="linux",
            environ={},
            include_running=False,
        )
        after = {str(p) for p in self.home.rglob("*")}
        self.assertEqual(before, after)

    def test_format_and_json_roundtrip(self) -> None:
        venv = self.home / ".local" / "pipx" / "venvs" / "agent-sudo-mcp"
        _make_install(venv, "0.5.6")
        report = build_inventory(
            home=self.home,
            path_env="",
            platform="linux",
            environ={},
            include_running=False,
        )
        text = format_inventory(report)
        self.assertIn("Installs found: 1", text)
        self.assertIn("0.5.6", text)
        data = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(data["newest_version"], "0.5.6")
        self.assertEqual(len(data["installs"]), 1)
        for key in ("root", "version", "discovered_via", "statuses", "recommendation"):
            self.assertIn(key, data["installs"][0])


class TomlFallbackTests(unittest.TestCase):
    def test_fallback_parses_sections_and_skips_comments(self) -> None:
        text = "\n".join(
            [
                "# [mcp_servers.commented]",
                '# command = "/dead/agent-sudo-mcp"',
                "[mcp_servers.agent-sudo]",
                'command = "/real/bin/agent-sudo-mcp"',
                'args = ["--flag", "value"]',
                "[other_section]",
                'command = "/not/an/mcp/server"',
            ]
        )
        entries = _mcp_entries_from_toml_fallback(text)
        self.assertEqual(
            entries, [("agent-sudo", "/real/bin/agent-sudo-mcp", ["--flag", "value"])]
        )


if __name__ == "__main__":
    unittest.main()

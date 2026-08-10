from __future__ import annotations

import io
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from agent_sudo.gateway import main
from agent_sudo.upgrade import (
    _preremove_scripts_on_windows,
    _restore_preremoved_scripts,
    handle_upgrade,
    is_generated_artifact,
    version_key,
)


class UpgradeTests(unittest.TestCase):
    def test_preremove_scripts_is_noop_off_windows(self) -> None:
        with unittest.mock.patch("agent_sudo.upgrade.sys.platform", "darwin"):
            self.assertEqual(_preremove_scripts_on_windows(), [])

    def test_preremove_and_restore_windows_launchers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = Path(tmpdir)
            python_exe = scripts_dir / "python.exe"
            python_exe.write_bytes(b"python")
            launchers = [
                scripts_dir / "agent-sudo.exe",
                scripts_dir / "agent-sudo-mcp.exe",
            ]
            for launcher in launchers:
                launcher.write_bytes(b"launcher")

            with (
                unittest.mock.patch("agent_sudo.upgrade.sys.platform", "win32"),
                unittest.mock.patch(
                    "agent_sudo.upgrade.sys.executable", str(python_exe)
                ),
            ):
                moved = _preremove_scripts_on_windows()

            self.assertEqual(
                [original for original, _ in moved],
                [launcher.resolve() for launcher in launchers],
            )
            self.assertTrue(all(not launcher.exists() for launcher in launchers))
            self.assertTrue(all(backup.exists() for _, backup in moved))

            _restore_preremoved_scripts(moved)
            self.assertTrue(all(launcher.exists() for launcher in launchers))
            self.assertTrue(all(not backup.exists() for _, backup in moved))

    def test_version_key_parsing(self) -> None:
        self.assertEqual(version_key("v0.3.4-beta"), (0, 3, 4))
        self.assertEqual(version_key("v0.4.0-rc1"), (0, 4, 0, 1))
        self.assertEqual(version_key("v0.4.0-rc4"), (0, 4, 0, 4))
        self.assertEqual(version_key("v0.4.0-rc5"), (0, 4, 0, 5))
        self.assertEqual(version_key("v0.4.0-rc8"), (0, 4, 0, 8))
        self.assertEqual(version_key("v0.4.0-rc9"), (0, 4, 0, 9))
        self.assertEqual(version_key("v0.4.0-rc10"), (0, 4, 0, 10))
        self.assertEqual(version_key("v0.4.0-rc11"), (0, 4, 0, 11))
        self.assertEqual(version_key("v0.4.0-rc12"), (0, 4, 0, 12))
        self.assertEqual(version_key("v0.12.0"), (0, 12, 0))
        self.assertEqual(version_key("0.3.3b0"), (0, 3, 3, 0))

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    def test_check_in_non_git_directory(self, mock_get_git_root) -> None:
        mock_get_git_root.return_value = None

        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["upgrade-local", "--check"])

        self.assertEqual(code, 1)
        self.assertIn(
            "This installation is not inside a git repository.", err.getvalue()
        )
        self.assertIn("pip install --upgrade agent-sudo-mcp", err.getvalue())

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_dirty_working_tree_refuses_upgrade(
        self, mock_run, mock_get_git_root
    ) -> None:
        mock_get_git_root.return_value = Path("/tmp/mock-repo")
        mock_run.side_effect = _mock_upgrade_run(" M README.md\n")

        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["upgrade-local"])

        self.assertEqual(code, 1)
        self.assertIn("Git working tree has uncommitted changes", err.getvalue())
        self.assertIn("User changes blocking upgrade", err.getvalue())
        self.assertIn(" M README.md", err.getvalue())
        self.assertFalse(_command_was_run(mock_run, ["git", "pull"]))

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_state_preservation_warning_appears(
        self, mock_run, mock_get_git_root
    ) -> None:
        mock_get_git_root.return_value = Path("/tmp/mock-repo")
        mock_run.side_effect = _mock_upgrade_run("")

        out = io.StringIO()
        with redirect_stdout(out):
            # Just do check to avoid actual pull/reinstall subprocesses running
            code = main(["upgrade-local", "--check"])

        self.assertEqual(code, 0)
        self.assertIn(
            "Local state, audit logs, and delegations under ~/.agent-sudo will be preserved",
            out.getvalue(),
        )

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_upgrade_cleans_egg_info_and_proceeds(
        self, mock_run, mock_get_git_root
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            git_root = Path(tmpdir)
            artifact = git_root / "agent_sudo.egg-info"
            artifact.mkdir()
            (artifact / "PKG-INFO").write_text("generated\n", encoding="utf-8")
            mock_get_git_root.return_value = git_root
            mock_run.side_effect = _mock_upgrade_run("?? agent_sudo.egg-info/\n")

            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["upgrade-local"])

            self.assertEqual(code, 0)
            self.assertFalse(artifact.exists())
            self.assertIn(
                "Found generated artifacts that can be safely removed", out.getvalue()
            )
            self.assertIn("- agent_sudo.egg-info/", out.getvalue())
            self.assertIn("Proceeding with upgrade", out.getvalue())
            self.assertTrue(_command_was_run(mock_run, ["git", "pull"]))

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_upgrade_cleans_cache_and_build_artifacts_and_proceeds(
        self, mock_run, mock_get_git_root
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            git_root = Path(tmpdir)
            artifacts = [
                git_root / "__pycache__",
                git_root / ".pytest_cache",
                git_root / ".mypy_cache",
                git_root / ".ruff_cache",
                git_root / "build",
                git_root / "dist",
            ]
            for artifact in artifacts:
                artifact.mkdir()
                (artifact / "generated.txt").write_text("generated\n", encoding="utf-8")
            ds_store = git_root / ".DS_Store"
            ds_store.write_text("generated\n", encoding="utf-8")
            mock_get_git_root.return_value = git_root
            mock_run.side_effect = _mock_upgrade_run(
                "?? __pycache__/\n"
                "?? .pytest_cache/\n"
                "?? .mypy_cache/\n"
                "?? .ruff_cache/\n"
                "?? build/\n"
                "?? dist/\n"
                "?? .DS_Store\n"
            )

            with redirect_stdout(io.StringIO()):
                code = main(["upgrade-local"])

            self.assertEqual(code, 0)
            self.assertTrue(all(not artifact.exists() for artifact in artifacts))
            self.assertFalse(ds_store.exists())
            self.assertTrue(_command_was_run(mock_run, ["git", "pull"]))

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_upgrade_blocks_unknown_untracked_file(
        self, mock_run, mock_get_git_root
    ) -> None:
        mock_get_git_root.return_value = Path("/tmp/mock-repo")
        mock_run.side_effect = _mock_upgrade_run("?? notes.txt\n")

        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["upgrade-local"])

        self.assertEqual(code, 1)
        self.assertIn("User changes blocking upgrade", err.getvalue())
        self.assertIn("?? notes.txt", err.getvalue())
        self.assertFalse(_command_was_run(mock_run, ["git", "pull"]))

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_mixed_generated_and_real_untracked_files_block(
        self, mock_run, mock_get_git_root
    ) -> None:
        mock_get_git_root.return_value = Path("/tmp/mock-repo")
        mock_run.side_effect = _mock_upgrade_run(
            "?? agent_sudo.egg-info/\n?? notes.txt\n"
        )

        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["upgrade-local"])

        self.assertEqual(code, 1)
        self.assertIn("Generated artifacts detected", err.getvalue())
        self.assertIn("- agent_sudo.egg-info/", err.getvalue())
        self.assertIn("User changes blocking upgrade", err.getvalue())
        self.assertIn("?? notes.txt", err.getvalue())
        self.assertFalse(_command_was_run(mock_run, ["git", "pull"]))

    @unittest.mock.patch("agent_sudo.upgrade.get_git_root")
    @unittest.mock.patch("agent_sudo.upgrade.subprocess.run")
    def test_allow_dirty_still_proceeds_without_cleaning(
        self, mock_run, mock_get_git_root
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            git_root = Path(tmpdir)
            artifact = git_root / "agent_sudo.egg-info"
            artifact.mkdir()
            unknown = git_root / "notes.txt"
            unknown.write_text("keep me\n", encoding="utf-8")
            mock_get_git_root.return_value = git_root
            mock_run.side_effect = _mock_upgrade_run(
                "?? agent_sudo.egg-info/\n?? notes.txt\n"
            )

            with redirect_stdout(io.StringIO()):
                code = main(["upgrade-local", "--allow-dirty"])

            self.assertEqual(code, 0)
            self.assertTrue(artifact.exists())
            self.assertTrue(unknown.exists())
            self.assertTrue(_command_was_run(mock_run, ["git", "pull"]))

    def test_generated_artifact_classifier(self) -> None:
        self.assertTrue(is_generated_artifact("agent_sudo.egg-info/"))
        self.assertTrue(is_generated_artifact("pkg/__pycache__/"))
        self.assertTrue(is_generated_artifact(".pytest_cache/"))
        self.assertTrue(is_generated_artifact(".mypy_cache/"))
        self.assertTrue(is_generated_artifact(".ruff_cache/"))
        self.assertTrue(is_generated_artifact("build/"))
        self.assertTrue(is_generated_artifact("dist/"))
        self.assertTrue(is_generated_artifact(".DS_Store"))
        self.assertFalse(is_generated_artifact("notes.txt"))
        self.assertFalse(is_generated_artifact("src/build_notes.md"))

    def test_does_not_touch_agent_sudo_dir(self) -> None:
        # Confirm that handle_upgrade does not attempt to access user home config path ~/.agent-sudo/ in tests
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir)
            with unittest.mock.patch("pathlib.Path.home", return_value=fake_home):
                with unittest.mock.patch(
                    "agent_sudo.upgrade.get_git_root"
                ) as mock_git_root:
                    mock_git_root.return_value = None
                    err = io.StringIO()
                    with redirect_stderr(err):
                        handle_upgrade(check_only=True)

            # Assert that no file or folder named .agent-sudo is created under the fake home directory
            agent_sudo_dir = fake_home / ".agent-sudo"
            self.assertFalse(agent_sudo_dir.exists())


def _mock_upgrade_run(status_stdout: str):
    def fake_run(cmd, *args, **kwargs):
        command = [str(part) for part in cmd]
        if command[:3] == ["git", "rev-parse", "--abbrev-ref"]:
            return unittest.mock.MagicMock(returncode=0, stdout="main\n", stderr="")
        if command[:3] == ["git", "rev-parse", "--short"]:
            return unittest.mock.MagicMock(returncode=0, stdout="abc123\n", stderr="")
        if command[:2] == ["git", "fetch"]:
            return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")
        if command == ["git", "tag"]:
            return unittest.mock.MagicMock(
                returncode=0, stdout="v0.4.0-rc12\n", stderr=""
            )
        if command[:3] == ["git", "status", "--porcelain"]:
            return unittest.mock.MagicMock(
                returncode=0, stdout=status_stdout, stderr=""
            )
        if command[:2] == ["git", "pull"]:
            return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")
        if command[-4:] == ["-m", "pip", "install", "-e"] or "pip" in command:
            return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")
        if "agent-sudo" in command[0] or "agent-sudo-mcp" in command[0]:
            return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")
        if "-m" in command and "agent_sudo.gateway" in command:
            return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")
        return unittest.mock.MagicMock(returncode=0, stdout="", stderr="")

    return fake_run


def _command_was_run(mock_run, expected_prefix: list[str]) -> bool:
    for call in mock_run.call_args_list:
        command = [str(part) for part in call.args[0]]
        if command[: len(expected_prefix)] == expected_prefix:
            return True
    return False


if __name__ == "__main__":
    unittest.main()

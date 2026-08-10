from __future__ import annotations

import io
import json
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

from agent_sudo.doctor import (
    DoctorCheck,
    doctor_exit_code,
    format_doctor_checks,
    run_doctor,
)
from agent_sudo.gateway import main
from agent_sudo.inventory import InstallRecord, InventoryReport
from agent_sudo.self_identity import SelfIdentity


class DoctorTests(unittest.TestCase):
    def test_doctor_runs_checks(self) -> None:
        checks = run_doctor()
        names = {check.name for check in checks}

        self.assertIn("Python version OK", names)
        self.assertIn("default policy exists", names)
        self.assertIn("audit log writable", names)
        self.assertIn("delegation store writable", names)
        # doctor reports user readiness only — no contributor/repo hygiene scan.
        self.assertNotIn("no personal data in repo", names)

    def test_doctor_never_runs_repo_hygiene_scan(self) -> None:
        # Even from a source checkout that contains the scanner, doctor must
        # not run it or surface its output to evaluators.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir).resolve()
            script_dir = tmp_path / "scripts"
            script_dir.mkdir()
            (script_dir / "check_no_personal_data.py").write_text(
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            venv_dir = tmp_path / "test_venv"
            venv_dir.mkdir()
            (venv_dir / "example.txt").write_text(
                "/Users/username/Library/Application Support/SuperApp",
                encoding="utf-8",
            )

            checks = run_doctor(repo_root=tmp_path)
            names = {check.name for check in checks}

            self.assertNotIn("no personal data in repo", names)

    def test_doctor_does_not_create_agent_sudo_in_cwd(self) -> None:
        # #71: doctor is a read-only diagnostic and must not leave a
        # .agent-sudo/ directory behind in the current working directory.
        prev = Path.cwd()
        with tempfile.TemporaryDirectory() as work_dir:
            import os

            os.chdir(work_dir)
            try:
                run_doctor()
                self.assertFalse((Path(work_dir) / ".agent-sudo").exists())
            finally:
                os.chdir(prev)

    def test_doctor_reports_single_consistent_state_root(self) -> None:
        # #71: the audit-log and delegation-store probes must report the same
        # state root, and the writability probe must not leave a doctor-audit
        # file behind.
        with tempfile.TemporaryDirectory() as state_dir:
            store_path = Path(state_dir) / "delegations.json"
            with unittest.mock.patch(
                "agent_sudo.doctor.default_delegations_path",
                return_value=store_path,
            ):
                checks = run_doctor()
            audit = next(c for c in checks if c.name == "audit log writable")
            deleg = next(c for c in checks if c.name == "delegation store writable")
            self.assertTrue(audit.ok)
            self.assertEqual(Path(audit.detail).parent, Path(deleg.detail).parent)
            self.assertFalse((store_path.parent / "doctor-audit.jsonl").exists())

    def test_doctor_exit_code_fails_required_check(self) -> None:
        checks = [DoctorCheck("Python version OK", False, "too old")]

        self.assertEqual(doctor_exit_code(checks), 1)

    def test_install_health_checks_present_by_default(self) -> None:
        names = {check.name for check in run_doctor()}
        self.assertIn("install up to date", names)
        self.assertIn("runtime matches install source", names)


class InstallHealthCheckTests(unittest.TestCase):
    """Stale-install and editable-drift detection (issue #110), WARN-only."""

    def _identity(self, **over) -> SelfIdentity:
        base = dict(
            version="0.5.6",
            install_type="editable",
            source_path="/repo/Agent_Sudo",
            package_path="/repo/Agent_Sudo/agent_sudo",
            python_executable="/py/bin/python",
            python_prefix="/py",
            python_version="3.11.14",
            origin="console-script",
        )
        base.update(over)
        return SelfIdentity(**base)

    def _report(self, *, newest: str, installs) -> InventoryReport:
        records = [
            InstallRecord(root=root, executable="", version=version)
            for root, version in installs
        ]
        return InventoryReport(
            installs=records, configs=[], warnings=[], newest_version=newest
        )

    def _by_name(self, checks):
        return {check.name: check for check in checks}

    def test_stale_pinned_install_warns(self) -> None:
        identity = self._identity(
            install_type="pinned-wheel",
            version="0.5.5",
            source_path="/venv/site-packages/agent_sudo",
            package_path="/venv/site-packages/agent_sudo",
        )
        report = self._report(
            newest="0.5.6",
            installs=[
                ("/venv", "0.5.5"),
                ("/Users/username/Developer/Agent_Sudo", "0.5.6"),
            ],
        )
        checks = self._by_name(run_doctor(identity=identity, inventory_report=report))
        stale = checks["install up to date"]
        self.assertFalse(stale.ok)
        self.assertIn("0.5.5", stale.detail)
        self.assertIn("0.5.6", stale.detail)
        self.assertIn("Developer/Agent_Sudo", stale.detail)
        # a pinned install has no editable source to drift, so this stays OK
        self.assertTrue(checks["runtime matches install source"].ok)
        # WARN-only: a stale install must not fail the doctor exit code
        self.assertEqual(
            doctor_exit_code(run_doctor(identity=identity, inventory_report=report)), 0
        )

    def test_editable_source_mismatch_warns(self) -> None:
        identity = self._identity(
            install_type="editable",
            version="0.5.6",
            source_path="/old/checkout/Agent_Sudo",
            package_path="/elsewhere/Agent_Sudo/agent_sudo",
        )
        report = self._report(
            newest="0.5.6", installs=[("/old/checkout/Agent_Sudo", "0.5.6")]
        )
        checks = self._by_name(run_doctor(identity=identity, inventory_report=report))
        drift = checks["runtime matches install source"]
        self.assertFalse(drift.ok)
        self.assertIn("/old/checkout/Agent_Sudo", drift.detail)
        self.assertIn("/elsewhere/Agent_Sudo", drift.detail)
        # version is newest, so staleness stays OK
        self.assertTrue(checks["install up to date"].ok)
        self.assertEqual(
            doctor_exit_code(run_doctor(identity=identity, inventory_report=report)), 0
        )

    def test_clean_current_install_is_ok(self) -> None:
        identity = self._identity()  # editable 0.5.6, package under source
        report = self._report(newest="0.5.6", installs=[("/repo/Agent_Sudo", "0.5.6")])
        checks = self._by_name(run_doctor(identity=identity, inventory_report=report))
        self.assertTrue(checks["install up to date"].ok)
        self.assertTrue(checks["runtime matches install source"].ok)
        self.assertEqual(
            doctor_exit_code(run_doctor(identity=identity, inventory_report=report)), 0
        )

    def test_unknown_versions_do_not_warn(self) -> None:
        identity = self._identity(version="unknown")
        report = self._report(newest="", installs=[])
        checks = self._by_name(run_doctor(identity=identity, inventory_report=report))
        self.assertTrue(checks["install up to date"].ok)

    def test_doctor_format_contains_status(self) -> None:
        text = format_doctor_checks(
            [DoctorCheck("approval config exists", False, "not initialized")]
        )

        self.assertIn("WARN: approval config exists", text)

    def test_doctor_command_prints_checks(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["doctor"])

        self.assertIn(code, {0, 1})
        self.assertIn("Python version OK", output.getvalue())

    def test_setup_command_is_dry_run_checklist(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["setup", "codex"])

        self.assertEqual(code, 0)
        self.assertIn("dry-run only", output.getvalue())
        self.assertIn("Verify with:", output.getvalue())

    def test_doctor_output_before_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            non_existent = Path(tmpdir) / "config.json"
            with unittest.mock.patch("agent_sudo.doctor.CONFIG_PATH", non_existent):
                output = io.StringIO()
                with redirect_stdout(output):
                    main(["doctor"])

                self.assertIn("APPROVALS: NOT INITIALIZED", output.getvalue())
                self.assertIn("agent-sudo init-approval", output.getvalue())

    def test_doctor_output_after_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            existent = Path(tmpdir) / "config.json"
            existent.write_text("{}", encoding="utf-8")
            with unittest.mock.patch("agent_sudo.doctor.CONFIG_PATH", existent):
                output = io.StringIO()
                with redirect_stdout(output):
                    main(["doctor"])

                self.assertNotIn("APPROVALS: NOT INITIALIZED", output.getvalue())
                self.assertIn("OK: approval config exists", output.getvalue())

    def test_approve_without_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            non_existent = Path(tmpdir) / "config.json"
            with unittest.mock.patch("agent_sudo.gateway.CONFIG_PATH", non_existent):
                err = io.StringIO()
                with unittest.mock.patch("sys.stderr", err):
                    code = main(["approve", "some-id"])

                self.assertEqual(code, 1)
                self.assertIn("approval system not initialized", err.getvalue())
                self.assertIn("agent-sudo init-approval", err.getvalue())


class DoctorBroadDelegationTests(unittest.TestCase):
    def _broad_token(self) -> dict:
        return {
            "token_id": "broad-1",
            "actor": "mcp-client",
            "allowed_actions": ["write_file"],
            "allowed_paths": ["*"],
            "denied_actions": [],
            "expires_at": "2026-06-06T05:00:00Z",
            "max_uses": 10,
            "uses": 0,
            "revoked": False,
            "critical": False,
            "created_at": "2026-06-06T01:00:00Z",
        }

    def _run_with_store(self, tokens: list) -> list[DoctorCheck]:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "delegations.json"
            store_path.write_text(json.dumps(tokens), encoding="utf-8")
            with unittest.mock.patch(
                "agent_sudo.doctor.default_delegations_path",
                return_value=store_path,
            ):
                return run_doctor()

    def test_warns_when_broad_delegation_present(self) -> None:
        checks = self._run_with_store([self._broad_token()])
        scope = next(c for c in checks if c.name == "delegation scope")
        self.assertFalse(scope.ok)
        self.assertIn("broad", scope.detail)
        self.assertIn("broad-1", scope.detail)
        # WARN only — must not flip the doctor exit code to failure.
        self.assertEqual(doctor_exit_code(checks), 0)

    def test_ok_when_no_broad_delegation(self) -> None:
        narrow = self._broad_token()
        narrow["allowed_paths"] = ["/ws/a.txt"]
        checks = self._run_with_store([narrow])
        scope = next(c for c in checks if c.name == "delegation scope")
        self.assertTrue(scope.ok)


class DuplicateInstallCheckTests(unittest.TestCase):
    """doctor surfaces multiple active installs (issue #111), WARN-only."""

    def _identity(self) -> SelfIdentity:
        return SelfIdentity(
            version="0.5.6",
            install_type="editable",
            source_path="/repo/Agent_Sudo",
            package_path="/repo/Agent_Sudo/agent_sudo",
            python_executable="/py/bin/python",
            python_prefix="/py",
            python_version="3.11.14",
            origin="console-script",
        )

    def _report(self, installs) -> InventoryReport:
        records = [
            InstallRecord(
                root=root, executable="", version=version, statuses=list(statuses)
            )
            for root, version, statuses in installs
        ]
        newest = max((r.version for r in records), default="")
        return InventoryReport(
            installs=records, configs=[], warnings=[], newest_version=newest
        )

    def _check(self, installs) -> DoctorCheck:
        checks = run_doctor(
            identity=self._identity(), inventory_report=self._report(installs)
        )
        return next(c for c in checks if c.name == "single active install")

    def test_no_duplicates_is_ok(self) -> None:
        check = self._check([("/repo/Agent_Sudo", "0.5.6", ["ACTIVE", "EDITABLE"])])
        self.assertTrue(check.ok)

    def test_duplicate_active_installs_warn(self) -> None:
        installs = [
            ("/venv/a", "0.5.6", ["ACTIVE", "DUPLICATE INSTALL"]),
            ("/venv/b", "0.5.6", ["ACTIVE", "DUPLICATE INSTALL"]),
        ]
        check = self._check(installs)
        self.assertFalse(check.ok)
        self.assertEqual(
            check.detail,
            "Multiple active Agent_Sudo installs detected. Run `agent-sudo inventory` "
            "to inspect and choose one canonical install.",
        )
        # WARN-only: must not fail the exit code.
        checks = run_doctor(
            identity=self._identity(), inventory_report=self._report(installs)
        )
        self.assertEqual(doctor_exit_code(checks), 0)

    def test_pyenv_shim_plus_resolved_install_not_double_counted(self) -> None:
        # A shim resolves to its version install; counting both would be a false
        # duplicate. The PYENV-SHIM record is excluded, leaving one real install.
        installs = [
            ("/home/.pyenv/shims", "", ["ACTIVE", "PYENV-SHIM"]),
            ("/home/.pyenv/versions/3.11.14", "0.5.6", ["ACTIVE", "EDITABLE"]),
        ]
        check = self._check(installs)
        self.assertTrue(check.ok)

    def test_same_version_editables_at_different_roots_warn(self) -> None:
        # Two editable installs, same version, different source roots — still a
        # duplicate because the roots differ.
        installs = [
            ("/repo/A", "0.5.6", ["ACTIVE", "EDITABLE", "DUPLICATE INSTALL"]),
            ("/repo/B", "0.5.6", ["ACTIVE", "EDITABLE", "DUPLICATE INSTALL"]),
        ]
        check = self._check(installs)
        self.assertFalse(check.ok)


if __name__ == "__main__":
    unittest.main()

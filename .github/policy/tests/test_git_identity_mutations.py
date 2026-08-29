from __future__ import annotations

import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
TEST_DIR = pathlib.Path(__file__).resolve().parent
MANIFEST = json.loads(
    (TEST_DIR / "git_identity_mutations.json").read_text(encoding="utf-8")
)

PYTHON_LEXICAL = (
    'if DRIVE_ROOT_RE.match(normalized) is None:  # POLICY_GUARD:LEXICAL_LOCAL'
)
PYTHON_TARGET = """\
        if ntpath.normcase(identity.path) != ntpath.normcase(  # POLICY_GUARD:TARGET_MATCH
            identity.requested_path
        ):
"""
POWERSHELL_LEXICAL = (
    "if ($normalized -cnotmatch '^[A-Za-z]:\\\\(?!\\\\)') { "
    "# POLICY_GUARD:LEXICAL_LOCAL"
)
POWERSHELL_TARGET = """\
        if (-not [String]::Equals( # POLICY_GUARD:TARGET_MATCH
                $identity.Path,
                $identity.RequestedPath,
                [StringComparison]::OrdinalIgnoreCase)) {
"""


def mutate_source(source: str, mutation: dict[str, str]) -> str:
    runtime = mutation["runtime"]
    guard = mutation["guard"]
    operator = mutation["operator"]
    if runtime == "python" and guard == "LEXICAL_LOCAL":
        replacement = (
            "if False:  # POLICY_GUARD:LEXICAL_LOCAL"
            if operator == "delete"
            else "if DRIVE_ROOT_RE.match(normalized) is not None:  "
            "# POLICY_GUARD:LEXICAL_LOCAL"
        )
        old = PYTHON_LEXICAL
    elif runtime == "python" and guard == "TARGET_MATCH":
        replacement = (
            "        if False:  # POLICY_GUARD:TARGET_MATCH\n"
            if operator == "delete"
            else PYTHON_TARGET.replace(" != ", " == ")
        )
        old = PYTHON_TARGET
    elif runtime == "powershell" and guard == "LEXICAL_LOCAL":
        replacement = (
            "if ($false) { # POLICY_GUARD:LEXICAL_LOCAL"
            if operator == "delete"
            else "if ($normalized -cmatch '^[A-Za-z]:\\\\(?!\\\\)') { "
            "# POLICY_GUARD:LEXICAL_LOCAL"
        )
        old = POWERSHELL_LEXICAL
    elif runtime == "powershell" and guard == "TARGET_MATCH":
        replacement = (
            "        if ($false) { # POLICY_GUARD:TARGET_MATCH\n"
            if operator == "delete"
            else POWERSHELL_TARGET.replace("if (-not [String]::Equals(", "if ([String]::Equals(")
        )
        old = POWERSHELL_TARGET
    else:
        raise AssertionError(f"unmodelled mutation {mutation!r}")
    if source.count(old) != 1:
        raise AssertionError(
            f"{mutation['id']} expected one source guard, found {source.count(old)}"
        )
    return source.replace(old, replacement)


PYTHON_NEGATIVE_LEXICAL = """
try:
    validator._lexical_local_file_path("relative\\\\git.exe")
except OSError:
    pass
else:
    raise AssertionError("MUTATION_SURVIVED")
"""
PYTHON_POSITIVE_LEXICAL = """
value = r"C:\\Program Files\\Git\\cmd\\git.exe"
assert validator._lexical_local_file_path(value) == value
"""
PYTHON_POSITIVE_TARGET = "validator._git_image()\n"
PYTHON_NEGATIVE_TARGET = r"""
real = validator._git_image()
with tempfile.TemporaryDirectory() as root:
    physical = os.path.join(root, "physical")
    junction = os.path.join(root, "junction")
    os.mkdir(physical)
    shutil.copyfile(real, os.path.join(physical, "git.exe"))
    result = subprocess.run(
        [os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"),
         "/d", "/c", "mklink", "/J", junction, physical],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode:
        raise RuntimeError("junction fixture unavailable")
    validator.TRUSTED_GIT_IMAGES = (os.path.join(junction, "git.exe"),)
    try:
        validator._git_image()
    except validator.PolicyError:
        pass
    else:
        raise AssertionError("MUTATION_SURVIVED")
"""

POWERSHELL_NEGATIVE_LEXICAL = r"""
$module = Get-Module PrivateRoot
try {
    & $module {
        ConvertTo-PolicyLexicalLocalFilePath -Path 'relative\git.exe' -Label test
    } | Out-Null
}
catch {
    exit 0
}
throw 'MUTATION_SURVIVED'
"""
POWERSHELL_POSITIVE_LEXICAL = r"""
$module = Get-Module PrivateRoot
$value = 'C:\Program Files\Git\cmd\git.exe'
$actual = & $module {
    param($v)
    ConvertTo-PolicyLexicalLocalFilePath -Path $v -Label test
} $value
if ($actual -cne $value) { throw 'MUTATION_SURVIVED' }
"""
POWERSHELL_POSITIVE_TARGET = "Get-PolicyGitImage | Out-Null\n"
POWERSHELL_NEGATIVE_TARGET = r"""
$real = Get-PolicyGitImage
$module = Get-Module PrivateRoot
$root = Join-Path $env:TEMP ('git-mutation-' + [Guid]::NewGuid().ToString('N'))
$physical = Join-Path $root physical
$junction = Join-Path $root junction
[void] [IO.Directory]::CreateDirectory($physical)
[IO.File]::Copy($real, (Join-Path $physical 'git.exe'))
New-Item -ItemType Junction -Path $junction -Target $physical -ErrorAction Stop | Out-Null
try {
    $alias = Join-Path $junction 'git.exe'
    & $module { param($v) $script:PolicyTrustedGitImages = @($v) } $alias
    try {
        Get-PolicyGitImage | Out-Null
    }
    catch {
        exit 0
    }
    throw 'MUTATION_SURVIVED'
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
"""


class GitIdentityMutationTests(unittest.TestCase):
    """Every manifest entry is one guard/operator mutant in the denominator."""

    maxDiff = None

    def python_probe(self, root: pathlib.Path, mutation: dict[str, str]) -> subprocess.CompletedProcess:
        body = {
            ("LEXICAL_LOCAL", "delete"): PYTHON_NEGATIVE_LEXICAL,
            ("LEXICAL_LOCAL", "invert"): PYTHON_POSITIVE_LEXICAL,
            ("TARGET_MATCH", "delete"): PYTHON_NEGATIVE_TARGET,
            ("TARGET_MATCH", "invert"): PYTHON_POSITIVE_TARGET,
        }[(mutation["guard"], mutation["operator"])]
        probe = (
            "import os, shutil, subprocess, sys, tempfile\n"
            f"sys.path.insert(0, {str(root)!r})\n"
            "import validator\n"
            + textwrap.dedent(body)
        )
        return subprocess.run(
            [sys.executable, "-B", "-c", probe],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def powershell_probe(
        self, root: pathlib.Path, mutation: dict[str, str]
    ) -> subprocess.CompletedProcess:
        body = {
            ("LEXICAL_LOCAL", "delete"): POWERSHELL_NEGATIVE_LEXICAL,
            ("LEXICAL_LOCAL", "invert"): POWERSHELL_POSITIVE_LEXICAL,
            ("TARGET_MATCH", "delete"): POWERSHELL_NEGATIVE_TARGET,
            ("TARGET_MATCH", "invert"): POWERSHELL_POSITIVE_TARGET,
        }[(mutation["guard"], mutation["operator"])]
        with tempfile.TemporaryDirectory() as directory:
            probe = pathlib.Path(directory) / "probe.ps1"
            probe.write_text(
                "$ErrorActionPreference = 'Stop'\n"
                f"Import-Module '{root / 'PrivateRoot.psm1'}' -Force\n"
                + textwrap.dedent(body),
                encoding="utf-8",
            )
            return subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(probe)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

    def test_manifest_mutants_are_all_independently_killed(self):
        ids = [mutation["id"] for mutation in MANIFEST]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            {
                (mutation["runtime"], mutation["guard"], mutation["operator"])
                for mutation in MANIFEST
            },
            {
                (runtime, guard, operator)
                for runtime in ("python", "powershell")
                for guard in ("LEXICAL_LOCAL", "TARGET_MATCH")
                for operator in ("delete", "invert")
            },
        )

        killed = []
        survived = []
        errors = []
        for mutation in MANIFEST:
            with self.subTest(mutation=mutation["id"]):
                source_path = POLICY_DIR / (
                    "validator.py"
                    if mutation["runtime"] == "python"
                    else "PrivateRoot.psm1"
                )
                source = source_path.read_text(encoding="utf-8")
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    if mutation["runtime"] == "python":
                        shutil.copyfile(POLICY_DIR / "policy_lib.py", root / "policy_lib.py")
                        mutated = mutate_source(source, mutation)
                        try:
                            ast.parse(mutated)
                        except SyntaxError as error:
                            errors.append(f"{mutation['id']}: {error}")
                            continue
                        (root / "validator.py").write_text(mutated, encoding="utf-8")
                        baseline = self.python_probe(POLICY_DIR, mutation)
                        result = self.python_probe(root, mutation)
                    else:
                        mutated = mutate_source(source, mutation)
                        (root / "PrivateRoot.psm1").write_text(mutated, encoding="utf-8")
                        parser = subprocess.run(
                            [
                                "pwsh",
                                "-NoProfile",
                                "-Command",
                                (
                                    "$e=$null;$t=$null;"
                                    "[Management.Automation.Language.Parser]::ParseFile("
                                    f"'{root / 'PrivateRoot.psm1'}',[ref]$t,[ref]$e)|Out-Null;"
                                    "if($e.Count){$e|% Message;exit 1}"
                                ),
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=False,
                        )
                        if parser.returncode:
                            errors.append(
                                f"{mutation['id']}: {parser.stdout}{parser.stderr}"
                            )
                            continue
                        baseline = self.powershell_probe(POLICY_DIR, mutation)
                        result = self.powershell_probe(root, mutation)

                    self.assertEqual(
                        baseline.returncode,
                        0,
                        f"baseline probe failed for {mutation['id']}:\n"
                        f"{baseline.stdout}\n{baseline.stderr}",
                    )
                    if result.returncode:
                        killed.append(mutation["id"])
                    else:
                        survived.append(mutation["id"])

        denominator = len(MANIFEST)
        print(
            "Git identity mutations: "
            f"{len(killed)}/{denominator} killed, "
            f"{len(survived)} survived, {len(errors)} errors; "
            "denominator=manifest entries"
        )
        self.assertEqual(errors, [])
        self.assertEqual(survived, [])
        self.assertEqual(len(killed), denominator)


if __name__ == "__main__":
    unittest.main()

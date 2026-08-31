#!/usr/bin/env python3
"""Automated fixture-based test suite for .ci/arm64-admission-guard.py.

Every test builds an isolated temporary repository tree (its own PKGBUILDs,
cone, rules, ledger, cone digest) and calls the guard against that tree
only -- no test ever reads, writes, or mutates a real/production PKGBUILD
anywhere in this repository. Run with:

    python .ci/tests/test_arm64_admission_guard.py -v
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD_PATH = Path(__file__).resolve().parent.parent / "arm64-admission-guard.py"
spec = importlib.util.spec_from_file_location("arm64_admission_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
sys.modules["arm64_admission_guard"] = guard
spec.loader.exec_module(guard)

RULES_TOML = GUARD_PATH.parent.joinpath("arm64-rules.toml").read_text(encoding="utf-8")
QUARANTINE_FULL = guard.QUARANTINE_COMMIT_FULL
LEDGER_HEADER = guard.LEDGER_HEADER


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_GITHUB_ACTIONS_ENV_KEYS = ("GITHUB_ACTIONS", "GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME")


def clean_subprocess_env(overrides: dict | None = None) -> dict:
    """Returns a copy of the current environment with the
    GITHUB_ACTIONS-family variables removed, so a guard CLI subprocess
    invoked by this test suite behaves as a genuine LOCAL run regardless
    of whether the suite itself happens to be executing inside a real
    GitHub Actions job (as it does in the shipped CI workflow) -- without
    this, every test that spawns its own throwaway git fixture and passes
    an unrelated --base-ref would spuriously collide with the REAL job's
    GITHUB_EVENT_PATH-derived base once derive_github_actions_base_ref()
    exists, since subprocess.run() inherits the parent environment by
    default. Pass `overrides` to instead deliberately SET a controlled
    GitHub-Actions-style environment for tests that exercise that path on
    purpose (see TestCLIBaseRefEndToEnd._invoke_as_github_actions).
    """
    env = dict(os.environ)
    if overrides is None:
        for key in _GITHUB_ACTIONS_ENV_KEYS:
            env.pop(key, None)
    else:
        env.update(overrides)
    return env


def pkgbuild_git_dual(pkgver="1.0.0") -> str:
    return (
        "pkgname=pkg-a\n"
        f"pkgver={pkgver}\n"
        "pkgrel=1\n"
        'source=("git://example.org/pkg-a.git#tag=v${pkgver}")\n'
        "sha256sums=('SKIP')\n"
    )


def pkgbuild_http(pkgver="2.0.0") -> str:
    return (
        "pkgname=pkg-b\n"
        f"pkgver={pkgver}\n"
        "pkgrel=1\n"
        'source=("http://example.org/pkg-b-${pkgver}.tar.gz")\n'
        "sha256sums=('SKIP')\n"
    )


def pkgbuild_clean() -> str:
    return (
        "pkgname=pkg-c\n"
        "pkgver=3.0.0\n"
        "pkgrel=1\n"
        'source=("https://example.org/pkg-c-${pkgver}.tar.gz")\n'
        "sha256sums=('SKIP')\n"
    )


def pkgbuild_toolchain_dev(pkgver="9.9.9dev") -> str:
    return (
        "pkgname=mingw-w64-cross-mingwarm64-toolchain\n"
        f"pkgver={pkgver}\n"
        "pkgrel=1\n"
        'source=("https://example.org/toolchain-${pkgver}.tar.gz")\n'
        "sha256sums=('SKIP')\n"
    )


_TEST_RULES = guard.load_rules(GUARD_PATH.parent / "arm64-rules.toml")


def ledger_row(path, field, rule_id, locator, matched=None, reason=None,
               introduced_by="0123abc", removal_gate="PR-1", expires="2999-01-01"):
    """Builds one ledger TSV row. `matched`/`reason` default to the
    AUTHORITATIVE canonical values re-derived the same way the guard itself
    validates them (see derive_canonical_matched / rules.toml `reason`) so
    ordinary fixtures don't need to hand-maintain text that must exactly
    track the rule registry; pass an explicit (wrong) value to deliberately
    test the forged-matched/forged-reason rejection paths.
    """
    rule_ids = tuple(rule_id.split(","))
    if matched is None:
        matched = guard.derive_canonical_matched(rule_ids, locator, _TEST_RULES)
        assert matched is not None, f"cannot auto-derive canonical matched for {rule_id!r}"
    if reason is None:
        reason_parts = [_TEST_RULES[r].reason for r in rule_ids]
        assert all(p is not None for p in reason_parts), f"cannot auto-derive canonical reason for {rule_id!r} (pass reason= explicitly for absolute-rule test rows)"
        reason = "; ".join(reason_parts)
    return "\t".join([
        path, field, rule_id, locator, guard.sha256_hex(locator), matched,
        reason, introduced_by, removal_gate, expires,
    ])


def make_ledger(*rows) -> str:
    return "\n".join([LEDGER_HEADER, *rows]) + "\n"


class FixtureRepo:
    """A throwaway repo tree under a TemporaryDirectory. Never touches the
    real MSYS2-packages checkout."""

    def __init__(self, tmp: Path):
        self.root = tmp
        (self.root / ".ci").mkdir(parents=True, exist_ok=True)
        self._cone_digest_enabled = True

    def add_pkg(self, directory: str, pkgbuild_text: str) -> None:
        write(self.root / directory / "PKGBUILD", pkgbuild_text)

    def set_cone(self, entries: list, pin_digest: bool = True) -> None:
        write(self.root / ".ci" / "arm64-cone.txt", "\n".join(entries) + "\n")
        if pin_digest:
            digest = sha256_of(self.root / ".ci" / "arm64-cone.txt")
            write(self.root / ".ci" / "arm64-cone.sha256", digest + "\n")
        self._cone_digest_enabled = pin_digest

    def set_cone_digest_raw(self, text: str) -> None:
        write(self.root / ".ci" / "arm64-cone.sha256", text)
        self._cone_digest_enabled = True

    def set_rules(self, text: str = RULES_TOML) -> None:
        write(self.root / ".ci" / "arm64-rules.toml", text)

    def set_ledger(self, text: str) -> None:
        write(self.root / ".ci" / "arm64-debt-ledger.tsv", text)

    def run(self, today="2026-01-01", base_ledger_text=None, base_reconciliation=None):
        from datetime import datetime
        base_ledger_path = None
        if base_ledger_text is not None:
            base_ledger_path = self.root / ".ci" / "arm64-debt-ledger.base.tsv"
            write(base_ledger_path, base_ledger_text)
        cone_digest_path = (self.root / ".ci" / "arm64-cone.sha256") if self._cone_digest_enabled else None
        return guard.run(
            cone_path=self.root / ".ci" / "arm64-cone.txt",
            rules_path=self.root / ".ci" / "arm64-rules.toml",
            ledger_path=self.root / ".ci" / "arm64-debt-ledger.tsv",
            today=datetime.strptime(today, "%Y-%m-%d").date(),
            repo_root=self.root,
            base_ledger_path=base_ledger_path,
            cone_digest_path=cone_digest_path,
            base_reconciliation=base_reconciliation,
        )

    def snapshot_reconciliation(self):
        """Computes `guard.reconcile_current_state` against whatever this
        fixture's on-disk content is RIGHT NOW, for use as a
        `base_reconciliation` snapshot in a LATER `run(...)` call -- this
        is the test-fixture equivalent of the real CLI's
        `resolve_base_reconciliation` (which materializes historical
        content via `git show <base_ref>:<path>`): both answer "was the
        rule's condition provably absent at the moment the ledger's row
        count reached zero for it", using whatever tree existed AT THAT
        MOMENT, not whatever the fixture is mutated to contain by the time
        `run()` is actually invoked. Call this immediately after writing
        the PKGBUILDs/cone that represent the "PR-1 just landed" state,
        before making any further mutations for a subsequent simulated PR.
        """
        cone = guard.load_cone(self.root / ".ci" / "arm64-cone.txt",
                                (self.root / ".ci" / "arm64-cone.sha256") if self._cone_digest_enabled else None)
        return guard.reconcile_current_state(cone, self.root)


class BaseFixtureTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.repo = FixtureRepo(Path(self._tmpdir.name))
        self.repo.set_rules()

    def baseline(self):
        """A small, realistic baseline: two source violations (one dual-rule,
        one single-rule), one toolchain dev-ver violation, one clean package,
        each with an exact matching ledger row (or none, for the clean one).
        """
        self.repo.add_pkg("pkg-a", pkgbuild_git_dual())
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.add_pkg("pkg-c", pkgbuild_clean())
        self.repo.add_pkg("mingw-w64-cross-mingwarm64-toolchain", pkgbuild_toolchain_dev())
        self.repo.set_cone(["mingw-w64-cross-mingwarm64-toolchain", "pkg-a", "pkg-b", "pkg-c"])
        rows = [
            ledger_row("mingw-w64-cross-mingwarm64-toolchain/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                       "9.9.9dev", "9.9.9dev", removal_gate="T0-corrected-toolchain"),
            ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF",
                       '"git://example.org/pkg-a.git#tag=v${pkgver}"', "#tag=,git://"),
            ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                       '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://"),
        ]
        self.repo.set_ledger(make_ledger(*rows))
        return rows


# ---------------------------------------------------------------------------
# 1. Baseline
# ---------------------------------------------------------------------------

class TestBaseline(BaseFixtureTest):
    def test_baseline_green(self):
        self.baseline()
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)
        self.assertEqual(problems, [])


# ---------------------------------------------------------------------------
# 2. New unlisted violation -> RED (V subset L violated)
# ---------------------------------------------------------------------------

class TestNewDebt(BaseFixtureTest):
    def test_new_git_violation_without_ledger_row_is_red(self):
        self.baseline()
        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("git://example.org/new-violation.git")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p for p in problems), problems)


class TestDeletedRowViolationRemains(BaseFixtureTest):
    def test_delete_row_violation_remains_is_red(self):
        rows = self.baseline()
        remaining = [r for r in rows if not r.startswith("pkg-b/")]
        self.repo.set_ledger(make_ledger(*remaining))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "pkg-b" in p for p in problems), problems)


class TestStaleRow(BaseFixtureTest):
    def test_fixed_violation_retained_row_is_red(self):
        self.baseline()
        self.repo.add_pkg("pkg-b", 'pkgname=pkg-b\npkgver=2.0.0\npkgrel=1\n'
                          'source=("https://example.org/pkg-b-${pkgver}.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("STALE_DEBT" in p and "pkg-b" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 5. Quarantine
# ---------------------------------------------------------------------------

class TestQuarantine(BaseFixtureTest):
    def test_full_quarantine_hash_is_red_absolute(self):
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          f'_commit="{QUARANTINE_FULL}"\n'
                          'source=("git+https://example.org/x.git#commit=${_commit}")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_abbreviated_quarantine_hash_is_red(self):
        self.baseline()
        abbrev = QUARANTINE_FULL[:12]
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          f'_commit="{abbrev}"\n'
                          'source=("git+https://example.org/x.git#commit=${_commit}")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_quarantine_cannot_be_ledgered(self):
        rows = self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          f'_commit="{QUARANTINE_FULL}"\n'
                          'source=("git+https://example.org/x.git#commit=${_commit}")\n'
                          "sha256sums=('SKIP')\n")
        bad_row = ledger_row("pkg-c/PKGBUILD", "source", "TOOLCHAIN_QUARANTINE",
                              f'"git+https://example.org/x.git#commit={QUARANTINE_FULL}"',
                              "quarantine", reason="attempted quarantine ledger entry (invalid)")
        self.repo.set_ledger(make_ledger(*rows, bad_row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID" in p and "absolute" in p for p in problems), problems)

    def test_quarantine_via_arbitrary_variable_name_not_just_commit(self):
        # Generalization proof: ANY scalar variable name, not a hardcoded
        # "_commit" special case.
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          f'_upstream_pin="{QUARANTINE_FULL}"\n'
                          'source=("git+https://example.org/x.git#commit=${_upstream_pin}")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 5th evasion form: hiding a marker/quarantine-hash behind an ordinary
# variable, not merely a raw quoting/dynamic-substitution trick. The guard
# never executes anything; it resolves ONLY statically-unambiguous
# single-assignment scalar variables and, for anything it cannot resolve,
# falls back to the same boundary-straddle reasoning already used for
# `$(...)`/backtick spans.
# ---------------------------------------------------------------------------

class TestVariableIndirectionBypass(BaseFixtureTest):
    def test_resolvable_git_proto_hidden_behind_variable_is_caught(self):
        # Exact adversarial example: _p=git; source=("${_p}://host/repo")
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          '_p=git\n'
                          'source=("${_p}://host/repo")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_GIT_PROTO" in p for p in problems), problems)

    def test_resolvable_insecure_http_hidden_behind_variable_is_caught(self):
        # Exact adversarial example: _h=http; source=("${_h}://host/file.tar.gz")
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          '_h=http\n'
                          'source=("${_h}://host/file.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_INSECURE_HTTP" in p for p in problems), problems)

    def test_resolvable_mutable_ref_fragment_hidden_behind_variable_is_caught(self):
        # Exact adversarial example:
        #   _frag='#tag=v1.0'; source=("git+https://host/repo${_frag}")
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          "_frag='#tag=v1.0'\n"
                          'source=("git+https://host/repo${_frag}")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_MUTABLE_REF" in p for p in problems), problems)

    def test_resolvable_quarantine_hash_hidden_behind_bare_variable_is_caught(self):
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          f'_h="{QUARANTINE_FULL}"\n'
                          'source=("${_h}")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_unresolvable_conditionally_assigned_variable_fails_closed(self):
        # _p is assigned on two different code paths (never resolvable
        # without evaluating control flow) and sits directly adjacent to
        # "://" -- must fail closed rather than silently pass the literal
        # "${_p}://host/repo" text through unmatched.
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          "if true; then\n_p=git\nelse\n_p=https\nfi\n"
                          'source=("${_p}://host/repo")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p or "NEW_DEBT" in p or "absolute" in p for p in problems), problems)

    def test_unresolvable_entirely_bare_variable_source_element_fails_closed(self):
        # The variable IS the entire source element with no static text
        # anywhere else -- its real value is completely unverifiable.
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          "if true; then\n_u=safe\nelse\n_u=other\nfi\n"
                          'source=("${_u}")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)

    def test_split_package_pkgname_array_source_url_is_not_a_false_positive(self):
        # Negative control: the real, common MSYS2 split-package idiom
        # (pkgbase= scalar, pkgname=(...) array) used constantly across the
        # actual 225-file cone. Bare `${pkgname}` here refers to the array's
        # first element via ordinary bash semantics; it must NOT be flagged
        # merely because this analyzer does not generically resolve arrays.
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgbase=pkg-c\npkgname=('pkg-c' 'pkg-c-devel')\npkgver=3.0.0\npkgrel=1\n"
                          'source=("https://example.org/${pkgname}/${pkgname}-${pkgver}.tar.bz2")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)

    def test_bare_makepkg_provided_variable_scalar_copy_is_not_a_false_positive(self):
        # Negative control: an ordinary, ubiquitous bare copy of a
        # makepkg-provided variable in a scalar assignment (never a
        # plausible carrier for the 40-character quarantine commit hash)
        # must not be flagged just because it is technically unresolved.
        self.baseline()
        self.repo.add_pkg("pkg-c", "pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n"
                          'DESTDIR="${pkgdir}"\n'
                          'source=("https://example.org/pkg-c-${pkgver}.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)


# ---------------------------------------------------------------------------
# B1: raw-vs-semantic word derivation -- quote-split / backslash / etc.
# ---------------------------------------------------------------------------

class TestSemanticWordDerivation(BaseFixtureTest):
    """Regression coverage for the audit-confirmed evasion class: bash
    concatenates adjacent quoted/unquoted fragments and processes escapes,
    so `matched`/quarantine checks against the RAW (still-quoted) text can
    be defeated by splitting a flagged substring across a boundary. These
    tests all assert against the derived SEMANTIC Word.value, exercised via
    the full guard pipeline (never a private helper), using one isolated
    fixture package per case via subTest.
    """

    def _one_pkg_finding(self, source_line: str, extra_lines: str = "", pkgname: str = "pkg-x"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(pkgname, f"pkgname={pkgname}\npkgver=1.0\npkgrel=1\n{extra_lines}{source_line}\nsha256sums=('SKIP')\n")
        repo.set_cone([pkgname])
        repo.set_ledger(make_ledger())
        return repo.run()

    def test_double_quote_split_git_and_tag(self):
        ok, problems = self._one_pkg_finding(
            'source=(\'git\'"://sourceware.org/git/x.git#ta"\'g=\'${pkgver})'
        )
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_GIT_PROTO" in p and "SRC_MUTABLE_REF" in p for p in problems), problems)

    def test_single_quote_split_http(self):
        ok, problems = self._one_pkg_finding("source=('ht'\"tp\"'://example.org/x.tar.gz')")
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_INSECURE_HTTP" in p for p in problems), problems)

    def test_mixed_quote_split_three_way(self):
        ok, problems = self._one_pkg_finding('source=(\'gi\'"t:"\'//\'"example.org/x")')
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_GIT_PROTO" in p for p in problems), problems)

    def test_empty_quote_filler_does_not_break_detection(self):
        ok, problems = self._one_pkg_finding("source=('git'''\"\"'://example.org/x')")
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_GIT_PROTO" in p for p in problems), problems)

    def test_unquoted_backslash_escape_split(self):
        # Each character individually backslash-escaped outside quotes.
        ok, problems = self._one_pkg_finding(r"source=(h\t\t\p://example.org/x.tar.gz)")
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_INSECURE_HTTP" in p for p in problems), problems)

    def test_backslash_line_continuation_inside_double_quotes(self):
        ok, problems = self._one_pkg_finding(
            'source=("git://example.org/x.git#ta\\\ng=v1")'
        )
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_GIT_PROTO" in p and "SRC_MUTABLE_REF" in p for p in problems), problems)

    def test_backslash_line_continuation_unquoted(self):
        ok, problems = self._one_pkg_finding(
            "source=(http://example.org/x-\\\n1.tar.gz)"
        )
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_INSECURE_HTTP" in p for p in problems), problems)

    def test_quoted_pkgver_dev_ver_double(self):
        ok, problems = self._one_pkg_finding(
            "source=(https://example.org/x.tar.gz)",
            pkgname="mingw-w64-cross-mingwarm64-gcc",
        )
        # replace pkgver line by re-running with quoted pkgver via extra_lines trick:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("mingw-w64-cross-mingwarm64-gcc",
                     'pkgname=mingw-w64-cross-mingwarm64-gcc\npkgver="15.0.0dev"\npkgrel=1\n'
                     'source=(https://example.org/x.tar.gz)\nsha256sums=(\'SKIP\')\n')
        repo.set_cone(["mingw-w64-cross-mingwarm64-gcc"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "TOOLCHAIN_DEV_VER" in p for p in problems), problems)

    def test_quoted_pkgver_dev_ver_single(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("mingw-w64-cross-mingwarm64-gcc",
                     "pkgname=mingw-w64-cross-mingwarm64-gcc\npkgver='15.0.0dev'\npkgrel=1\n"
                     "source=(https://example.org/x.tar.gz)\nsha256sums=('SKIP')\n")
        repo.set_cone(["mingw-w64-cross-mingwarm64-gcc"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "TOOLCHAIN_DEV_VER" in p for p in problems), problems)

    def test_exact_forbidden_hash_split_double_quote(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        half = len(QUARANTINE_FULL) // 2
        part1, part2 = QUARANTINE_FULL[:half], QUARANTINE_FULL[half:]
        repo.add_pkg("pkg-x", "pkgname=pkg-x\npkgver=1.0\npkgrel=1\n"
                     f'_commit="{part1}""{part2}"\n'
                     'source=("git+https://example.org/x.git#commit=${_commit}")\n'
                     "sha256sums=('SKIP')\n")
        repo.set_cone(["pkg-x"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_legitimate_https_with_command_substitution_still_safe(self):
        # The real bash/readline idiom -- must NOT be flagged.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("pkg-safe", "pkgname=pkg-safe\npkgver=1.0\npkgrel=1\n"
                     'source=(https://example.org/patches/x-$(printf "%03d" 1){,.sig})\n'
                     "sha256sums=('SKIP')\n")
        repo.set_cone(["pkg-safe"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertTrue(ok, problems)

    def test_dynamic_boundary_risk_git_proto_split_across_command_subst(self):
        # Adversarial: "git" immediately before the substitution, "://"
        # immediately after -- a marker straddling the gap.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("pkg-dyn", "pkgname=pkg-dyn\npkgver=1.0\npkgrel=1\n"
                     'source=(git$(echo)://example.org/x.tar.gz)\n'
                     "sha256sums=('SKIP')\n")
        repo.set_cone(["pkg-dyn"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("DYNAMIC_SOURCE" in p or "cannot be safely verified" in p for p in problems), problems)

    # -- N1: ANSI-C $'...' quoting is fail-closed rejected (verified: no
    # in-cone recipe uses this construct -- see the module docstring). --

    def test_ansi_c_quote_hex_escape_is_rejected_fail_closed(self):
        ok, problems = self._one_pkg_finding(r"source=($'\x68ttp://example.org/x')")
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "ANSI-C" in p for p in problems), problems)

    def test_ansi_c_quote_octal_escape_is_rejected_fail_closed(self):
        ok, problems = self._one_pkg_finding(r"source=($'\150ttp://example.org/x')")
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "ANSI-C" in p for p in problems), problems)

    def test_ansi_c_quote_in_scalar_assignment_is_rejected_fail_closed(self):
        ok, problems = self._one_pkg_finding(
            "source=(https://example.org/x.tar.gz)",
            extra_lines="_x=$'git\\x3a//example.org'\n",
        )
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "ANSI-C" in p for p in problems), problems)

    def test_ansi_c_quote_tag_marker_is_rejected_fail_closed(self):
        ok, problems = self._one_pkg_finding(r"source=($'z#tag\x3dv1')")
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "ANSI-C" in p for p in problems), problems)

    # -- N2: legacy backtick command substitution -- opaque, never
    # executed, real usage in scalar assignments (unquoted and inside
    # double quotes, in both source elements and scalar assignments). --

    def test_backtick_unquoted_in_source_is_opaque_and_safe(self):
        # Mirrors the real bash/readline $(...) idiom, but with backticks;
        # must not be flagged (no marker straddles the substitution).
        ok, problems = self._one_pkg_finding("source=(https://example.org/patch-`echo 1`.tar.gz)")
        self.assertTrue(ok, problems)

    def test_backtick_in_double_quotes_in_scalar_assignment_is_opaque(self):
        # Real ca-certificates-style idiom: a backtick command substitution
        # (containing a nested single-quoted sed script) as a scalar
        # variable's value.
        ok, problems = self._one_pkg_finding(
            "source=(https://example.org/x.tar.gz)",
            extra_lines="_x=`sed -n '/^# alias=/{s/^.*=//;p;q;}' f`\n",
        )
        self.assertTrue(ok, problems)

    def test_backtick_split_git_proto_across_boundary(self):
        ok, problems = self._one_pkg_finding("source=(git`echo x`://example.org/x.tar.gz)")
        self.assertFalse(ok)
        self.assertTrue(any("DYNAMIC_SOURCE" in p or "cannot be safely verified" in p for p in problems), problems)

    def test_backtick_split_quarantine_hash_below_7_char_threshold(self):
        # "9bbaa" alone is only 5 hex chars -- below QUARANTINE_MIN_ABBREV --
        # but the deliberate backtick-split must still be caught.
        ok, problems = self._one_pkg_finding(
            "source=(https://example.org/x.tar.gz)",
            extra_lines="_c=9bbaa`echo x`7b7a36ae51328cbff6acb720dcfa472db37\n",
        )
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_backtick_split_quarantine_hash_in_source(self):
        ok, problems = self._one_pkg_finding("source=(htt`echo p`://9bbaa7b7a36ae51328cbff6acb720dcfa472db37)")
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_unterminated_backtick_is_parse_fail(self):
        ok, problems = self._one_pkg_finding("source=(https://example.org/x-`echo 1.tar.gz)")
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p for p in problems), problems)

    def test_malformed_nested_backtick_is_handled(self):
        # A quoted string inside the backtick containing something
        # backtick-like must not confuse the terminator search.
        ok, problems = self._one_pkg_finding(
            "source=(https://example.org/x.tar.gz)",
            extra_lines='_x=`echo "no backtick here" | sed \'s/a/b/\'`\n',
        )
        self.assertTrue(ok, problems)

    # -- N3: $(...) / backtick nested inside double quotes was previously
    # invisible to the dynamic-boundary-risk and quarantine-split checks. --

    def test_quoted_command_subst_split_http_across_boundary(self):
        ok, problems = self._one_pkg_finding('source=("htt$(echo t)p://example.org/x.tar.gz")')
        self.assertFalse(ok)
        self.assertTrue(any("DYNAMIC_SOURCE" in p or "cannot be safely verified" in p for p in problems), problems)

    def test_quoted_command_subst_split_git_proto_across_boundary(self):
        ok, problems = self._one_pkg_finding('source=("git$(echo :)//example.org/x.tar.gz")')
        self.assertFalse(ok)
        self.assertTrue(any("DYNAMIC_SOURCE" in p or "cannot be safely verified" in p for p in problems), problems)

    def test_quoted_command_subst_split_tag_marker_across_boundary(self):
        ok, problems = self._one_pkg_finding('source=("git://example.org/x.git#ta$(echo g)=v1")')
        self.assertFalse(ok)
        self.assertTrue(any("DYNAMIC_SOURCE" in p or "cannot be safely verified" in p for p in problems), problems)

    def test_quoted_command_subst_split_quarantine_hash(self):
        ok, problems = self._one_pkg_finding(
            "source=(https://example.org/x.tar.gz)",
            extra_lines='_c="9bbaa7b7a$(echo)36ae51328cbff6acb720dcfa472db37"\n',
        )
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_real_bash_readline_quoted_command_subst_idiom_still_accepted(self):
        # The ACTUAL idiom used by bash/readline in this repository (quoted
        # form) must remain accepted -- no marker straddles the boundary.
        ok, problems = self._one_pkg_finding(
            'source=("https://ftp.gnu.org/gnu/bash/bash-5.2-patches/bash52-$(printf "%03d" 1){,.sig}")'
        )
        self.assertTrue(ok, problems)

    # -- Negative controls: precise bash semantics must NOT over-trigger. --

    def test_backslash_t_inside_double_quotes_is_not_a_tab_and_not_flagged(self):
        # Inside double quotes, backslash retains NO special meaning before
        # 't' -- \t stays two literal characters (backslash, t), so "http"
        # never becomes contiguous. This must NOT be flagged.
        ok, problems = self._one_pkg_finding(r'source=("ht\tp://example.org/x.tar.gz")')
        self.assertTrue(ok, problems)

    def test_single_quotes_do_not_line_continue(self):
        # Single quotes perform NO escape processing at all -- a literal
        # backslash-newline sequence inside single quotes is NOT a
        # continuation; it is two ordinary literal characters (and single
        # quotes may contain a literal embedded newline). This must parse
        # without error and must not be treated as a continuation.
        ok, problems = self._one_pkg_finding(
            "source=('http://example.org/x\\\n.tar.gz')"
        )
        self.assertFalse(ok)  # http:// is still a real, correctly-detected violation
        self.assertTrue(any("NEW_DEBT" in p and "SRC_INSECURE_HTTP" in p for p in problems), problems)

    # -- matched/reason are authoritative, proof-bearing columns. --

    def test_forged_matched_is_rejected(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("pkg-b", pkgbuild_http())
        repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', matched="totally-forged-value")
        repo.set_ledger(make_ledger(row))
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("matched" in p and "authoritative" in p for p in problems), problems)

    def test_forged_reason_is_rejected(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("pkg-b", pkgbuild_http())
        repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', reason="totally forged justification")
        repo.set_ledger(make_ledger(row))
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("reason" in p and "authoritative" in p for p in problems), problems)

    def test_toolchain_dev_ver_matched_must_equal_locator_value(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("mingw-w64-cross-mingwarm64-gcc", pkgbuild_toolchain_dev(pkgver="9.9.9dev"))
        repo.set_cone(["mingw-w64-cross-mingwarm64-gcc"])
        row = ledger_row("mingw-w64-cross-mingwarm64-gcc/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                          "9.9.9dev", matched="8.8.8dev", removal_gate="T0-corrected-toolchain")
        repo.set_ledger(make_ledger(row))
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("matched" in p and "authoritative" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# Audit round 4: VCS-transport-vs-VCS-type split, full fragment-key
# vocabulary (per-VCS-type, not hardcoded to git's commit/tag/branch),
# pkgver() override, source/. include directive, and the delimiter-hiding
# fix for the structural (resolve-first-classify-second) SRC_* matcher.
# ---------------------------------------------------------------------------

class TestVcsTransportVsType(BaseFixtureTest):
    def _one_pkg_finding(self, source_line: str, pkgname: str = "pkg-x"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(pkgname, f"pkgname={pkgname}\npkgver=1.0\npkgrel=1\n{source_line}\nsha256sums=('SKIP')\n")
        repo.set_cone([pkgname])
        repo.set_ledger(make_ledger())
        return repo.run()

    def test_git_plus_https_is_secure_transport_not_flagged(self):
        # download_git() does `url=${url#git+}` and hands the REMAINDER
        # (here "https://...") straight to `git clone` -- this is a
        # secure HTTPS fetch, not the insecure native git:// protocol,
        # even though makepkg's own get_protocol() reports VCS type "git"
        # for dispatch purposes. Regression for a real defect this
        # analyzer had mid-development (flagging every real
        # mingw-w64-cross-*/PKGBUILD "git+https://" source as SRC_GIT_PROTO).
        ok, problems = self._one_pkg_finding('source=("git+https://example.org/x.git#commit=abc123")')
        self.assertTrue(ok, problems)

    def test_git_plus_git_is_insecure_transport_flagged(self):
        # "git+git://" explicitly REQUESTS the native insecure git://
        # transport via the "+transport" suffix (unlike "git+https").
        ok, problems = self._one_pkg_finding('source=("git+git://example.org/x.git#commit=abc123")')
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_GIT_PROTO" in p for p in problems), problems)

    def test_git_plus_http_is_insecure_transport_flagged(self):
        ok, problems = self._one_pkg_finding('source=("git+http://example.org/x.git#commit=abc123")')
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_INSECURE_HTTP" in p for p in problems), problems)


class TestFragmentKeyVocabulary(BaseFixtureTest):
    def _one_pkg_finding(self, source_line: str, pkgname: str = "pkg-x"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(pkgname, f"pkgname={pkgname}\npkgver=1.0\npkgrel=1\n{source_line}\nsha256sums=('SKIP')\n")
        repo.set_cone([pkgname])
        repo.set_ledger(make_ledger())
        return repo.run()

    def test_branch_fragment_is_mutable_ref(self):
        # The vocabulary gap the audit's ninth finding identified:
        # extract_git() honours branch|tag|commit, but the original
        # implementation matched only literal "#tag=". A branch is the
        # MORE mutable of the two (moves on every upstream push, with no
        # forged-ref check unlike tags) and was previously a total,
        # undetected bypass: `source=("git+https://h/r#branch=main")`.
        ok, problems = self._one_pkg_finding('source=("git+https://h/r#branch=main")')
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "SRC_MUTABLE_REF" in p for p in problems), problems)

    def test_commit_fragment_is_immutable_no_finding(self):
        ok, problems = self._one_pkg_finding('source=("git+https://h/r#commit=abc123")')
        self.assertTrue(ok, problems)

    def test_unrecognized_git_fragment_key_fails_closed(self):
        # makepkg's extract_git() itself aborts the build on any key
        # outside commit/tag/branch ("Unrecognized reference"), so this
        # can neither be treated as compliant nor silently ignored.
        ok, problems = self._one_pkg_finding('source=("git://example.org/x.git#foo=bar")')
        self.assertFalse(ok)
        self.assertTrue(any("not one makepkg" in p or "PARSE_FAIL" in p or "TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_svn_revision_key_is_immutable_no_finding(self):
        # svn's extract_svn() only ever recognizes "revision", and it is
        # immutable (an exact numbered revision), unlike git's tag/branch.
        ok, problems = self._one_pkg_finding('source=("svn+https://example.org/repo/trunk#revision=42")')
        self.assertTrue(ok, problems)

    def test_svn_unrecognized_key_fails_closed(self):
        ok, problems = self._one_pkg_finding('source=("svn+https://example.org/repo/trunk#branch=main")')
        self.assertFalse(ok)
        self.assertTrue(any("not one makepkg" in p or "TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_unrecognized_vcs_type_with_fragment_fails_closed(self):
        # An unrecognized VCS type (not git/fossil/hg/svn/bzr) combined
        # with a fragment cannot be assumed either compliant or inert --
        # unlike http/https/ftp, where a fragment (if any) is an ordinary,
        # makepkg-uninterpreted URI fragment.
        ok, problems = self._one_pkg_finding('source=("cvs+https://example.org/repo#branch=main")')
        self.assertFalse(ok)
        self.assertTrue(any("not one this analyzer recognizes" in p or "TOOLCHAIN_QUARANTINE" in p for p in problems), problems)

    def test_https_fragment_is_inert_no_vcs_semantics(self):
        # A plain https:// download's "#fragment" (if any) has no
        # makepkg-interpreted VCS-ref semantics at all -- must not be
        # flagged as an unrecognized VCS type/key.
        ok, problems = self._one_pkg_finding('source=("https://example.org/x.tar.gz#readme")')
        self.assertTrue(ok, problems)


class TestPkgverFunctionOverride(BaseFixtureTest):
    def test_pkgver_function_in_toolchain_recipe_fails_closed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(
            "mingw-w64-cross-mingwarm64-toolchain",
            "pkgname=mingw-w64-cross-mingwarm64-toolchain\n"
            "pkgver=1.0.0\n"
            "pkgrel=1\n"
            'source=("https://example.org/toolchain-${pkgver}.tar.gz")\n'
            "sha256sums=('SKIP')\n"
            "pkgver() {\n"
            "  cd \"${srcdir}\"\n"
            '  git describe --long | sed "s/-/./g"\n'
            "}\n",
        )
        repo.set_cone(["mingw-w64-cross-mingwarm64-toolchain"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "pkgver()" in p for p in problems), problems)

    def test_pkgver_function_in_non_toolchain_recipe_is_not_flagged(self):
        # TOOLCHAIN_DEV_VER only ever inspects mingwarm64 toolchain
        # recipes, so a pkgver() function elsewhere (a common, legitimate
        # VCS-derived-version idiom, e.g. mingw-w64-cross-crt/PKGBUILD)
        # is out of scope for this specific check.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(
            "pkg-c",
            "pkgname=pkg-c\n"
            "pkgver=1.0.0\n"
            "pkgrel=1\n"
            'source=("https://example.org/pkg-c-${pkgver}.tar.gz")\n'
            "sha256sums=('SKIP')\n"
            "pkgver() {\n"
            '  git describe --long | sed "s/-/./g"\n'
            "}\n",
        )
        repo.set_cone(["pkg-c"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertTrue(ok, problems)


class TestSourceIncludeDirective(BaseFixtureTest):
    def test_source_command_with_space_fails_closed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(
            "pkg-x",
            "pkgname=pkg-x\npkgver=1.0\npkgrel=1\n"
            "source ./helpers.sh\n"
            'source=("https://example.org/x.tar.gz")\n'
            "sha256sums=('SKIP')\n",
        )
        repo.set_cone(["pkg-x"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "file-inclusion" in p for p in problems), problems)

    def test_dot_command_fails_closed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(
            "pkg-x",
            "pkgname=pkg-x\npkgver=1.0\npkgrel=1\n"
            ". ./helpers.sh\n"
            'source=("https://example.org/x.tar.gz")\n'
            "sha256sums=('SKIP')\n",
        )
        repo.set_cone(["pkg-x"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p and "file-inclusion" in p for p in problems), problems)

    def test_source_array_assignment_is_not_a_false_positive(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(
            "pkg-x",
            "pkgname=pkg-x\npkgver=1.0\npkgrel=1\n"
            'source=("https://example.org/x.tar.gz")\n'
            "sha256sums=('SKIP')\n",
        )
        repo.set_cone(["pkg-x"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertTrue(ok, problems)

    def test_word_source_as_list_element_on_continuation_line_is_not_a_false_positive(self):
        # Regression for a real false positive found against the actual
        # repo baseline: bash/PKGBUILD's `for f in bg bind ... source
        # suspend ... ; do` builtin-name enumeration, continued across
        # physical lines via trailing backslashes, where "source" is a
        # bash KEYWORD NAME being listed, not a command being invoked.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(
            "pkg-x",
            "pkgname=pkg-x\npkgver=1.0\npkgrel=1\n"
            'source=("https://example.org/x.tar.gz")\n'
            "sha256sums=('SKIP')\n"
            "package() {\n"
            "  for f in bg bind break builtin \\\n"
            "    source suspend then time \\\n"
            "    unset until wait; do\n"
            "    echo $f\n"
            "  done\n"
            "}\n",
        )
        repo.set_cone(["pkg-x"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertTrue(ok, problems)


class TestDelimiterHidingAcrossDynamicSpan(BaseFixtureTest):
    def _one_pkg_finding(self, source_line: str, pkgname: str = "pkg-x"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg(pkgname, f"pkgname={pkgname}\npkgver=1.0\npkgrel=1\n{source_line}\nsha256sums=('SKIP')\n")
        repo.set_cone([pkgname])
        repo.set_ledger(make_ledger())
        return repo.run()

    def test_scheme_colon_slash_slash_split_across_command_subst_fails_closed(self):
        # A LITERAL text search for "://" (what the structural
        # resolve-first-classify-second matcher uses to locate the
        # decisive VCS-type/transport/fragment-key positions) would
        # simply MISS this: "git$(echo :)//example.org/x.tar.gz" never
        # contains "://" as literal text at all (the ":" is produced by
        # the substitution), so a naive `.find("://")` would incorrectly
        # conclude there is no scheme here rather than failing closed.
        ok, problems = self._one_pkg_finding('source=("git$(echo :)//example.org/x.tar.gz")')
        self.assertFalse(ok)
        self.assertTrue(any("TOOLCHAIN_QUARANTINE" in p and "could hide" in p for p in problems), problems)

    def test_ordinary_unresolved_expansion_before_path_separator_is_not_a_false_positive(self):
        # The false-positive flood this fix had to avoid: an unresolved
        # `${pkgver%.*}`-style expansion sits immediately before a bare
        # "/" constantly in ordinary compliant source URLs, and that
        # single-character overlap with "://"'s own trailing "/" must not
        # be treated as "the delimiter could be hidden here".
        ok, problems = self._one_pkg_finding(
            'source=("https://example.org/sources/${pkgver%.*}/pkg-x-${pkgver}.tar.gz")'
        )
        self.assertTrue(ok, problems)


# ---------------------------------------------------------------------------
# 6/9. Wildcard/regex/bypass metacharacters vs legitimate ${...} braces
# ---------------------------------------------------------------------------

class TestBypassCharacters(BaseFixtureTest):
    def test_each_forbidden_metachar_is_independently_rejected(self):
        for ch in ["*", "?", "[", "]", "(", ")", "|", "\\"]:
            with self.subTest(char=ch):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                repo = FixtureRepo(Path(tmp.name))
                repo.set_rules()
                locator_text = '"http://example.org/a' + ch + 'b.tar.gz"'
                repo.add_pkg("pkg-x", "pkgname=pkg-x\npkgver=1.0.0\npkgrel=1\n"
                             "source=(" + locator_text + ")\n"
                             "sha256sums=('SKIP')\n")
                repo.set_cone(["pkg-x"])
                bad_row = ledger_row("pkg-x/PKGBUILD", "source", "SRC_INSECURE_HTTP", locator_text, "http://")
                repo.set_ledger(make_ledger(bad_row))
                ok, problems = repo.run()
                self.assertFalse(ok, f"metachar {ch!r} should have been rejected")
                self.assertTrue(any("metacharacter" in p for p in problems), problems)

    def test_literal_dollar_brace_var_in_locator_is_accepted(self):
        self.baseline()
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)
        ledger_text = (self.repo.root / ".ci" / "arm64-debt-ledger.tsv").read_text(encoding="utf-8")
        self.assertIn("${pkgver}", ledger_text)

    def test_brace_in_cone_entry_is_rejected(self):
        self.baseline()
        self.repo.set_cone(["mingw-w64-cross-mingwarm64-toolchain", "pkg-{a}", "pkg-b", "pkg-c"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p and "metacharacter" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 7. Tamper: locator text changed so stored hash no longer binds
# ---------------------------------------------------------------------------

class TestTamperedBinding(BaseFixtureTest):
    def test_tampered_locator_hash_mismatch_is_red(self):
        rows = self.baseline()
        tampered = rows[:]
        tampered[2] = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                                  '"http://example.org/pkg-b-${pkgver}-TAMPERED.tar.gz"', "http://")
        self.repo.set_ledger(make_ledger(*tampered))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p or "STALE_DEBT" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 8. Expiry
# ---------------------------------------------------------------------------

class TestExpiry(BaseFixtureTest):
    def test_past_expiry_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          expires="2000-01-01")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run(today="2026-01-01")
        self.assertFalse(ok)
        self.assertTrue(any("EXPIRED" in p for p in problems), problems)

    def test_not_yet_expired_is_fine(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          expires="2999-01-01")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run(today="2026-01-01")
        self.assertTrue(ok, problems)


# ---------------------------------------------------------------------------
# 9. Malformed / unparseable in-cone PKGBUILD
# ---------------------------------------------------------------------------

class TestParseFail(BaseFixtureTest):
    def test_unterminated_quote_is_red_parse_fail(self):
        self.repo.add_pkg("pkg-broken", 'pkgname=pkg-broken\npkgver=1.0\npkgrel=1\n'
                          'source=("http://example.org/unterminated\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-broken"])
        self.repo.set_ledger(make_ledger())
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p for p in problems), problems)

    def test_unsupported_unquoted_paren_is_red_parse_fail(self):
        self.repo.add_pkg("pkg-broken", 'pkgname=pkg-broken\npkgver=1.0\npkgrel=1\n'
                          'source=(foo(bar))\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-broken"])
        self.repo.set_ledger(make_ledger())
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p for p in problems), problems)

    def test_dangling_backslash_is_red_parse_fail(self):
        self.repo.add_pkg("pkg-broken", 'pkgname=pkg-broken\npkgver=1.0\npkgrel=1\n'
                          "source=(http://example.org/x\\")
        self.repo.set_cone(["pkg-broken"])
        self.repo.set_ledger(make_ledger())
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("PARSE_FAIL" in p for p in problems), problems)

    def test_opaque_command_substitution_is_supported_and_never_executed(self):
        fd, marker_path = tempfile.mkstemp()
        os.close(fd)
        marker = Path(marker_path)
        marker.unlink()
        marker_posix = marker.as_posix()
        self.repo.add_pkg("pkg-cmdsub", 'pkgname=pkg-cmdsub\npkgver=1.0\npkgrel=1\n'
                          'source=(https://example.org/x-$(touch ' + marker_posix + ' && echo z).tar.gz)\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-cmdsub"])
        self.repo.set_ledger(make_ledger())
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)
        self.assertFalse(marker.exists(), "guard must never execute $(...) command substitutions")


# ---------------------------------------------------------------------------
# 10. Noncanonical / unsorted / duplicate ledger, cone, rules
# ---------------------------------------------------------------------------

class TestCanonicalForm(BaseFixtureTest):
    def test_unsorted_ledger_is_red(self):
        self.repo.add_pkg("pkg-a", pkgbuild_git_dual())
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-a", "pkg-b"])
        row_a = ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF",
                            '"git://example.org/pkg-a.git#tag=v${pkgver}"', "#tag=,git://")
        row_b = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                            '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
        self.repo.set_ledger(make_ledger(row_b, row_a))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("sorted" in p for p in problems), problems)

    def test_duplicate_ledger_key_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
        self.repo.set_ledger(make_ledger(row, row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("duplicate" in p for p in problems), problems)

    def test_unsorted_cone_is_red(self):
        self.baseline()
        self.repo.set_cone(["pkg-c", "pkg-a", "pkg-b", "mingw-w64-cross-mingwarm64-toolchain"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("canonical sorted order" in p for p in problems), problems)

    def test_duplicate_cone_entry_is_red(self):
        self.baseline()
        self.repo.set_cone(["mingw-w64-cross-mingwarm64-toolchain", "pkg-a", "pkg-a", "pkg-b", "pkg-c"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("duplicate entry" in p for p in problems), problems)

    def test_malformed_rules_toml_is_red(self):
        self.baseline()
        self.repo.set_rules("this is not [ valid toml")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(rules)" in p for p in problems), problems)

    def test_new_ratchetable_rule_without_reconciler_is_red(self):
        # A ratchetable rule that names no entry in
        # RATCHETABLE_RULE_RECONCILERS would be structurally EXEMPT from
        # removal-authorization/promotion-totality checking -- as
        # dangerous, by construction, as the original CONTROLLING DEFECT.
        # Adding one must fail closed at rules-load time, not silently
        # admit an ungoverned ratchetable rule.
        self.baseline()
        bad_rules = RULES_TOML + (
            "\n[rule.SRC_FTP_INSECURE]\n"
            'severity = "ratchetable"\n'
            "promote_when_clear = true\n"
            'description = "hypothetical new rule with no reconciler"\n'
            'matched_marker = "ftp://"\n'
            'reason = "insecure ftp:// transport"\n'
        )
        self.repo.set_rules(bad_rules)
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any(
            "SCHEMA_INVALID(rules)" in p and "SRC_FTP_INSECURE" in p and "reconciler" in p for p in problems
        ), problems)


# ---------------------------------------------------------------------------
# B3: cone digest binding (monotonic 225-entry declared BUILD closure)
# ---------------------------------------------------------------------------

class TestConeDigestBinding(BaseFixtureTest):
    def test_tampered_cone_without_updated_digest_is_red(self):
        self.baseline()
        # Directly rewrite cone.txt WITHOUT updating the pinned digest --
        # simulates removing (or substituting) an entry to hide it from
        # scanning without an accompanying reviewed digest update.
        write(self.repo.root / ".ci" / "arm64-cone.txt", "mingw-w64-cross-mingwarm64-toolchain\npkg-a\npkg-c\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p and "digest" in p for p in problems), problems)

    def test_same_size_substitution_without_updated_digest_is_red(self):
        self.baseline()
        self.repo.add_pkg("pkg-d", pkgbuild_clean())
        # Swap pkg-b for pkg-d (same array length) without updating digest.
        write(self.repo.root / ".ci" / "arm64-cone.txt", "mingw-w64-cross-mingwarm64-toolchain\npkg-a\npkg-c\npkg-d\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p and "digest" in p for p in problems), problems)

    def test_reviewed_cone_change_with_updated_digest_is_structurally_accepted(self):
        self.baseline()
        # A legitimate reviewed change: remove pkg-b from the cone AND its
        # ledger row (both in the same change), correctly re-pinning the
        # digest -- must NOT trigger SCHEMA_INVALID(cone) (may still need
        # the ledger row removed to satisfy L subset V, which we also do).
        self.repo.set_cone(["mingw-w64-cross-mingwarm64-toolchain", "pkg-a", "pkg-c"])
        remaining = [
            ledger_row("mingw-w64-cross-mingwarm64-toolchain/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                       "9.9.9dev", "9.9.9dev", removal_gate="T0-corrected-toolchain"),
            ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF",
                       '"git://example.org/pkg-a.git#tag=v${pkgver}"', "#tag=,git://"),
        ]
        self.repo.set_ledger(make_ledger(*remaining))
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)
        self.assertFalse(any("digest" in p for p in problems), problems)

    def test_unledgered_package_cannot_be_hidden_by_cone_removal(self):
        # pkg-b has a REAL, unledgered violation. Removing it from the cone
        # (to "hide" it from scanning) without updating the digest fails
        # closed on the digest mismatch alone -- proving the evasion does
        # not work even before considering V==L.
        self.repo.add_pkg("pkg-a", pkgbuild_git_dual())
        self.repo.add_pkg("pkg-b", pkgbuild_http())  # unledgered violation
        self.repo.set_cone(["pkg-a", "pkg-b"])
        self.repo.set_ledger(make_ledger(
            ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF",
                       '"git://example.org/pkg-a.git#tag=v${pkgver}"', "#tag=,git://")
        ))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "pkg-b" in p for p in problems), problems)
        # Now attempt the evasion: remove pkg-b from cone.txt without
        # touching the pinned digest.
        write(self.repo.root / ".ci" / "arm64-cone.txt", "pkg-a\n")
        ok2, problems2 = self.repo.run()
        self.assertFalse(ok2)
        self.assertTrue(any("digest" in p for p in problems2), problems2)

    def test_malformed_digest_file_is_red(self):
        self.baseline()
        self.repo.set_cone_digest_raw("not-a-valid-hex-digest\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 11. PR-1 simulation: clear all source debt -> GREEN, then rule promotion
# ---------------------------------------------------------------------------

class TestPromotion(BaseFixtureTest):
    def test_pr1_simulation_then_promoted_rule_blocks_new_debt(self):
        pre_pr1_ledger_text = make_ledger(*self.baseline())

        self.repo.add_pkg("pkg-a", 'pkgname=pkg-a\npkgver=1.0.0\npkgrel=1\n'
                          'source=("git+https://example.org/pkg-a.git#commit=deadbeef")\n'
                          "sha256sums=('SKIP')\n")
        self.repo.add_pkg("pkg-b", 'pkgname=pkg-b\npkgver=2.0.0\npkgrel=1\n'
                          'source=("https://example.org/pkg-b-${pkgver}.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        remaining = [ledger_row("mingw-w64-cross-mingwarm64-toolchain/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                                 "9.9.9dev", "9.9.9dev", removal_gate="T0-corrected-toolchain")]
        post_pr1_ledger_text = make_ledger(*remaining)
        self.repo.set_ledger(post_pr1_ledger_text)
        ok, problems = self.repo.run(base_ledger_text=pre_pr1_ledger_text)
        self.assertTrue(ok, problems)

        # Snapshot the independent reconciliation state of the tree AS IT
        # EXISTS RIGHT NOW -- i.e. the moment PR-1 lands and SRC_GIT_PROTO/
        # SRC_INSECURE_HTTP/SRC_MUTABLE_REF's ledger counts all reach zero.
        # This is what the SECOND run below must use to decide whether
        # that historical zero-count was legitimately total (see `run`'s
        # promotion-totality gate) -- using the CURRENT (post-pkg-c) tree
        # instead would defeat the very promotion this test exists to
        # prove, since the reintroduced pkg-c violation would make
        # totality look false FOREVER rather than being caught as an
        # immediate hard failure the way a genuinely promoted rule must.
        post_pr1_reconciliation = self.repo.snapshot_reconciliation()

        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("http://example.org/new-insecure.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        with_new_row = remaining + [ledger_row("pkg-c/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                                                '"http://example.org/new-insecure.tar.gz"', "http://")]
        self.repo.set_ledger(make_ledger(*with_new_row))
        ok, problems = self.repo.run(base_ledger_text=post_pr1_ledger_text, base_reconciliation=post_pr1_reconciliation)
        self.assertFalse(ok)
        self.assertTrue(any("promoted" in p for p in problems), problems)

    def test_pr1_simulation_promotion_withheld_without_reconciliation_evidence(self):
        # Negative control for the totality gate itself: the SAME
        # zero-row transition as above, but WITHOUT a base_reconciliation
        # snapshot (e.g. an ad hoc local run with no base-tree access at
        # all). Promotion must be WITHHELD, not assumed -- so a new,
        # correctly-ledgered SRC_INSECURE_HTTP row is legal (no "promoted"
        # problem), even though the base ledger already shows zero rows
        # for that rule. This is the deliberate, safe default: absence of
        # totality proof never grants promotion.
        pre_pr1_ledger_text = make_ledger(*self.baseline())
        self.repo.add_pkg("pkg-a", 'pkgname=pkg-a\npkgver=1.0.0\npkgrel=1\n'
                          'source=("git+https://example.org/pkg-a.git#commit=deadbeef")\n'
                          "sha256sums=('SKIP')\n")
        self.repo.add_pkg("pkg-b", 'pkgname=pkg-b\npkgver=2.0.0\npkgrel=1\n'
                          'source=("https://example.org/pkg-b-${pkgver}.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        remaining = [ledger_row("mingw-w64-cross-mingwarm64-toolchain/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                                 "9.9.9dev", "9.9.9dev", removal_gate="T0-corrected-toolchain")]
        self.repo.set_ledger(make_ledger(*remaining))

        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("http://example.org/new-insecure.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        with_new_row = remaining + [ledger_row("pkg-c/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                                                '"http://example.org/new-insecure.tar.gz"', "http://")]
        self.repo.set_ledger(make_ledger(*with_new_row))
        ok, problems = self.repo.run(base_ledger_text=pre_pr1_ledger_text, base_reconciliation=None)
        self.assertTrue(ok, problems)

    def test_post_promotion_reintroduction_still_fails(self):
        # "Post-promotion reintroduction must still fail": once a rule is
        # legitimately promoted (zero rows + proven totality at the base
        # commit), a run whose CURRENT tree reintroduces the condition
        # via an EXISTING (not brand-new) path must fail -- via ordinary
        # NEW_DEBT if unledgered, since the reintroduction cannot ever be
        # authorized as tracked debt again.
        self.repo.add_pkg("pkg-a", 'pkgname=pkg-a\npkgver=1.0.0\npkgrel=1\n'
                          'source=("https://example.org/pkg-a.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-a"])
        self.repo.set_ledger(make_ledger())
        base_reconciliation = self.repo.snapshot_reconciliation()

        # Reintroduce the exact insecure condition on the SAME path.
        self.repo.add_pkg("pkg-a", 'pkgname=pkg-a\npkgver=1.0.0\npkgrel=1\n'
                          'source=("http://example.org/pkg-a.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run(base_ledger_text=make_ledger(), base_reconciliation=base_reconciliation)
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p for p in problems), problems)

    def test_no_base_ledger_means_nothing_promoted_yet(self):
        self.baseline()
        ok, problems = self.repo.run(base_ledger_text=None)
        self.assertTrue(ok, problems)


# ---------------------------------------------------------------------------
# 12. Cone scoping: out-of-cone violations ignored; escapes rejected
# ---------------------------------------------------------------------------

class TestConeScoping(BaseFixtureTest):
    def test_out_of_cone_violation_is_ignored(self):
        self.baseline()
        self.repo.add_pkg("pkg-outside", pkgbuild_git_dual())
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)

    def test_cone_entry_with_parent_traversal_is_rejected(self):
        self.baseline()
        self.repo.set_cone(["../outside", "pkg-a", "pkg-b", "pkg-c"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p for p in problems), problems)

    def test_cone_entry_with_absolute_path_is_rejected(self):
        self.baseline()
        self.repo.set_cone(["/etc/passwd", "pkg-a", "pkg-b", "pkg-c"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p for p in problems), problems)

    def test_cone_entry_missing_pkgbuild_is_rejected(self):
        self.baseline()
        self.repo.set_cone(["does-not-exist", "pkg-a", "pkg-b", "pkg-c"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID(cone)" in p for p in problems), problems)

    def test_cone_symlink_traversal_is_rejected(self):
        self.baseline()
        target = self.repo.root / "pkg-a"
        link = self.repo.root / "pkg-a-link"
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted in this environment")
        self.repo.set_cone(["mingw-w64-cross-mingwarm64-toolchain", "pkg-a", "pkg-a-link", "pkg-b", "pkg-c"])
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("symlink" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# Ledger schema edge cases: unknown rule/field, invalid sha/date,
# removal_gate, extra column
# ---------------------------------------------------------------------------

class TestLedgerSchema(BaseFixtureTest):
    def test_unknown_rule_id_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_NOT_A_REAL_RULE",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          reason="fake rule for testing")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("unknown rule_id" in p for p in problems), problems)

    def test_unknown_field_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "not_a_field", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("unknown field" in p for p in problems), problems)

    def test_invalid_sha_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        locator = '"http://example.org/pkg-b-${pkgver}.tar.gz"'
        row = "\t".join([
            "pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP", locator,
            "not-a-valid-sha256", "http://",
            "source fetched over plaintext http://", "0123abc", "PR-1", "2999-01-01",
        ])
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("locator_sha256" in p for p in problems), problems)

    def test_invalid_date_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          expires="not-a-date")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("expires is not ISO-8601" in p for p in problems), problems)

    def test_missing_removal_gate_value_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          removal_gate="")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("field 'removal_gate' is empty" in p for p in problems), problems)

    def test_invalid_removal_gate_value_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          removal_gate="PR-99-made-up")
        self.repo.set_ledger(make_ledger(row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("removal_gate must be one of" in p for p in problems), problems)

    def test_unexpected_extra_column_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        base = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                           '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
        row_with_removal_pr = base + "\t#123"
        self.repo.set_ledger(make_ledger(row_with_removal_pr))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("expected 10 tab-separated fields" in p for p in problems), problems)

    def test_missing_ledger_header_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
        write(self.repo.root / ".ci" / "arm64-debt-ledger.tsv", row + "\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("header mismatch" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# Field identity: source_<arch> arrays must not be conflated with `source`
# ---------------------------------------------------------------------------

class TestFieldIdentity(BaseFixtureTest):
    def test_source_x86_64_array_gets_its_own_field_identity(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("pkg-arch", "pkgname=pkg-arch\npkgver=1.0\npkgrel=1\n"
                     "source=()\n"
                     'source_x86_64=("http://example.org/x86_64-only.tar.gz")\n'
                     "sha256sums_x86_64=('SKIP')\n")
        repo.set_cone(["pkg-arch"])
        repo.set_ledger(make_ledger())
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "field=source_x86_64" in p for p in problems), problems)
        # A row incorrectly claiming field="source" (instead of
        # "source_x86_64") must NOT satisfy V==L for this locator.
        row = ledger_row("pkg-arch/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/x86_64-only.tar.gz"', "http://")
        repo.set_ledger(make_ledger(row))
        ok2, problems2 = repo.run()
        self.assertFalse(ok2)
        self.assertTrue(any("field=source_x86_64" in p for p in problems2), problems2)
        self.assertTrue(any("STALE_DEBT" in p and "field=source" in p for p in problems2), problems2)


# ---------------------------------------------------------------------------
# introduced_by provenance: verified against real git history when available
# ---------------------------------------------------------------------------

class TestProvenance(unittest.TestCase):
    def test_introduced_by_verified_against_real_git_history(self):
        tmp = tempfile.mkdtemp(prefix="arm64-provenance-")
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        repo_root = Path(tmp)
        (repo_root / ".ci").mkdir(parents=True)
        (repo_root / "pkg-b").mkdir()
        write(repo_root / "pkg-b" / "PKGBUILD", pkgbuild_http())
        write(repo_root / ".ci" / "arm64-rules.toml", RULES_TOML)
        write(repo_root / ".ci" / "arm64-cone.txt", "pkg-b\n")
        digest = sha256_of(repo_root / ".ci" / "arm64-cone.txt")
        write(repo_root / ".ci" / "arm64-cone.sha256", digest + "\n")

        def run_git(*args):
            return subprocess.run(["git", *args], cwd=repo_root, capture_output=True, text=True, check=True)

        run_git("init", "-q")
        run_git("config", "user.email", "test@example.com")
        run_git("config", "user.name", "test")
        run_git("add", "-A")
        run_git("commit", "-q", "-m", "initial")
        real_sha = run_git("rev-parse", "HEAD").stdout.strip()

        # A row whose introduced_by is a real commit sha -> no provenance complaint.
        row_real = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                               '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                               introduced_by=real_sha)
        write(repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row_real))
        from datetime import date
        ok, problems = guard.run(
            cone_path=repo_root / ".ci" / "arm64-cone.txt",
            rules_path=repo_root / ".ci" / "arm64-rules.toml",
            ledger_path=repo_root / ".ci" / "arm64-debt-ledger.tsv",
            today=date(2026, 1, 1),
            repo_root=repo_root,
            cone_digest_path=repo_root / ".ci" / "arm64-cone.sha256",
        )
        self.assertTrue(ok, problems)

        # A row whose introduced_by is a syntactically-valid-looking but
        # FAKE commit sha -> must be rejected as it names no real commit.
        row_fake = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                               '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                               introduced_by="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        write(repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row_fake))
        ok2, problems2 = guard.run(
            cone_path=repo_root / ".ci" / "arm64-cone.txt",
            rules_path=repo_root / ".ci" / "arm64-rules.toml",
            ledger_path=repo_root / ".ci" / "arm64-debt-ledger.tsv",
            today=date(2026, 1, 1),
            repo_root=repo_root,
            cone_digest_path=repo_root / ".ci" / "arm64-cone.sha256",
        )
        self.assertFalse(ok2)
        self.assertTrue(any("does not name a real commit" in p for p in problems2), problems2)

    def test_provenance_check_skipped_gracefully_when_not_a_git_repo(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        repo.add_pkg("pkg-b", pkgbuild_http())
        repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://",
                          introduced_by="deadbeefdead")
        repo.set_ledger(make_ledger(row))
        ok, problems = repo.run()
        # No .git directory in this fixture -> provenance check must not
        # fire at all (it's a fixture, not a real history).
        self.assertTrue(ok, problems)


# ---------------------------------------------------------------------------
# No env-var bypass
# ---------------------------------------------------------------------------

class TestNoEnvSkip(BaseFixtureTest):
    def test_plausible_bypass_env_vars_have_no_effect(self):
        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("git://example.org/unlisted.git")\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-c"])
        self.repo.set_ledger(make_ledger())
        bypass_vars = ("ARM64_GUARD_SKIP", "SKIP_ADMISSION_GUARD", "CI_SKIP", "MAKEPKG_LINT_PKGBUILD")
        for var in bypass_vars:
            os.environ[var] = "1"
        try:
            ok, problems = self.repo.run()
        finally:
            for var in bypass_vars:
                os.environ.pop(var, None)
        self.assertFalse(ok, "no environment variable may bypass the guard")


# ---------------------------------------------------------------------------
# Duplicate source triggers within the same file (two rules, one locator)
# ---------------------------------------------------------------------------

class TestMultiRuleLocator(BaseFixtureTest):
    def test_single_locator_two_rules_yields_one_combined_row(self):
        rows = self.baseline()
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)
        pkg_a_rows = [r for r in rows if r.startswith("pkg-a/")]
        self.assertEqual(len(pkg_a_rows), 1)
        self.assertIn("SRC_GIT_PROTO,SRC_MUTABLE_REF", pkg_a_rows[0])


# ---------------------------------------------------------------------------
# B2: real CLI --repo-root / --base-ref end-to-end (with real git history),
# temp-file cleanup, and deterministic exit codes.
# ---------------------------------------------------------------------------

class TestCLIExitCodes(BaseFixtureTest):
    def _invoke_cli(self, repo, today="2026-01-01", extra_args=None):
        args = [sys.executable, str(GUARD_PATH),
                 "--cone", str(repo.root / ".ci" / "arm64-cone.txt"),
                 "--cone-digest", str(repo.root / ".ci" / "arm64-cone.sha256"),
                 "--rules", str(repo.root / ".ci" / "arm64-rules.toml"),
                 "--ledger", str(repo.root / ".ci" / "arm64-debt-ledger.tsv"),
                 "--repo-root", str(repo.root),
                 "--today", today]
        if extra_args:
            args.extend(extra_args)
        return subprocess.run(args, capture_output=True, text=True, env=clean_subprocess_env())

    def test_pass_exits_zero(self):
        self.baseline()
        result = self._invoke_cli(self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_fail_exits_one(self):
        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("git://example.org/unlisted.git")\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-c"])
        self.repo.set_ledger(make_ledger())
        result = self._invoke_cli(self.repo)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", result.stderr)


class TestCLIBaseRefEndToEnd(unittest.TestCase):
    """Exercises the REAL CLI --base-ref flag against a REAL temporary git
    repository with real commits -- this is exactly the code path the CI
    workflow invokes unconditionally on every run, and a `run()`-level test
    that hands in an already-materialized base_ledger_path is NOT sufficient
    coverage for it (it bypasses resolve_default_base_ledger, the git
    subprocess call, and the temp-file lifecycle entirely).
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="arm64-baseref-e2e-")
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.repo_root = Path(self.tmp)
        (self.repo_root / ".ci").mkdir(parents=True)
        (self.repo_root / "pkg-a").mkdir()
        write(self.repo_root / ".ci" / "arm64-rules.toml", RULES_TOML)
        write(self.repo_root / ".ci" / "arm64-cone.txt", "pkg-a\n")
        write(self.repo_root / ".ci" / "arm64-cone.sha256",
              sha256_of(self.repo_root / ".ci" / "arm64-cone.txt") + "\n")

        def run_git(*args):
            return subprocess.run(["git", *args], cwd=self.repo_root, capture_output=True, text=True, check=True)
        self.run_git = run_git
        run_git("init", "-q")
        run_git("config", "user.email", "test@example.com")
        run_git("config", "user.name", "test")

    def _invoke(self, base_ref=None, extra_args=None, env=None):
        args = [sys.executable, str(GUARD_PATH),
                "--cone", str(self.repo_root / ".ci" / "arm64-cone.txt"),
                "--cone-digest", str(self.repo_root / ".ci" / "arm64-cone.sha256"),
                "--rules", str(self.repo_root / ".ci" / "arm64-rules.toml"),
                "--ledger", str(self.repo_root / ".ci" / "arm64-debt-ledger.tsv"),
                "--repo-root", str(self.repo_root),
                "--today", "2026-01-01"]
        if base_ref is not None:
            args += ["--base-ref", base_ref]
        if extra_args:
            args += extra_args
        # Isolate from whatever real GitHub-Actions-environment this test
        # suite might itself be running inside (e.g. its own CI job): by
        # default, explicitly clear the GITHUB_ACTIONS-family variables so
        # `derive_github_actions_base_ref` behaves as a genuine local run
        # regardless of the outer environment. Tests that specifically
        # exercise the GitHub-Actions-derived path pass their own
        # controlled `env` (see `_invoke_as_github_actions`).
        return subprocess.run(args, cwd=self.repo_root, capture_output=True, text=True, env=clean_subprocess_env(env))

    def _invoke_as_github_actions(self, event: dict, event_name: str = "pull_request", base_ref=None, extra_args=None):
        """Writes `event` as a GITHUB_EVENT_PATH-style JSON file and invokes
        the CLI with a controlled GITHUB_ACTIONS/GITHUB_EVENT_NAME
        environment simulating a real GitHub Actions job -- this is the
        exact mechanism derive_github_actions_base_ref relies on, so it
        must be exercised through the real subprocess boundary, not just
        by calling the Python function directly."""
        event_path = Path(self.tmp) / "github_event.json"
        write(event_path, json.dumps(event))
        return self._invoke(base_ref=base_ref, extra_args=extra_args, env={
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": event_name,
            "GITHUB_EVENT_PATH": str(event_path),
        })

    def test_base_ref_absent_ledger_first_run_behavior(self):
        # No prior commit has ever had a ledger file -- --base-ref points at
        # a real commit, but that commit predates the ledger's existence.
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "before ledger existed")
        commit_before = self.run_git("rev-parse", "HEAD").stdout.strip()

        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git://example.org/pkg-a.git#tag=v1.0")\n')
        locator = '"git://example.org/pkg-a.git#tag=v1.0"'
        row = ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF", locator, "#tag=,git://",
                          introduced_by=commit_before)
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))

        result = self._invoke(base_ref=commit_before)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_unresolvable_base_ref_is_a_hard_fail_not_a_silent_skip(self):
        # B3 condition 1: an explicitly-supplied --base-ref that does not
        # resolve to a real commit must hard-fail, never silently degrade
        # to "no base available" (which would make the entire cross-commit
        # mechanism bypassable by simply supplying a broken/nonexistent
        # ref). This is distinct from the legitimate first-run case (a
        # VALID ref whose target file didn't exist yet), covered by
        # test_base_ref_absent_ledger_first_run_behavior above.
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        result = self._invoke(base_ref="this-commit-does-not-exist-anywhere")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", result.stdout + result.stderr)
        self.assertIn("does not resolve to a real commit", result.stderr)

    def test_empty_base_ref_is_a_hard_fail(self):
        # An empty string --base-ref (e.g. a workflow that failed to
        # compute a trusted base and passed through an empty value) must
        # also hard-fail, not be silently treated the same as omitting
        # --base-ref entirely.
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        result = self._invoke(base_ref="")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_omitting_base_ref_entirely_still_runs_without_cross_commit_check(self):
        # Contrast with the above: NOT passing --base-ref at all (as
        # opposed to passing an empty/broken one) remains a supported,
        # deliberate "no cross-commit check" mode for ad hoc local runs --
        # the shipped CI workflow always supplies a real --base-ref, so
        # this path is never exercised in CI.
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        result = self._invoke(base_ref=None)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_base_ref_present_ledger_not_yet_promoted(self):
        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git://example.org/pkg-a.git#tag=v1.0")\n')
        locator = '"git://example.org/pkg-a.git#tag=v1.0"'
        row = ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF", locator, "#tag=,git://")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: baseline with SRC_* debt")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git+https://example.org/pkg-a.git#commit=deadbeef")\n')
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())

        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_base_ref_promoted_rule_rejects_new_debt(self):
        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git://example.org/pkg-a.git#tag=v1.0")\n')
        locator = '"git://example.org/pkg-a.git#tag=v1.0"'
        row = ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF", locator, "#tag=,git://")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git+https://example.org/pkg-a.git#commit=deadbeef")\n')
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit2 (PR-1): clears SRC_* debt")
        commit2 = self.run_git("rev-parse", "HEAD").stdout.strip()

        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git://example.org/new-violation.git")\n')
        locator3 = '"git://example.org/new-violation.git"'
        row3 = ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO", locator3, "git://")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row3))

        result = self._invoke(base_ref=commit2)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("promoted", result.stderr)

    def test_base_ledger_temp_file_is_cleaned_up(self):
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        import glob
        tmp_glob = str(Path(tempfile.gettempdir()) / "arm64-base-ledger-*")
        before = set(glob.glob(tmp_glob))
        result = self._invoke(base_ref=commit1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = set(glob.glob(tmp_glob))
        self.assertEqual(before, after, f"temp base-ledger file(s) not cleaned up: {after - before}")

    # -----------------------------------------------------------------
    # B3 hardening: the base identity itself must be GitHub-supplied
    # (derived from GITHUB_EVENT_PATH), never a caller-editable
    # --base-ref string a workflow YAML computes -- on a `pull_request`
    # trigger the workflow file expressing that computation is itself
    # part of the diff under review.
    # -----------------------------------------------------------------

    def _commit_ledger_free_baseline(self):
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        # No ledger file at all at this commit -- genuinely predates PR-0.
        (self.repo_root / ".ci" / "arm64-debt-ledger.tsv").unlink(missing_ok=True)
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "genuinely predates the ledger")
        return self.run_git("rev-parse", "HEAD").stdout.strip()

    def test_github_actions_derives_base_from_event_path_not_workflow(self):
        # The core fix: with NO --base-ref passed at all (mirroring the
        # simplified workflow, which no longer computes or passes one),
        # running inside a simulated GitHub Actions pull_request job still
        # performs the cross-commit check, using the base SHA taken
        # directly from GITHUB_EVENT_PATH.
        old_commit = self._commit_ledger_free_baseline()

        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git://example.org/pkg-a.git#tag=v1.0")\n')
        locator = '"git://example.org/pkg-a.git#tag=v1.0"'
        row = ledger_row("pkg-a/PKGBUILD", "source", "SRC_GIT_PROTO,SRC_MUTABLE_REF", locator, "#tag=,git://",
                          introduced_by=old_commit)
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))

        result = self._invoke_as_github_actions(
            event={"pull_request": {"base": {"sha": old_commit}}}, event_name="pull_request",
        )
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_github_actions_missing_event_path_is_hard_fail(self):
        # GITHUB_ACTIONS=true but GITHUB_EVENT_PATH pointing at a
        # nonexistent file must hard-fail, never silently degrade to "no
        # base available" -- that would make the entire cross-commit
        # mechanism bypassable simply by GITHUB_EVENT_PATH being
        # unreadable for any reason.
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        result = self._invoke(env={
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_EVENT_PATH": str(Path(self.tmp) / "does-not-exist.json"),
        })
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", result.stdout + result.stderr)

    def test_github_actions_malformed_event_json_is_hard_fail(self):
        result = self._invoke_as_github_actions(event={"pull_request": {}}, event_name="pull_request")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", result.stdout + result.stderr)

    def test_github_actions_empty_event_path_is_hard_fail(self):
        # NB-2: GITHUB_ACTIONS=true with GITHUB_EVENT_PATH explicitly set
        # to an EMPTY STRING (as distinct from missing/nonexistent) must
        # ALSO hard-fail -- the real Actions runner always sets a
        # non-empty value, so this can only indicate something is wrong
        # with the environment, never legitimate "not really in Actions".
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        result = self._invoke(env={
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_EVENT_PATH": "",
        })
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", result.stdout + result.stderr)

    def test_workflow_supplied_base_ref_mismatching_github_event_is_hard_fail(self):
        # If a workflow-computed --base-ref were ever (re-)introduced and
        # disagreed with the trusted, event-derived base, that must be a
        # hard failure -- never a silent preference for either value --
        # since a mismatch is exactly what a rewritten workflow file
        # attempting to smuggle in a different base would produce.
        old_commit = self._commit_ledger_free_baseline()
        write(self.repo_root / "pkg-a" / "PKGBUILD",
              "pkgname=pkg-a\npkgver=1.0\npkgrel=1\n"
              'source=("git://example.org/pkg-a.git#tag=v1.0")\n')
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit2")

        result = self._invoke_as_github_actions(
            event={"pull_request": {"base": {"sha": old_commit}}}, event_name="pull_request",
            base_ref="some-other-ref-the-workflow-computed",
        )
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not match the trusted", result.stderr)

    def test_pull_request_targeting_old_base_predating_ledger_is_legitimate_first_run(self):
        # Distinguishing this from the attack it might resemble: a PR
        # that genuinely targets an old base (predating the ledger) is
        # legitimate first-run behavior ONLY because the base identity
        # itself is trustworthy here (GitHub-event-derived, not
        # attacker-chosen) -- an attacker cannot make the event carry an
        # arbitrary base of their choosing, only the PR's REAL target.
        old_commit = self._commit_ledger_free_baseline()
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit2, still no new violations")

        result = self._invoke_as_github_actions(
            event={"pull_request": {"base": {"sha": old_commit}}}, event_name="pull_request",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_push_event_before_all_zeros_is_legitimate_no_base(self):
        # GitHub's sentinel for "no prior commit" (e.g. a brand-new
        # branch) -- legitimately no base to compare against, not a
        # malformed event that should hard-fail.
        write(self.repo_root / "pkg-a" / "PKGBUILD", "pkgname=pkg-a\npkgver=1.0\npkgrel=1\nsource=()\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")

        result = self._invoke_as_github_actions(
            event={"before": "0000000000000000000000000000000000000000"}, event_name="push",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)


# ---------------------------------------------------------------------------
# Reconciliation architecture: removal-authorization and promotion-totality
# gating, exercised end-to-end through the REAL --base-ref CLI path (real
# git history, real `git show` materialization of the base commit's tree
# via `resolve_base_reconciliation`) -- this is the CONTROLLING DEFECT the
# reconciliation layer exists to close: a ledgered debt row must never be
# removable just because a narrower/respelled locator makes the PRIMARY
# detector stop noticing it.
# ---------------------------------------------------------------------------

class TestReconciliationRemovalAuthorization(unittest.TestCase):
    TOOLCHAIN_PKG = "mingw-w64-cross-mingwarm64-toolchain"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="arm64-reconcile-e2e-")
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.repo_root = Path(self.tmp)
        (self.repo_root / ".ci").mkdir(parents=True)
        (self.repo_root / self.TOOLCHAIN_PKG).mkdir()
        write(self.repo_root / ".ci" / "arm64-rules.toml", RULES_TOML)
        write(self.repo_root / ".ci" / "arm64-cone.txt", self.TOOLCHAIN_PKG + "\n")
        write(self.repo_root / ".ci" / "arm64-cone.sha256",
              sha256_of(self.repo_root / ".ci" / "arm64-cone.txt") + "\n")

        def run_git(*args):
            return subprocess.run(["git", *args], cwd=self.repo_root, capture_output=True, text=True, check=True)
        self.run_git = run_git
        run_git("init", "-q")
        run_git("config", "user.email", "test@example.com")
        run_git("config", "user.name", "test")

    def _write_pkgbuild(self, pkgver: str) -> None:
        write(self.repo_root / self.TOOLCHAIN_PKG / "PKGBUILD",
              f"pkgname={self.TOOLCHAIN_PKG}\npkgver={pkgver}\npkgrel=1\n"
              f'source=("https://example.org/toolchain-{pkgver}.tar.gz")\n'
              "sha256sums=('SKIP')\n")

    def _invoke(self, base_ref=None):
        args = [sys.executable, str(GUARD_PATH),
                "--cone", str(self.repo_root / ".ci" / "arm64-cone.txt"),
                "--cone-digest", str(self.repo_root / ".ci" / "arm64-cone.sha256"),
                "--rules", str(self.repo_root / ".ci" / "arm64-rules.toml"),
                "--ledger", str(self.repo_root / ".ci" / "arm64-debt-ledger.tsv"),
                "--repo-root", str(self.repo_root),
                "--today", "2026-01-01"]
        if base_ref is not None:
            args += ["--base-ref", base_ref]
        return subprocess.run(args, cwd=self.repo_root, capture_output=True, text=True, env=clean_subprocess_env())

    def test_respell_with_row_kept_is_stale_debt(self):
        # "respell + old row": the ledgered locator text no longer exists
        # anywhere on disk once respelled, so the EXISTING same-commit
        # STALE_DEBT check (no cross-commit machinery needed) must already
        # catch this -- confirms the baseline protection this whole
        # mechanism builds on top of is intact.
        self._write_pkgbuild("2.44dev")
        row = ledger_row(f"{self.TOOLCHAIN_PKG}/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                          "2.44dev", "2.44dev", removal_gate="T0-corrected-toolchain")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: baseline dev pin")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        self._write_pkgbuild("2.44.r474.g9c93e483b")
        # ledger row for "2.44dev" left UNCHANGED (not deleted, not updated)

        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("STALE_DEBT", result.stderr)

    def test_respell_with_row_deleted_is_unverified_removal(self):
        # THE CONTROLLING DEFECT, exercised end-to-end: respell the exact
        # audit-cited case (2.44dev -> 2.44.r474.g9c93e483b, a live
        # git-describe-style snapshot spelling TOOLCHAIN_DEV_VER_RE does
        # NOT match) AND delete the now-"undetected" ledger row in the
        # SAME change. Before the reconciliation architecture, this
        # combination passed green (V and L both silently agree on
        # absence). It must now fail via UNVERIFIED_DEBT_REMOVAL.
        self._write_pkgbuild("2.44dev")
        row = ledger_row(f"{self.TOOLCHAIN_PKG}/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                          "2.44dev", "2.44dev", removal_gate="T0-corrected-toolchain")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: baseline dev pin")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        self._write_pkgbuild("2.44.r474.g9c93e483b")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())  # row deleted

        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("UNVERIFIED_DEBT_REMOVAL", result.stderr)
        self.assertIn("TOOLCHAIN_DEV_VER", result.stderr)

    def test_genuine_remediation_with_row_deleted_passes(self):
        # The positive control proving this mechanism is not merely
        # fail-closed-always: a TRUE fix (a clean, fully-released numeric
        # version, no VCS ambiguity) combined with deleting the
        # now-obsolete ledger row must PASS.
        self._write_pkgbuild("2.44dev")
        row = ledger_row(f"{self.TOOLCHAIN_PKG}/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                          "2.44dev", "2.44dev", removal_gate="T0-corrected-toolchain")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: baseline dev pin")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        self._write_pkgbuild("2.44.0")  # clean release: genuinely fixed
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())  # row deleted

        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_unknown_dynamic_content_with_row_deleted_is_unverified_removal(self):
        # An unresolvable/dynamic pkgver at the CURRENT commit -- neither
        # provably present nor provably absent -- must block removal just
        # as firmly as a provably-present one (RECON_UNKNOWN and
        # RECON_PRESENT are both non-authorizing).
        self._write_pkgbuild("2.44dev")
        row = ledger_row(f"{self.TOOLCHAIN_PKG}/PKGBUILD", "pkgver", "TOOLCHAIN_DEV_VER",
                          "2.44dev", "2.44dev", removal_gate="T0-corrected-toolchain")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: baseline dev pin")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        write(self.repo_root / self.TOOLCHAIN_PKG / "PKGBUILD",
              f"pkgname={self.TOOLCHAIN_PKG}\n"
              "if true; then\n_v=2.44.0\nelse\n_v=2.45.0\nfi\n"
              "pkgver=${_v}\npkgrel=1\n"
              'source=("https://example.org/toolchain-${pkgver}.tar.gz")\n'
              "sha256sums=('SKIP')\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())  # row deleted

        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("UNVERIFIED_DEBT_REMOVAL", result.stderr)

    def test_zero_count_promotion_withheld_when_base_tree_reconciler_shows_present(self):
        # "zero-count promotion with incomplete reconciler": the BASE
        # ledger already shows zero SRC_INSECURE_HTTP rows (naive
        # promotion condition satisfied), but the BASE TREE itself, at
        # that exact historical commit, still had an undetected plaintext
        # HTTP fetch reachable only through a respelling the primary
        # detector missed (simulated here directly: a source element
        # whose scheme is provided via a conditionally-assigned,
        # therefore-UNKNOWN variable). Promotion must be withheld --
        # confirmed by checking that a SUBSEQUENT new SRC_INSECURE_HTTP
        # ledger row is accepted (not rejected as "promoted").
        write(self.repo_root / self.TOOLCHAIN_PKG / "PKGBUILD",
              f"pkgname={self.TOOLCHAIN_PKG}\npkgver=1.0.0\npkgrel=1\n"
              "if true; then\n_p=https\nelse\n_p=http\nfi\n"
              'source=("${_p}://example.org/x.tar.gz")\n'
              "sha256sums=('SKIP')\n")
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())  # zero rows already
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: base has zero SRC_INSECURE_HTTP rows, but is UNKNOWN not proven absent")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        write(self.repo_root / self.TOOLCHAIN_PKG / "PKGBUILD",
              f"pkgname={self.TOOLCHAIN_PKG}\npkgver=1.0.0\npkgrel=1\n"
              'source=("http://example.org/new-insecure.tar.gz")\n'
              "sha256sums=('SKIP')\n")
        row = ledger_row(f"{self.TOOLCHAIN_PKG}/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/new-insecure.tar.gz"', "http://", introduced_by=commit1)
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger(row))

        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("promoted", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)


class TestBaseConeMonotonicity(unittest.TestCase):
    """B3: the declared ARM64 build-closure cone may only grow (a reviewed,
    digest-updated addition) -- it may never shrink or same-size-substitute
    an entry, even if the current commit's cone+digest are internally
    self-consistent. This is a CROSS-COMMIT check (mirrors the ledger's
    promotion mechanism): it materializes the base commit's real cone.txt
    via the real CLI --base-ref flag against a real temporary git repo, and
    rejects any base entry that is absent from the current cone.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="arm64-basecone-e2e-")
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.repo_root = Path(self.tmp)
        (self.repo_root / ".ci").mkdir(parents=True)
        write(self.repo_root / ".ci" / "arm64-rules.toml", RULES_TOML)
        write(self.repo_root / ".ci" / "arm64-debt-ledger.tsv", make_ledger())

        def run_git(*args):
            return subprocess.run(["git", *args], cwd=self.repo_root, capture_output=True, text=True, check=True)
        self.run_git = run_git
        run_git("init", "-q")
        run_git("config", "user.email", "test@example.com")
        run_git("config", "user.name", "test")

    def _set_cone(self, entries):
        write(self.repo_root / ".ci" / "arm64-cone.txt", "\n".join(sorted(entries)) + "\n")
        write(self.repo_root / ".ci" / "arm64-cone.sha256",
              sha256_of(self.repo_root / ".ci" / "arm64-cone.txt") + "\n")

    def _add_clean_pkg(self, name):
        write(self.repo_root / name / "PKGBUILD",
              f"pkgname={name}\npkgver=1.0\npkgrel=1\nsource=()\n")

    def _invoke(self, base_ref=None):
        args = [sys.executable, str(GUARD_PATH),
                "--cone", str(self.repo_root / ".ci" / "arm64-cone.txt"),
                "--cone-digest", str(self.repo_root / ".ci" / "arm64-cone.sha256"),
                "--rules", str(self.repo_root / ".ci" / "arm64-rules.toml"),
                "--ledger", str(self.repo_root / ".ci" / "arm64-debt-ledger.tsv"),
                "--repo-root", str(self.repo_root),
                "--today", "2026-01-01"]
        if base_ref is not None:
            args += ["--base-ref", base_ref]
        return subprocess.run(args, cwd=self.repo_root, capture_output=True, text=True, env=clean_subprocess_env())

    def test_base_cone_absent_first_run_does_not_crash_or_disable_check(self):
        # This is the commit that first introduces the cone -- there is
        # genuinely no base to compare against. Must PASS cleanly (not
        # crash), and the absence of a base cone must not silently skip
        # OTHER checks (digest pinning still applies).
        self._add_clean_pkg("pkg-a")
        self._set_cone(["pkg-a"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "introduce cone")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()
        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_base_cone_present_unchanged_passes(self):
        self._add_clean_pkg("pkg-a")
        self._add_clean_pkg("pkg-b")
        self._set_cone(["pkg-a", "pkg-b"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()
        # No changes at all in the working tree; validate HEAD against itself.
        result = self._invoke(base_ref=commit1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_base_cone_removal_with_repin_is_rejected(self):
        self._add_clean_pkg("pkg-a")
        self._add_clean_pkg("pkg-b")
        self._set_cone(["pkg-a", "pkg-b"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: two packages")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        # Remove pkg-b from the cone AND correctly re-pin the digest --
        # internally self-consistent, but must still be rejected because
        # pkg-b was present at the base commit.
        self._set_cone(["pkg-a"])
        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SCHEMA_INVALID(cone)", result.stderr)
        self.assertIn("pkg-b", result.stderr)

    def test_base_cone_same_size_substitution_with_repin_is_rejected(self):
        self._add_clean_pkg("pkg-a")
        self._add_clean_pkg("pkg-b")
        self._set_cone(["pkg-a", "pkg-b"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: two packages")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        # Swap pkg-b for pkg-c: same COUNT, correctly re-pinned digest --
        # must still be rejected (pkg-b vanished relative to the base).
        self._add_clean_pkg("pkg-c")
        self._set_cone(["pkg-a", "pkg-c"])
        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SCHEMA_INVALID(cone)", result.stderr)
        self.assertIn("pkg-b", result.stderr)

    def test_base_cone_legitimate_addition_with_repin_is_accepted(self):
        self._add_clean_pkg("pkg-a")
        self._set_cone(["pkg-a"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: one package")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        # Add pkg-b, correctly re-pin the digest -- every base entry
        # (pkg-a) is still present, so this is a legitimate, accepted growth.
        self._add_clean_pkg("pkg-b")
        self._set_cone(["pkg-a", "pkg-b"])
        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_base_cone_temp_file_is_cleaned_up(self):
        self._add_clean_pkg("pkg-a")
        self._set_cone(["pkg-a"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        import glob
        tmp_glob = str(Path(tempfile.gettempdir()) / "arm64-base-cone-*")
        before = set(glob.glob(tmp_glob))
        result = self._invoke(base_ref=commit1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = set(glob.glob(tmp_glob))
        self.assertEqual(before, after, f"temp base-cone file(s) not cleaned up: {after - before}")

    def test_deleting_current_cone_file_fails_not_first_run(self):
        # A pull request that DELETES the current cone.txt entirely must
        # hard-fail (SCHEMA_INVALID), never be reinterpreted as a
        # "legitimate first run" -- the first-run carve-out is about the
        # BASE commit lacking the file, which is a completely separate
        # question from whether the CURRENT commit has one. load_cone() on
        # the current path is unconditional and runs before any
        # base/first-run logic at all.
        self._add_clean_pkg("pkg-a")
        self._set_cone(["pkg-a"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: cone exists")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        (self.repo_root / ".ci" / "arm64-cone.txt").unlink()
        (self.repo_root / ".ci" / "arm64-cone.sha256").unlink()
        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SCHEMA_INVALID(cone)", result.stderr)

    def test_deleting_current_ledger_file_fails_not_first_run(self):
        self._add_clean_pkg("pkg-a")
        self._set_cone(["pkg-a"])
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "commit1: ledger exists")
        commit1 = self.run_git("rev-parse", "HEAD").stdout.strip()

        (self.repo_root / ".ci" / "arm64-debt-ledger.tsv").unlink()
        result = self._invoke(base_ref=commit1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SCHEMA_INVALID(ledger)", result.stderr)


if __name__ == "__main__":
    unittest.main()

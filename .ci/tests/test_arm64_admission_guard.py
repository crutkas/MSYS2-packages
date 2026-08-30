#!/usr/bin/env python3
"""Automated fixture-based test suite for .ci/arm64-admission-guard.py.

Every test builds an isolated temporary repository tree (its own PKGBUILDs,
cone, rules, and ledger) and calls the guard against that tree only -- no
test ever reads, writes, or mutates a real/production PKGBUILD anywhere in
this repository. Run with:

    python -m unittest .ci/tests/test_arm64_admission_guard.py -v

or simply:

    python .ci/tests/test_arm64_admission_guard.py
"""
from __future__ import annotations

import importlib.util
import os
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


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


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


LEDGER_HEADER = guard.LEDGER_HEADER


def ledger_row(path, field, rule_id, locator, matched, reason="test reason",
               introduced_by="0123abc", removal_gate="PR-1", expires="2999-01-01"):
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

    def add_pkg(self, directory: str, pkgbuild_text: str) -> None:
        write(self.root / directory / "PKGBUILD", pkgbuild_text)

    def set_cone(self, entries: list) -> None:
        write(self.root / ".ci" / "arm64-cone.txt", "\n".join(entries) + "\n")

    def set_rules(self, text: str = RULES_TOML) -> None:
        write(self.root / ".ci" / "arm64-rules.toml", text)

    def set_ledger(self, text: str) -> None:
        write(self.root / ".ci" / "arm64-debt-ledger.tsv", text)

    def run(self, today="2026-01-01", base_ledger_text=None):
        from datetime import datetime
        base_ledger_path = None
        if base_ledger_text is not None:
            base_ledger_path = self.root / ".ci" / "arm64-debt-ledger.base.tsv"
            write(base_ledger_path, base_ledger_text)
        return guard.run(
            cone_path=self.root / ".ci" / "arm64-cone.txt",
            rules_path=self.root / ".ci" / "arm64-rules.toml",
            ledger_path=self.root / ".ci" / "arm64-debt-ledger.tsv",
            today=datetime.strptime(today, "%Y-%m-%d").date(),
            repo_root=self.root,
            base_ledger_path=base_ledger_path,
        )


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
        # Add a brand-new violation in an existing in-cone recipe with no
        # ledger row for it.
        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("git://example.org/new-violation.git")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 3. Delete one baseline row while its violation remains -> RED
# ---------------------------------------------------------------------------

class TestDeletedRowViolationRemains(BaseFixtureTest):
    def test_delete_row_violation_remains_is_red(self):
        rows = self.baseline()
        # Drop the pkg-b row but keep pkg-b's violating PKGBUILD unchanged.
        remaining = [r for r in rows if not r.startswith("pkg-b/")]
        self.repo.set_ledger(make_ledger(*remaining))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p and "pkg-b" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 4. Fix a violation but retain its row -> RED (L subset V violated / stale)
# ---------------------------------------------------------------------------

class TestStaleRow(BaseFixtureTest):
    def test_fixed_violation_retained_row_is_red(self):
        self.baseline()
        # "Fix" pkg-b by switching to https, but keep its ledger row.
        self.repo.add_pkg("pkg-b", 'pkgname=pkg-b\npkgver=2.0.0\npkgrel=1\n'
                          'source=("https://example.org/pkg-b-${pkgver}.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("STALE_DEBT" in p and "pkg-b" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 5. Quarantine: full hash, abbreviated hash, and ledgering attempt
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
                              "quarantine")
        self.repo.set_ledger(make_ledger(*rows, bad_row))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("SCHEMA_INVALID" in p and "absolute" in p for p in problems), problems)


# ---------------------------------------------------------------------------
# 6/9. Wildcard/regex/bypass metacharacters vs legitimate ${...} braces
# ---------------------------------------------------------------------------

class TestBypassCharacters(BaseFixtureTest):
    def test_each_forbidden_metachar_is_independently_rejected(self):
        for ch, tag in [("*", "star"), ("?", "qmark"), ("[", "lbrak"), ("]", "rbrak"),
                        ("(", "lparen"), (")", "rparen"), ("|", "pipe"), ("\\", "bslash")]:
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
        # ${pkgver}-style braces are pervasive, legitimate bash syntax and
        # MUST NOT be treated as a wildcard/bypass character.
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

    def test_locator_is_literal_data_not_regex_or_glob(self):
        # A locator containing regex-special characters that are NOT in the
        # forbidden set (e.g. '.', '+', '^', '$') must bind only to the
        # EXACT literal string, never as a pattern.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = FixtureRepo(Path(tmp.name))
        repo.set_rules()
        exact = '"http://example.org/a.b+c.tar.gz"'
        similar_but_different = '"http://example.org/aXbXc.tar.gz"'  # would match '.'-as-wildcard, '+' as regex, but must NOT
        repo.add_pkg("pkg-x", "pkgname=pkg-x\npkgver=1.0.0\npkgrel=1\n"
                     "source=(" + similar_but_different + ")\n"
                     "sha256sums=('SKIP')\n")
        repo.set_cone(["pkg-x"])
        # Ledger names the *different* literal string -- if the guard treated
        # locators as regex/glob patterns this could spuriously "match" and
        # incorrectly pass; it must instead correctly report new debt (the
        # on-disk locator has no ledger entry) because sha256 binding is
        # exact-string, not pattern-based.
        row = ledger_row("pkg-x/PKGBUILD", "source", "SRC_INSECURE_HTTP", exact, "http://")
        repo.set_ledger(make_ledger(row))
        ok, problems = repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("NEW_DEBT" in p for p in problems) and any("STALE_DEBT" in p for p in problems), problems)


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

    def test_opaque_command_substitution_is_supported_and_never_executed(self):
        fd, marker_path = tempfile.mkstemp()
        os.close(fd)
        marker = Path(marker_path)
        marker.unlink()  # ensure it does not exist before the guard runs
        marker_posix = marker.as_posix()
        self.repo.add_pkg("pkg-cmdsub", 'pkgname=pkg-cmdsub\npkgver=1.0\npkgrel=1\n'
                          'source=(https://example.org/x-$(touch ' + marker_posix + ' && echo z).tar.gz)\n'
                          "sha256sums=('SKIP')\n")
        self.repo.set_cone(["pkg-cmdsub"])
        self.repo.set_ledger(make_ledger())
        ok, problems = self.repo.run()
        self.assertTrue(ok, problems)  # https:// only, no rule violated, parses fine
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
        # Reversed (b before a) -- not canonically sorted by path.
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


# ---------------------------------------------------------------------------
# 11. PR-1 simulation: clear all source debt -> GREEN, then rule promotion
# ---------------------------------------------------------------------------

class TestPromotion(BaseFixtureTest):
    def test_pr1_simulation_then_promoted_rule_blocks_new_debt(self):
        pre_pr1_ledger_text = make_ledger(*self.baseline())

        # Simulate "PR-1": fix pkg-a and pkg-b to secure transports, delete
        # their ledger rows, keep only the toolchain dev-ver row. Validated
        # against the pre-PR-1 state as its base (SRC_* rules still had rows
        # there, so they are not yet promoted -- PR-1 itself is allowed to
        # reach zero).
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

        # Now, validated against PR-1's own merged state as base (which had
        # ZERO SRC_* rows), SRC_GIT_PROTO/SRC_MUTABLE_REF/SRC_INSECURE_HTTP
        # are permanently promoted -- a brand-new insecure http source, even
        # WITH an attempted ledger row, must still be rejected.
        self.repo.add_pkg("pkg-c", 'pkgname=pkg-c\npkgver=3.0.0\npkgrel=1\n'
                          'source=("http://example.org/new-insecure.tar.gz")\n'
                          "sha256sums=('SKIP')\n")
        with_new_row = remaining + [ledger_row("pkg-c/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                                                '"http://example.org/new-insecure.tar.gz"', "http://")]
        self.repo.set_ledger(make_ledger(*with_new_row))
        ok, problems = self.repo.run(base_ledger_text=post_pr1_ledger_text)
        self.assertFalse(ok)
        self.assertTrue(any("promoted" in p for p in problems), problems)

    def test_no_base_ledger_means_nothing_promoted_yet(self):
        # This is the PR-0 case: the ledger is being introduced for the
        # first time, so there is no prior state and nothing can be
        # "already cleared" -- the baseline must pass with no base ledger.
        self.baseline()
        ok, problems = self.repo.run(base_ledger_text=None)
        self.assertTrue(ok, problems)


# ---------------------------------------------------------------------------
# 12. Cone scoping: out-of-cone violations ignored; escapes rejected
# ---------------------------------------------------------------------------

class TestConeScoping(BaseFixtureTest):
    def test_out_of_cone_violation_is_ignored(self):
        self.baseline()
        # pkg-outside has a real violation but is NOT listed in the cone.
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
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
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
            "not-a-valid-sha256", "http://", "reason", "0123abc", "PR-1", "2999-01-01",
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
        row_with_removal_pr = base + "\t#123"  # a fabricated 11th column
        self.repo.set_ledger(make_ledger(row_with_removal_pr))
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("expected 10 tab-separated fields" in p for p in problems), problems)

    def test_missing_ledger_header_is_red(self):
        self.repo.add_pkg("pkg-b", pkgbuild_http())
        self.repo.set_cone(["pkg-b"])
        row = ledger_row("pkg-b/PKGBUILD", "source", "SRC_INSECURE_HTTP",
                          '"http://example.org/pkg-b-${pkgver}.tar.gz"', "http://")
        write(self.repo.root / ".ci" / "arm64-debt-ledger.tsv", row + "\n")  # no header line
        ok, problems = self.repo.run()
        self.assertFalse(ok)
        self.assertTrue(any("header mismatch" in p for p in problems), problems)


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
# Deterministic CLI exit codes
# ---------------------------------------------------------------------------

class TestCLIExitCodes(BaseFixtureTest):
    def _invoke_cli(self, repo, today="2026-01-01"):
        return subprocess.run(
            [sys.executable, str(GUARD_PATH),
             "--cone", str(repo.root / ".ci" / "arm64-cone.txt"),
             "--rules", str(repo.root / ".ci" / "arm64-rules.toml"),
             "--ledger", str(repo.root / ".ci" / "arm64-debt-ledger.tsv"),
             "--repo-root", str(repo.root),
             "--today", today],
            capture_output=True, text=True,
        )

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


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import pathlib
import sys
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY_DIR))

from policy_lib import (  # noqa: E402
    NameStatus,
    PolicyError,
    TreeEntry,
    TreeManifest,
    assert_safe_diff,
    diff_manifests,
    normalize_policy_path,
    path_is_controlled,
)


TREE_A = "a" * 40
TREE_B = "b" * 40
BLOB_A = "1" * 40
BLOB_B = "2" * 40
BLOB_C = "3" * 40


def blob(path, sha=BLOB_A, mode="100644", size=4):
    return TreeEntry(path=path, mode=mode, type="blob", sha=sha, size=size)


def tree(path, sha=BLOB_C):
    return TreeEntry(path=path, mode="040000", type="tree", sha=sha)


def manifest(tree_sha, *entries):
    return TreeManifest(tree_sha, entries)


class ManifestTests(unittest.TestCase):
    def assert_policy_error(self, code, function):
        with self.assertRaises(PolicyError) as raised:
            function()
        self.assertEqual(raised.exception.code, code)

    def assert_diff_denied(self, base, candidate, prefix=b"plain data\n"):
        changes = diff_manifests(base, candidate)
        with self.assertRaises(PolicyError) as raised:
            assert_safe_diff(
                changes,
                [".github/policy/locks/"],
                lambda path, entry, length: prefix[:length],
            )
        return changes, raised.exception

    def test_exact_rename_reports_and_checks_source_and_destination(self):
        base = manifest(
            TREE_A, blob(".github/workflows/policy.yml"), blob("README.md", BLOB_B)
        )
        candidate = manifest(
            TREE_B, blob("docs/innocent.txt"), blob("README.md", BLOB_B)
        )
        changes, error = self.assert_diff_denied(base, candidate)
        self.assertEqual(
            changes,
            [
                NameStatus(
                    "R100",
                    ".github/workflows/policy.yml",
                    "docs/innocent.txt",
                    base.entries[".github/workflows/policy.yml"],
                    candidate.entries["docs/innocent.txt"],
                )
            ],
        )
        self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")
        self.assertIn(".github/workflows/policy.yml", error.message)

    def test_exact_copy_reports_and_checks_controlled_source(self):
        base = manifest(TREE_A, blob(".github/policy/validator.py"))
        candidate = manifest(
            TREE_B,
            blob(".github/policy/validator.py"),
            blob("docs/copied.txt"),
        )
        changes, error = self.assert_diff_denied(base, candidate)
        self.assertEqual(changes[0].status, "C100")
        self.assertEqual(changes[0].old_path, ".github/policy/validator.py")
        self.assertEqual(changes[0].new_path, "docs/copied.txt")
        self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")

    def test_modified_rename_still_exposes_deleted_source(self):
        base = manifest(TREE_A, blob(".ci/helper.sh", BLOB_A))
        candidate = manifest(TREE_B, blob("docs/helper.txt", BLOB_B))
        changes, error = self.assert_diff_denied(base, candidate)
        self.assertEqual({change.status for change in changes}, {"A", "D"})
        self.assertTrue(
            any(change.old_path == ".ci/helper.sh" for change in changes)
        )
        self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")

    def test_deletion_of_control_test_or_lock_fails_closed(self):
        for path in (
            ".github/workflows/gate.yaml",
            ".github/policy/tests/test_gate.py",
            ".github/policy/locks/artifact.json",
            ".ci/ci-build.sh",
            ".github/actions/local/action.yml",
            ".gitattributes",
            "nested/.gitattributes",
            ".gitmodules",
        ):
            with self.subTest(path=path):
                base = manifest(TREE_A, blob(path))
                candidate = manifest(TREE_B)
                _, error = self.assert_diff_denied(base, candidate)
                self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")

    def test_yml_yaml_case_and_renamed_extension_cannot_route_around_policy(self):
        for path in (
            ".github/workflows/new.yml",
            ".github/workflows/new.yaml",
            ".GiThUb/WoRkFlOwS/new.YAML",
            ".github/workflows/new.txt",
        ):
            with self.subTest(path=path):
                base = manifest(TREE_A)
                candidate = manifest(TREE_B, blob(path))
                _, error = self.assert_diff_denied(base, candidate)
                self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")

    def test_mode_change_on_controlled_file_is_type_status_and_denied(self):
        base = manifest(TREE_A, blob(".github/policy/validator.py", mode="100644"))
        candidate = manifest(
            TREE_B, blob(".github/policy/validator.py", mode="100755")
        )
        changes, error = self.assert_diff_denied(base, candidate)
        self.assertEqual(changes[0].status, "T")
        self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")

    def test_symlink_and_submodule_changes_deny_anywhere(self):
        symlink = TreeEntry(
            path="docs/link",
            mode="120000",
            type="blob",
            sha=BLOB_A,
            size=6,
        )
        submodule = TreeEntry(
            path="vendor/repo",
            mode="160000",
            type="commit",
            sha=BLOB_B,
        )
        for entry in (symlink, submodule):
            with self.subTest(path=entry.path):
                base = manifest(TREE_A)
                candidate = manifest(TREE_B, entry)
                _, error = self.assert_diff_denied(base, candidate)
                self.assertIn(
                    error.code,
                    {"EXECUTABLE_SURFACE_CHANGE", "SOURCE_ADMISSION_REQUIRED"},
                )

    def test_executable_extensions_and_modes_outside_prefixes_deny(self):
        entries = (
            blob("tools/new-helper.py"),
            blob("tools/launch", mode="100755"),
            blob("nested/action.yaml"),
            blob("containers/Dockerfile"),
            blob("zlib/PKGBUILD"),
            blob("busybox/busybox.install"),
        )
        for entry in entries:
            with self.subTest(path=entry.path):
                base = manifest(TREE_A)
                candidate = manifest(TREE_B, entry)
                _, error = self.assert_diff_denied(base, candidate)
                if entry.path.casefold().endswith(("/action.yml", "/action.yaml")):
                    self.assertEqual(error.code, "SOURCE_ADMISSION_REQUIRED")
                else:
                    self.assertEqual(error.code, "EXECUTABLE_SURFACE_CHANGE")

    def test_shebang_without_script_extension_denies(self):
        base = manifest(TREE_A)
        candidate = manifest(TREE_B, blob("tools/runner", mode="100644"))
        _, error = self.assert_diff_denied(
            base, candidate, prefix=b"#!/usr/bin/env bash\n"
        )
        self.assertEqual(error.code, "EXECUTABLE_SURFACE_CHANGE")

    def test_expanded_executable_suffixes_deny(self):
        suffixes = (
            ".bash",
            ".zsh",
            ".pl",
            ".php",
            ".lua",
            ".vbs",
            ".wsf",
            ".jse",
            ".scr",
            ".mk",
        )
        for suffix in suffixes:
            for spelling in (suffix, suffix.upper(), suffix.capitalize()):
                path = f"package/build{spelling}"
                with self.subTest(path=path):
                    base = manifest(TREE_A)
                    # Mode 100644 and no shebang: the suffix alone must deny.
                    candidate = manifest(TREE_B, blob(path, mode="100644"))
                    _, error = self.assert_diff_denied(base, candidate)
                    self.assertEqual(error.code, "EXECUTABLE_SURFACE_CHANGE")

    def test_directly_executable_build_scripts_deny(self):
        names = (
            "GNUmakefile",
            "CMakeLists.txt",
            "meson.build",
            "SConstruct",
            "build.gradle",
            "Makefile",
            "justfile",
            "Dockerfile",
            "PKGBUILD",
        )
        for name in names:
            for spelling in (name, name.upper(), name.lower()):
                path = f"package/{spelling}"
                with self.subTest(path=path):
                    base = manifest(TREE_A)
                    candidate = manifest(TREE_B, blob(path, mode="100644"))
                    _, error = self.assert_diff_denied(base, candidate)
                    self.assertEqual(error.code, "EXECUTABLE_SURFACE_CHANGE")

    def test_shebangless_mode_100644_data_still_admits(self):
        for path in ("package/README.md", "package/data.txt", "package/notes.rst"):
            with self.subTest(path=path):
                base = manifest(TREE_A, blob(path, BLOB_A))
                candidate = manifest(TREE_B, blob(path, BLOB_B))
                changes = diff_manifests(base, candidate)
                assert_safe_diff(
                    changes,
                    [".github/policy/locks/"],
                    lambda path, entry, length: b"ordinary package metadata\n",
                )

    def test_plain_package_data_change_is_not_mislabeled_executable(self):
        base = manifest(TREE_A, blob("package/data.txt", BLOB_A))
        candidate = manifest(TREE_B, blob("package/data.txt", BLOB_B))
        changes = diff_manifests(base, candidate)
        assert_safe_diff(
            changes,
            [".github/policy/locks/"],
            lambda path, entry, length: b"ordinary package metadata\n",
        )
        self.assertEqual(changes[0].status, "M")

    def test_path_traversal_backslash_absolute_and_device_forms_reject(self):
        for path in (
            "../escape",
            "/absolute",
            "a//b",
            "a/./b",
            "a\\b",
            "C:/device",
            "name:stream",
        ):
            with self.subTest(path=path):
                with self.assertRaises(PolicyError):
                    normalize_policy_path(path)

    def test_unicode_normalization_and_case_collisions_reject(self):
        decomposed = "docs/cafe\u0301.txt"
        self.assert_policy_error(
            "PATH_NFC", lambda: normalize_policy_path(decomposed)
        )
        self.assert_policy_error(
            "TREE_CASE_COLLISION",
            lambda: manifest(
                TREE_A,
                blob("docs/Policy.txt", BLOB_A),
                blob("docs/policy.txt", BLOB_B),
            ),
        )

    def test_truncated_tree_api_rejects(self):
        payload = {"sha": TREE_A, "truncated": True, "tree": []}
        self.assert_policy_error(
            "TREE_TRUNCATED", lambda: TreeManifest.from_api(payload, TREE_A)
        )

    def test_lock_path_must_be_regular_and_symlink_free(self):
        candidate = manifest(
            TREE_A,
            tree(".github"),
            tree(".github/policy"),
            tree(".github/policy/locks"),
            TreeEntry(
                path=".github/policy/locks/release.json",
                mode="120000",
                type="blob",
                sha=BLOB_A,
                size=8,
            ),
        )
        self.assert_policy_error(
            "LOCK_PATH_TYPE",
            lambda: candidate.assert_symlink_free_path(
                ".github/policy/locks/release.json"
            ),
        )

    def test_all_control_names_are_case_insensitive(self):
        for path in (
            ".GITHUB/POLICY/x",
            ".Github/Actions/x",
            ".CI/x",
            ".github/CODEOWNERS",
            "nested/ACTION.YML",
            "nested/.gitattributes",
            ".gitmodules",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    path_is_controlled(path, [".github/policy/locks/"])
                )


if __name__ == "__main__":
    unittest.main()

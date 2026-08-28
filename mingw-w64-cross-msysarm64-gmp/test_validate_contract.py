#!/usr/bin/env python3
"""Mutation tests for the fail-closed GMP infrastructure contract."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from validate_contract import DENIED_RUNTIME, validate


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_root = Path(__file__).resolve().parent.parent

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        target_lane = self.root / "mingw-w64-cross-msysarm64-gmp"
        target_lane.mkdir()
        source_lane = self.source_root / "mingw-w64-cross-msysarm64-gmp"
        for source in source_lane.iterdir():
            if source.is_file() and source.name not in {
                "gmp-6.3.0.tar.xz",
                "gmp-6.3.0.tar.xz.sig",
                "mingw-w64-cross-msysarm64-gmp-6.3.0-2-x86_64.pkg.tar.zst",
                "mingw-w64-cross-msysarm64-gmp-devel-6.3.0-2-x86_64.pkg.tar.zst",
            }:
                shutil.copy2(source, target_lane / source.name)
        workflow_dir = self.root / ".github/workflows"
        workflow_dir.mkdir(parents=True)
        shutil.copy2(
            self.source_root / ".github/workflows/msysarm64-gmp.yml",
            workflow_dir / "msysarm64-gmp.yml",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def lane(self) -> Path:
        return self.root / "mingw-w64-cross-msysarm64-gmp"

    def load_lock(self) -> dict:
        return json.loads(
            (self.lane / "dependency-lock.json").read_text(encoding="utf-8")
        )

    def save_lock(self, lock: dict) -> None:
        (self.lane / "dependency-lock.json").write_text(
            json.dumps(lock, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.refresh_lock_checksum()

    def refresh_lock_checksum(self) -> None:
        import hashlib
        import re

        lock_hash = hashlib.sha256(
            (self.lane / "dependency-lock.json").read_bytes()
        ).hexdigest()
        path = self.lane / "PKGBUILD"
        text = path.read_text(encoding="utf-8")
        sums = list(
            re.finditer(r"(?m)^\s+'([0-9a-f]{64})'\s*$", text)
        )
        self.assertEqual(len(sums), 9)
        match = sums[8]
        text = text[: match.start(1)] + lock_hash + text[match.end(1) :]
        path.write_text(text, encoding="utf-8", newline="\n")

    def assert_rejected(self, message: str) -> None:
        with self.assertRaisesRegex(ValueError, message):
            validate(self.root)

    def test_accepts_blocked_infrastructure(self) -> None:
        validate(self.root)

    def test_rejects_revoked_runtime_escape(self) -> None:
        lock = self.load_lock()
        lock["canonical_runtime"]["version"] = DENIED_RUNTIME["version"]
        self.save_lock(lock)
        self.assert_rejected("revoked runtime escaped deny_tests")

    def test_rejects_reclassified_build(self) -> None:
        lock = self.load_lock()
        lock["build_classification"]["status"] = "buildable"
        self.save_lock(lock)
        self.assert_rejected("build classification")

    def test_rejects_candidate_admission(self) -> None:
        lock = self.load_lock()
        lock["package_candidates"]["records"][0]["admitted"] = True
        self.save_lock(lock)
        self.assert_rejected("candidate must remain unresolved")

    def test_rejects_duplicate_candidate_package(self) -> None:
        lock = self.load_lock()
        lock["package_candidates"]["records"][1]["package"] = (
            "mingw-w64-cross-msysarm64-gmp"
        )
        self.save_lock(lock)
        self.assert_rejected("package candidate set")

    def test_rejects_host_asset_manifest_mutation(self) -> None:
        lock = self.load_lock()
        lock["host_assets"][0]["sha256"] = "0" * 64
        self.save_lock(lock)
        self.assert_rejected("immutable host asset closure")

    def test_rejects_product_ownership_expansion(self) -> None:
        lock = self.load_lock()
        lock["product_ownership"]["product_residual_paths"].append(
            "usr/lib/libgmp.a"
        )
        self.save_lock(lock)
        self.assert_rejected("one-DLL ownership")

    def test_rejects_stale_local_source_checksum(self) -> None:
        path = self.lane / "gmp-consumer.c"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.assert_rejected("local source checksum is stale")

    def test_rejects_enabled_package_job(self) -> None:
        path = self.root / ".github/workflows/msysarm64-gmp.yml"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace("if: ${{ false }}", "if: ${{ true }}", 1),
            encoding="utf-8",
            newline="\n",
        )
        self.assert_rejected("not blocked at job scope")

    def test_rejects_unpinned_action(self) -> None:
        path = self.root / ".github/workflows/msysarm64-gmp.yml"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/checkout@v4",
            ),
            encoding="utf-8",
            newline="\n",
        )
        self.assert_rejected("action is not SHA-pinned")

    def test_rejects_bootstrap_admission_bypass(self) -> None:
        path = self.lane / "bootstrap-private-root.ps1"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(
                "$lock.canonical_runtime_admitted -ne $true",
                "$lock.canonical_runtime_admitted -ne $false",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        self.assert_rejected("bootstrap fail-closed")

    def test_rejects_revoked_lifecycle_input(self) -> None:
        path = self.lane / "validate-package-lifecycle.sh"
        path.write_text(
            path.read_text(encoding="utf-8")
            + f"\n# {DENIED_RUNTIME['release_tag']}\n",
            encoding="utf-8",
            newline="\n",
        )
        self.assert_rejected("lifecycle contains a revoked runtime")


if __name__ == "__main__":
    unittest.main()

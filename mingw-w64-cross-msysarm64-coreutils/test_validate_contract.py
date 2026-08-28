#!/usr/bin/env python3

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "validate_contract", PACKAGE_DIR / "validate_contract.py"
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (PACKAGE_DIR / "path-manifest.json").read_text(encoding="utf-8")
        )
        cls.lock = json.loads(
            (PACKAGE_DIR / "dependency-lock.json").read_text(encoding="utf-8")
        )

    def test_current_contract(self):
        VALIDATOR.validate_all(PACKAGE_DIR)

    def test_source_hash_mismatch_fails(self):
        lock = copy.deepcopy(self.lock)
        lock["sources"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(VALIDATOR.ContractError, "source hash mismatch"):
            VALIDATOR.validate_dependency_lock(lock)

    def test_metadata_mismatch_fails(self):
        lock = copy.deepcopy(self.lock)
        lock["personality"] = "CYGWIN"
        with self.assertRaisesRegex(VALIDATOR.ContractError, "personality mismatch"):
            VALIDATOR.validate_dependency_lock(lock)

    def test_path_overlap_fails(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["native_coreutils"]["paths"][0] = "usr/bin/cp.exe"
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "BusyBox overlaps native coreutils"
        ):
            VALIDATOR.validate_path_manifest(manifest)

    def test_semantic_lane_overlap_fails(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["native_coreutils"]["paths"][0] = "usr/bin/chmod.exe"
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "semantic proof.*overlaps native coreutils"
        ):
            VALIDATOR.validate_path_manifest(manifest)

    def test_dependency_removal_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["dependency_removals"] = ["usr/lib/coreutils/libstdbuf.dll"]
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "dependency removals are forbidden"
        ):
            VALIDATOR.validate_path_manifest(manifest)

    def test_historical_busybox_cannot_receive_admission_credit(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["busybox"]["admission_credit"] = True
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "historical identity received admission credit"
        ):
            VALIDATOR.validate_path_manifest(manifest)

    def test_unresolved_inputs_fail_admission(self):
        lock = copy.deepcopy(self.lock)
        lock["final_build_admitted"] = True
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "final build admitted with unresolved inputs"
        ):
            VALIDATOR.validate_dependency_lock(lock)

    def test_denied_busybox_identity_fails(self):
        lock = copy.deepcopy(self.lock)
        candidate = next(
            entry for entry in lock["execution_inputs"]
            if entry["name"] == "clean-busybox-payload"
        )
        candidate.update({
            "repository": "crutkas/build-extra",
            "commit": "50de8f12409d8cc8e16aef190629073db1a8606d",
            "workflow_run": 1,
            "release_tag": "denied",
            "asset_name": "denied.zip",
            "url": "https://example.invalid/denied.zip",
            "size": 1,
            "sha256": "0" * 64,
            "admitted": True,
        })
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "denied BusyBox lineage was admitted"
        ):
            VALIDATOR.validate_dependency_lock(lock)

    def test_diagnostic_toolchain_asset_cannot_be_admitted(self):
        lock = copy.deepcopy(self.lock)
        lock["toolchain_assets"][1]["admitted"] = True
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "diagnostic toolchain asset admitted"
        ):
            VALIDATOR.validate_dependency_lock(lock)

    def test_unowned_required_path_fails(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["required_unowned_paths"] = ["usr/bin/stat.exe"]
        with self.assertRaisesRegex(VALIDATOR.ContractError, "unowned"):
            VALIDATOR.validate_path_manifest(manifest)

    def test_ownership_manifest_mismatch_fails(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["baseline"]["ownership_manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            VALIDATOR.ContractError, "ownership manifest hash mismatch"
        ):
            VALIDATOR.validate_path_manifest(manifest)

    def test_wrong_architecture_fails(self):
        with self.assertRaisesRegex(VALIDATOR.ContractError, "architecture"):
            VALIDATOR.validate_pe_audit(
                "architecture: i386:x86-64, file format pei-x86-64",
                ["msys-2.0.dll"],
            )

    def test_wrong_import_fails(self):
        with self.assertRaisesRegex(VALIDATOR.ContractError, "foreign"):
            VALIDATOR.validate_pe_audit(
                "architecture: aarch64, file format pei-aarch64-little",
                ["msys-2.0.dll", "cygwin1.dll"],
            )

    def test_wrong_personality_fails(self):
        with self.assertRaisesRegex(VALIDATOR.ContractError, "personality"):
            VALIDATOR.validate_pe_audit(
                "architecture: aarch64, file format pei-aarch64-little",
                ["msys-2.0.dll"],
                personality="MINGW",
            )

    def test_missing_archive_armap_fails(self):
        with self.assertRaisesRegex(VALIDATOR.ContractError, "armap"):
            VALIDATOR.validate_archive_audit(
                "no symbols", [
                    "architecture: aarch64, file format pe-aarch64-little"
                ],
            )

    def test_private_root_argument_omission_fails(self):
        source = (
            PACKAGE_DIR / "validate-package-lifecycle.sh"
        ).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / PACKAGE_DIR.name
            package.mkdir()
            for name in ("PKGBUILD", "path-manifest.json",
                         "dependency-lock.json", "validate_contract.py"):
                (package / name).write_bytes((PACKAGE_DIR / name).read_bytes())
            (package / "validate-package-lifecycle.sh").write_text(
                source.replace("--hookdir", "--omitted-hookdir"),
                encoding="utf-8",
            )
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "arm64-coreutils.yml").write_bytes(
                (PACKAGE_DIR.parent / ".github" / "workflows" /
                 "arm64-coreutils.yml").read_bytes()
            )
            with self.assertRaisesRegex(
                VALIDATOR.ContractError, "private-root argument omitted"
            ):
                VALIDATOR.validate_text_contract(package)

    def test_unpinned_workflow_action_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / PACKAGE_DIR.name
            package.mkdir()
            for name in (
                "PKGBUILD", "path-manifest.json", "dependency-lock.json",
                "validate_contract.py", "validate-package-lifecycle.sh",
            ):
                (package / name).write_bytes((PACKAGE_DIR / name).read_bytes())
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            source = (
                PACKAGE_DIR.parent / ".github" / "workflows" /
                "arm64-coreutils.yml"
            ).read_text(encoding="utf-8")
            (workflow / "arm64-coreutils.yml").write_text(
                source.replace(
                    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                    "actions/checkout@v4",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VALIDATOR.ContractError, "workflow action is not SHA-pinned"
            ):
                VALIDATOR.validate_text_contract(package)

    def test_incomplete_native_evidence_fails(self):
        with self.assertRaisesRegex(VALIDATOR.ContractError, "incomplete"):
            VALIDATOR.validate_native_evidence({
                "host_architecture": "Arm64",
                "x64_process_or_module_count": 0,
                "result": "pass",
                "cases": ["permissions"],
            })


if __name__ == "__main__":
    unittest.main()

import copy
import unittest

import validate_contract


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.lock = validate_contract.load_lock()

    def admit_libiconv(self, lock):
        release = "msysarm64-libiconv-pr22-cfd0c449-20260827"
        lock["libiconv_admission"]["canonical_release_tag"] = release
        for index, dependency in enumerate(lock["target_dependency_assets"]):
            dependency["admitted"] = True
            dependency["release_tag"] = release
            dependency["asset_name"] = dependency["expected_asset_name"]
            dependency["size"] = index + 1
            dependency["sha256"] = f"{index + 1:064x}"
            dependency["record_sha256"] = validate_contract.libiconv_record_digest(
                dependency
            )
        lock["final_build_admitted"] = True

    def test_repository_contract(self):
        validate_contract.validate_lock(self.lock)
        validate_contract.validate_text_contracts()

    def test_provisional_libiconv_bytes_are_rejected(self):
        lock = copy.deepcopy(self.lock)
        dependency = lock["target_dependency_assets"][0]
        dependency["asset_name"] = "provisional.pkg.tar.zst"
        with self.assertRaisesRegex(AssertionError, "provisional dependency"):
            validate_contract.validate_lock(lock)

    def test_admitted_libiconv_requires_complete_identity(self):
        lock = copy.deepcopy(self.lock)
        dependency = lock["target_dependency_assets"][0]
        dependency["admitted"] = True
        with self.assertRaisesRegex(AssertionError, "asset name drift"):
            validate_contract.validate_lock(lock)

    def test_complete_libiconv_admission_is_accepted(self):
        lock = copy.deepcopy(self.lock)
        self.admit_libiconv(lock)
        validate_contract.validate_lock(lock)

    def test_final_build_cannot_be_enabled_early(self):
        lock = copy.deepcopy(self.lock)
        lock["final_build_admitted"] = True
        with self.assertRaisesRegex(AssertionError, "final admission"):
            validate_contract.validate_lock(lock)

    def test_libiconv_admission_hash_requires_both_splits(self):
        with self.assertRaisesRegex(AssertionError, "not fully admitted"):
            validate_contract.libiconv_admission_hash(self.lock)

    def test_libiconv_admission_hash_is_order_independent(self):
        lock = copy.deepcopy(self.lock)
        self.admit_libiconv(lock)
        forward = validate_contract.libiconv_admission_hash(lock)
        lock["target_dependency_assets"].reverse()
        reverse = validate_contract.libiconv_admission_hash(lock)
        self.assertEqual(forward, reverse)

    def test_string_false_is_not_a_boolean(self):
        for path in ("base", "dependency", "final"):
            with self.subTest(path=path):
                lock = copy.deepcopy(self.lock)
                if path == "base":
                    lock["private_host_base"]["admitted"] = "false"
                elif path == "dependency":
                    lock["target_dependency_assets"][0]["admitted"] = "false"
                else:
                    lock["final_build_admitted"] = "false"
                with self.assertRaisesRegex(AssertionError, "JSON boolean"):
                    validate_contract.validate_lock(lock)

    def test_swapped_libiconv_split_assets_are_rejected(self):
        lock = copy.deepcopy(self.lock)
        self.admit_libiconv(lock)
        records = lock["target_dependency_assets"]
        records[0]["asset_name"], records[1]["asset_name"] = (
            records[1]["asset_name"],
            records[0]["asset_name"],
        )
        with self.assertRaisesRegex(AssertionError, "asset name drift"):
            validate_contract.validate_lock(lock)

    def test_libiconv_provides_mutation_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["target_dependency_assets"][0]["provides"] = ["wrong=1"]
        with self.assertRaisesRegex(AssertionError, "static contract digest mismatch"):
            validate_contract.validate_lock(lock)

    def test_libiconv_owned_path_mutation_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["target_dependency_assets"][1]["owned_paths"].append("/usr/lib/host.a")
        with self.assertRaisesRegex(AssertionError, "static contract digest mismatch"):
            validate_contract.validate_lock(lock)

    def test_libiconv_full_record_digest_is_required(self):
        lock = copy.deepcopy(self.lock)
        self.admit_libiconv(lock)
        lock["target_dependency_assets"][0]["record_sha256"] = "0" * 64
        with self.assertRaisesRegex(AssertionError, "full record digest mismatch"):
            validate_contract.validate_lock(lock)

    def test_arbitrary_canonical_release_tag_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        self.admit_libiconv(lock)
        wrong_release = "msysarm64-libiconv-pr22-deadbeef-20991231"
        lock["libiconv_admission"]["canonical_release_tag"] = wrong_release
        for dependency in lock["target_dependency_assets"]:
            dependency["release_tag"] = wrong_release
            dependency["record_sha256"] = validate_contract.libiconv_record_digest(
                dependency
            )
        with self.assertRaisesRegex(AssertionError, "canonical libiconv release tag"):
            validate_contract.validate_lock(lock)

    def test_host_closure_digest_rejects_mutation(self):
        host_lock = validate_contract.load_lock(validate_contract.HOST_LOCK)
        host_lock["assets"][0]["size"] += 1
        with self.assertRaisesRegex(AssertionError, "host closure digest mismatch"):
            validate_contract.validate_host_lock(host_lock)

    def test_private_base_signature_cannot_be_partial(self):
        lock = copy.deepcopy(self.lock)
        lock["private_host_base"]["signature_sha256"] = "076f5623"
        with self.assertRaisesRegex(AssertionError, "base signature not pinned"):
            validate_contract.validate_lock(lock)

    def test_target_is_exact(self):
        lock = copy.deepcopy(self.lock)
        lock["target"] = "aarch64-w64-mingw32"
        with self.assertRaisesRegex(AssertionError, "wrong target"):
            validate_contract.validate_lock(lock)


if __name__ == "__main__":
    unittest.main()

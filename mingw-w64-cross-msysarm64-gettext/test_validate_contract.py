import copy
import unittest

import validate_contract


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.lock = validate_contract.load_lock()

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
        with self.assertRaisesRegex(AssertionError, "admitted dependency lacks"):
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
        for index, dependency in enumerate(lock["target_dependency_assets"]):
            dependency["admitted"] = True
            dependency["release_tag"] = "release"
            dependency["asset_name"] = f"asset-{index}.pkg.tar.zst"
            dependency["size"] = index + 1
            dependency["sha256"] = f"{index + 1:064x}"
        forward = validate_contract.libiconv_admission_hash(lock)
        lock["target_dependency_assets"].reverse()
        reverse = validate_contract.libiconv_admission_hash(lock)
        self.assertEqual(forward, reverse)

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

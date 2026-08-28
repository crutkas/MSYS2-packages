import subprocess
import sys
import unittest
from pathlib import Path


POLICY_DIR = Path(__file__).resolve().parents[1]
REPOSITORY = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(POLICY_DIR))

import validate as workflow_policy


NOW = workflow_policy.parse_now("2028-01-01T00:00:00Z")


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = workflow_policy.load_policy()

    def workflow_violations(self, name):
        return workflow_policy.validate_workflow(
            FIXTURES / name, FIXTURES, self.policy, NOW
        )

    def test_valid_producer(self):
        self.assertEqual([], self.workflow_violations("valid-producer.yml"))

    def test_valid_consumer_and_complete_lock(self):
        self.assertEqual([], self.workflow_violations("valid-consumer.yml"))

    def test_fail_closed_fixture_matrix(self):
        cases = {
            "invalid-push-head.yml": {
                "MISSING_PUSH_HEAD_CHECKOUT",
                "MISSING_PUSH_HEAD_VERIFY",
                "CHECKOUT_REF",
            },
            "invalid-pr-merge.yml": {
                "MISSING_PR_HEAD_CHECKOUT",
                "MISSING_PR_HEAD_VERIFY",
                "CHECKOUT_REF",
            },
            "invalid-action-pins.yml": {
                "ACTION_PIN",
                "LOCAL_ACTION",
                "UNREVIEWED_ACTION",
            },
            "invalid-unsupported-yaml.yml": {
                "UNSUPPORTED_YAML",
            },
            "invalid-explicit-scalar.yml": {
                "UNSUPPORTED_YAML",
            },
            "invalid-noncanonical-structure.yml": {
                "JOB_STRUCTURE",
            },
            "invalid-shared-root.yml": {
                "SHARED_MSYS_ROOT",
                "PRIVATE_MSYS_ROOT",
            },
            "invalid-package-without-root.yml": {
                "PACKAGE_TRANSACTION_ROOT",
            },
            "invalid-missing-evidence.yml": {
                "MISSING_CONSUMER_LOCK",
            },
            "invalid-cross-job.yml": {
                "MISSING_PUSH_HEAD_VERIFY",
                "EVIDENCE_RUNTIME_CHECK",
            },
        }
        for fixture, expected_codes in cases.items():
            with self.subTest(fixture=fixture):
                actual = {item.code for item in self.workflow_violations(fixture)}
                self.assertTrue(expected_codes <= actual, (expected_codes, actual))

    def test_expired_artifact_evidence_is_rejected(self):
        evidence = workflow_policy.validate_evidence(
            FIXTURES / "expired-consumer-lock.json", FIXTURES, NOW
        )
        self.assertIn("EVIDENCE_EXPIRED", {item.code for item in evidence.violations})

    def test_mutable_release_fields_are_rejected(self):
        evidence = workflow_policy.validate_evidence(
            FIXTURES / "mutable-release-lock.json", FIXTURES, NOW
        )
        actual = {item.code for item in evidence.violations}
        self.assertTrue(
            {
                "RELEASE_URL",
                "RELEASE_TAG_SHA",
                "RELEASE_ASSET_NAME",
                "RELEASE_ASSET_DIGEST",
                "RELEASE_ASSET_URL",
            }
            <= actual
        )

    def test_default_main_action_audit_is_complete(self):
        main = workflow_policy.load_workflow(
            REPOSITORY / ".github/workflows/main.yml", REPOSITORY
        )
        actual = [step.uses for step in main.steps if step.uses]
        audited = [
            item["uses"] for item in self.policy["action_resolution_audit"]
        ]
        self.assertEqual(actual, audited)
        self.assertTrue(
            all(
                item["status"]
                in {
                    "required_sha_known_mutable_use_rejected",
                    "unresolved_review",
                }
                for item in self.policy["action_resolution_audit"]
            )
        )

    def test_changed_default_main_is_currently_gated(self):
        violations = workflow_policy.validate_workflow(
            REPOSITORY / ".github/workflows/main.yml",
            REPOSITORY,
            self.policy,
            NOW,
        )
        actual = {item.code for item in violations}
        self.assertTrue({"ACTION_PIN", "PRIVATE_MSYS_ROOT"} <= actual)

    def test_control_workflow_uses_only_approved_action_pins(self):
        control = workflow_policy.load_workflow(
            REPOSITORY / self.policy["control_workflow"], REPOSITORY
        )
        action_violations = []
        for step in control.steps:
            if step.uses:
                action_violations.extend(
                    workflow_policy.validate_action(control, step, self.policy)
                )
        self.assertEqual([], action_violations)
        self.assertIn("push", control.triggers)
        self.assertIn("pull_request_target", control.triggers)
        self.assertNotIn("pull_request", control.triggers)
        self.assertIn("${{ github.event.after }}", control.text)
        self.assertIn(
            "${{ github.event.pull_request.head.sha }}", control.text
        )

    def test_verify_head_accepts_only_exact_head(self):
        expected = subprocess.run(
            ["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        script = POLICY_DIR / "verify_head.py"
        accepted = subprocess.run(
            [
                sys.executable,
                str(script),
                expected,
                "--repository",
                str(REPOSITORY),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        rejected = subprocess.run(
            [
                sys.executable,
                str(script),
                "0000000000000000000000000000000000000000",
                "--repository",
                str(REPOSITORY),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, accepted.returncode)
        self.assertEqual(1, rejected.returncode)


if __name__ == "__main__":
    unittest.main()

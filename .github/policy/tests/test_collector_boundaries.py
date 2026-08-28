from __future__ import annotations

import copy
import datetime as dt
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY_DIR))

from policy_lib import PolicyError  # noqa: E402
from validator import validate_event, verify_repository_rules  # noqa: E402


BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


class FakeRulesApi:
    def __init__(self, rules, enforcement="active"):
        self.rules = copy.deepcopy(rules)
        for rule in self.rules:
            rule.setdefault("ruleset_id", 42)
        self.rulesets = [
            {
                "id": 42,
                "enforcement": enforcement,
                "target": "branch",
            }
        ]
        self.trusted_now = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)

    def get(self, path):
        return copy.deepcopy(self.rules)

    def get_paginated(self, path):
        return copy.deepcopy(self.rulesets)


class CollectorBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = json.loads(
            (POLICY_DIR / "approval-graph.json").read_text(encoding="utf-8")
        )

    def event(self, fork=False):
        repository = self.graph["repository"]
        head_name = "contributor/MSYS2-packages" if fork else repository["full_name"]
        head_id = 999 if fork else repository["id"]
        return {
            "action": "synchronize",
            "number": 17,
            "repository": {
                "id": repository["id"],
                "full_name": repository["full_name"],
            },
            "pull_request": {
                "number": 17,
                "state": "open",
                "merged": False,
                "base": {
                    "sha": BASE_SHA,
                    "ref": "master",
                    "repo": {
                        "id": repository["id"],
                        "full_name": repository["full_name"],
                    },
                },
                "head": {
                    "sha": HEAD_SHA,
                    "repo": {
                        "id": head_id,
                        "full_name": head_name,
                        "html_url": f"https://github.com/{head_name}",
                    },
                },
            },
        }

    def assert_policy_error(self, code, function):
        with self.assertRaises(PolicyError) as raised:
            function()
        self.assertEqual(raised.exception.code, code)

    def test_fork_is_explicitly_modeled_as_data_only(self):
        info = validate_event(self.event(fork=True), self.graph)
        self.assertTrue(info["fork"])
        self.assertEqual(info["head_repository"], "contributor/MSYS2-packages")

    def test_same_repository_head_is_not_mislabeled_fork(self):
        info = validate_event(self.event(), self.graph)
        self.assertFalse(info["fork"])

    def test_event_rejects_wrong_repository_branch_host_state_and_sha(self):
        mutations = []
        event = self.event()
        event["repository"]["id"] = 1
        mutations.append(("EVENT_REPOSITORY", event))
        event = self.event()
        event["pull_request"]["base"]["ref"] = "feature"
        mutations.append(("EVENT_BASE_BRANCH", event))
        event = self.event(fork=True)
        event["pull_request"]["head"]["repo"]["html_url"] = "https://evil.invalid/x"
        mutations.append(("EVENT_HEAD_REPOSITORY", event))
        event = self.event()
        event["pull_request"]["state"] = "closed"
        mutations.append(("EVENT_PULL_REQUEST_STATE", event))
        event = self.event()
        event["pull_request"]["head"]["sha"] = "g" * 40
        mutations.append(("EVENT_HEAD_SHA", event))
        for code, mutated in mutations:
            with self.subTest(code=code):
                self.assert_policy_error(
                    code, lambda mutated=mutated: validate_event(mutated, self.graph)
                )

    def test_only_allowlisted_pr_activity_types_are_accepted(self):
        for action in ("closed", "labeled", "converted_to_draft"):
            event = self.event()
            event["action"] = action
            with self.subTest(action=action):
                self.assert_policy_error(
                    "EVENT_ACTION", lambda event=event: validate_event(event, self.graph)
                )

    def test_required_rule_and_actions_integration_are_authoritative(self):
        rules = [
            {"type": "pull_request", "parameters": {}},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {
                            "context": "workflow-policy / verify",
                            "integration_id": 15368,
                        }
                    ]
                },
            },
            {
                "type": "workflows",
                "parameters": {
                    "workflows": [
                        {
                            "repository_id": 1333319488,
                            "path": ".github/workflows/workflow-policy.yml",
                            "ref": "refs/heads/master",
                        }
                    ]
                },
            },
        ]
        verify_repository_rules(
            FakeRulesApi(rules), self.graph["repository"], "master", BASE_SHA
        )

    def test_missing_rule_check_or_integration_is_explicit_bootstrap_deny(self):
        cases = (
            [],
            [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {
                                "context": "workflow-policy / verify",
                                "integration_id": 15368,
                            }
                        ]
                    },
                }
            ],
            [
                {"type": "pull_request", "parameters": {}},
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {
                                "context": "workflow-policy / verify",
                                "integration_id": 1,
                            }
                        ]
                    },
                },
            ],
            [
                {"type": "pull_request", "parameters": {}},
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": False,
                        "required_status_checks": [
                            {
                                "context": "workflow-policy / verify",
                                "integration_id": 15368,
                            }
                        ],
                    },
                },
                {
                    "type": "workflows",
                    "parameters": {
                        "workflows": [
                            {
                                "repository_id": 1333319488,
                                "path": ".github/workflows/workflow-policy.yml",
                                "ref": "refs/heads/master",
                            }
                        ]
                    },
                },
            ],
        )
        for rules in cases:
            with self.subTest(rules=rules):
                self.assert_policy_error(
                    "BOOTSTRAP_NOT_ACTIVATED",
                    lambda rules=rules: verify_repository_rules(
                        FakeRulesApi(rules),
                        self.graph["repository"],
                        "master",
                        BASE_SHA,
                    ),
                )

    def test_named_actions_check_without_protected_workflow_rule_cannot_spoof_gate(self):
        rules = [
            {"type": "pull_request", "parameters": {}},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {
                            "context": "workflow-policy / verify",
                            "integration_id": 15368,
                        }
                    ],
                },
            },
        ]
        self.assert_policy_error(
            "BOOTSTRAP_NOT_ACTIVATED",
            lambda: verify_repository_rules(
                FakeRulesApi(rules), self.graph["repository"], "master", BASE_SHA
            ),
        )

    def test_required_workflow_rule_is_bound_to_repo_path_ref_and_optional_base_sha(self):
        status_rule = {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "required_status_checks": [
                    {
                        "context": "workflow-policy / verify",
                        "integration_id": 15368,
                    }
                ],
            },
        }
        for field, value in (
            ("repository_id", 1),
            ("path", ".github/workflows/spoof.yml"),
            ("ref", "refs/heads/attacker"),
            ("sha", "0" * 40),
        ):
            workflow = {
                "repository_id": 1333319488,
                "path": ".github/workflows/workflow-policy.yml",
                "ref": "refs/heads/master",
            }
            workflow[field] = value
            rules = [
                {"type": "pull_request", "parameters": {}},
                status_rule,
                {
                    "type": "workflows",
                    "parameters": {"workflows": [workflow]},
                },
            ]
            with self.subTest(field=field):
                self.assert_policy_error(
                    "BOOTSTRAP_NOT_ACTIVATED",
                    lambda rules=rules: verify_repository_rules(
                        FakeRulesApi(rules),
                        self.graph["repository"],
                        "master",
                        BASE_SHA,
                    ),
                )

    def test_inactive_or_evaluate_ruleset_cannot_activate_gate(self):
        rules = [
            {"type": "pull_request", "parameters": {}},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {
                            "context": "workflow-policy / verify",
                            "integration_id": 15368,
                        }
                    ],
                },
            },
            {
                "type": "workflows",
                "parameters": {
                    "workflows": [
                        {
                            "repository_id": 1333319488,
                            "path": ".github/workflows/workflow-policy.yml",
                            "ref": "refs/heads/master",
                        }
                    ]
                },
            },
        ]
        for enforcement in ("evaluate", "disabled"):
            with self.subTest(enforcement=enforcement):
                self.assert_policy_error(
                    "BOOTSTRAP_NOT_ACTIVATED",
                    lambda enforcement=enforcement: verify_repository_rules(
                        FakeRulesApi(rules, enforcement=enforcement),
                        self.graph["repository"],
                        "master",
                        BASE_SHA,
                    ),
                )

    def test_unique_non_actions_app_is_an_acceptable_synthetic_anchor(self):
        repository = copy.deepcopy(self.graph["repository"])
        repository["dedicated_check"]["integration_id"] = 987654
        rules = [
            {"type": "pull_request", "parameters": {}},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {
                            "context": "workflow-policy / verify",
                            "integration_id": 15368,
                        },
                        {
                            "context": "workflow-policy / anchored-admission",
                            "integration_id": 987654,
                        },
                    ],
                },
            },
        ]
        verify_repository_rules(
            FakeRulesApi(rules), repository, "master", BASE_SHA
        )

    def test_workflow_has_no_candidate_or_payload_fallback(self):
        workflow = (POLICY_DIR.parents[1] / ".github/workflows/workflow-policy.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("download-artifact", workflow)
        self.assertNotIn("head.sha }}", workflow)
        self.assertIn("pull_request_target:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn('python -B "$env:GITHUB_WORKSPACE', workflow)

    def test_removed_workflows_have_no_dispatch_write_remote_pipe_or_payload_jobs(self):
        workflows = POLICY_DIR.parents[1] / ".github/workflows"
        self.assertEqual(
            sorted(path.name for path in workflows.iterdir()),
            ["workflow-policy.yml"],
        )

    def test_validator_invocation_mode_cannot_write_bytecode_into_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = pathlib.Path(directory)
            shutil.copy2(POLICY_DIR / "validator.py", temporary / "validator.py")
            shutil.copy2(POLICY_DIR / "policy_lib.py", temporary / "policy_lib.py")
            subprocess.run(
                [sys.executable, "-B", str(temporary / "validator.py"), "--help"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertFalse((temporary / "__pycache__").exists())
            self.assertEqual(list(temporary.glob("*.pyc")), [])


if __name__ == "__main__":
    unittest.main()

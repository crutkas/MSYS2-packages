from __future__ import annotations

import ast
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

from policy_lib import (  # noqa: E402
    PolicyError,
    parse_workflow_yaml,
    validate_approval_graph,
)
from validator import validate_event, verify_repository_rules  # noqa: E402


BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


REPOSITORY = "crutkas/MSYS2-packages"
REPOSITORY_ID = 1333319488
WORKFLOW_PATH = ".github/workflows/workflow-policy.yml"
WORKFLOW_REF = "refs/heads/master"
RULE_SHA = "c" * 40
WORKFLOW_BLOB = "d" * 40
TREE_SHA = "e" * 40


def workflow_rule(**overrides):
    entry = {
        "repository_id": REPOSITORY_ID,
        "path": WORKFLOW_PATH,
        "ref": WORKFLOW_REF,
        "sha": RULE_SHA,
    }
    entry.update(overrides.pop("entry", {}))
    for key in list(overrides):
        if key == "drop":
            for name in overrides.pop("drop"):
                entry.pop(name, None)
    return {"type": "workflows", "parameters": {"workflows": [entry]}}


def status_rule(context="workflow-policy / verify", integration_id=15368, strict=True):
    return {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": strict,
            "required_status_checks": [
                {"context": context, "integration_id": integration_id}
            ],
        },
    }


def complete_rules():
    return [
        {"type": "pull_request", "parameters": {}},
        {"type": "non_fast_forward", "parameters": {}},
        {"type": "deletion", "parameters": {}},
        status_rule(),
        workflow_rule(),
    ]


class FakeRulesApi:
    """Models the live ruleset, rules, compare, commit, and tree endpoints."""

    def __init__(
        self,
        rules,
        enforcement="active",
        target="branch",
        source_type="Repository",
        source=REPOSITORY,
        ref_include=None,
        ref_exclude=None,
        bypass_actors=None,
        conditions_extra=None,
        ruleset_id=42,
        rule_sha=RULE_SHA,
        workflow_blob=WORKFLOW_BLOB,
        topology="ahead",
        detail_id=None,
    ):
        self.rules = copy.deepcopy(rules)
        for rule in self.rules:
            rule.setdefault("ruleset_id", ruleset_id)
        self.ruleset_id = ruleset_id
        self.summary = {
            "id": ruleset_id,
            "name": "policy",
            "enforcement": enforcement,
            "target": target,
        }
        conditions = {
            "ref_name": {
                "include": ["refs/heads/master"] if ref_include is None else ref_include,
                "exclude": [] if ref_exclude is None else ref_exclude,
            }
        }
        if conditions_extra:
            conditions.update(conditions_extra)
        self.detail = {
            "id": ruleset_id if detail_id is None else detail_id,
            "name": "policy",
            "enforcement": enforcement,
            "target": target,
            "source_type": source_type,
            "source": source,
            "bypass_actors": [] if bypass_actors is None else bypass_actors,
            "conditions": conditions,
        }
        self.rule_sha = rule_sha
        self.workflow_blob = workflow_blob
        self.topology = topology
        self.trusted_now = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)

    def get(self, path):
        if path.startswith(f"/repos/{REPOSITORY}/rules/branches/"):
            return copy.deepcopy(self.rules)
        if path == f"/repos/{REPOSITORY}/rulesets/{self.ruleset_id}":
            return copy.deepcopy(self.detail)
        if path.startswith(f"/repos/{REPOSITORY}/rulesets/"):
            raise PolicyError("GITHUB_API_HTTP", "unknown ruleset")
        if path.startswith(f"/repos/{REPOSITORY}/compare/"):
            ancestor = path.rsplit("/", 1)[-1].split("...")[0]
            return {
                "status": self.topology,
                "merge_base_commit": {"sha": ancestor},
            }
        if path.startswith(f"/repos/{REPOSITORY}/git/commits/"):
            return {
                "sha": path.rsplit("/", 1)[-1],
                "tree": {"sha": TREE_SHA},
            }
        if path.startswith(f"/repos/{REPOSITORY}/git/trees/"):
            return {
                "sha": TREE_SHA,
                "truncated": False,
                "tree": [
                    {
                        "path": WORKFLOW_PATH,
                        "mode": "100644",
                        "type": "blob",
                        "sha": self.workflow_blob,
                        "size": 10,
                    }
                ],
            }
        raise PolicyError("GITHUB_API_HTTP", f"unexpected path {path}")

    def get_paginated(self, path):
        if path == f"/repos/{REPOSITORY}/rulesets":
            return [copy.deepcopy(self.summary)]
        raise PolicyError("GITHUB_API_HTTP", f"unexpected page {path}")


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

    def rules_repository(self):
        return self.graph["repository"]

    def activate(self, api):
        verify_repository_rules(
            api, self.rules_repository(), "master", BASE_SHA, WORKFLOW_BLOB
        )

    def assert_not_activated(self, api):
        self.assert_policy_error("BOOTSTRAP_NOT_ACTIVATED", lambda: self.activate(api))

    def test_repository_sourced_active_ruleset_grants_authority(self):
        self.activate(FakeRulesApi(complete_rules()))

    def test_live_repo_with_no_rulesets_stays_dormant(self):
        # This is today's state: GET /rulesets returns [].
        class EmptyApi(FakeRulesApi):
            def get_paginated(self, path):
                return []

        self.assert_not_activated(EmptyApi(complete_rules()))

    def test_every_required_rule_type_is_load_bearing(self):
        for omitted in (
            "pull_request",
            "non_fast_forward",
            "deletion",
            "required_status_checks",
        ):
            rules = [rule for rule in complete_rules() if rule["type"] != omitted]
            with self.subTest(omitted=omitted):
                self.assert_not_activated(FakeRulesApi(rules))

    def test_workflow_rule_fields_are_exact(self):
        cases = {
            "wrong-repo": {"repository_id": 1},
            "bool-repo": {"repository_id": True},
            "string-repo": {"repository_id": "1333319488"},
            "wrong-path": {"path": ".github/workflows/other.yml"},
            "wrong-ref": {"ref": "refs/heads/release"},
            "null-sha": {"sha": None},
            "short-sha": {"sha": "c" * 7},
            "upper-sha": {"sha": "C" * 40},
            "bool-sha": {"sha": True},
            "extra-field": {"enabled": True},
        }
        for label, entry in cases.items():
            rules = [rule for rule in complete_rules() if rule["type"] != "workflows"]
            rules.append(workflow_rule(entry=entry))
            with self.subTest(label=label):
                self.assert_not_activated(FakeRulesApi(rules))

    def test_missing_workflow_rule_field_denies(self):
        for dropped in ("repository_id", "path", "ref", "sha"):
            rules = [rule for rule in complete_rules() if rule["type"] != "workflows"]
            entry = {
                "repository_id": REPOSITORY_ID,
                "path": WORKFLOW_PATH,
                "ref": WORKFLOW_REF,
                "sha": RULE_SHA,
            }
            entry.pop(dropped)
            rules.append({"type": "workflows", "parameters": {"workflows": [entry]}})
            with self.subTest(dropped=dropped):
                self.assert_not_activated(FakeRulesApi(rules))

    def test_workflow_rule_must_pin_a_commit_containing_the_approved_blob(self):
        self.assert_not_activated(
            FakeRulesApi(complete_rules(), workflow_blob="f" * 40)
        )

    def test_workflow_rule_commit_must_be_reachable_from_the_protected_base(self):
        for topology in ("diverged", "behind"):
            with self.subTest(topology=topology):
                self.assert_not_activated(
                    FakeRulesApi(complete_rules(), topology=topology)
                )

    def test_multiple_or_empty_workflow_entries_deny(self):
        for workflows in ([], [{}, {}]):
            rules = [rule for rule in complete_rules() if rule["type"] != "workflows"]
            rules.append({"type": "workflows", "parameters": {"workflows": workflows}})
            with self.subTest(workflows=workflows):
                self.assert_not_activated(FakeRulesApi(rules))

    def test_disabled_or_evaluate_ruleset_cannot_activate(self):
        for enforcement in ("disabled", "evaluate", "", None):
            with self.subTest(enforcement=enforcement):
                self.assert_not_activated(
                    FakeRulesApi(complete_rules(), enforcement=enforcement)
                )

    def test_non_branch_target_cannot_activate(self):
        for target in ("tag", "push", "repository", None):
            with self.subTest(target=target):
                self.assert_not_activated(
                    FakeRulesApi(complete_rules(), target=target)
                )

    def test_org_or_inherited_ruleset_is_not_modelled_authority(self):
        for source_type in ("Organization", "Enterprise", None):
            with self.subTest(source_type=source_type):
                self.assert_not_activated(
                    FakeRulesApi(complete_rules(), source_type=source_type)
                )

    def test_foreign_ruleset_source_cannot_activate(self):
        self.assert_not_activated(
            FakeRulesApi(complete_rules(), source="attacker/repo")
        )

    def test_ref_condition_must_be_exactly_the_protected_branch(self):
        cases = (
            ["refs/heads/*"],
            ["~ALL"],
            ["~DEFAULT_BRANCH"],
            ["refs/heads/master", "refs/heads/release"],
            [],
            ["refs/heads/Master"],
        )
        for include in cases:
            with self.subTest(include=include):
                self.assert_not_activated(
                    FakeRulesApi(complete_rules(), ref_include=include)
                )

    def test_ref_exclusion_or_extra_condition_denies(self):
        self.assert_not_activated(
            FakeRulesApi(complete_rules(), ref_exclude=["refs/heads/master"])
        )
        self.assert_not_activated(
            FakeRulesApi(
                complete_rules(),
                conditions_extra={"repository_name": {"include": ["*"]}},
            )
        )

    def test_any_bypass_actor_denies(self):
        for actors in (
            [{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}],
            [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}],
            [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
        ):
            with self.subTest(actors=actors):
                self.assert_not_activated(
                    FakeRulesApi(complete_rules(), bypass_actors=actors)
                )

    def test_ruleset_detail_identity_must_match_summary(self):
        self.assert_not_activated(FakeRulesApi(complete_rules(), detail_id=99))

    def test_rules_from_an_unlisted_ruleset_are_ignored(self):
        rules = complete_rules()
        for rule in rules:
            rule["ruleset_id"] = 999
        self.assert_not_activated(FakeRulesApi(rules))

    def test_inherited_rule_source_type_is_ignored(self):
        rules = complete_rules()
        for rule in rules:
            rule["ruleset_source_type"] = "Organization"
        self.assert_not_activated(FakeRulesApi(rules))

    def test_duplicate_conflicting_rules_deny(self):
        rules = complete_rules() + [workflow_rule()]
        self.assert_policy_error(
            "BOOTSTRAP_RULES", lambda: self.activate(FakeRulesApi(rules))
        )

    def test_strictness_and_integration_are_exact(self):
        for label, rule in {
            "not-strict": status_rule(strict=False),
            "bool-strict": status_rule(strict=1),
            "wrong-integration": status_rule(integration_id=1),
            "bool-integration": status_rule(integration_id=True),
            "wrong-context": status_rule(context="ci / build"),
        }.items():
            rules = [
                item
                for item in complete_rules()
                if item["type"] != "required_status_checks"
            ]
            rules.append(rule)
            with self.subTest(label=label):
                self.assert_not_activated(FakeRulesApi(rules))

    def test_generic_actions_named_check_alone_cannot_spoof_the_gate(self):
        # Everything present EXCEPT the workflow rule: a candidate workflow can
        # publish a check with this exact name and integration, so the named
        # check alone must never be sufficient.
        rules = [rule for rule in complete_rules() if rule["type"] != "workflows"]
        self.assert_not_activated(FakeRulesApi(rules))

    def test_candidate_cannot_forge_authority_by_naming_its_own_workflow(self):
        rules = [rule for rule in complete_rules() if rule["type"] != "workflows"]
        rules.append(
            workflow_rule(entry={"repository_id": 987654321, "path": ".github/workflows/candidate.yml"})
        )
        self.assert_not_activated(FakeRulesApi(rules))

    def test_dedicated_non_actions_app_remains_an_alternative_anchor(self):
        repository = copy.deepcopy(self.graph["repository"])
        repository["dedicated_check"]["integration_id"] = 99999
        rules = [
            rule
            for rule in complete_rules()
            if rule["type"] not in {"workflows", "required_status_checks"}
        ]
        rules.append(
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
                            "integration_id": 99999,
                        },
                    ],
                },
            }
        )
        verify_repository_rules(
            FakeRulesApi(rules), repository, "master", BASE_SHA, WORKFLOW_BLOB
        )

    def test_dedicated_anchor_cannot_reuse_the_actions_integration(self):
        repository = copy.deepcopy(self.graph["repository"])
        repository["dedicated_check"]["integration_id"] = 15368
        rules = [rule for rule in complete_rules() if rule["type"] != "workflows"]
        rules.append(
            status_rule(
                context="workflow-policy / anchored-admission", integration_id=15368
            )
        )
        self.assert_policy_error(
            "GRAPH_CHECK",
            lambda: validate_approval_graph(
                dict(self.graph, repository=repository)
            ),
        )

    def test_graph_models_repository_sourced_ruleset_authority(self):
        model = self.graph["repository"]["required_workflow_ruleset"]
        self.assertEqual(model["source_type"], "Repository")
        self.assertEqual(model["enforcement"], "active")
        self.assertEqual(model["target"], "branch")
        self.assertEqual(model["ref"], "refs/heads/master")
        validate_approval_graph(copy.deepcopy(self.graph))

    def test_graph_ruleset_model_fields_are_exact(self):
        for key, value in (
            ("source_type", "Organization"),
            ("enforcement", "evaluate"),
            ("target", "tag"),
            ("ref", "refs/heads/main"),
        ):
            graph = copy.deepcopy(self.graph)
            graph["repository"]["required_workflow_ruleset"][key] = value
            with self.subTest(key=key):
                self.assert_policy_error(
                    "GRAPH_RULESET", lambda graph=graph: validate_approval_graph(graph)
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

    def test_pull_request_target_is_pinned_to_the_protected_base_branch(self):
        workflow = (POLICY_DIR.parents[1] / ".github/workflows/workflow-policy.yml").read_text(
            encoding="utf-8"
        )
        document = parse_workflow_yaml(workflow)
        trigger = document["on"]["pull_request_target"]
        self.assertEqual(trigger["branches"], ["master"])
        self.assertEqual(set(document["on"]), {"pull_request_target"})

    def test_local_base_is_verified_before_graph_and_live_rules(self):
        source = (POLICY_DIR / "validator.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        collect = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "collect"
        )
        order = sorted(
            (node.lineno, node.func.id)
            for node in ast.walk(collect)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id
            in {
                "verify_local_base",
                "load_local_graph",
                "validate_event",
                "verify_repository_rules",
                "verify_live_identity",
                "verify_approval_surface",
                "verify_locks",
            }
        )
        names = [name for _, name in order]
        self.assertEqual(names[0], "verify_local_base")
        for later in (
            "load_local_graph",
            "validate_event",
            "verify_repository_rules",
            "verify_live_identity",
            "verify_approval_surface",
            "verify_locks",
        ):
            with self.subTest(call=later):
                self.assertIn(later, names)
                self.assertLess(
                    names.index("verify_local_base"),
                    names.index(later),
                    f"{later} must not run before the base checkout is proven",
                )

    def test_tree_and_commit_shas_are_validated_before_url_interpolation(self):
        source = (POLICY_DIR / "validator.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        for name in ("_commit_and_tree", "_tree_manifest"):
            function = next(
                node
                for node in module.body
                if isinstance(node, ast.FunctionDef) and node.name == name
            )
            guard_lines = [
                node.lineno
                for node in ast.walk(function)
                if isinstance(node, ast.Attribute)
                and node.attr == "fullmatch"
                and isinstance(node.value, ast.Name)
                and node.value.id == "SHA1_RE"
            ]
            request_lines = [
                node.lineno
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
            ]
            with self.subTest(function=name):
                self.assertTrue(guard_lines, f"{name} must apply SHA1_RE")
                self.assertTrue(request_lines)
                self.assertLess(min(guard_lines), min(request_lines))

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

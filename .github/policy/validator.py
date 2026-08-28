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
    ACQUISITION_MARKERS,
    APPROVED_ACTIONS,
    CAPABILITY_VOCABULARY,
    DANGEROUS_GIT_SUBCOMMANDS,
    FORBIDDEN_PYTHON_BUILTINS,
    FORBIDDEN_PYTHON_CALLS,
    FORBIDDEN_PYTHON_MODULES,
    MODELED_GIT_SUBCOMMANDS,
    NETWORK_COMMANDS,
    NETWORK_PYTHON_MODULES,
    PACKAGE_COMMANDS,
    PROCESS_PYTHON_MODULES,
    SURFACE_CODES,
    SURFACE_ORDER,
    PolicyError,
    REPOSITORY_RE,
    SHA1_RE,
    SUBPROCESS_ENTRYPOINTS,
    TreeEntry,
    TreeManifest,
    assert_safe_diff,
    decode_github_blob,
    diff_manifests,
    exact_equal,
    is_exact_int,
    is_positive_id,
    normalize_policy_path,
    parse_json_strict,
    parse_workflow_yaml,
    require,
    require_exact_keys,
    validate_approval_graph,
    validate_workflow_document,
    verify_artifact_lock,
    verify_release_lock,
    verify_trusted_topology,
)


MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_BLOB_BYTES = 4 * 1024 * 1024
ALLOWED_PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}
TRUSTED_GIT_PATHS = (
    r"C:\Program Files\Git\cmd\git.exe",
    r"C:\Program Files\Git\bin\git.exe",
    r"C:\Program Files (x86)\Git\cmd\git.exe",
    "/usr/bin/git",
)


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
                "User-Agent": "msys2-workflow-policy-v3",
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


GIT_COMMANDS = {
    "head": ("rev-parse", "--verify", "HEAD"),
    "head-tree": ("rev-parse", "--verify", "HEAD^{tree}"),
    "graph-blob": ("rev-parse", "--verify", "HEAD:.github/policy/approval-graph.json"),
    "status": ("status", "--porcelain=v2", "--untracked-files=all"),
    "origin": ("remote", "get-url", "origin"),
}
GIT_COMMAND_KEYS = frozenset(GIT_COMMANDS)
# Git honours dozens of environment variables that redirect the repository,
# inject configuration, or run arbitrary programs (GIT_DIR, GIT_WORK_TREE,
# GIT_INDEX_FILE, GIT_CONFIG*, GIT_SSH*, GIT_PROXY_COMMAND, GIT_EXTERNAL_DIFF,
# GIT_ALTERNATE_OBJECT_DIRECTORIES, core.fsmonitor, ...). The policy therefore
# builds the child environment from scratch instead of filtering the parent's.
GIT_ENVIRONMENT_ALLOWLIST = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP")
GIT_FORCED_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_ALLOW_PROTOCOL": "none",
    "HOME": "",
    "XDG_CONFIG_HOME": "",
    "USERPROFILE": "",
    "HOMEDRIVE": "",
    "HOMEPATH": "",
    "LC_ALL": "C",
}
# Config that disables every remaining hook/command execution vector, applied on
# the command line so no config file can override it.
GIT_FORCED_CONFIG = (
    "core.fsmonitor=",
    "core.hooksPath=",
    "core.askPass=",
    "core.editor=false",
    "core.pager=cat",
    "core.sshCommand=",
    "core.alternateRefsCommand=",
    "core.symlinks=false",
    "diff.external=",
    "protocol.allow=never",
    "uploadpack.packObjectsHook=",
    "credential.helper=",
    "safe.directory=*",
    "gc.auto=0",
    "advice.detachedHead=false",
)


def _git_executable() -> str:
    """Resolve git to an absolute path under the trusted system root."""
    override = os.environ.get("POLICY_GIT_EXECUTABLE")
    candidates = [override] if override else list(TRUSTED_GIT_PATHS)
    for candidate in candidates:
        if candidate and os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
    raise PolicyError(
        "BASE_CHECKOUT_GIT",
        "no absolute trusted git executable is available; refusing to resolve "
        "git through PATH",
    )


def _git_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in GIT_ENVIRONMENT_ALLOWLIST
        if name in os.environ
    }
    environment.update(GIT_FORCED_ENVIRONMENT)
    # A deliberately minimal PATH: git must not discover helper programs.
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR") or ""
    environment["PATH"] = (
        os.pathsep.join([os.path.join(system_root, "System32"), system_root])
        if system_root
        else ""
    )
    # Forced configuration is supplied through the scrubbed environment rather
    # than argv, so the command line stays a fixed literal. GIT_CONFIG_COUNT is
    # authoritative here precisely because the environment was rebuilt from
    # scratch; nothing the caller exported can add or renumber an entry.
    for index, setting in enumerate(GIT_FORCED_CONFIG):
        key, _, value = setting.partition("=")
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    environment["GIT_CONFIG_COUNT"] = str(len(GIT_FORCED_CONFIG))
    return environment


def _run_git(checkout: pathlib.Path, command: str) -> str:
    require(
        command in GIT_COMMANDS,
        "BASE_CHECKOUT_GIT",
        f"unmodelled git command key {command!r}",
    )
    first, second, third = GIT_COMMANDS[command]
    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), first, second, third],
            executable=_git_executable(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
            env=_git_environment(),
            cwd=str(checkout),
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PolicyError(
            "BASE_CHECKOUT_GIT", f"git {command} failed: {error}"
        ) from error
    return completed.stdout.strip()


def verify_local_base(
    checkout: pathlib.Path,
    repository: str,
    expected_commit: str,
) -> str:
    require(checkout.is_absolute(), "BASE_CHECKOUT_PATH", "checkout must be absolute")
    require(checkout.is_dir(), "BASE_CHECKOUT_PATH", "checkout is absent")
    require(not checkout.is_symlink(), "BASE_CHECKOUT_PATH", "checkout is a symlink")
    require(
        REPOSITORY_RE.fullmatch(repository) is not None,
        "BASE_CHECKOUT_ORIGIN",
        "bound repository name is invalid",
    )
    require(
        SHA1_RE.fullmatch(expected_commit) is not None,
        "BASE_CHECKOUT_HEAD",
        "expected base commit is not a lowercase SHA-1",
    )
    origin = _run_git(checkout, "origin")
    require(
        origin
        in {
            f"https://github.com/{repository}",
            f"https://github.com/{repository}.git",
        },
        "BASE_CHECKOUT_ORIGIN",
        "local protected base origin changed",
    )
    require(
        _run_git(checkout, "head") == expected_commit,
        "BASE_CHECKOUT_HEAD",
        "local protected base HEAD changed",
    )
    local_tree = _run_git(checkout, "head-tree")
    require(
        SHA1_RE.fullmatch(local_tree) is not None,
        "BASE_CHECKOUT_TREE",
        "local protected base tree is not a lowercase SHA-1",
    )
    require(
        _run_git(checkout, "status") == "",
        "BASE_CHECKOUT_DIRTY",
        "local protected base is dirty",
    )
    return local_tree


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
        and is_exact_int(head_repository.get("id"))
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
        is_positive_id(number),
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


def _ruleset_detail(
    api: HttpGitHubApi, repository: Mapping[str, Any], ruleset_id: int
) -> Mapping[str, Any]:
    require(
        is_positive_id(ruleset_id),
        "BOOTSTRAP_RULES",
        "ruleset id is not an exact positive integer",
    )
    detail = api.get(f"/repos/{repository['full_name']}/rulesets/{ruleset_id}")
    require(isinstance(detail, dict), "BOOTSTRAP_RULES", "ruleset shape changed")
    return detail


def _ruleset_is_authoritative(
    detail: Mapping[str, Any], repository: Mapping[str, Any], model: Mapping[str, Any]
) -> bool:
    """A ruleset may carry authority only if every framing field is exact.

    Enforcement must be active (never `disabled` or `evaluate`), the ruleset
    must be sourced from this repository (an organization or inherited ruleset
    is a different trust domain and is not modelled), it must target branches,
    it must name exactly the protected ref with no wildcard and no exclusion,
    and it must grant no bypass to anyone.
    """
    if detail.get("enforcement") != model["enforcement"]:
        return False
    if detail.get("target") != model["target"]:
        return False
    if detail.get("source_type") != model["source_type"]:
        return False
    if detail.get("source") != repository["full_name"]:
        return False
    bypass = detail.get("bypass_actors")
    if bypass is None:
        bypass = []
    if not isinstance(bypass, list) or bypass:
        return False
    conditions = detail.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    if not exact_equal(ref_name.get("include"), [model["ref"]]):
        return False
    exclude = ref_name.get("exclude")
    if exclude is None:
        exclude = []
    if not exact_equal(exclude, []):
        return False
    if set(conditions) - {"ref_name"}:
        return False
    return True


def _workflow_rule_matches(
    rule: Mapping[str, Any], repository: Mapping[str, Any]
) -> str | None:
    """Exact commit SHA named by a well-formed `workflows` rule, else None."""
    parameters = rule.get("parameters")
    if not isinstance(parameters, dict):
        return None
    workflows = parameters.get("workflows")
    if not isinstance(workflows, list) or len(workflows) != 1:
        return None
    entry = workflows[0]
    if not isinstance(entry, dict):
        return None
    if set(entry) - {"repository_id", "path", "ref", "sha"}:
        return None
    if not is_exact_int(entry.get("repository_id")):
        return None
    if entry["repository_id"] != repository["id"]:
        return None
    if entry.get("path") != repository["required_workflow"]:
        return None
    if entry.get("ref") != repository["required_workflow_ref"]:
        return None
    sha = entry.get("sha")
    # A null or short SHA would let the rule float to whatever master points at,
    # which is exactly the authority a candidate could try to influence.
    if not isinstance(sha, str) or SHA1_RE.fullmatch(sha) is None:
        return None
    return sha


def _workflow_rule_is_anchored(
    api: HttpGitHubApi,
    repository: Mapping[str, Any],
    sha: str,
    protected_base_sha: str,
    workflow_blob: str,
) -> bool:
    """The pinned commit must contain the exact approved workflow blob.

    It must also be reachable from the protected base, so a rule cannot pin some
    unrelated or abandoned commit that merely happens to exist.
    """
    try:
        verify_trusted_topology(api, repository["full_name"], sha, protected_base_sha)
        _, tree_sha = _commit_and_tree(api, repository["full_name"], sha)
        manifest = _tree_manifest(api, repository["full_name"], tree_sha)
        entry = manifest.assert_symlink_free_path(repository["required_workflow"])
    except PolicyError:
        return False
    return entry.mode == "100644" and entry.sha == workflow_blob


def verify_repository_rules(
    api: HttpGitHubApi,
    repository: Mapping[str, Any],
    branch: str,
    protected_base_sha: str,
    workflow_blob: str | None = None,
) -> None:
    model = repository["required_workflow_ruleset"]
    quoted_branch = urllib.parse.quote(branch, safe="")
    rules = api.get(f"/repos/{repository['full_name']}/rules/branches/{quoted_branch}")
    require(isinstance(rules, list), "BOOTSTRAP_RULES", "rules API shape changed")
    rulesets = api.get_paginated(f"/repos/{repository['full_name']}/rulesets")
    require(isinstance(rulesets, list), "BOOTSTRAP_RULES", "rulesets API shape changed")

    authoritative: set[int] = set()
    for summary in rulesets:
        if not isinstance(summary, dict):
            continue
        ruleset_id = summary.get("id")
        if not is_positive_id(ruleset_id):
            continue
        if summary.get("enforcement") != model["enforcement"]:
            continue
        if summary.get("target") != model["target"]:
            continue
        detail = _ruleset_detail(api, repository, ruleset_id)
        if detail.get("id") != ruleset_id:
            continue
        if _ruleset_is_authoritative(detail, repository, model):
            authoritative.add(ruleset_id)

    required_check = repository["required_check"]
    integration_id = repository["github_actions_integration_id"]
    dedicated_check = repository["dedicated_check"]
    seen_types: dict[str, int] = {}
    has_pull_request_rule = False
    has_required_check = False
    has_required_workflow = False
    has_dedicated_check = False
    has_non_fast_forward = False
    has_deletion = False

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("ruleset_id") not in authoritative:
            continue
        # An organization or inherited rule reaching this branch is a different
        # trust domain; it is not modelled and must not contribute authority.
        if rule.get("ruleset_source_type") not in {None, model["source_type"]}:
            continue
        if rule.get("ruleset_source") not in {None, repository["full_name"]}:
            continue
        rule_type = rule.get("type")
        if not isinstance(rule_type, str):
            continue
        seen_types[rule_type] = seen_types.get(rule_type, 0) + 1

        if rule_type == "pull_request":
            has_pull_request_rule = True
        elif rule_type == "non_fast_forward":
            has_non_fast_forward = True
        elif rule_type == "deletion":
            has_deletion = True
        elif rule_type == "workflows":
            sha = _workflow_rule_matches(rule, repository)
            if sha is not None and workflow_blob is not None:
                has_required_workflow = _workflow_rule_is_anchored(
                    api, repository, sha, protected_base_sha, workflow_blob
                )
        elif rule_type == "required_status_checks":
            parameters = rule.get("parameters")
            if not isinstance(parameters, dict):
                continue
            if parameters.get("strict_required_status_checks_policy") is not True:
                continue
            checks = parameters.get("required_status_checks")
            if not isinstance(checks, list):
                continue
            for check in checks:
                if not isinstance(check, dict):
                    continue
                if (
                    check.get("context") == required_check
                    and is_exact_int(check.get("integration_id"))
                    and check.get("integration_id") == integration_id
                ):
                    has_required_check = True
                if (
                    dedicated_check["integration_id"] is not None
                    and check.get("context") == dedicated_check["context"]
                    and is_exact_int(check.get("integration_id"))
                    and check.get("integration_id") == dedicated_check["integration_id"]
                ):
                    has_dedicated_check = True

    duplicated = sorted(
        name
        for name, count in seen_types.items()
        if count > 1 and name in set(model["required_rule_types"])
    )
    require(
        not duplicated,
        "BOOTSTRAP_RULES",
        f"conflicting duplicate rules of type {duplicated}",
    )

    require(
        has_pull_request_rule
        and has_required_check
        and has_non_fast_forward
        and has_deletion
        and (has_required_workflow or has_dedicated_check),
        "BOOTSTRAP_NOT_ACTIVATED",
        "activation requires an ACTIVE repository-sourced branch ruleset that "
        f"targets exactly {model['ref']!r} with no bypass actors, blocks force "
        "pushes and deletion, requires pull requests, requires the strict "
        f"status check {required_check!r} from integration {integration_id}, and "
        "either pins the exact workflow "
        f"(repository {repository['id']}, path "
        f"{repository['required_workflow']!r}, ref "
        f"{repository['required_workflow_ref']!r}, exact commit SHA containing "
        "the approved workflow blob) or supplies the dedicated non-Actions check "
        f"{dedicated_check['context']!r}; a generic Actions-named status check is "
        "spoofable and is never a substitute"
    )


def _commit_and_tree(
    api: HttpGitHubApi, repository: str, commit_sha: str
) -> tuple[Mapping[str, Any], str]:
    require(
        SHA1_RE.fullmatch(commit_sha) is not None,
        "COMMIT_IDENTITY",
        "commit SHA is not a lowercase SHA-1",
    )
    commit = api.get(f"/repos/{repository}/git/commits/{commit_sha}")
    require(commit.get("sha") == commit_sha, "COMMIT_IDENTITY", commit_sha)
    tree_sha = commit.get("tree", {}).get("sha")
    require(
        isinstance(tree_sha, str) and SHA1_RE.fullmatch(tree_sha) is not None,
        "COMMIT_TREE",
        commit_sha,
    )
    return commit, tree_sha


def _tree_manifest(
    api: HttpGitHubApi, repository: str, tree_sha: str
) -> TreeManifest:
    require(
        SHA1_RE.fullmatch(tree_sha) is not None,
        "COMMIT_TREE",
        "tree SHA is not a lowercase SHA-1",
    )
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


def _python_surfaces(path: str, source: str, active: bool) -> set[str]:
    """Derive the capability surfaces a Python helper actually exercises."""
    try:
        syntax = ast.parse(source, filename=path)
    except SyntaxError as error:
        raise PolicyError("HELPER_SYNTAX", f"{path}: {error}") from error

    modules: set[str] = set()
    # Names bound by `from X import Y [as Z]` -> the fully qualified target.
    bound: dict[str, str] = {}
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
                bound[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                raise PolicyError(
                    "HELPER_DYNAMIC_EXECUTION", f"{path} uses a relative import"
                )
            modules.add(node.module)
            for alias in node.names:
                bound[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    for module in modules:
        root = module.split(".")[0]
        require(
            root not in FORBIDDEN_PYTHON_MODULES,
            "HELPER_DYNAMIC_EXECUTION",
            f"{path} imports the unmodelled module {module}",
        )

    surfaces: set[str] = set()
    if any(
        module == name or module.startswith(name + ".")
        for module in modules
        for name in NETWORK_PYTHON_MODULES
    ):
        surfaces.add("github-api-read")
    if any(
        module == name or module.startswith(name + ".")
        for module in modules
        for name in PROCESS_PYTHON_MODULES
    ):
        surfaces.add("git-read-local")

    if not active:
        return surfaces

    def qualified(func: ast.expr) -> str:
        parts: list[str] = []
        current: ast.expr | None = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(bound.get(current.id, current.id))
        parts.reverse()
        return ".".join(parts)

    for node in ast.walk(syntax):
        if isinstance(node, ast.Call):
            name = qualified(node.func)
            if isinstance(node.func, ast.Name):
                resolved = bound.get(node.func.id, node.func.id)
                require(
                    resolved not in FORBIDDEN_PYTHON_CALLS
                    and node.func.id not in FORBIDDEN_PYTHON_BUILTINS,
                    "HELPER_DYNAMIC_EXECUTION",
                    f"{path} uses {node.func.id}",
                )
            else:
                require(
                    name not in FORBIDDEN_PYTHON_CALLS,
                    "HELPER_DYNAMIC_EXECUTION",
                    f"{path} uses {name}",
                )
            leaf = name.rsplit(".", 1)[-1]
            if leaf == "_run_git":
                require(
                    len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in GIT_COMMAND_KEYS,
                    "HELPER_GIT_UNMODELED",
                    f"{path} passes a dynamic or unmodelled Git command key",
                )
            if name.split(".")[0] == "subprocess" or name in SUBPROCESS_ENTRYPOINTS:
                surfaces.add("git-read-local")
                _assert_subprocess_command(path, node)
        elif isinstance(node, ast.Attribute):
            if node.attr in {"__globals__", "__builtins__", "__subclasses__", "__class__"}:
                raise PolicyError(
                    "HELPER_DYNAMIC_EXECUTION",
                    f"{path} reaches through {node.attr}",
                )
    return surfaces


def _assert_subprocess_command(path: str, node: ast.Call) -> None:
    """A subprocess invocation must be a literal, fully modelled git read."""
    require(node.args, "HELPER_PROCESS_COMMAND", path)
    command = node.args[0]
    require(
        isinstance(command, (ast.List, ast.Tuple)),
        "HELPER_PROCESS_COMMAND",
        f"{path} invokes a constructed subprocess command",
    )
    require(
        not any(isinstance(element, ast.Starred) for element in command.elts),
        "HELPER_PROCESS_COMMAND",
        f"{path} splats unmodelled arguments into a subprocess command",
    )
    require(
        command.elts
        and isinstance(command.elts[0], ast.Constant)
        and command.elts[0].value == "git",
        "HELPER_PROCESS_COMMAND",
        f"{path} invokes a non-Git or constructed subprocess",
    )
    literals = [
        element.value
        for element in command.elts
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
    ]
    dangerous = [value for value in literals if value in DANGEROUS_GIT_SUBCOMMANDS]
    require(
        not dangerous,
        "HELPER_GIT_UNMODELED",
        f"{path} invokes git {dangerous!r}",
    )
    for keyword in node.keywords:
        require(
            keyword.arg != "shell"
            or not isinstance(keyword.value, ast.Constant)
            or keyword.value.value is not True,
            "HELPER_PROCESS_SHELL",
            f"{path} enables subprocess shell execution",
        )
        require(
            keyword.arg != "env"
            or isinstance(keyword.value, (ast.Dict, ast.Name))
            or (
                isinstance(keyword.value, ast.Call)
                and isinstance(keyword.value.func, ast.Name)
            ),
            "HELPER_PROCESS_COMMAND",
            f"{path} passes an unmodelled subprocess environment",
        )
        require(
            keyword.arg != "env"
            or not isinstance(keyword.value, ast.Attribute),
            "HELPER_PROCESS_COMMAND",
            f"{path} inherits the ambient environment into a subprocess",
        )
    require(
        any(keyword.arg == "env" for keyword in node.keywords),
        "HELPER_PROCESS_COMMAND",
        f"{path} runs a subprocess without an explicit scrubbed environment",
    )


def _powershell_surfaces(path: str, source: str) -> set[str]:
    """Derive the capability surfaces a PowerShell helper actually exercises."""
    text = source.casefold()
    words = set(re.findall(r"[a-z][a-z0-9_.-]*", text))

    denied = words & (NETWORK_COMMANDS | {"invoke-webrequest", "invoke-restmethod"})
    require(
        not denied,
        "HELPER_NETWORK_UNMODELED",
        f"{path} references network commands {sorted(denied)}",
    )
    packages = words & PACKAGE_COMMANDS
    require(
        not packages,
        "HELPER_PACKAGE_UNMODELED",
        f"{path} references package commands {sorted(packages)}",
    )
    marker = next((item for item in ACQUISITION_MARKERS if item in text), None)
    require(
        marker is None,
        "HELPER_NETWORK_UNMODELED",
        f"{path} references the acquisition surface {marker!r}",
    )
    dynamic = words & {
        "invoke-expression",
        "iex",
        "invoke-command",
        "icm",
        "new-object",
        "add-type",
        "start-process",
    }
    require(
        not dynamic,
        "HELPER_DYNAMIC_EXECUTION",
        f"{path} uses dynamic execution {sorted(dynamic)}",
    )
    for subcommand in DANGEROUS_GIT_SUBCOMMANDS:
        require(
            re.search(rf"git[^\n]{{0,64}}?(?<![a-z0-9-]){re.escape(subcommand)}(?![a-z0-9-])", text)
            is None,
            "HELPER_GIT_UNMODELED",
            f"{path} references git {subcommand}",
        )

    surfaces: set[str] = set()
    if re.search(r"(?<![a-z0-9_])git(?:\.exe)?(?![a-z0-9_-])", text):
        surfaces.add("git-read-local")
    if re.search(r"\[(?:system\.)?io\.", text) or "[io.path]" in text:
        surfaces.add("dotnet-filesystem")
    if (
        "security.accesscontrol" in text
        or "security.principal" in text
        or "get-acl" in text
        or "set-acl" in text
    ):
        surfaces.add("dotnet-acl")
    if "gettype(" in text or "getmethod(" in text or ".invoke(" in text:
        surfaces.add("dotnet-reflection")
    return surfaces


def _helper_capabilities(
    path: str, content: bytes, capabilities: set[str], active: bool
) -> None:
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("HELPER_ENCODING", f"{path} is not UTF-8") from error

    unknown = capabilities - CAPABILITY_VOCABULARY
    require(
        not unknown,
        "HELPER_CAPABILITY_UNKNOWN",
        f"{path} declares capabilities outside the vocabulary: {sorted(unknown)}",
    )

    if "legacy-disabled" in capabilities:
        require(
            not active,
            "HELPER_LEGACY_ACTIVE",
            f"{path} is disabled legacy code but has an active consumer",
        )
        return

    if path.endswith((".py",)):
        surfaces = _python_surfaces(path, source, active)
    elif path.endswith((".ps1", ".psm1", ".psd1")):
        surfaces = _powershell_surfaces(path, source)
    else:
        surfaces = set()
        require(
            not capabilities,
            "HELPER_CAPABILITY_UNMODELED",
            f"{path} is inert data but declares {sorted(capabilities)}",
        )

    undeclared = surfaces - capabilities
    if undeclared:
        surface = sorted(undeclared, key=lambda item: SURFACE_ORDER.index(item))[0]
        raise PolicyError(
            SURFACE_CODES[surface],
            f"{path} exercises the undeclared surface {surface!r}",
        )
    dormant = capabilities - surfaces
    require(
        not dormant,
        "HELPER_CAPABILITY_DORMANT",
        f"{path} declares unused surfaces {sorted(dormant)}",
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

    # The protected base checkout is the root of trust: it supplies the approval
    # graph and every helper, so its repository, commit, and tree are proven
    # before the graph is parsed and before any live repository rule is read.
    workflow_repository = os.environ.get("POLICY_REPOSITORY", "")
    environment_base_sha = os.environ.get("POLICY_BASE_SHA", "")
    require(
        REPOSITORY_RE.fullmatch(workflow_repository) is not None,
        "WORKFLOW_REPOSITORY",
        "workflow repository environment is missing or invalid",
    )
    require(
        SHA1_RE.fullmatch(environment_base_sha) is not None,
        "BASE_CHECKOUT_HEAD",
        "workflow base SHA environment is missing or invalid",
    )
    local_base_tree = verify_local_base(
        checkout, workflow_repository, environment_base_sha
    )
    require(
        os.environ.get("POLICY_BASE_TREE") == local_base_tree,
        "BASE_TREE_ENV",
        "base tree from the root guard changed",
    )
    local_graph_blob = _run_git(checkout, "graph-blob")
    require(
        SHA1_RE.fullmatch(local_graph_blob) is not None,
        "GRAPH_BASE_BINDING",
        "checked-out graph object id is invalid",
    )

    graph, _ = load_local_graph(graph_path)
    require(
        workflow_repository == graph["repository"]["full_name"],
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
    require(
        event_info["base_sha"] == environment_base_sha,
        "BASE_CHECKOUT_HEAD",
        "event base SHA differs from the verified protected base checkout",
    )

    api = HttpGitHubApi(
        graph["repository"]["api_url"],
        os.environ.get("POLICY_GITHUB_TOKEN", ""),
    )
    verify_repository_rules(
        api,
        graph["repository"],
        graph["repository"]["default_branch"],
        event_info["base_sha"],
        graph["workflows"][graph["repository"]["required_workflow"]]["blob"],
    )
    base_manifest, candidate_manifest = verify_live_identity(api, graph, event_info)
    require(
        base_manifest.tree_sha == local_base_tree,
        "BASE_CHECKOUT_TREE",
        "live protected base tree differs from the verified local checkout",
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
    parser = argparse.ArgumentParser(description="Protected-base workflow policy v3")
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

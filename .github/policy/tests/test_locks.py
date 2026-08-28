from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import pathlib
import sys
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY_DIR))

from policy_lib import (  # noqa: E402
    PolicyError,
    verify_artifact_lock,
    verify_release_lock,
)


REPOSITORY = "crutkas/MSYS2-packages"
REPOSITORY_ID = 1333319488
BASE_SHA = "d" * 40
RUN_SHA = "c" * 40
RUN_TREE = "8" * 40
TAG_OBJECT = "e" * 40
TAG_COMMIT = "f" * 40
TAG_TREE = "9" * 40
DIGEST = "sha256:" + "1" * 64
# Mirrors the artifact_fixture() producer identity so the attestation branch
# tests can mutate one field at a time.
ARTIFACT_NAME = "clangarm64-source"
WORKFLOW_REF = "refs/heads/master"
WORKFLOW_PATH = ".github/workflows/payload.yml"
HEAD_SHA = RUN_SHA
RUN_EVENT = "push"
RUN_ID = 100
RUN_ATTEMPT = 2


def iso(day, hour=0, minute=0):
    return f"2026-01-{day:02d}T{hour:02d}:{minute:02d}:00Z"


def attestation(name, digest, ref, sha, workflow_path, event_name, run_id, attempt):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "name": name,
                "digest": {"sha256": digest.removeprefix("sha256:")},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "repository": f"https://github.com/{REPOSITORY}",
                        "ref": ref,
                        "path": workflow_path,
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": event_name,
                        "repository_id": str(REPOSITORY_ID),
                        "repository_owner_id": "1",
                        "runner_environment": "github-hosted",
                    },
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+https://github.com/{REPOSITORY}@{ref}",
                        "digest": {"gitCommit": sha},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner/github-hosted"
                },
                "metadata": {
                    "invocationId": (
                        f"https://github.com/{REPOSITORY}/actions/runs/"
                        f"{run_id}/attempts/{attempt}"
                    )
                }
            },
        },
    }
    encoded = base64.b64encode(
        json.dumps(statement, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    encoded = "\n".join(
        encoded[index : index + 60] for index in range(0, len(encoded), 60)
    )
    return {
        "attestations": [
            {"bundle": {"dsseEnvelope": {"payload": encoded}}}
        ]
    }


class FakeApi:
    def __init__(self, responses, pages):
        self.responses = copy.deepcopy(responses)
        self.pages = copy.deepcopy(pages)
        self.trusted_now = dt.datetime(
            2026, 1, 10, 12, 0, tzinfo=dt.timezone.utc
        )

    def get(self, path):
        if path not in self.responses:
            raise AssertionError(f"unexpected API request: {path}")
        return copy.deepcopy(self.responses[path])

    def get_paginated(self, path):
        if path not in self.pages:
            raise AssertionError(f"unexpected paginated API request: {path}")
        return copy.deepcopy(self.pages[path])


def repository_lock():
    return {
        "full_name": REPOSITORY,
        "id": REPOSITORY_ID,
        "api_url": f"https://api.github.com/repos/{REPOSITORY}",
        "html_url": f"https://github.com/{REPOSITORY}",
    }


def common_repository_response():
    return {
        "id": REPOSITORY_ID,
        "full_name": REPOSITORY,
        "url": f"https://api.github.com/repos/{REPOSITORY}",
        "html_url": f"https://github.com/{REPOSITORY}",
    }


def artifact_fixture():
    run_id = 100
    attempt = 2
    job_id = 200
    artifact_id = 300
    artifact_name = "clangarm64-source"
    run_api = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
    job_api = f"https://api.github.com/repos/{REPOSITORY}/actions/jobs/{job_id}"
    artifact_api = (
        f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}"
    )
    archive_api = f"{artifact_api}/zip"
    lock = {
        "kind": "github-actions-artifact-v2",
        "repository": repository_lock(),
        "workflow": {
            "id": 55,
            "path": ".github/workflows/payload.yml",
            "ref": "refs/heads/master",
            "sha": RUN_SHA,
        },
        "run": {
            "id": run_id,
            "attempt": attempt,
            "event": "push",
            "head_sha": RUN_SHA,
            "head_tree": RUN_TREE,
            "created_at": iso(1),
            "updated_at": iso(1, 0, 10),
            "api_url": run_api,
        },
        "job": {
            "id": job_id,
            "name": "source-only",
            "run_attempt": attempt,
            "api_url": job_api,
        },
        "artifact": {
            "id": artifact_id,
            "name": artifact_name,
            "digest": DIGEST,
            "size": 4096,
            "api_url": artifact_api,
            "archive_download_url": archive_api,
            "created_at": iso(1, 0, 5),
            "expires_at": "2026-02-01T00:00:00Z",
        },
        "validity": {
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-01-20T00:00:00Z",
        },
    }
    run = {
        "id": run_id,
        "run_attempt": attempt,
        "event": "push",
        "head_sha": RUN_SHA,
        "workflow_id": 55,
        "path": ".github/workflows/payload.yml",
        "status": "completed",
        "conclusion": "success",
        "created_at": iso(1),
        "updated_at": iso(1, 0, 10),
        "repository": {"id": REPOSITORY_ID},
        "head_repository": {"id": REPOSITORY_ID},
        "head_branch": "master",
        "url": run_api,
    }
    job = {
        "id": job_id,
        "name": "source-only",
        "run_attempt": attempt,
        "head_sha": RUN_SHA,
        "status": "completed",
        "conclusion": "success",
        "url": job_api,
    }
    artifact = {
        "id": artifact_id,
        "name": artifact_name,
        "digest": DIGEST,
        "size_in_bytes": 4096,
        "url": artifact_api,
        "archive_download_url": archive_api,
        "created_at": iso(1, 0, 5),
        "expires_at": "2026-02-01T00:00:00Z",
        "expired": False,
        "workflow_run": {
            "id": run_id,
            "head_sha": RUN_SHA,
            "repository_id": REPOSITORY_ID,
        },
    }
    responses = {
        f"/repos/{REPOSITORY}": common_repository_response(),
        f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}": run,
        f"/repos/{REPOSITORY}/git/commits/{RUN_SHA}": {
            "tree": {"sha": RUN_TREE}
        },
        f"/repos/{REPOSITORY}/compare/{RUN_SHA}...{BASE_SHA}": {
            "status": "ahead",
            "merge_base_commit": {"sha": RUN_SHA},
        },
        f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}": artifact,
        f"/repos/{REPOSITORY}/attestations/{DIGEST}": attestation(
            artifact_name,
            DIGEST,
            "refs/heads/master",
            RUN_SHA,
            ".github/workflows/payload.yml",
            "push",
            run_id,
            attempt,
        ),
    }
    pages = {
        (
            f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs"
        ): [job]
    }
    return lock, responses, pages


def release_fixture():
    release_id = 400
    asset_id = 500
    run_id = 600
    run_attempt = 3
    job_id = 700
    tag = "v1.0.0"
    asset_name = "source.tar.zst"
    tag_api = (
        f"https://api.github.com/repos/{REPOSITORY}/git/tags/{TAG_OBJECT}"
    )
    release_api = (
        f"https://api.github.com/repos/{REPOSITORY}/releases/{release_id}"
    )
    release_html = f"https://github.com/{REPOSITORY}/releases/tag/{tag}"
    asset_api = (
        f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}"
    )
    run_api = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
    job_api = f"https://api.github.com/repos/{REPOSITORY}/actions/jobs/{job_id}"
    download_url = (
        f"https://github.com/{REPOSITORY}/releases/download/{tag}/{asset_name}"
    )
    lock = {
        "kind": "github-release-v2",
        "repository": repository_lock(),
        "tag": {
            "name": tag,
            "object_id": TAG_OBJECT,
            "object_api_url": tag_api,
            "tagger_date": iso(2),
            "peeled_commit": TAG_COMMIT,
            "peeled_tree": TAG_TREE,
        },
        "provenance": {
            "workflow": {
                "id": 77,
                "path": ".github/workflows/release-source.yml",
                "ref": f"refs/tags/{tag}",
                "sha": TAG_COMMIT,
            },
            "run": {
                "id": run_id,
                "attempt": run_attempt,
                "event": "push",
                "head_sha": TAG_COMMIT,
                "head_tree": TAG_TREE,
                "created_at": iso(2, 1),
                "updated_at": iso(2, 1, 10),
                "api_url": run_api,
            },
            "job": {
                "id": job_id,
                "name": "release-source",
                "run_attempt": run_attempt,
                "api_url": job_api,
            },
        },
        "release": {
            "id": release_id,
            "tag_name": tag,
            "name": "Source v1.0.0",
            "api_url": release_api,
            "html_url": release_html,
            "published_at": iso(3),
        },
        "assets": [
            {
                "id": asset_id,
                "name": asset_name,
                "size": 8192,
                "digest": DIGEST,
                "content_type": "application/zstd",
                "api_url": asset_api,
                "browser_download_url": download_url,
                "created_at": iso(3, 0, 5),
                "updated_at": iso(3, 0, 6),
            }
        ],
        "validity": {
            "not_before": "2026-01-03T00:00:00Z",
            "not_after": "2026-01-20T00:00:00Z",
        },
    }
    live_asset = {
        "id": asset_id,
        "name": asset_name,
        "size": 8192,
        "digest": DIGEST,
        "content_type": "application/zstd",
        "url": asset_api,
        "browser_download_url": download_url,
        "created_at": iso(3, 0, 5),
        "updated_at": iso(3, 0, 6),
        "state": "uploaded",
    }
    responses = {
        f"/repos/{REPOSITORY}": common_repository_response(),
        f"/repos/{REPOSITORY}/git/ref/tags/{tag}": {
            "object": {"type": "tag", "sha": TAG_OBJECT}
        },
        f"/repos/{REPOSITORY}/git/tags/{TAG_OBJECT}": {
            "tag": tag,
            "sha": TAG_OBJECT,
            "object": {"type": "commit", "sha": TAG_COMMIT},
            "tagger": {"date": iso(2)},
            "url": tag_api,
        },
        f"/repos/{REPOSITORY}/git/commits/{TAG_COMMIT}": {
            "tree": {"sha": TAG_TREE}
        },
        f"/repos/{REPOSITORY}/compare/{TAG_COMMIT}...{BASE_SHA}": {
            "status": "ahead",
            "merge_base_commit": {"sha": TAG_COMMIT},
        },
        f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}": {
            "id": run_id,
            "run_attempt": run_attempt,
            "event": "push",
            "head_sha": TAG_COMMIT,
            "workflow_id": 77,
            "path": ".github/workflows/release-source.yml",
            "status": "completed",
            "conclusion": "success",
            "created_at": iso(2, 1),
            "updated_at": iso(2, 1, 10),
            "repository": {"id": REPOSITORY_ID},
            "head_repository": {"id": REPOSITORY_ID},
            "url": run_api,
        },
        f"/repos/{REPOSITORY}/releases/{release_id}": {
            "id": release_id,
            "tag_name": tag,
            "name": "Source v1.0.0",
            "url": release_api,
            "html_url": release_html,
            "published_at": iso(3),
            "draft": False,
            "prerelease": False,
        },
        f"/repos/{REPOSITORY}/attestations/{DIGEST}": attestation(
            asset_name,
            DIGEST,
            f"refs/tags/{tag}",
            TAG_COMMIT,
            ".github/workflows/release-source.yml",
            "push",
            run_id,
            run_attempt,
        ),
    }
    pages = {
        f"/repos/{REPOSITORY}/releases/{release_id}/assets": [live_asset],
        (
            f"/repos/{REPOSITORY}/actions/runs/{run_id}"
            f"/attempts/{run_attempt}/jobs"
        ): [
            {
                "id": job_id,
                "name": "release-source",
                "run_attempt": run_attempt,
                "head_sha": TAG_COMMIT,
                "status": "completed",
                "conclusion": "success",
                "url": job_api,
            }
        ],
    }
    return lock, responses, pages


class AttestationBranchTests(unittest.TestCase):
    """Synthetic coverage for the SLSA evidence branches.

    The active graph carries no artifact or release locks, so these branches are
    unreachable in production today. They are retained because the intended
    policy admits externally produced artifacts only through them, so every
    schema, topology, digest, replay, duplicate, and failure path is exercised
    here rather than left as unaudited authority.
    """

    def assert_policy_error(self, code, function):
        with self.assertRaises(PolicyError) as raised:
            function()
        self.assertEqual(raised.exception.code, code)

    def artifact(self):
        return artifact_fixture()

    def test_missing_attestation_list_denies(self):
        for payload in ({}, {"attestations": []}, {"attestations": "nope"}):
            lock, responses, pages = self.artifact()
            responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = payload
            with self.subTest(payload=payload):
                self.assert_policy_error(
                    "ATTESTATION_MISSING",
                    lambda lock=lock, responses=responses, pages=pages: (
                        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)
                    ),
                )

    def test_non_string_payload_is_skipped_and_denies(self):
        lock, responses, pages = self.artifact()
        responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = {
            "attestations": [
                {"bundle": {"dsseEnvelope": {"payload": None}}},
                {"bundle": {"dsseEnvelope": {}}},
                {"bundle": {}},
                {},
            ]
        }
        self.assert_policy_error(
            "ATTESTATION_MISMATCH",
            lambda: verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_undecodable_payload_is_skipped_and_denies(self):
        cases = {
            "not-base64": "!!!!not base64!!!!",
            "not-utf8": base64.b64encode(b"\xff\xfe\x00\x01").decode("ascii"),
            "not-json": base64.b64encode(b"definitely not json").decode("ascii"),
            "duplicate-keys": base64.b64encode(
                b'{"_type": "a", "_type": "b"}'
            ).decode("ascii"),
        }
        for label, payload in cases.items():
            lock, responses, pages = self.artifact()
            responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = {
                "attestations": [{"bundle": {"dsseEnvelope": {"payload": payload}}}]
            }
            with self.subTest(label=label):
                self.assert_policy_error(
                    "ATTESTATION_MISMATCH",
                    lambda lock=lock, responses=responses, pages=pages: (
                        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)
                    ),
                )

    def _mutated_statement(self, **overrides):
        lock, responses, pages = self.artifact()
        payload = attestation(
            overrides.get("name", ARTIFACT_NAME),
            overrides.get("digest", DIGEST),
            overrides.get("ref", WORKFLOW_REF),
            overrides.get("sha", HEAD_SHA),
            overrides.get("workflow_path", WORKFLOW_PATH),
            overrides.get("event_name", RUN_EVENT),
            overrides.get("run_id", RUN_ID),
            overrides.get("attempt", RUN_ATTEMPT),
        )
        encoded = payload["attestations"][0]["bundle"]["dsseEnvelope"]["payload"]
        statement = json.loads(
            base64.b64decode(encoded.replace("\n", "")).decode("utf-8")
        )
        for path, value in overrides.get("statement", {}).items():
            target = statement
            keys = path.split(".")
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = value
        reencoded = base64.b64encode(
            json.dumps(statement, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = {
            "attestations": [{"bundle": {"dsseEnvelope": {"payload": reencoded}}}]
        }
        return lock, responses, pages

    def test_every_statement_field_is_load_bearing(self):
        mutations = {
            "type": {"_type": "https://in-toto.io/Statement/v0.1"},
            "predicate-type": {"predicateType": "https://slsa.dev/provenance/v0.2"},
            "build-type": {
                "predicate.buildDefinition.buildType": "https://attacker.invalid/build"
            },
            "workflow-repository": {
                "predicate.buildDefinition.externalParameters.workflow.repository": (
                    "https://github.com/attacker/repo"
                )
            },
            "runner-environment": {
                "predicate.buildDefinition.internalParameters.github."
                "runner_environment": "self-hosted"
            },
            "repository-id": {
                "predicate.buildDefinition.internalParameters.github."
                "repository_id": "999"
            },
            "builder-host": {
                "predicate.runDetails.builder.id": "https://attacker.invalid/runner"
            },
            "builder-type": {"predicate.runDetails.builder.id": 42},
        }
        for label, statement in mutations.items():
            lock, responses, pages = self._mutated_statement(statement=statement)
            with self.subTest(label=label):
                self.assert_policy_error(
                    "ATTESTATION_MISMATCH",
                    lambda lock=lock, responses=responses, pages=pages: (
                        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)
                    ),
                )

    def test_replayed_provenance_from_another_run_or_attempt_denies(self):
        for label, overrides in {
            "run-id": {"run_id": RUN_ID + 1},
            "attempt": {"attempt": RUN_ATTEMPT + 1},
            "ref": {"ref": "refs/heads/attacker"},
            "workflow-path": {"workflow_path": ".github/workflows/attacker.yml"},
            "commit": {"sha": "9" * 40},
            "event": {"event_name": "workflow_dispatch"},
            "subject-name": {"name": "other-artifact"},
        }.items():
            lock, responses, pages = self._mutated_statement(**overrides)
            with self.subTest(label=label):
                self.assert_policy_error(
                    "ATTESTATION_MISMATCH",
                    lambda lock=lock, responses=responses, pages=pages: (
                        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)
                    ),
                )

    def test_one_valid_statement_among_decoys_still_admits(self):
        lock, responses, pages = self.artifact()
        valid = responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"][
            "attestations"
        ][0]
        responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = {
            "attestations": [
                {"bundle": {"dsseEnvelope": {"payload": None}}},
                {"bundle": {"dsseEnvelope": {"payload": "!!!"}}},
                valid,
            ]
        }
        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)

    def test_duplicate_identical_statements_are_idempotent(self):
        lock, responses, pages = self.artifact()
        valid = responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"][
            "attestations"
        ][0]
        responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = {
            "attestations": [valid, copy.deepcopy(valid), copy.deepcopy(valid)]
        }
        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)

    def test_malformed_timestamps_deny(self):
        cases = {
            "not-iso": "yesterday",
            "no-timezone": "2026-01-01T00:00:00",
            "not-a-string": 20260101,
            "empty": "",
        }
        for label, value in cases.items():
            lock, responses, pages = self.artifact()
            lock["run"]["created_at"] = value
            responses[
                f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}"
            ]["created_at"] = value
            with self.subTest(label=label):
                self.assert_policy_error(
                    "TIME_VALUE",
                    lambda lock=lock, responses=responses, pages=pages: (
                        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)
                    ),
                )


class LockTests(unittest.TestCase):
    def assert_policy_error(self, code, function):
        with self.assertRaises(PolicyError) as raised:
            function()
        self.assertEqual(raised.exception.code, code)

    def test_authoritative_artifact_lock_happy_path(self):
        lock, responses, pages = artifact_fixture()
        verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)

    def test_artifact_exact_identity_fields_are_not_self_proving(self):
        mutations = (
            ("repository", "id", 1, "LOCK_REPOSITORY"),
            ("workflow", "path", ".github/workflows/other.yml", "ARTIFACT_RUN"),
            ("run", "head_tree", "7" * 40, "ARTIFACT_TREE"),
            ("job", "name", "other-job", "ARTIFACT_JOB"),
            ("artifact", "name", "other-name", "ARTIFACT_FIELDS"),
            ("artifact", "size", 1, "ARTIFACT_FIELDS"),
            (
                "artifact",
                "api_url",
                "https://evil.invalid/artifact",
                "ARTIFACT_FIELDS",
            ),
        )
        for section, field, value, code in mutations:
            lock, responses, pages = artifact_fixture()
            lock[section][field] = value
            with self.subTest(section=section, field=field):
                self.assert_policy_error(
                    code,
                    lambda lock=lock, responses=responses, pages=pages: verify_artifact_lock(
                        lock, FakeApi(responses, pages), BASE_SHA
                    ),
                )

    def test_artifact_run_attempt_and_numeric_ids_are_exact(self):
        lock, responses, pages = artifact_fixture()
        original_path = f"/repos/{REPOSITORY}/actions/runs/100/attempts/2"
        responses[f"/repos/{REPOSITORY}/actions/runs/100/attempts/3"] = responses[
            original_path
        ]
        lock["run"]["attempt"] = 3
        self.assert_policy_error(
            "ARTIFACT_RUN",
            lambda: verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        for section in ("run", "job", "artifact"):
            lock, responses, pages = artifact_fixture()
            lock[section]["id"] = "100"
            with self.subTest(section=section):
                with self.assertRaises(PolicyError):
                    verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA)

    def test_artifact_expiry_and_validity_are_checked_against_api_time(self):
        lock, responses, pages = artifact_fixture()
        lock["artifact"]["expires_at"] = "2026-01-09T00:00:00Z"
        responses[f"/repos/{REPOSITORY}/actions/artifacts/300"]["expires_at"] = (
            "2026-01-09T00:00:00Z"
        )
        self.assert_policy_error(
            "ARTIFACT_EXPIRED",
            lambda: verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        lock, responses, pages = artifact_fixture()
        lock["validity"]["not_after"] = "2026-01-10T00:00:00Z"
        self.assert_policy_error(
            "LOCK_EXPIRED",
            lambda: verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_artifact_topology_must_reach_protected_base(self):
        lock, responses, pages = artifact_fixture()
        comparison = responses[
            f"/repos/{REPOSITORY}/compare/{RUN_SHA}...{BASE_SHA}"
        ]
        comparison["status"] = "diverged"
        self.assert_policy_error(
            "LOCK_TOPOLOGY",
            lambda: verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_artifact_digest_requires_independent_attestation(self):
        lock, responses, pages = artifact_fixture()
        responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = attestation(
            "different-artifact",
            DIGEST,
            "refs/heads/master",
            RUN_SHA,
            ".github/workflows/payload.yml",
            "push",
            100,
            2,
        )
        self.assert_policy_error(
            "ATTESTATION_MISMATCH",
            lambda: verify_artifact_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_authoritative_release_lock_happy_path(self):
        lock, responses, pages = release_fixture()
        verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA)

    def test_release_requires_immutable_annotated_tag_and_exact_peel(self):
        cases = (
            ("type", "commit", "RELEASE_TAG_LIGHTWEIGHT"),
            ("sha", "0" * 40, "RELEASE_TAG"),
        )
        for field, value, code in cases:
            lock, responses, pages = release_fixture()
            ref = responses[f"/repos/{REPOSITORY}/git/ref/tags/v1.0.0"]["object"]
            ref[field] = value
            with self.subTest(field=field):
                self.assert_policy_error(
                    code,
                    lambda lock=lock, responses=responses, pages=pages: verify_release_lock(
                        lock, FakeApi(responses, pages), BASE_SHA
                    ),
                )
        lock, responses, pages = release_fixture()
        responses[f"/repos/{REPOSITORY}/git/commits/{TAG_COMMIT}"]["tree"]["sha"] = (
            "0" * 40
        )
        self.assert_policy_error(
            "RELEASE_TREE",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_release_and_asset_numeric_ids_and_urls_are_exact(self):
        lock, responses, pages = release_fixture()
        lock["release"]["id"] = "400"
        self.assert_policy_error(
            "RELEASE_ID",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        lock, responses, pages = release_fixture()
        lock["assets"][0]["id"] = "500"
        self.assert_policy_error(
            "RELEASE_ASSET_ID",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        lock, responses, pages = release_fixture()
        lock["assets"][0]["browser_download_url"] = "https://evil.invalid/source"
        self.assert_policy_error(
            "RELEASE_ASSET_FIELDS",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_release_producer_run_attempt_head_tree_workflow_and_job_are_exact(self):
        mutations = (
            ("workflow", "path", ".github/workflows/other.yml", "RELEASE_PROVENANCE_RUN"),
            ("run", "head_tree", "0" * 40, "RELEASE_PROVENANCE_RUN"),
            ("run", "event", "workflow_dispatch", "RELEASE_PROVENANCE_RUN"),
            ("job", "name", "other-job", "RELEASE_PROVENANCE_JOB"),
            (
                "job",
                "api_url",
                "https://evil.invalid/job",
                "LOCK_URL",
            ),
        )
        for section, field, value, code in mutations:
            lock, responses, pages = release_fixture()
            lock["provenance"][section][field] = value
            with self.subTest(section=section, field=field):
                self.assert_policy_error(
                    code,
                    lambda lock=lock, responses=responses, pages=pages: verify_release_lock(
                        lock, FakeApi(responses, pages), BASE_SHA
                    ),
                )

    def test_release_tag_and_asset_names_cannot_change_url_structure(self):
        lock, responses, pages = release_fixture()
        lock["tag"]["name"] = "../other"
        self.assert_policy_error(
            "RELEASE_TAG",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        lock, responses, pages = release_fixture()
        lock["assets"][0]["name"] = "../source.tar.zst"
        self.assert_policy_error(
            "RELEASE_ASSET_NAME",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_release_asset_manifest_is_complete_with_no_extras(self):
        lock, responses, pages = release_fixture()
        pages[f"/repos/{REPOSITORY}/releases/400/assets"].append(
            {
                "id": 501,
                "name": "unlocked.exe",
                "size": 1,
                "digest": "sha256:" + "2" * 64,
            }
        )
        self.assert_policy_error(
            "RELEASE_ASSET_MANIFEST",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_release_asset_digest_requires_independent_run_evidence(self):
        lock, responses, pages = release_fixture()
        responses[f"/repos/{REPOSITORY}/attestations/{DIGEST}"] = attestation(
            "source.tar.zst",
            DIGEST,
            "refs/tags/v1.0.0",
            TAG_COMMIT,
            ".github/workflows/release-source.yml",
            "push",
            999,
            3,
        )
        self.assert_policy_error(
            "ATTESTATION_MISMATCH",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )

    def test_release_repository_host_time_and_topology_are_bound(self):
        lock, responses, pages = release_fixture()
        lock["repository"]["html_url"] = "https://evil.invalid/repo"
        self.assert_policy_error(
            "LOCK_URL",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        lock, responses, pages = release_fixture()
        responses[f"/repos/{REPOSITORY}/compare/{TAG_COMMIT}...{BASE_SHA}"][
            "merge_base_commit"
        ]["sha"] = "0" * 40
        self.assert_policy_error(
            "LOCK_TOPOLOGY",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )
        lock, responses, pages = release_fixture()
        lock["validity"]["not_after"] = "2026-01-09T00:00:00Z"
        self.assert_policy_error(
            "LOCK_EXPIRED",
            lambda: verify_release_lock(lock, FakeApi(responses, pages), BASE_SHA),
        )


if __name__ == "__main__":
    unittest.main()

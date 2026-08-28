# Workflow policy v2

This directory is a protected-base, fail-closed admission boundary for workflow
and executable-helper changes. The only remaining workflow is
`workflow-policy.yml`. It runs on `pull_request_target` with `contents: read`,
checks out the exact protected-base commit, and treats the pull request head
only as GitHub API data. It never checks out, imports, invokes, or tests
candidate source, and it neither uploads nor consumes candidate artifacts.

The validator obtains complete base and candidate Git tree manifests, derives
name-status records with exact rename/copy detection, and checks both sides of
every change. Any add, delete, rename, copy, content, type, mode, symlink, or
submodule change involving workflows, policy, tests, locks, local actions, or
`.ci` requires separate source admission. Executable-looking changes elsewhere
also deny. Both `.yml` and `.yaml` are governed case-insensitively, while
noncanonical case, Unicode normalization, separators, and path collisions are
rejected.

Candidate trees must contain the exact approved control surface from the
current protected base. A pull request opened before a policy/control update
must rebase or merge the current `master` before it can be admitted; an older
control blob is intentionally indistinguishable from an attempted rollback.

Workflow YAML is interpreted by an intentionally strict semantic subset
parser. It accepts two-space block mappings/sequences and literal `|` run
blocks. It rejects aliases, anchors, tags, directives, flow collections,
folded/chomped blocks, comments, duplicate keys, ambiguous scalars, and every
more-indented continuation after a plain scalar. Unsupported YAML is a denial,
not a fallback.

The approval graph binds the repository numeric ID and hosts, exact workflow
and helper Git blobs, transitive consumers, command capabilities, events,
permissions, runner, steps, action inputs, and the four permitted lowercase
action SHAs. Local, Docker, and reusable actions; delegated helpers; raw Git
acquisition; package/network execution; step or job conditions; error
continuation; timeouts; containers; services; secrets; write permissions; and
unmodeled fork execution all deny.

The private root stores only an ephemeral local decision report. It is never
uploaded or accepted as a payload lock; the required check conclusion is the
admission signal.

## Artifact and release locks

Lock files must live below `.github/policy/locks/` as regular, symlink-free
base-tree blobs listed in the protected approval graph. The validator does not
download payloads. It verifies locks against live GitHub API records and API
`Date`: repository IDs and hosts, run and attempt, head commit and tree,
workflow and job, numeric artifact/release/asset IDs, exact names, sizes,
digests and URLs, nonexpired times, complete release asset manifests,
independent GitHub attestation statements, immutable annotated tag objects,
peeled commits/trees, and ancestry from the protected base. A caller-supplied
string is never accepted as evidence for itself.

## Bootstrap denial

Commit `73248abe6bc25e73486c29f876094b3eeab79547` has no protected-base policy
workflow and the repository currently has no enforcing branch rule. Therefore
this bootstrap change cannot run or admit itself. Candidate-controlled runs are
diagnostics only and are not admission evidence.

Landing requires independent source review/admission. After landing, an
active rulesets for `master` must require pull requests and the exact diagnostic
check `workflow-policy / verify` from the GitHub Actions integration
(application ID `15368`), with strict up-to-date status checks. Admission also
requires one independently anchored producer: either
`.github/workflows/workflow-policy.yml` from repository ID `1333319488` at
`refs/heads/master`, or `workflow-policy / anchored-admission` from a unique
non-Actions app ID that has been rebound into this graph after independent
review of its protected exact source. The validator cross-checks the branch
rules against active ruleset IDs. Until the live APIs prove these properties,
it returns `BOOTSTRAP_NOT_ACTIVATED`. This change does not modify branch
protection, rules, releases, tags, or repository settings.

GitHub currently limits required-workflow rules to organization or enterprise
scope, while this repository is owned by the personal account `crutkas`.
Therefore the gate intentionally remains blocked after landing under the
current ownership: a named check tied only to the generic GitHub Actions app is
not an acceptable substitute because a candidate workflow can spoof it. Secure
activation requires a separately approved platform transition and source
rebind to an organization-scoped required workflow, or a separately designed
dedicated non-Actions check integration and graph update. The current dedicated
integration ID is deliberately `null`; neither external transition is performed
by this change.

## Offline verification

Run the standard-library-only suites from the repository root:

```powershell
python -m unittest discover .github/policy/tests -v
pwsh -NoProfile -File .github/policy/tests/private-root.tests.ps1
```

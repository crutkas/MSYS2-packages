# Workflow policy v3

This directory is a protected-base, fail-closed admission boundary for workflow
and executable-helper changes. The only remaining workflow is
`workflow-policy.yml`. It runs on `pull_request_target` restricted to the
`master` base branch with `contents: read`, checks out the exact protected-base
commit, and treats the pull request head only as GitHub API data. It never
checks out, imports, invokes, or tests candidate source, and it neither uploads
nor consumes candidate artifacts.

The validator obtains complete base and candidate Git tree manifests, derives
name-status records with exact rename/copy detection, and checks both sides of
every change. Any add, delete, rename, copy, content, type, mode, symlink, or
submodule change involving workflows, policy, tests, locks, local actions, or
`.ci` requires separate source admission. Executable-looking changes elsewhere
also deny: interpreter and build-script suffixes (including `.bash`, `.zsh`,
`.pl`, `.php`, `.lua`, `.vbs`, `.wsf`, `.jse`, `.scr`, and `.mk`), directly
executable build files (`GNUmakefile`, `Makefile`, `CMakeLists.txt`,
`meson.build`, `SConstruct`, `build.gradle`, `PKGBUILD`, `Dockerfile`,
`justfile`), any executable mode bit, and any introduced shebang. Both `.yml`
and `.yaml` are governed case-insensitively, while noncanonical case, Unicode
normalization, separators, and path collisions are rejected.

Candidate trees must contain the exact approved control surface from the
current protected base. A pull request opened before a policy/control update
must rebase or merge the current `master` before it can be admitted; an older
control blob is intentionally indistinguishable from an attempted rollback.

Workflow YAML is interpreted by an intentionally strict semantic subset
parser. It accepts two-space block mappings/sequences and literal `|` run
blocks. It rejects aliases, anchors, tags, directives, flow collections,
folded/chomped blocks, comments, duplicate keys, ambiguous scalars, and every
more-indented continuation after a plain scalar. Before any line splitting it
rejects NUL, BOM, bare CR, and every remaining C0 control plus `U+0085`,
`U+2028`, and `U+2029` with `YAML_CONTROL`, so no byte where this parser's line
model could diverge from a conforming YAML reader's can smuggle a second
logical line into one scalar. Unsupported YAML is a denial, not a fallback.

The approval graph binds the repository numeric ID and hosts, exact workflow
and helper Git blobs, transitive consumers, command capabilities, events, base
branches, permissions, runner, steps, action inputs, and the exact lowercase
action SHAs. Graph comparisons use recursive exact-type equality, so a JSON
`true` never satisfies a modeled `1` and a `false` never satisfies a `0`. Local,
Docker, and reusable actions; delegated helpers; raw Git acquisition;
package/network execution; step or job conditions; error continuation; timeouts;
containers; services; secrets; write permissions; and unmodeled fork execution
all deny.

Secret and `github.token` references are matched with a bounded expression and
token model rather than an exact string. Every `${{ ... }}` body — including
unterminated openers, embedded occurrences inside larger strings, arbitrary
internal whitespace, mixed case, and index syntax such as `secrets['NAME']` — is
scanned. A run step may reference `github.token` only where the graph declares
it, a declared token that is never used is rejected as dormant authority, and a
token reference anywhere outside a declared run-step environment denies.

Run blocks are scanned with a typed tokenizer, not a growing regex. Command
positions are tracked across newlines, `;`, `|`, `||`, `&&`, `&`, `(`, `{`, and
`=`; command names are normalized for `.exe`, `.cmd`, `.bat`, `.com`, and `.ps1`
suffixes and for directory prefixes, so `curl.exe` and
`C:\Windows\System32\curl.exe` are the same command as `curl`. Nested shells and
process hosts (`cmd /c`, `powershell -c`, `pwsh -c`, `bash -c`, `wsl`, `sudo`,
`Start-Process`), dynamic execution (`Invoke-Expression`, `&{...}`, `& $variable`,
dot sourcing, subexpression substitution, backticks, `New-Object`, `Add-Type`),
and .NET or tooling acquisition surfaces (`WebClient`, `HttpClient`,
`DownloadString`/`DownloadFile`, `Start-BitsTransfer`, `certutil`, `bitsadmin`,
`MSXML2`, `Reflection.Assembly`) all deny. Only the exact protected commands are
permitted, only the approved `$env:` anchors may be interpolated into a command
target, and an unrecognized command is denied as `COMMAND_UNMODELED` rather than
being success-shaped.

The private root is created by a literal directory API with its restrictive,
non-inherited ACL supplied to the create call itself, so it never exists with
inherited permissions. The ACL is reverified after creation. Every temp and root
operation uses literal path APIs. The root stores only an ephemeral local
decision report. It is never uploaded or accepted as a payload lock; the
required check conclusion is the admission signal.

The protected base checkout is the root of trust, so it is proven first: its
origin, HEAD commit, tree, and cleanliness are verified before the approval
graph is parsed and before any live repository rule, ruleset, or manifest is
read. The live base tree and the event base SHA are then required to equal the
already-verified local values, and every commit and tree SHA is matched against
`SHA1_RE` before it is interpolated into an API URL.

## Approved actions

`approved_actions` contains only `actions/checkout`, which is the sole action
with an exact current workflow need. Artifact upload/download and MSYS2 setup
approvals were removed rather than carried as dormant authority; no action
becomes preapproved without a current workflow requirement.

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

The graph currently lists no artifact or release locks, so this code is
unreachable in production today. It is retained because the intended policy
admits externally produced artifacts only through it, and its schema, topology,
digest, replay, duplicate, and failure branches are covered by synthetic tests
so it is audited authority rather than dormant authority.

## Bootstrap denial

Commit `73248abe6bc25e73486c29f876094b3eeab79547` has no protected-base policy
workflow and the repository currently has no enforcing branch rule. Therefore
this bootstrap change cannot run or admit itself. Candidate-controlled runs are
diagnostics only and are not admission evidence.

Landing requires independent source review/admission. After landing, an
active ruleset for `master` must require pull requests and the exact diagnostic
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
python -B -m unittest discover .github/policy/tests -v
pwsh -NoProfile -File .github/policy/tests/private-root.tests.ps1
```

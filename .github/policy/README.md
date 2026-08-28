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
inherited permissions. The create also establishes exclusive absence: creating
over an existing path fails, so an attacker who pre-plants the directory loses
the race instead of inheriting our trust, and intermediates are created the same
way. If the atomic API is unavailable the helper **fails closed** — there is no
create-then-protect fallback, because that fallback is the race the design
exists to remove. Afterwards the root is reverified for owner, protected DACL,
exact principal set, full-control rights, inheritance and propagation flags,
absence of inherited or non-allow ACEs, reparse points, and object identity.
Existence alone is never treated as success. Every temp and root operation uses
literal path APIs. The root stores only an ephemeral local decision report. It
is never uploaded or accepted as a payload lock; the required check conclusion
is the admission signal.

The protected base checkout is the root of trust, so it is proven first: its
origin, HEAD commit, tree, and cleanliness are verified before the approval
graph is parsed and before any live repository rule, ruleset, or manifest is
read. The live base tree and the event base SHA are then required to equal the
already-verified local values, and every commit and tree SHA is matched against
`SHA1_RE` before it is interpolated into an API URL.

Git itself is invoked only through an absolute, trusted executable — never
resolved through `PATH` — with a fixed literal argument vector drawn from a
closed command table. The child environment is rebuilt from scratch rather than
filtered, so `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_CONFIG*`,
`GIT_SSH*`, `GIT_PROXY_COMMAND`, `GIT_EXTERNAL_DIFF`,
`GIT_ALTERNATE_OBJECT_DIRECTORIES`, and the rest cannot survive from the
caller. Forced configuration supplied through that scrubbed environment
neutralises every remaining command-execution vector — `core.fsmonitor`,
`core.hooksPath`, `core.sshCommand`, `core.askPass`, `core.pager`,
`core.editor`, `diff.external`, `uploadpack.packObjectsHook`,
`credential.helper` — and disables system and per-user config entirely.

Helper capabilities are a closed vocabulary (`github-api-read`,
`git-read-local`, `dotnet-filesystem`, `dotnet-acl`, `dotnet-reflection`,
`legacy-disabled`). Each helper is parsed — Python by AST, PowerShell by
surface scan — and the surfaces it actually exercises must equal the surfaces
it declares: an undeclared surface denies, and a declared-but-unused surface
denies as dormant authority. Python helpers may not import or call the
forbidden module and builtin sets, may not reach through dunder attributes, and
may only spawn a literal, non-splatted `git` argument vector with an explicit
scrubbed environment and `shell` disabled. PowerShell helpers may not reference
network, package, dynamic-execution, or acquisition surfaces at all.

Integer identities are exact: `is_exact_int` rejects `bool` everywhere, because
Python treats `True` as `1`. Strict JSON parsing rejects duplicate keys and the
non-JSON constants `NaN`, `Infinity`, and `-Infinity` through `parse_constant`.

Path classification uses the name Windows would actually open. Trailing dots
and spaces are folded on every component, so `.github./workflows/x` is still a
controlled path and `evil.ps1.` is still a script. Alternate data streams,
backslashes, absolute paths, and `..` traversal are refused when the manifest is
built, before any classification runs. Shebangs are detected behind a UTF-8 or
UTF-16 BOM and leading blanks.

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
workflow and the repository currently has no ruleset at all
(`GET /repos/crutkas/MSYS2-packages/rulesets` returns `[]`). Therefore this
change cannot run or admit itself. Candidate-controlled runs are diagnostics
only and are not admission evidence.

## Activation authority

Authority is granted only by a **live, ACTIVE, repository-sourced branch
ruleset**. GitHub exposes a repository ruleset rule of `type: workflows` with an
exact `repository_id`, `path`, `ref`, and `sha`, and repository rulesets are
available to this public user-owned repository. The validator accepts that path
only when every one of the following holds:

- the ruleset `enforcement` is exactly `active` (never `disabled` or
  `evaluate`), and its `target` is exactly `branch`;
- its `source_type` is exactly `Repository` and its `source` is this
  repository. Organization, enterprise, and inherited rules are a different
  trust domain and are not modelled, so they contribute no authority;
- its `conditions.ref_name.include` is exactly `["refs/heads/master"]` with an
  empty `exclude` and no other condition key. Wildcards such as `refs/heads/*`,
  `~ALL`, and `~DEFAULT_BRANCH` are refused, as is any drift in spelling;
- its `bypass_actors` list is empty. Any bypass actor, of any type or mode,
  removes authority;
- the branch carries, from that same ruleset, a `pull_request` rule, a
  `non_fast_forward` rule, a `deletion` rule, and a `required_status_checks`
  rule whose `strict_required_status_checks_policy` is exactly `true` and which
  requires the context `workflow-policy / verify` from `integration_id` 15368;
- no required rule type appears twice, so conflicting duplicates cannot be used
  to shadow a weaker rule;
- the `workflows` rule names exactly one entry with no extra keys, whose
  `repository_id` is the exact integer `1333319488` (a JSON `true` is not an
  ID), whose `path` is `.github/workflows/workflow-policy.yml`, whose `ref` is
  `refs/heads/master`, and whose `sha` is a full 40-character lowercase commit
  SHA. A `null`, short, uppercase, or missing SHA is refused, because a floating
  rule would follow whatever `master` points at.
- that pinned commit is verified live: it must be reachable from the protected
  base, and the blob at the required workflow path in its tree must equal the
  approved workflow blob in the graph.

A dedicated non-Actions check app remains a supported alternative anchor: a
`workflow-policy / anchored-admission` context from a unique `integration_id`
that is not the GitHub Actions app and has been rebound into this graph after
independent review. It is no longer the only viable path.

A named status check tied only to the generic GitHub Actions app is **never** a
substitute, because a candidate workflow can publish a check with that exact
name and integration. Repository-level workflow execution protections are
defense-in-depth actor/event controls with no documented public API; they are
not treated as authority.

Until the live APIs prove these properties the validator returns
`BOOTSTRAP_NOT_ACTIVATED`. This change does not modify branch protection,
rules, rulesets, releases, tags, or repository settings, and it does not claim
activation.

### Two-step activation after source audit

Activation is deliberately a separate, human, post-audit operation:

1. **Land the audited source.** After independent source review, fast-forward
   or merge this policy to `master` with no other change. At this point the
   policy is present but still inert, because no ruleset exists.
2. **Create the exact-SHA ruleset.** Create an active, repository-sourced
   branch ruleset targeting exactly `refs/heads/master`, with no bypass actors,
   carrying the `pull_request`, `non_fast_forward`, `deletion`, strict
   `required_status_checks`, and `workflows` rules described above. The
   `workflows` rule must pin the exact commit SHA that contains the audited
   workflow blob.

Any later change to the policy or its configuration then arrives as a
separately audited activation/config pull request, which is itself validated by
the now-required protected-base workflow. The candidate is never able to create
or amend the ruleset that authorizes it, so it can never become
self-authorizing.

## Offline verification

Run the standard-library-only suites from the repository root:

```powershell
python -B -m unittest discover .github/policy/tests -v
pwsh -NoProfile -File .github/policy/tests/private-root.tests.ps1
```

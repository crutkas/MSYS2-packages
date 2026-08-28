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

The private root is created exclusively. The .NET ACL-at-create helper is **not**
exclusive on its own: when the target already exists it neither throws nor
applies the security descriptor, so an attacker-planted directory with a
permissive ACL would survive untouched, and a check-then-create guard around it
is racy. The module therefore creates the directory under an unguessable
staging name — where the descriptor genuinely is applied because the path is
fresh — proves the descriptor landed, and only then publishes it with a rename,
which fails if the destination already exists. That rename is the exclusivity
primitive. If the ACL-at-create API is unavailable the helper **fails closed**;
there is no create-then-protect fallback, because that fallback is the race the
design exists to remove.

Afterwards the root is reverified for owner and group, protected DACL, exact
principal set, full-control rights, inheritance and propagation flags, absence
of inherited or non-allow ACEs, reparse points, resolved link targets, volume
identity, and object identity. Existence alone is never treated as success.
Every temp and root operation uses literal path APIs. The root stores only an
ephemeral local decision report. It is never uploaded or accepted as a payload
lock; the required check conclusion is the admission signal.

The private root is **not** owner-only. Its DACL grants full control to exactly
three principals: the runner identity, `NT AUTHORITY\SYSTEM` (`S-1-5-18`), and
`BUILTIN\Administrators` (`S-1-5-32-544`). An earlier version of this document
described it as owner-only, which was inaccurate.

Object identity binds the NTFS volume serial number read from the storage layer
plus a 256-bit secret nonce written inside the root at creation. **Residual,
stated accurately:** a true 128-bit NTFS file id would need `CreateFile` with
`FILE_FLAG_BACKUP_SEMANTICS` and `GetFileInformationByHandle`, which .NET does
not surface without P/Invoke, and the only route to it from PowerShell is
runtime type compilation — precisely the dynamic surface this policy forbids
elsewhere. The nonce is a *different* control, not a strictly stronger one. An
earlier version of this document claimed it was strictly stronger than a file
id; that was wrong, and a real file id would catch substitutions the nonce does
not. Specifically, the nonce detects a directory replaced by one that does not
carry the secret, but it does **not** detect a substitution that preserves or
copies the claim file, whereas a file id would. The nonce is harder to forge
blind, since file ids can be reused after deletion; a file id is harder to
launder, since copying content does not copy identity. Both would be better than
either.

Branch rules are read paginated. A duplicate or conflicting rule hiding on the
second page is still authoritative to GitHub, so it must be visible to the
checks below rather than silently truncated away.

The protected base checkout is the root of trust, so it is proven first: its
origin, HEAD commit, tree, and cleanliness are verified before the approval
graph is parsed and before any live repository rule, ruleset, or manifest is
read. The live base tree and the event base SHA are then required to equal the
already-verified local values, and every commit and tree SHA is matched against
`SHA1_RE` before it is interpolated into an API URL.

Git itself is invoked only through a canonical image chosen from a fixed
allowlist — never resolved through `PATH`, and with **no environment or
parameter override of any kind**. An override that accepts "any absolute file"
is equivalent to arbitrary code execution here: a native stub can forge origin,
HEAD, tree, and cleanliness through the same code path and defeat the base
verification entirely. The allowlisted path must also be canonical — a real
file, not a symlink or reparse point, whose resolved path is itself the
allowlisted path — so a redirected entry is refused. The image is passed as
`argv[0]`; `subprocess`'s `executable=` is never used, because it would let
`argv[0]` keep saying `git` while another binary runs.

The argument vector is a fixed literal drawn from a closed command table, and
the child environment is rebuilt from scratch rather than filtered, so `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_CONFIG*`, `GIT_SSH*`,
`GIT_PROXY_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`,
and the rest cannot survive from the caller.

**The repository-local `.git/config` is a separate problem, and forced
configuration does not solve it.** That file is always read and cannot be
switched off by any environment variable, so a checkout-controlled key can make
Git execute a process — `filter.<n>.clean`, `diff.<n>.textconv`,
`merge.<n>.driver`, `core.fsmonitor`, `core.pager`, `core.sshCommand`,
`credential.helper`, `alias.*`, `include`/`includeIf`, `url.*.insteadOf` and
more — *before* this policy reaches a verdict. Clearing keys by name cannot be
made complete, because filter, diff, and merge driver names are arbitrary and
therefore cannot be pre-cleared by `-c` or `GIT_CONFIG_KEY_n`. An earlier
version of this document claimed that forced configuration neutralised "every
remaining command-execution vector"; that claim was false and is withdrawn.

The actual control is an **allow-list scan of the full effective configuration**
that runs before any command that reads the worktree. The scan uses
`git config --list --show-scope -z`, not a single-scope listing, and it asserts
on the scope structure rather than merely reading values out of it: the `system`
and `global` scopes must be **absent** (the child environment is rebuilt from
scratch, so their presence would mean the rebuild failed), the only scopes
permitted are `local`, `worktree` and `command`, and the `command` scope must
equal exactly the policy's own forced settings.

An earlier version scanned `git config --local --list` only. That was
scope-blind: Git honours per-checkout configuration at
`.git/worktrees/<name>/config.worktree`, which a `--local` listing does not show,
so a `filter.<n>.clean` placed in that scope was invisible to the scan and would
still execute. Measured: the key is invisible to `--local --list`, visible to
`--show-scope`, and the driver is live — `git add` in that checkout runs the
process. Not claimed: execution through the exact production `status` command in
a linked worktree; local scope fires under `status`, but the linked-worktree case
did not fire across five trigger shapes. The scope-blindness and the process
execution are both real; that one chain is not demonstrated.

Dropping `extensions.worktreeConfig` from the key allow-list would
have closed that one instance while leaving the class open, because the scan
would have stayed scope-blind and any future permitted scope-adding key would
reopen it. Scanning every scope is the control; the key is no longer permitted
either, and a test proves the scope scan still denies when the key *is* permitted.

The protected base checkout is
produced by the pinned `actions/checkout` step from a trusted SHA, so its config
is predictable, and any key outside the modelled set denies. The scan is
intrinsic to the command — `status` is gated on the scan having passed in both
languages — so the protection cannot be lost by calling things in the wrong
order. Reading configuration does not run filters, drivers, or hooks, so it is
safe to do first. Forced configuration is retained as defence in depth for the
keys that do have fixed names.

Helper capabilities are a closed vocabulary (`github-api-read`,
`git-read-local`, `dotnet-filesystem`, `dotnet-acl`, `dotnet-reflection`,
`legacy-disabled`). Each helper is parsed — Python by AST, PowerShell by
surface scan — and the surfaces it actually exercises must equal the surfaces
it declares.

Process launchers are identified by **resolved binding, never by spelling**, and
anything that cannot be resolved is denied rather than assumed benign. A launcher
may only appear as the callee of a direct qualified call: taking a reference to
one (`f = subprocess.run`, `functools.partial`, a dispatch table, subclassing
`Popen`), aliasing the module, importing from it, star-importing, or rebinding a
name are all refused. The trusted image resolver is likewise checked by binding:
it must be a single, module-level, undecorated, parameterless `FunctionDef` that
is never rebound, never imported, and whose every return is a literal or a
module-level literal constant **whose values are images this policy trusts** —
so a helper cannot define, import, decorate, or shadow its own resolver and
choose the binary that runs.

The argument vector must resolve to literals. `argv[0]` is either the literal
`git` or a call to the modelled resolver; every other operand must be a literal
except the directory operand, which may be `str(<name>)`. That closes
`['git', sub, 'x']` and `'cl' + 'one'`. Splatted arguments, splatted keywords,
empty commands, `executable=`, `preexec_fn`, `start_new_session`,
`creationflags`, `startupinfo`, `pass_fds`, `user`, and the redirecting Git
global options (`-c`, `--exec-path`, `--git-dir`, `--work-tree`, `--namespace`,
`--upload-pack`, `--receive-pack`, `--config-env`) are all refused. `shell` must
be literal `False` — `shell=1` and `shell=flag` are not accepted. `cwd` must be
literal. `env` must be a literal mapping or a call to a modelled builder, so
`env=environ`, `env=dict(os.environ)`, and `AMB = os.environ; env=AMB` are all
refused.

PowerShell helpers may not reference network, package, dynamic-execution, or
acquisition surfaces at all; comments are scanned too, so helper authors must
avoid spelling the forbidden tokens even in prose.

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

> **`private-root.tests.ps1` is NOT a Pester file.** Despite the `.tests.ps1`
> name it is a standalone assertion script and must be invoked directly, as
> above. `Invoke-Pester` discovers **zero** tests in it and reports
> `Tests Passed: 0` with **exit code 0** — so a CI job that wired it through
> Pester would report success while running nothing at all. Run directly it
> executes 103 assertions and exits 0. The script now throws if the Pester
> module is loaded, so the mistake fails loudly instead of passing silently.

## Trusted Git image

`TRUSTED_GIT_IMAGES` contains only drive-letter-rooted paths. A UNC entry is
refused because it routes image resolution through the network redirector, so
the "trusted" image would be whatever a remote server serves — the
arbitrary-code-execution equivalence the check exists to prevent. Extended-length
(`\\?\`) and device (`\\.\`) prefixes are refused because they bypass path
normalisation. Both of those forms *resolve to themselves*, so "resolves to
itself" is **not** a sufficient definition of canonicality on its own; a
drive-letter root is required as well. An earlier version of this document
described the check as enforcing canonicality when it only enforced
resolves-to-itself; that wording was inaccurate and the predicate has been
tightened to match the promise.

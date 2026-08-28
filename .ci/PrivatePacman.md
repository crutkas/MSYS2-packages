# Private pacman v2 contract

`PrivatePacman.psm1` runs one local `pacman -U` transaction in a fresh,
session-owned root without repository access. It is intended for CI source
that must not mutate an existing MSYS2 installation, especially
`C:\msys64`.

This helper is not package or native admission. It does not download,
install, build, publish, or approve packages by itself. A caller must provide
an independently prepared private seed, a complete local package root, and
separately pinned signed ownership evidence.

## Safety boundary

The helper:

- accepts only canonical DOS paths on a local fixed drive;
- rejects UNC, device, provider, mapped, substituted, and share paths;
- rejects traversal, reserved names, alternate data streams, junctions,
  symbolic links, other reparse ancestors, and filesystem aliases;
- requires the workspace, seed, and package root to use the same fixed drive;
- copies a reparse-free seed into a random sibling staging directory, verifies
  the source and copied byte manifests, then atomically renames the staging
  directory to the final root;
- creates an external, exclusively locked owner sentinel before publishing
  the private root;
- requires a canonical manifest that binds one owner and session to every
  package path, length, SHA-256, and deterministic package-set SHA-256;
- requires the raw manifest SHA-256 and ECDSA P-256 public-key SHA-256 to be
  supplied independently, and verifies a detached DER signature over the
  exact UTF-8 manifest bytes;
- rejects missing, extra, non-package, aliased, or reparse entries anywhere
  in the package root before creating session state;
- constructs the complete native argument list internally and accepts no
  caller-provided pacman options;
- permits only local `-U`, with package files locked against writes, renames,
  and deletion for the entire transaction;
- writes a repository-free config and requires both configured and
  root-local hook directories to be empty;
- closes native standard input, removes `POSIXLY_CORRECT`, and sets
  `MSYS=winsymlinks:nativestrict`;
- holds the private config, executable, owner marker, and package inputs
  against replacement while pacman runs;
- snapshots every protected tree by hashing each regular file's bytes and
  rejects every nested reparse entry before transaction state is admitted;
- binds each root and entry's owner SID, group/DACL security descriptor SDDL,
  and complete Windows attribute mask into the canonical digest and evidence;
- watches security and attribute changes in addition to names, writes, and
  sizes, so restored metadata changes remain fatal even when final digests
  match;
- enumerates named streams on every admitted root, directory, and file and
  fails closed if any alternate data stream is present; rejecting reparse
  entries prevents stream enumeration from following an external link target;
- always includes canonical `C:\msys64` in the protected set, even when it is
  absent;
- reuses the quiet preflight digest as canonical `C:\msys64` before evidence,
  avoiding a redundant full shared-root walk before any private-root work;
- requires every additional protected root's preflight digest to match its
  authoritative monitored before snapshot, without discarding watcher events;
- requires a separate disposable preflight watcher to observe a quiet interval
  before authoritative monitoring starts; only pre-monitor noise is discarded;
- starts protected-root watchers before publishing the before evidence, keeps
  them active through private-root cleanup, and fails on any change event,
  watcher error, or before/after digest difference;
- removes reparse entries as leaves during cleanup and never follows their
  targets; and
- preserves evidence outside the disposable private root on success and
  failure.

The process receives exactly one value for each isolation switch:

```text
--root
--dbpath
--cachedir
--logfile
--config
--hookdir
--gpgdir
```

It also receives `--noconfirm`, `--noscriptlet`, one `-U`, one helper-owned
`--`, and only canonical package paths after that separator. The generated
config has an `[options]` section and no repository, `Server`, or `Include`
directive.

## Threat model

The module fails closed against accidental shared-root use, ambiguous paths,
normal concurrent changes, input replacement, child failure, timeout, and
cleanup errors. It is not a security sandbox against a malicious process
running as the same Windows user. Such a process can attack the helper,
pacman, or evidence storage with the caller's authority.

`FileSystemWatcher` events supplement, but do not replace, full byte
snapshots. A normal completed invocation requires both mechanisms to remain
clean. If the owning PowerShell process crashes, watcher continuity is lost;
recovery can remove only roots with matching internal and external ownership
records and records the outcome as failed, never successful.

The canonical security evidence contains owner, group, and DACL state readable
with `READ_CONTROL`. Audit SACL access requires `SeSecurityPrivilege` and is
not claimed as an admission signal. Security watcher events still invalidate a
transaction while monitoring is active.

## Usage

All private inputs must be on the same fixed drive. `SeedRoot` must contain
the private executable at `usr\bin\pacman.exe` and must not overlap a
protected root. Ownership manifest, signature, and public-key files must be
distinct, canonical, outside the package root, and locked for the transaction.

The canonical ownership manifest schema is
`private-pacman-package-ownership/v2`. Its ordered fields are `Schema`,
`Owner`, `SessionId`, `SignatureAlgorithm`, `PackageSetSha256`, and
`Packages`. Package entries are sorted by path and contain only `Path`,
`Length`, and `Sha256`. The detached signature file contains one base64 DER
ECDSA P-256 signature over the exact UTF-8 manifest bytes. The public key is
PEM subject-public-key-info. The caller must obtain expected manifest and
public-key hashes from a trusted control plane rather than from adjacent
files.

`New-PrivatePacmanOwnershipManifest` can create the unsigned canonical
manifest from an isolated package root. Signature creation and trusted hash
distribution intentionally remain outside this module.

```powershell
Import-Module "$repository\.ci\PrivatePacman.psm1" -Force

$layout = New-PrivatePacmanLayout `
    -WorkspaceRoot 'D:\runner-temp\private-pacman' `
    -SessionId "arm64-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"

try {
    $result = Invoke-PrivatePacmanUpgrade `
        -Layout $layout `
        -SeedRoot 'D:\private-msys2-seed' `
        -PackageRoot 'D:\local-packages' `
        -OwnershipManifestPath 'D:\ownership\packages.ownership.json' `
        -OwnershipSignaturePath 'D:\ownership\packages.ownership.sig' `
        -OwnershipPublicKeyPath 'D:\ownership\packages.ownership.pem' `
        -ExpectedManifestSha256 $trustedManifestSha256 `
        -ExpectedPublicKeySha256 $trustedPublicKeySha256 `
        -ExpectedOwner 'arm64-campaign:run-123' `
        -ProtectedRoot @('D:\other-shared-package-state')
}
catch {
    # The terminating error includes the external result.json path when
    # initialization advanced far enough to create evidence.
    throw
}
```

The layout explicitly names:

- `Root`
- `DatabasePath`
- `CachePath`
- `LogPath`
- `ConfigPath`
- `HookPath`
- `GpgPath`
- `PacmanPath`
- `StateDirectory`
- `EvidenceDirectory`

The module rederives and verifies every layout property before touching the
filesystem, so a serialized or modified layout cannot redirect a managed
path.

## Evidence and cleanup

The external state directory contains:

- `owner.json`: session ID, nonce, exact root paths, owning process,
  protected roots, phase, and final result digest;
- `evidence/invocation.json`: executable, exact argv, locked package hashes,
  signed ownership identity, seed-copy digest, managed-config digest, and
  controlled environment;
- `evidence/protected-*-before.json` and
  `evidence/protected-*-after.json`: full byte, owner/group/DACL, attribute,
  reparse-rejection, and named-stream-policy manifests;
- `evidence/result.json`: process output and exit status, before/after
  protected digests, watcher events/errors, cleanup status, and failures.

The private root is removed on success, child crash, timeout, protected-state
drift, and other handled failures. Evidence remains external.

If the owning PowerShell process itself terminates before `finally` runs,
the root and sentinel intentionally remain. After confirming the child
process is gone, recover only that exact session:

```powershell
Remove-PrivatePacmanSession -Layout $layout -Confirm:$false
```

Recovery takes an exclusive sentinel lock, requires matching internal and
external nonces and canonical paths, removes only the recorded root or
staging root, and writes `evidence/recovery.json`. Recovery always records
`WatcherContinuity = false` and `Result = cleaned-fail-closed`.

## Diagnostic workflow boundary

`private-pacman-contract.yml` runs for every pull request. A fork pull request
gets a visible failing job rather than a skipped result. A same-repository run
checks out and verifies the exact PR head and uploads only its JSON diagnostic
report.

This workflow is defined by candidate-controlled source and is not an
authoritative admission gate. Production use requires protected default-branch
governance that the candidate cannot alter or self-certify.

There is no production caller in this change. Before one can be admitted, a
separate trusted integration must pin raw manifest and public-key source URLs
or commits, bind expected repository and host identities across redirects,
allowlist signer keys and ownership names, and establish trusted time and
revocation policy. Those gates are intentionally unresolved here.

## Contract tests

Run the dependency-free source contract:

```powershell
pwsh -NoLogo -NoProfile -NonInteractive `
    -File .ci\Test-PrivatePacman.ps1 `
    -ReportPath "$env:TEMP\private-pacman-contract.json"
```

The test script compiles a small argv recorder from checked-in C# source with
the Windows inbox .NET Framework compiler. It never invokes pacman or consumes
a campaign candidate artifact; package-shaped test files contain only
synthetic fixture text in a temporary directory. The suite covers canonical
manifest determinism, raw hash and key pinning, signature tampering,
owner/session binding, complete package enumeration, signed traversal,
argv completeness, repository absence, path aliases, drive mismatch,
UNC/device/share paths, junctions, file symlinks, seed reparse points, atomic
collisions, concurrent sentinel ownership, package/config/root locks,
permanent and restored ACL/attribute drift, permanent and transient alternate
data streams, transient protected-state races, child crashes, timeouts,
parent-process crash recovery, and reparse-safe cleanup.

The JSON report and logs expose `ExistedBefore`, `ExistedAfter`, entry counts,
and pre/post content and canonical digests for a deterministic populated
protected-root fixture. One native-boundary transaction protects the literal
canonical `C:\msys64`; its transaction evidence and separate suite-level
pre/post snapshot are reported. Remaining adversarial transactions substitute
a small populated fixed-drive root by changing private module state only inside
the test harness; the production command surface has no canonical-root
override. This avoids repeatedly walking a hosted multi-gigabyte installation
without weakening production behavior. An absent hosted-run root remains an
explicit non-admission gate rather than evidence for a populated installation.

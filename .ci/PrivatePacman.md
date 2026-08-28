# Private pacman v2 contract

`PrivatePacman.psm1` runs one local `pacman -U` transaction in a fresh,
session-owned root without repository access. It is intended for CI source
that must not mutate an existing MSYS2 installation, especially
`C:\msys64`.

This helper is not package or native admission. It does not download,
install, build, publish, or approve packages by itself. A caller must provide
an independently prepared private seed and local package paths.

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
  recording directory and reparse-link identities;
- always includes canonical `C:\msys64` in the protected set, even when it is
  absent;
- requires an initial preflight digest to match the authoritative monitored
  before snapshot, without discarding any watcher events;
- keeps protected-root watchers active from the before snapshot through
  private-root cleanup, and fails on any change event, watcher error, or
  before/after digest difference;
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

## Usage

All private inputs must be on the same fixed drive. `SeedRoot` must contain
the private executable at `usr\bin\pacman.exe` and must not overlap a
protected root.

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
        -PackagePath @('example.pkg.tar.zst') `
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
  seed-copy digest, managed-config digest, and controlled environment;
- `evidence/protected-*-before.json` and
  `evidence/protected-*-after.json`: full byte manifests;
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

## Contract tests

Run the dependency-free source contract:

```powershell
pwsh -NoLogo -NoProfile -NonInteractive `
    -File .ci\Test-PrivatePacman.ps1 `
    -ReportPath "$env:TEMP\private-pacman-contract.json"
```

The test script compiles a small argv recorder from checked-in C# source with
the Windows inbox .NET Framework compiler. It never invokes pacman or consumes
a package artifact. The suite covers argv completeness, repository absence,
traversal, path aliases, drive mismatch, UNC/device/share paths, junctions,
file symlinks, seed reparse points, atomic collisions, concurrent sentinel
ownership, package/config/root locks, transient protected-state races, child
crashes, timeouts, parent-process crash recovery, and reparse-safe cleanup.
It snapshots canonical `C:\msys64` before and after the entire suite and
requires identical existence and byte digests.

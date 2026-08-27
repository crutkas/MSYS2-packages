# Private pacman safety helper

Use `PrivatePacman.psm1` for package transactions that must not mutate the
shared `C:\msys64` installation. The helper creates a fresh, session-owned
root atomically below an existing local fixed-drive parent, writes a root-local
immutable `pacman.conf` and empty hook directory, supplies all pacman isolation
arguments, and records transaction evidence. Mutating
operations also compare external snapshots of the shared pacman log and local
database while a recursive watcher fingerprints every shared-root change event.
Any drift or watcher overflow fails the transaction; the helper never repairs
or rolls back shared state.

## Threat model

This helper prevents accidental direct or partially isolated pacman use and
preserves evidence integrity. It is not a security sandbox against a malicious
concurrent process running as the same Windows user. Such a process could
transiently add and remove a child junction while pacman runs. Directory and
file locks narrow that race, and the shared-root watcher fingerprint invalidates
the transaction evidence if shared state changes, but the helper cannot promise
prevention or rollback.

The helper treats only query, dependency-test, version, and help operations as
read-only. Everything else fails closed as mutating and requires the
session-owned root sentinel. This explicitly includes download-only sync
operations such as `-Sw`. Local `-U` package paths additionally require an
explicit package root and cannot escape it. All invocations force
`--noscriptlet` when the selected pacman transaction parser supports
scriptlets; inherently scriptless query/dependency operations omit it.
Print-only `-Sp`, `-Rp`, and `--print` transactions also omit
`--noscriptlet`, while retaining mutating isolation and evidence capture.
`ArgumentList` must begin with one exact, case-sensitive pacman operation
selector; abbreviated or later operation selectors are rejected.

```powershell
Import-Module "$repo\.ci\PrivatePacman.psm1" -Force

$sessionId = "arm64-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
$root = Join-Path $env:RUNNER_TEMP $sessionId
$context = New-PrivatePacmanContext `
    -Root $root `
    -DbPath "$root\var\lib\pacman" `
    -CacheDir "$root\var\cache\pacman\pkg" `
    -LogFile "$root\var\log\pacman.log" `
    -ConfigFile "$root\etc\pacman.conf" `
    -HookDir "$root\etc\pacman.d\hooks" `
    -GpgDir "$root\etc\pacman.d\gnupg" `
    -EvidenceDir "$root\evidence" `
    -PacmanPath "$root\usr\bin\pacman.exe" `
    -PrivatePacmanSeed $privatePacmanSeed `
    -RepositoryRoot $repo `
    -SessionId $sessionId `
    -Repositories @{
        clangarm64 = 'https://repo.msys2.org/mingw/clangarm64'
    }

Invoke-PrivatePacman `
    -Context $context `
    -ArgumentList @('-U', '--noconfirm') `
    -PackageRoot $artifactDirectory `
    -PackagePath $packagePath
```

Mutating operations require `PacmanPath` itself to resolve inside the immutable
private root. `PrivatePacmanSeed` must be an independently prepared private
distribution; a seed or bootstrap client under shared `C:\msys64` is rejected.
Seeding occurs before the helper writes and seals its managed config and hook
directories. The helper compares the seed manifest before and after copying and
requires the copied tree to match it exactly. It records and revalidates that
provenance plus the
private executable's hash and Windows file identity, and rejects a hardlink to
a protected shared pacman executable.
Populate the private GnuPG directory when repository signature validation needs
an initialized keyring. Supply HTTPS repositories through `-Repositories`;
never edit the generated config. It is hash-checked and locked through process
completion, and it intentionally contains no destination directives or
`Include`. Isolation options (`--root`, `--dbpath`,
`--cachedir`, `--logfile`, `--config`, `--hookdir`, `--gpgdir`, and
`--sysroot`) are helper-owned and rejected in `ArgumentList`, including
abbreviated and short forms. Caller-supplied `--` is also rejected. The helper
requires PowerShell 7 so native arguments use
`ProcessStartInfo.ArgumentList`; it removes `POSIXLY_CORRECT`, controls `MSYS`,
uses `winsymlinks:nativestrict`, and closes child standard input. Native
reparse links, Cygwin magic-file links, and shortcut links that could escape
the root are rejected. Relevant directory chains are held against rename or
deletion through process completion, alongside the config and package-file
locks. Mutable package-owned descendants are intentionally not locked so real
upgrades and removals can replace them. Root-local pacman log additions are
checked for file/transaction failures even when the process exits zero. Both
the configured hook directory and pacman's root-relative
`usr\share\libalpm\hooks` directory must be empty for mutations.

The canonical `C:\msys64` root is always observed regardless of caller
configuration, alongside any additional configured protected root. The
transaction evidence records a deterministic hash of recursive change events.
Watcher shutdown waits for queued callbacks to drain. Post-transaction
observation errors are recorded in the evidence before the helper fails closed.
Direct tree manifests record directory and file reparse link type, raw target,
and resolved target so retargeting cannot compare equal.

Run the compiled argv-recorder safety tests without invoking pacman (`dotnet`
with the .NET 8 targeting pack is required):

```powershell
pwsh -NoProfile -File .ci\Test-PrivatePacman.ps1
```

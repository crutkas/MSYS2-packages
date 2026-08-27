# Private pacman safety helper

Use `PrivatePacman.psm1` for package transactions that must not mutate the
shared `C:\msys64` installation. The helper creates a fresh, session-owned
root, writes a root-local `pacman.conf` and empty hook directory, supplies all
pacman isolation arguments, and records transaction evidence. Mutating
operations also compare external snapshots of the shared pacman log and local
database before and after execution. Drift fails the transaction; the helper
never repairs or rolls back shared state.

The helper treats only query, dependency-test, version, and help operations as
read-only. Everything else fails closed as mutating and requires the
session-owned root sentinel. This explicitly includes download-only sync
operations such as `-Sw`. Local `-U` package paths additionally require an
explicit package root and cannot escape it.

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
    -PacmanPath 'C:\msys64\usr\bin\pacman.exe' `
    -RepositoryRoot $repo `
    -SessionId $sessionId

Invoke-PrivatePacman `
    -Context $context `
    -ArgumentList @('-U', '--noconfirm') `
    -PackageRoot $artifactDirectory `
    -PackagePath $packagePath
```

Using the shared `pacman.exe` as a bootstrap client is allowed only because the
helper still supplies and revalidates every private destination. Prefer a
pacman executable located inside the private root when one is available.
Populate the private GnuPG directory when repository signature validation needs
an initialized keyring. Callers may add repository sections to the generated
private config before a sync operation; do not include or edit
`C:\msys64\etc\pacman.conf`. Isolation options (`--root`, `--dbpath`,
`--cachedir`, `--logfile`, `--config`, `--hookdir`, `--gpgdir`, and
`--sysroot`) are helper-owned and rejected in `ArgumentList`, including
abbreviated and short forms. Caller-supplied `--` is also rejected.

Run the fake-client safety tests without invoking pacman:

```powershell
pwsh -NoProfile -File .ci\Test-PrivatePacman.ps1
```

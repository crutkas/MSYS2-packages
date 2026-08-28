[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$lane = Join-Path $repo 'mingw-w64-cross-msysarm64-gnupg'
$lockPath = Join-Path $lane 'dependencies.lock.json'
$inventoryPath = Join-Path $lane 'inventory.json'
$pkgbuildPath = Join-Path $lane 'PKGBUILD'
$lockValidator = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGDependencyLock.ps1'
$packageValidator = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGPackage.ps1'
$scannerWrapper = Join-Path $PSScriptRoot 'Invoke-Aarch64PseudoRelocScanner.ps1'
$nativeTest = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGNative.ps1'
$rootTest = Join-Path $PSScriptRoot 'Initialize-Aarch64GnuPGPrivateRoot.ps1'
$splitTest = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGSplitPackages.ps1'
$pathScanner = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGForbiddenPaths.ps1'
$buildComparer = Join-Path $PSScriptRoot 'Compare-Aarch64GnuPGBuilds.ps1'
$releaseValidator = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGReleaseAdmission.ps1'
$staticEvidenceGenerator = Join-Path $PSScriptRoot 'New-Aarch64GnuPGStaticEvidence.ps1'
$staticEvidenceValidator = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGStaticEvidence.ps1'
$workflowPath = Join-Path $repo '.github\workflows\aarch64-msys-gnupg.yml'
$temp = Join-Path ([IO.Path]::GetTempPath()) "gnupg-static-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $temp | Out-Null

function Invoke-ExpectedExit {
    param(
        [int] $Code,
        [string] $Script,
        [string[]] $Arguments
    )
    & pwsh -NoProfile -File $Script @Arguments *> (Join-Path $temp 'last-command.log')
    if ($LASTEXITCODE -ne $Code) {
        $output = Get-Content -LiteralPath (Join-Path $temp 'last-command.log') -Raw
        throw "Expected exit $Code from $Script, got $LASTEXITCODE`: $output"
    }
}

function Assert-Fails {
    param([string] $Script, [string[]] $Arguments)
    & pwsh -NoProfile -File $Script @Arguments *> (Join-Path $temp 'last-command.log')
    if ($LASTEXITCODE -eq 0) {
        throw "Expected failure from $Script"
    }
}

try {
    & $lockValidator -LockPath $lockPath -AllowUnresolved | Out-Null
    Assert-Fails $lockValidator @('-LockPath', $lockPath)
    $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
    foreach ($runtimeId in @(
        'runtime-headers', 'runtime', 'runtime-devel', 'runtime-sysroot', 'default-manifest',
        'gcc', 'gcc-libs', 'libstdcxx-headers', 'w32api-runtime', 'binutils'
    )) {
        $runtime = @($lock.dependencies | Where-Object id -eq $runtimeId)
        if ($runtime.Count -ne 1 -or $runtime[0].status -ne 'unresolved' -or $null -ne $runtime[0].package) {
            throw "Revoked runtime component is not fail-closed: $runtimeId"
        }
    }
    if (@($lock.dependencies | Where-Object release_tag -eq 'msysarm64-runtime-pr10-a527-20260824').Count -ne 0) {
        throw 'Revoked runtime release remains referenced by a dependency'
    }
    foreach ($libgpgId in @('libgpg-error-runtime', 'libgpg-error-devel')) {
        $libgpg = @($lock.dependencies | Where-Object id -eq $libgpgId)
        if ($libgpg.Count -ne 1 -or $libgpg[0].status -ne 'unresolved' -or
            $null -ne $libgpg[0].release_tag -or $null -ne $libgpg[0].package) {
            throw "Quarantined libgpg-error component is not fail-closed: $libgpgId"
        }
    }

    $mutations = @(
        @{ name = 'size'; old = '"asset_bytes": 83876291'; new = '"asset_bytes": 83876292' },
        @{ name = 'hash'; old = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'; new = ('0' * 64) },
        @{ name = 'release'; old = '"release_id": 377482427'; new = '"release_id": 377482428' },
        @{ name = 'tag'; old = 'msysarm64-gcc-pr13-20260826'; new = 'msysarm64-gcc-pr13-drift' }
    )
    $lockRaw = Get-Content -LiteralPath $lockPath -Raw
    foreach ($mutation in $mutations) {
        $path = Join-Path $temp "$($mutation.name).json"
        $changed = $lockRaw.Replace($mutation.old, $mutation.new)
        if ($changed -eq $lockRaw) {
            throw "Mutation did not alter lock: $($mutation.name)"
        }
        Set-Content -LiteralPath $path -Value $changed -Encoding utf8NoBOM
        Assert-Fails $lockValidator @('-LockPath', $path, '-AllowUnresolved')
    }
    $provisionalMutation = $lockRaw | ConvertFrom-Json
    $provisionalMutation.dependencies |
        Where-Object id -eq 'gcc' |
        ForEach-Object { $_.release_tag = 'provisional-release' }
    $provisionalMutationPath = Join-Path $temp 'provisional.json'
    $provisionalMutation | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $provisionalMutationPath -Encoding utf8NoBOM
    Assert-Fails $lockValidator @('-LockPath', $provisionalMutationPath, '-AllowUnresolved')
    $revokedMutation = $lockRaw | ConvertFrom-Json
    $revokedMutation.revoked_releases += [pscustomobject]@{
        release_tag = 'msysarm64-gcc-pr13-20260826'
        reason = 'adversarial static fixture'
    }
    $revokedMutation.dependencies |
        Where-Object id -eq 'gcc' |
        ForEach-Object { $_.release_tag = 'msysarm64-gcc-pr13-20260826' }
    $revokedMutationPath = Join-Path $temp 'revoked-reference.json'
    $revokedMutation | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $revokedMutationPath -Encoding utf8NoBOM
    Assert-Fails $lockValidator @('-LockPath', $revokedMutationPath, '-AllowUnresolved')
    $quarantineMutation = $lockRaw | ConvertFrom-Json
    $quarantineMutation.quarantined_releases += [pscustomobject]@{
        release_tag = 'msysarm64-gcc-pr13-20260826'
        reason = 'adversarial static fixture'
        immutable = $false
        diagnostic_only = $true
    }
    $quarantineMutationPath = Join-Path $temp 'quarantined-reference.json'
    $quarantineMutation | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $quarantineMutationPath -Encoding utf8NoBOM
    Assert-Fails $lockValidator @('-LockPath', $quarantineMutationPath, '-AllowUnresolved')

    $releaseFixtureRoot = Join-Path $temp 'release-fixtures'
    New-Item -ItemType Directory -Path $releaseFixtureRoot | Out-Null
    $releaseLock = [ordered]@{
        dependencies = @(
            [ordered]@{
                id = 'fixture'
                required = $true
                status = 'admitted'
                release_id = 900001
                release_tag = 'fixture-tag'
                release_immutable = $true
                asset_id = 900002
                asset_url = 'https://github.com/crutkas/MSYS2-packages/releases/download/fixture-tag/fixture.pkg.tar.zst'
                asset_name = 'fixture.pkg.tar.zst'
                asset_bytes = 123
                asset_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            },
            [ordered]@{
                id = 'not-applicable-fixture'
                required = $false
                status = 'not-applicable'
            }
        )
    }
    $releaseLockPath = Join-Path $releaseFixtureRoot 'lock.json'
    $releaseLock | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $releaseLockPath -Encoding utf8NoBOM
    $releaseResponse = [ordered]@{
        id = 900001
        tag_name = 'fixture-tag'
        immutable = $true
        assets = @([ordered]@{
            id = 900002
            name = 'fixture.pkg.tar.zst'
            size = 123
            digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            browser_download_url = 'https://github.com/crutkas/MSYS2-packages/releases/download/fixture-tag/fixture.pkg.tar.zst'
        })
    }
    $releaseResponsePath = Join-Path $releaseFixtureRoot '900001.json'
    $releaseResponse | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $releaseResponsePath -Encoding utf8NoBOM
    Invoke-ExpectedExit 0 $releaseValidator @(
        '-LockPath', $releaseLockPath,
        '-ResponseDirectory', $releaseFixtureRoot
    )
    foreach ($mutation in @(
        @{ name = 'immutable-false'; apply = { param($value) $value.immutable = $false } },
        @{ name = 'missing-immutable'; apply = { param($value) $value.PSObject.Properties.Remove('immutable') } },
        @{ name = 'release-drift'; apply = { param($value) $value.id = 900003 } },
        @{ name = 'tag-drift'; apply = { param($value) $value.tag_name = 'wrong-tag' } },
        @{ name = 'asset-drift'; apply = { param($value) $value.assets[0].id = 900004 } }
    )) {
        $value = $releaseResponse | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        & $mutation.apply $value
        $value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $releaseResponsePath -Encoding utf8NoBOM
        Assert-Fails $releaseValidator @(
            '-LockPath', $releaseLockPath,
            '-ResponseDirectory', $releaseFixtureRoot
        )
    }
    $releaseResponse | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $releaseResponsePath -Encoding utf8NoBOM
    $knownQuarantineLock = $releaseLock | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $knownQuarantineLock.dependencies[0].release_id = 377908415
    $knownQuarantineLockPath = Join-Path $releaseFixtureRoot 'known-quarantine-lock.json'
    $knownQuarantineLock | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $knownQuarantineLockPath -Encoding utf8NoBOM
    Copy-Item -LiteralPath $releaseResponsePath -Destination (Join-Path $releaseFixtureRoot '377908415.json')
    Assert-Fails $releaseValidator @(
        '-LockPath', $knownQuarantineLockPath,
        '-ResponseDirectory', $releaseFixtureRoot
    )

    $pkgbuild = Get-Content -LiteralPath $pkgbuildPath -Raw
    foreach ($required in @(
        '_target=aarch64-pc-msys',
        'ALTROOT must name the fresh private package root',
        '--host="${_target}"',
        '--disable-gnutls',
        '--disable-ldap',
        '--disable-nls',
        'mingw-w64-cross-msysarm64-runtime-devel=0.unresolved',
        'mingw-w64-cross-cygwinarm64-binutils=0.unresolved',
        'mingw-w64-cross-msysarm64-gcc=0.unresolved',
        'mingw-w64-cross-msysarm64-gcc-libs=0.unresolved',
        'mingw-w64-cross-msysarm64-w32api-runtime=0.unresolved',
        'mingw-w64-cross-msysarm64-sysroot=0.unresolved',
        'mingw-w64-cross-msysarm64-runtime=0.unresolved',
        'mingw-w64-cross-msysarm64-npth-devel=0.unresolved',
        'mingw-w64-cross-msysarm64-libgpg-error-devel=0.unresolved',
        'mingw-w64-cross-msysarm64-libgpg-error=0.unresolved',
        'mingw-w64-cross-msysarm64-pinentry=0.unresolved',
        '043bd2067efc5ad5837767fef556096dd42490f98bc12a47c6ef0e42fa552560',
        'validpgpkeys=(',
        'cygwin-compile-only.specs',
        '_pei386_runtime_relocator'
    )) {
        if (-not $pkgbuild.Contains($required)) {
            throw "PKGBUILD is missing required cross-build evidence: $required"
        }
    }
    foreach ($forbidden in @('aarch64-w64-mingw32', 'aarch64-pc-cygwin-gcc', '/c/msys64/usr/include')) {
        if ($pkgbuild.Contains($forbidden)) {
            throw "PKGBUILD contains forbidden target or host leakage: $forbidden"
        }
    }

    $inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
    if (@($inventory.expected_pe).Count -ne 25 -or
        @($inventory.expected_pe | Sort-Object -Unique).Count -ne 25) {
        throw 'Expected PE replacement inventory must contain exactly 25 unique paths'
    }
    foreach ($package in $inventory.packages.psobject.Properties.Value) {
        if (-not $package.requires_nonempty -or @($package.path_prefixes).Count -eq 0) {
            throw 'Every package split must have a nonempty output contract'
        }
    }

    $scannerText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'check-aarch64-pseudo-relocs.ps1')).Replace("`r`n", "`n")
    $scannerHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($scannerText))
    ).ToLowerInvariant()
    if ($scannerHash -ne '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') {
        throw "Canonical scanner hash mismatch: $scannerHash"
    }

    $empty = Join-Path $temp 'empty.bin'
    [IO.File]::WriteAllBytes($empty, @())
    Invoke-ExpectedExit 0 $scannerWrapper @('-TablePath', $empty, '-OutputPath', (Join-Path $temp 'empty.json'))
    foreach ($flag in @(8, 16, 32, 64, 12, 21, 99)) {
        $bytes = [Collections.Generic.List[byte]]::new()
        foreach ($value in @(0, 0, 1, 1, 2, $flag)) {
            $bytes.AddRange([BitConverter]::GetBytes([uint32] $value))
        }
        $path = Join-Path $temp "flag-$flag.bin"
        [IO.File]::WriteAllBytes($path, $bytes.ToArray())
        if ($flag -in @(8, 16, 32, 64)) {
            Invoke-ExpectedExit 0 $scannerWrapper @('-TablePath', $path, '-OutputPath', (Join-Path $temp "flag-$flag.json"))
        }
        else {
            Assert-Fails $scannerWrapper @('-TablePath', $path, '-OutputPath', (Join-Path $temp "flag-$flag.json"))
        }
    }
    $malformed = Join-Path $temp 'malformed.bin'
    [IO.File]::WriteAllBytes($malformed, [byte[]] @(1, 2, 3, 4, 5))
    Assert-Fails $scannerWrapper @('-TablePath', $malformed, '-OutputPath', (Join-Path $temp 'malformed.json'))

    $fakeRoot = Join-Path $temp 'fake-root'
    New-Item -ItemType Directory -Force -Path (Join-Path $fakeRoot 'usr\bin') | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $fakeRoot 'usr\bin\gpg.exe'), [byte[]] (0..63))
    $fakeInventory = [ordered]@{
        expected_pe = @('usr/bin/gpg.exe')
        allowed_target_dll_patterns = @('^msys-2\.0\.dll$', '^kernel32\.dll$')
        forbidden_import_patterns = @('cygwin1\.dll', 'x86_64', 'mingw')
        archive_policy = @{ expected = $false }
    }
    $fakeInventoryPath = Join-Path $temp 'fake-inventory.json'
    $fakeInventory | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $fakeInventoryPath -Encoding utf8NoBOM
    $nm = Join-Path $temp 'nm.cmd'
    @'
@echo off
echo 0000000000001000 T __RUNTIME_PSEUDO_RELOC_LIST__
echo 0000000000001000 T __RUNTIME_PSEUDO_RELOC_LIST_END__
'@ | Set-Content -LiteralPath $nm -Encoding ascii
    $objdump = Join-Path $temp 'objdump.cmd'
    @'
@echo off
if "%1"=="-f" (
  echo architecture: aarch64
  echo file format pei-aarch64-little
  exit /b 0
)
if "%1"=="-p" (
  echo DLL Name: msys-2.0.dll
  echo DLL Name: KERNEL32.dll
  exit /b 0
)
if "%1"=="-h" (
  echo  0 .data 00002000 0000000000001000 0000000000001000 00000010 2**2
  exit /b 0
)
'@ | Set-Content -LiteralPath $objdump -Encoding ascii
    & $packageValidator -CandidateRoot $fakeRoot -InventoryPath $fakeInventoryPath -Objdump $objdump -Nm $nm -Ar $objdump -EvidencePath (Join-Path $temp 'good-package.json')

    Set-Content -LiteralPath $nm -Encoding ascii -Value '@echo off'
    Assert-Fails $packageValidator @('-CandidateRoot', $fakeRoot, '-InventoryPath', $fakeInventoryPath, '-Objdump', $objdump, '-Nm', $nm, '-Ar', $objdump)

    @'
@echo off
if "%1"=="-f" (
  echo architecture: i386:x86-64
  echo file format pei-x86-64
  exit /b 0
)
'@ | Set-Content -LiteralPath $objdump -Encoding ascii
    Assert-Fails $packageValidator @('-CandidateRoot', $fakeRoot, '-InventoryPath', $fakeInventoryPath, '-Objdump', $objdump, '-Nm', $nm, '-Ar', $objdump)

    @'
@echo off
if "%1"=="-f" (
  echo architecture: aarch64
  echo file format pe-aarch64-little
  exit /b 0
)
'@ | Set-Content -LiteralPath $objdump -Encoding ascii
    Assert-Fails $packageValidator @('-CandidateRoot', $fakeRoot, '-InventoryPath', $fakeInventoryPath, '-Objdump', $objdump, '-Nm', $nm, '-Ar', $objdump)

    @'
@echo off
if "%1"=="-f" (
  echo architecture: aarch64
  echo file format pei-aarch64-little
  exit /b 0
)
if "%1"=="-p" (
  echo DLL Name: msys-2.0.dll
  echo DLL Name: cygwin1.dll
  exit /b 0
)
'@ | Set-Content -LiteralPath $objdump -Encoding ascii
    Assert-Fails $packageValidator @('-CandidateRoot', $fakeRoot, '-InventoryPath', $fakeInventoryPath, '-Objdump', $objdump, '-Nm', $nm, '-Ar', $objdump)

    $boundsPe = Join-Path $temp 'bounds.exe'
    [IO.File]::WriteAllBytes($boundsPe, [byte[]] (0..63))
    @'
@echo off
echo 0000000000001000 T __RUNTIME_PSEUDO_RELOC_LIST__
echo 0000000000002000 T __RUNTIME_PSEUDO_RELOC_LIST_END__
'@ | Set-Content -LiteralPath $nm -Encoding ascii
    @'
@echo off
if "%1"=="-f" (
  echo architecture: aarch64
  echo file format pei-aarch64-little
  exit /b 0
)
if "%1"=="-h" (
  echo  0 .data 00002000 0000000000001000 0000000000001000 00000010 2**2
  exit /b 0
)
'@ | Set-Content -LiteralPath $objdump -Encoding ascii
    Assert-Fails $scannerWrapper @('-PePath', $boundsPe, '-OutputPath', (Join-Path $temp 'bounds.json'), '-Objdump', $objdump, '-Nm', $nm)

    $archiveRoot = Join-Path $temp 'archive-root'
    New-Item -ItemType Directory -Force -Path (Join-Path $archiveRoot 'lib') | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $archiveRoot 'lib\unexpected.a'), [byte[]] (0..15))
    $archiveInventory = [ordered]@{
        expected_pe = @()
        allowed_target_dll_patterns = @()
        forbidden_import_patterns = @()
        archive_policy = @{ expected = $true }
    }
    $archiveInventoryPath = Join-Path $temp 'archive-inventory.json'
    $archiveInventory | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $archiveInventoryPath -Encoding utf8NoBOM
    $ar = Join-Path $temp 'ar.cmd'
    Set-Content -LiteralPath $ar -Encoding ascii -Value "@echo member.o"
    Set-Content -LiteralPath $nm -Encoding ascii -Value "@echo no-index"
    Assert-Fails $packageValidator @('-CandidateRoot', $archiveRoot, '-InventoryPath', $archiveInventoryPath, '-Objdump', $objdump, '-Nm', $nm, '-Ar', $ar)

    $nativeText = Get-Content -LiteralPath $nativeTest -Raw
    foreach ($scenario in @($inventory.native_evidence_required)) {
        if (-not $nativeText.Contains("'$scenario'")) {
            throw "Native test does not emit required evidence: $scenario"
        }
    }
    foreach ($required in @('Get-PeMachine', '0x8664', 'gpg-agent.exe', 'OPTION no-grab', 'verify-commit', 'verify-tag')) {
        if (-not $nativeText.Contains($required)) {
            throw "Native test is missing required gate: $required"
        }
    }
    foreach ($required in @('GnuPGJobTracker', 'WaitForQuiescence', 'LoadModuleBarrier', 'telemetry_barrier', 'Win32_ModuleLoadTrace', 'Win32_ProcessStopTrace', 'TransactionEvidencePath', 'Get-CanonicalSnapshot')) {
        if (-not $nativeText.Contains($required)) {
            throw "Native test is missing complete process/module/shared-state closure: $required"
        }
    }

    $rootText = Get-Content -LiteralPath $rootTest -Raw
    foreach ($argument in @('--root', '--dbpath', '--cachedir', '--logfile', '--config', '--hookdir')) {
        if (-not $rootText.Contains("'$argument'")) {
            throw "Private-root transaction omits $argument"
        }
    }
    if ($rootText -match "(?i)pacman.*-Sw") {
        throw 'Shared or download-only pacman usage is forbidden'
    }
    foreach ($required in @('--noscriptlet', "'-Qlq'", "'-Qkk'", 'qkk_detected_corruption', 'exact_reinstall_recovered_sha256', 'Get-MtreePaths', 'Get-ArchiveManifest', 'mtree_sha256', 'final_installed_manifest', 'etc/pacman.d/hooks')) {
        if (-not $rootText.Contains($required)) {
            throw "Private-root lifecycle is missing integrity evidence: $required"
        }
    }
    $splitText = Get-Content -LiteralPath $splitTest -Raw
    foreach ($required in @('path_prefixes', 'requires_nonempty', 'Missing or duplicate split package')) {
        if (-not $splitText.Contains($required)) {
            throw "Split-package validator is missing required gate: $required"
        }
    }

    $cleanRoot = Join-Path $temp 'path-clean'
    New-Item -ItemType Directory -Path $cleanRoot | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $cleanRoot 'clean.bin'), [byte[]] (0..255))
    $cleanPathEvidence = Join-Path $temp 'clean-path-evidence.json'
    Invoke-ExpectedExit 0 $pathScanner @(
        '-InputPath', $cleanRoot,
        '-ForbiddenPath', 'C:\private\gnupg-build-root',
        '-EvidencePath', $cleanPathEvidence
    )
    $cleanScan = Get-Content -LiteralPath $cleanPathEvidence -Raw | ConvertFrom-Json
    if ($cleanScan.result -ne 'pass' -or @($cleanScan.scanned_entries).Count -ne 1 -or
        $cleanScan.scanned_entries[0].bytes -ne 256) {
        throw 'Forbidden-path scanner skipped a clean binary entry'
    }
    $forbidden = 'C:\private\gnupg-build-root'
    $pathFixtures = @{}
    $pathFixtures.ascii = [Text.Encoding]::ASCII.GetBytes("prefix-$forbidden-suffix")
    $pathFixtures.utf16le = [Text.Encoding]::Unicode.GetBytes($forbidden)
    $utf16be = [Text.Encoding]::Unicode.GetBytes($forbidden)
    for ($index = 0; $index -lt $utf16be.Length; $index += 2) {
        $temporary = $utf16be[$index]
        $utf16be[$index] = $utf16be[$index + 1]
        $utf16be[$index + 1] = $temporary
    }
    $pathFixtures.utf16be = $utf16be
    $nulRich = [Collections.Generic.List[byte]]::new()
    foreach ($value in [Text.Encoding]::ASCII.GetBytes($forbidden)) {
        $nulRich.Add($value)
        $nulRich.Add(0)
        $nulRich.Add(0)
    }
    $pathFixtures.nulrich = $nulRich.ToArray()
    foreach ($fixture in $pathFixtures.GetEnumerator()) {
        $fixtureRoot = Join-Path $temp "path-$($fixture.Key)"
        New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
        $padding = [byte[]]::new(65535)
        $bytes = [byte[]]::new($padding.Length + $fixture.Value.Length)
        [Array]::Copy($padding, $bytes, $padding.Length)
        [Array]::Copy($fixture.Value, 0, $bytes, $padding.Length, $fixture.Value.Length)
        $fixtureName = if ($fixture.Key -eq 'nulrich') { '.MTREE' } else { "payload-$($fixture.Key)" }
        [IO.File]::WriteAllBytes((Join-Path $fixtureRoot $fixtureName), $bytes)
        Assert-Fails $pathScanner @(
            '-InputPath', $fixtureRoot,
            '-ForbiddenPath', $forbidden
        )
        $expectedMode = if ($fixture.Key -eq 'nulrich') { 'nul_rich' } else { $fixture.Key }
        if ((Get-Content -LiteralPath (Join-Path $temp 'last-command.log') -Raw) -notmatch "as $expectedMode") {
            throw "Forbidden-path fixture did not exercise $expectedMode detection"
        }
    }

    $buildA = Join-Path $temp 'build-a'
    $buildB = Join-Path $temp 'build-b'
    New-Item -ItemType Directory -Path $buildA, $buildB | Out-Null
    $packageName = 'mingw-w64-cross-msysarm64-gnupg-2.4.7-1-x86_64.pkg.tar.zst'
    $packageBytes = [Text.Encoding]::ASCII.GetBytes('byte-identical-package-fixture')
    [IO.File]::WriteAllBytes((Join-Path $buildA $packageName), $packageBytes)
    [IO.File]::WriteAllBytes((Join-Path $buildB $packageName), $packageBytes)
    foreach ($fixture in @(
        @{ name = 'build-identity-evidence.json'; value = @{ schema_version = 1; result = 'pass'; source_signature_verified = $true } },
        @{ name = 'package-evidence.json'; value = @{ schema_version = 1; result = 'pass'; target = 'aarch64-pc-msys'; pe_count = 1; pe = @(@{ pseudo_reloc = @{ result = 'pass' } }) } },
        @{ name = 'candidate-transaction.json'; value = @{ schema_version = 1; result = 'pass'; candidate_integrity = @(@{ qkk_detected_corruption = $true; mtree_sha256 = ('1' * 64); exact_reinstall_recovered_sha256 = ('2' * 64); final_installed_manifest = @('entry') }) } }
    )) {
        foreach ($build in @($buildA, $buildB)) {
            $value = $fixture.value.Clone()
            if ($fixture.name -eq 'build-identity-evidence.json') {
                $value.build_id = if ($build -eq $buildA) { 'a' } else { 'b' }
            }
            elseif ($fixture.name -eq 'candidate-transaction.json') {
                $value.candidate_integrity[0].archive = $packageName
                $value.candidate_integrity[0].archive_bytes = $packageBytes.Length
                $value.candidate_integrity[0].archive_sha256 = [Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($packageBytes)
                ).ToLowerInvariant()
            }
            $value | ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath (Join-Path $build $fixture.name) -Encoding utf8NoBOM
        }
    }
    foreach ($build in @($buildA, $buildB)) {
        $packageHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($packageBytes)
        ).ToLowerInvariant()
        @{
            schema_version = 1
            result = 'pass'
            encodings = @('ascii', 'utf16le', 'utf16be', 'nul_rich')
            inputs = @(@{
                path = (Join-Path $build $packageName)
                type = 'archive'
                bytes = $packageBytes.Length
                sha256 = $packageHash
            })
            scanned_entries = @(@{ input = (Join-Path $build $packageName) })
        } | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath (Join-Path $build 'forbidden-path-evidence.json') -Encoding utf8NoBOM
    }
    Invoke-ExpectedExit 0 $buildComparer @(
        '-BuildAPath', $buildA,
        '-BuildBPath', $buildB,
        '-OutputPath', (Join-Path $temp 'matched'),
        '-EvidencePath', (Join-Path $temp 'reproducibility.json'),
        '-InventoryPath', $inventoryPath
    )
    [IO.File]::AppendAllText((Join-Path $buildB $packageName), 'different')
    Assert-Fails $buildComparer @(
        '-BuildAPath', $buildA,
        '-BuildBPath', $buildB,
        '-OutputPath', (Join-Path $temp 'mismatch-output'),
        '-EvidencePath', (Join-Path $temp 'mismatch.json'),
        '-InventoryPath', $inventoryPath
    )
    [IO.File]::WriteAllBytes((Join-Path $buildB $packageName), $packageBytes)
    $scanEvidencePath = Join-Path $buildB 'forbidden-path-evidence.json'
    $scanEvidence = Get-Content -LiteralPath $scanEvidencePath -Raw | ConvertFrom-Json
    $validScanHash = $scanEvidence.inputs[0].sha256
    $scanEvidence.inputs[0].sha256 = '0' * 64
    $scanEvidence | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $scanEvidencePath -Encoding utf8NoBOM
    Assert-Fails $buildComparer @(
        '-BuildAPath', $buildA,
        '-BuildBPath', $buildB,
        '-OutputPath', (Join-Path $temp 'wrong-scan-hash-output'),
        '-EvidencePath', (Join-Path $temp 'wrong-scan-hash.json'),
        '-InventoryPath', $inventoryPath
    )
    $scanEvidence.inputs[0].sha256 = $validScanHash
    $scanEvidence | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $scanEvidencePath -Encoding utf8NoBOM
    Remove-Item -LiteralPath (Join-Path $buildB 'package-evidence.json')
    Assert-Fails $buildComparer @(
        '-BuildAPath', $buildA,
        '-BuildBPath', $buildB,
        '-OutputPath', (Join-Path $temp 'missing-evidence-output'),
        '-EvidencePath', (Join-Path $temp 'missing-evidence.json'),
        '-InventoryPath', $inventoryPath
    )

    Add-Type -AssemblyName System.IO.Compression
    $dotArchive = Join-Path $temp 'dot-hook.zip'
    $zip = [IO.Compression.ZipFile]::Open($dotArchive, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $zip.CreateEntry('etc/pacman.d/./hooks/evil.hook')
        $writer = [IO.StreamWriter]::new($entry.Open())
        try {
            $writer.Write('[Trigger]')
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $zip.Dispose()
    }
    Assert-Fails $pathScanner @(
        '-InputPath', $dotArchive,
        '-ForbiddenPath', $forbidden
    )

    $workflowText = Get-Content -LiteralPath $workflowPath -Raw
    foreach ($required in @(
        'independent_build: [a, b]',
        'Compare-Aarch64GnuPGBuilds.ps1',
        'build-identity-evidence.json',
        'Require byte-identical independent packages',
        'Test-Aarch64GnuPGForbiddenPaths.ps1',
        'environment: gnupg-native-admission',
        'GNUPG_COORDINATOR_ADMISSION_SHA256',
        'package_manifest_sha256'
    )) {
        if (-not $workflowText.Contains($required)) {
            throw "Workflow is missing a fail-closed build/admission gate: $required"
        }
    }
    $symbolicActions = @(
        [regex]::Matches($workflowText, '(?m)^\s*-\s+uses:\s+\S+@(?![0-9a-f]{40}(?:\s|$))')
    )
    if ($symbolicActions.Count -ne 0) {
        throw 'Every action in the GnuPG workflow must be pinned to a full commit SHA'
    }
    foreach ($required in @(
        'New-Aarch64GnuPGStaticEvidence.ps1',
        'Test-Aarch64GnuPGStaticEvidence.ps1',
        'gnupg-static-evidence.json',
        'Test-Aarch64GnuPGReleaseAdmission.ps1',
        'ref: ${{ github.event.pull_request.head.sha || github.sha }}'
    )) {
        if (-not $workflowText.Contains($required)) {
            throw "Workflow is missing static admission evidence: $required"
        }
    }
    $lockGate = $workflowText.IndexOf('Require a complete admitted dependency lock', [StringComparison]::Ordinal)
    $liveGate = $workflowText.IndexOf('Require live immutable release identities', [StringComparison]::Ordinal)
    $setup = $workflowText.IndexOf('uses: msys2/setup-msys2@', [StringComparison]::Ordinal)
    if ($lockGate -lt 0 -or $liveGate -lt $lockGate -or $setup -lt $liveGate) {
        throw 'Lock and live release gates must precede setup-msys2'
    }
    foreach ($scriptPath in @($staticEvidenceGenerator, $staticEvidenceValidator)) {
        $scriptText = Get-Content -LiteralPath $scriptPath -Raw
        foreach ($required in @(
            'repository', 'base_commit', 'head_commit', 'tree', 'lock_sha256',
            'inventory_sha256', 'scanner_sha256', 'action_pins',
            'unresolved_dependencies', 'setup_msys2', 'dependency_download',
            'package_install', 'package_build', 'native_execution'
        )) {
            if (-not $scriptText.Contains($required)) {
                throw "Static evidence contract omits $required in $scriptPath"
            }
        }
        if (-not $scriptText.Contains('Get-NormalizedSha256 $ScannerPath')) {
            throw "Static evidence must normalize the scanner hash in $scriptPath"
        }
    }
    if ($workflowText.IndexOf('Preflight every package byte and archive path', [StringComparison]::Ordinal) -gt
        $workflowText.IndexOf('& C:\msys64\usr\bin\bsdtar.exe -xf', [StringComparison]::Ordinal)) {
        throw 'Package archive preflight must run before direct extraction'
    }
    $pathScannerText = Get-Content -LiteralPath $pathScanner -Raw
    foreach ($required in @('Assert-SafeArchivePath', 'Assert-SafeLinkTarget', '-HardLink', 'LinkType')) {
        if (-not $pathScannerText.Contains($required)) {
            throw "Forbidden-path preflight is missing archive/link containment: $required"
        }
    }
    foreach ($seal in @(
        '2befdd85bb926912a084ca5ec9db5b088252540e7d224d1d5bafd8003733b758',
        '2ec9adc67172cf78837786071e0fc0e7b47a3e6fd3bf00213bb8d2be2a291c93'
    )) {
        if (-not $pkgbuild.Contains($seal)) {
            throw "PKGBUILD does not pin the current static policy seal: $seal"
        }
    }

    Write-Host 'AArch64 GnuPG static tests passed'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

exit 0

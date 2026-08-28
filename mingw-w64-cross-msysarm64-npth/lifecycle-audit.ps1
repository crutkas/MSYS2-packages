<#
.SYNOPSIS
  Private-base pacman lifecycle audit for the npth candidate packages.

.DESCRIPTION
  Runs install / remove / reinstall of the two compared npth candidates using
  ONLY the pacman binary shipped inside the immutable msys2-base 20260611 root,
  against a throwaway transaction root. Every pacman invocation passes explicit
  --root/--dbpath/--cachedir/--logfile/--config/--hookdir/--gpgdir and a config
  whose LocalFileSigLevel is Never (each local archive was hash-verified before
  it reached this job). No live repository is ever contacted; --nodeps and
  --assume-installed are never used - the full local dependency closure is
  installed from real archives so pacman resolves genuinely.

  The shared runner database and pacman log are sealed before and after and must
  be byte-for-byte identical afterwards. The immutable private base's own
  1178-entry local database is likewise sealed and must be unchanged. This job
  only reads/compares shared paths; it never uses their tools for package work.

  Pure helpers are dot-sourceable (set $LifecycleDotSource before dot-sourcing)
  so test-lifecycle-audit.ps1 can drive them offline with synthetic fixtures.
#>
[CmdletBinding()]
param(
  [string] $Pacman,
  [string] $Bsdtar = 'bsdtar',
  [string] $TransactionRoot,
  [string[]] $DependencyArchive = @(),
  [string[]] $CandidateArchive = @(),
  [string] $ReportDirectory,
  [string] $PrivateBaseLocalDb,
  [int] $ExpectedBaseDbEntries = 0,
  [int] $ExpectedSharedDbEntries = 0,
  [string] $SharedDatabase = 'C:\msys64\var\lib\pacman\local',
  [string] $SharedLog = 'C:\msys64\var\log\pacman.log'
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$script:ExpectedNames = @(
  'mingw-w64-cross-msysarm64-npth',
  'mingw-w64-cross-msysarm64-npth-devel'
)
$script:ExpectedVersion = '1.8-2'
$script:RuntimeVersion = '3.6.10.r0.ga527ace21'
$script:AllowedPathPrefix = @('opt/aarch64-pc-msys/usr/', 'usr/share/licenses/')

function Get-PackageInfo {
  param([Parameter(Mandatory)] [string] $Archive, [Parameter(Mandatory)] [string] $Bsdtar)
  $lines = & $Bsdtar -xOf $Archive .PKGINFO
  if ($LASTEXITCODE -ne 0) { throw "Unable to read .PKGINFO from $Archive" }
  $result = @{}
  foreach ($line in $lines) {
    if ($line -match '^([^#][^=]+?) = (.*)$') {
      $key = $Matches[1].Trim()
      if (-not $result.ContainsKey($key)) {
        $result[$key] = [System.Collections.Generic.List[string]]::new()
      }
      $result[$key].Add($Matches[2])
    }
  }
  return $result
}

function Get-PackageFiles {
  param([Parameter(Mandatory)] [string] $Archive, [Parameter(Mandatory)] [string] $Bsdtar)
  $files = & $Bsdtar -tf $Archive
  if ($LASTEXITCODE -ne 0) { throw "Unable to list $Archive" }
  return @($files | Where-Object {
      $_ -and -not $_.EndsWith('/') -and $_ -notin @('.BUILDINFO', '.MTREE', '.PKGINFO')
    })
}

function Test-CandidateMetadata {
  <# Validates one candidate's identity/dependency/provides/conflict metadata.
     Throws on any deviation from the coordinator-approved contract. #>
  param([Parameter(Mandatory)] [hashtable] $Info)

  $name = @($Info['pkgname'])[0]
  $version = @($Info['pkgver'])[0]
  if ($name -notin $script:ExpectedNames) { throw "Unexpected package identity: $name" }
  if ($version -ne $script:ExpectedVersion) { throw "Unexpected version $version for $name" }

  $required = switch ($name) {
    'mingw-w64-cross-msysarm64-npth' {
      @("aarch64-pc-msys-runtime=$($script:RuntimeVersion)")
    }
    'mingw-w64-cross-msysarm64-npth-devel' {
      @(
        'mingw-w64-cross-msysarm64-npth=1.8-2',
        "aarch64-pc-msys-runtime=$($script:RuntimeVersion)",
        "aarch64-pc-msys-sysroot=$($script:RuntimeVersion)"
      )
    }
  }
  $depends = @(if ($Info.ContainsKey('depend')) { $Info['depend'] } else { @() })
  if ((($depends | Sort-Object) -join "`n") -ne (($required | Sort-Object) -join "`n")) {
    throw "$name has unexpected dependency metadata: $($depends -join ', ')"
  }
  $expectedProvide = $name.Replace('mingw-w64-cross-msysarm64-', 'aarch64-pc-msys-') + '=1.8'
  $provides = @(if ($Info.ContainsKey('provides')) { $Info['provides'] } else { @() })
  if ($provides.Count -ne 1 -or $provides[0] -ne $expectedProvide) {
    throw "$name has unexpected provides metadata: $($provides -join ', ')"
  }
  $expectedConflict = $expectedProvide.Split('=')[0]
  $conflicts = @(if ($Info.ContainsKey('conflict')) { $Info['conflict'] } else { @() })
  if ($conflicts.Count -ne 1 -or $conflicts[0] -ne $expectedConflict) {
    throw "$name has unexpected conflicts metadata: $($conflicts -join ', ')"
  }
  return $name
}

function Get-CandidateOwnership {
  <# Builds path -> owning package map for the candidate set, enforcing the
     approved prefixes and rejecting cross-package ownership collisions. #>
  param([Parameter(Mandatory)] [hashtable] $FilesByPackage)
  $owners = [ordered]@{}
  foreach ($name in $FilesByPackage.Keys) {
    foreach ($file in $FilesByPackage[$name]) {
      $ok = $false
      foreach ($prefix in $script:AllowedPathPrefix) {
        if ($file.StartsWith($prefix)) { $ok = $true; break }
      }
      if (-not $ok) { throw "$name owns a path outside approved prefixes: $file" }
      if ($owners.Contains($file)) {
        throw "Ownership collision: $file is owned by both $($owners[$file]) and $name"
      }
      $owners[$file] = $name
    }
  }
  return $owners
}

function Get-TreeSeal {
  <# Deterministic SHA-256 seal over a directory's regular-file contents and
     relative paths. Order-independent via sorting. #>
  param([Parameter(Mandatory)] [string] $Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "Path does not exist: $Path" }
  $root = (Resolve-Path -LiteralPath $Path).Path
  $prefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $lines = Get-ChildItem -LiteralPath $root -Recurse -File -Force |
    Sort-Object FullName |
    ForEach-Object {
      $rel = ([IO.Path]::GetFullPath($_.FullName)).Substring($prefix.Length) -replace '\\', '/'
      '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $rel
    }
  $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Get-FileSeal {
  param([Parameter(Mandatory)] [string] $Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "File does not exist: $Path" }
  $item = Get-Item -LiteralPath $Path
  return [pscustomobject]@{
    path         = $item.FullName
    size         = $item.Length
    sha256       = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    lastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
  }
}

function Get-LocalDbEntryCount {
  <# Counts installed-package entries in an ALPM local database: each entry is a
     subdirectory containing a 'desc' file. #>
  param([Parameter(Mandatory)] [string] $LocalDbPath)
  if (-not (Test-Path -LiteralPath $LocalDbPath)) { throw "Local DB not found: $LocalDbPath" }
  return @(Get-ChildItem -LiteralPath $LocalDbPath -Directory -Force |
      Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'desc') }).Count
}

function Invoke-Pacman {
  param([Parameter(Mandatory)] [string] $Pacman, [Parameter(Mandatory)] [string[]] $Arguments)
  & $Pacman @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "pacman failed (exit $LASTEXITCODE): $($Arguments -join ' ')"
  }
}

function Invoke-LifecycleAudit {
  param(
    [Parameter(Mandatory)] [string] $Pacman,
    [Parameter(Mandatory)] [string] $Bsdtar,
    [Parameter(Mandatory)] [string] $TransactionRoot,
    [Parameter(Mandatory)] [string[]] $DependencyArchive,
    [Parameter(Mandatory)] [string[]] $CandidateArchive,
    [Parameter(Mandatory)] [string] $ReportDirectory,
    [Parameter(Mandatory)] [string] $PrivateBaseLocalDb,
    [int] $ExpectedBaseDbEntries = 0,
    [int] $ExpectedSharedDbEntries = 0,
    [string] $SharedDatabase = 'C:\msys64\var\lib\pacman\local',
    [string] $SharedLog = 'C:\msys64\var\log\pacman.log'
  )

  $buildInfoValidator = Join-Path $PSScriptRoot 'validate-buildinfo-path.ps1'
  New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null

  $full = [IO.Path]::GetFullPath($TransactionRoot)
  if ([IO.Path]::GetPathRoot($full) -eq $full -or [IO.Path]::GetFileName($full) -notmatch 'npth') {
    throw "Refusing unsafe transaction root: $full"
  }
  $TransactionRoot = $full

  if ($CandidateArchive.Count -ne 2) {
    throw "Expected exactly two npth candidates, found $($CandidateArchive.Count)"
  }

  # --- seal shared + private-base databases BEFORE any transaction -----------
  $sharedBefore = Get-TreeSeal -Path $SharedDatabase
  $sharedLogBefore = Get-FileSeal -Path $SharedLog
  $sharedEntriesBefore = Get-LocalDbEntryCount -LocalDbPath $SharedDatabase
  if ($ExpectedSharedDbEntries -gt 0 -and $sharedEntriesBefore -ne $ExpectedSharedDbEntries) {
    throw "Shared C:\msys64 local DB has $sharedEntriesBefore entries, expected $ExpectedSharedDbEntries"
  }
  $baseBefore = Get-TreeSeal -Path $PrivateBaseLocalDb
  $baseEntriesBefore = Get-LocalDbEntryCount -LocalDbPath $PrivateBaseLocalDb
  if ($ExpectedBaseDbEntries -gt 0 -and $baseEntriesBefore -ne $ExpectedBaseDbEntries) {
    throw "Private base local DB has $baseEntriesBefore entries, expected $ExpectedBaseDbEntries"
  }
  $sharedBefore | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-before.sha256')
  $baseBefore | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'base-db-before.sha256')
  $sharedLogBefore | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'shared-log-before.json')

  # --- validate candidate metadata + ownership -------------------------------
  $filesByPackage = [ordered]@{}
  $records = @()
  foreach ($archive in $CandidateArchive) {
    if (-not (Test-Path -LiteralPath $archive)) { throw "Candidate archive missing: $archive" }
    $info = Get-PackageInfo -Archive $archive -Bsdtar $Bsdtar
    $name = Test-CandidateMetadata -Info $info
    $filesByPackage[$name] = @(Get-PackageFiles -Archive $archive -Bsdtar $Bsdtar)
    if ($filesByPackage[$name].Count -eq 0) { throw "$name has an empty payload" }

    $buildInfoPath = Join-Path $ReportDirectory "$name.BUILDINFO"
    & $Bsdtar -xOf $archive .BUILDINFO | Set-Content -Encoding ascii $buildInfoPath
    if (Test-Path -LiteralPath $buildInfoValidator) { & $buildInfoValidator -Path $buildInfoPath }
    $records += [pscustomobject]@{
      name   = $name
      sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
      size   = (Get-Item -LiteralPath $archive).Length
      files  = $filesByPackage[$name].Count
    }
  }
  if ((($filesByPackage.Keys | Sort-Object) -join "`n") -ne (($script:ExpectedNames | Sort-Object) -join "`n")) {
    throw 'The candidate set is incomplete'
  }
  $owners = Get-CandidateOwnership -FilesByPackage $filesByPackage
  $records | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'candidate-seal.json')

  # --- build the isolated transaction root -----------------------------------
  if (Test-Path -LiteralPath $TransactionRoot) { Remove-Item -LiteralPath $TransactionRoot -Recurse -Force }
  $stateRoot = "$TransactionRoot-state"
  if (Test-Path -LiteralPath $stateRoot) {
    Remove-Item -LiteralPath $stateRoot -Recurse -Force
  }
  $db = Join-Path $TransactionRoot 'var\lib\pacman'
  $cache = Join-Path $stateRoot 'cache'
  $log = Join-Path $stateRoot 'pacman.log'
  $config = Join-Path $TransactionRoot 'etc\pacman-local.conf'
  $hooks = Join-Path $TransactionRoot 'etc\pacman.d\hooks'
  $gpg = Join-Path $TransactionRoot 'etc\pacman.d\gnupg'
  New-Item -ItemType Directory -Force -Path $db, $cache, $stateRoot, $hooks, $gpg | Out-Null
  @'
[options]
Architecture = auto
LocalFileSigLevel = Never
SigLevel = Never
'@ | Set-Content -Encoding ascii $config

  # Every transaction is local (-U/-R/-Q) against explicit, isolated databases.
  $common = @(
    '--root', $TransactionRoot,
    '--dbpath', $db,
    '--cachedir', $cache,
    '--logfile', $log,
    '--config', $config,
    '--hookdir', $hooks,
    '--gpgdir', $gpg,
    '--noconfirm'
  )

  # Install the full local dependency closure first, so the candidate install
  # resolves genuinely - no --nodeps, no --assume-installed.
  if ($DependencyArchive.Count -gt 0) {
    Invoke-Pacman -Pacman $Pacman -Arguments ($common + @('-U') + $DependencyArchive)
  }

  # Seal the post-dependency tree: removal of the candidates must restore it.
  $baselineTree = Get-TreeSeal -Path $TransactionRoot

  Invoke-Pacman -Pacman $Pacman -Arguments ($common + @('-U') + $CandidateArchive)
  $installed = & $Pacman @common -Q
  if ($LASTEXITCODE -ne 0) { throw 'Unable to query isolated database after install' }
  $installed | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'installed-first.txt')
  $installedText = $installed -join "`n"
  foreach ($name in $script:ExpectedNames) {
    if ($installedText -notmatch "(?m)^$([regex]::Escape($name)) $([regex]::Escape($script:ExpectedVersion))$") {
      throw "$name was not installed at the expected version"
    }
  }
  foreach ($file in $owners.Keys) {
    if (-not (Test-Path -LiteralPath (Join-Path $TransactionRoot ($file -replace '/', '\')))) {
      throw "Installed candidate is missing an owned path: $file"
    }
  }

  # Remove both candidates with a plain -R (nothing external depends on them);
  # -Rdd/--nodeps is deliberately never used.
  Invoke-Pacman -Pacman $Pacman -Arguments ($common + @('-R') + $script:ExpectedNames)
  foreach ($file in $owners.Keys) {
    if (Test-Path -LiteralPath (Join-Path $TransactionRoot ($file -replace '/', '\'))) {
      throw "Package-owned path survived removal: $file"
    }
  }
  $restoredTree = Get-TreeSeal -Path $TransactionRoot
  if ($restoredTree -ne $baselineTree) {
    throw 'Transaction root was not restored to its pre-candidate state after removal'
  }

  # Reinstall to prove idempotence.
  Invoke-Pacman -Pacman $Pacman -Arguments ($common + @('-U') + $CandidateArchive)
  $reinstalled = & $Pacman @common -Q
  if ($LASTEXITCODE -ne 0) { throw 'Unable to query isolated database after reinstall' }
  $reinstalled | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'installed-reinstall.txt')
  $reinstalledText = $reinstalled -join "`n"
  foreach ($name in $script:ExpectedNames) {
    if ($reinstalledText -notmatch "(?m)^$([regex]::Escape($name)) $([regex]::Escape($script:ExpectedVersion))$") {
      throw "$name was not reinstalled at the expected version"
    }
  }
  Copy-Item -LiteralPath $log -Destination (Join-Path $ReportDirectory 'transaction-pacman.log')

  # --- re-seal shared + private base and require exact equality ---------------
  $sharedAfter = Get-TreeSeal -Path $SharedDatabase
  $sharedLogAfter = Get-FileSeal -Path $SharedLog
  $sharedEntriesAfter = Get-LocalDbEntryCount -LocalDbPath $SharedDatabase
  $baseAfter = Get-TreeSeal -Path $PrivateBaseLocalDb
  $baseEntriesAfter = Get-LocalDbEntryCount -LocalDbPath $PrivateBaseLocalDb
  $sharedAfter | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-after.sha256')
  $baseAfter | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'base-db-after.sha256')
  $sharedLogAfter | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'shared-log-after.json')

  if ($sharedAfter -ne $sharedBefore) { throw 'Shared C:\msys64 package database changed during the transaction' }
  if ($sharedEntriesAfter -ne $sharedEntriesBefore -or
      ($ExpectedSharedDbEntries -gt 0 -and $sharedEntriesAfter -ne $ExpectedSharedDbEntries)) {
    throw "Shared C:\msys64 local DB entry count changed to $sharedEntriesAfter (before $sharedEntriesBefore)"
  }
  if ($sharedLogAfter.sha256 -ne $sharedLogBefore.sha256 -or $sharedLogAfter.size -ne $sharedLogBefore.size) {
    throw 'Shared C:\msys64 pacman log changed during the transaction'
  }
  if ($baseAfter -ne $baseBefore) { throw 'Private base local database changed during the transaction' }
  if ($baseEntriesAfter -ne $baseEntriesBefore) {
    throw "Private base local DB entry count changed to $baseEntriesAfter (expected $baseEntriesBefore)"
  }

  Write-Output "Lifecycle audit passed: install/remove/reinstall verified; shared C:\msys64 database unchanged ($sharedEntriesBefore entries) and private base unchanged ($baseEntriesBefore entries)."
}

$script:LifecycleDotSourced = $false
$dotVar = Get-Variable -Name LifecycleDotSource -Scope Global -ErrorAction SilentlyContinue
if ($dotVar -and [bool]$dotVar.Value) { $script:LifecycleDotSourced = $true }

if (-not $script:LifecycleDotSourced) {
  foreach ($required in @('Pacman', 'TransactionRoot', 'ReportDirectory', 'PrivateBaseLocalDb')) {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $required -ValueOnly))) {
      throw "Required parameter -$required was not supplied"
    }
  }
  if ($CandidateArchive.Count -eq 0) { throw 'Required parameter -CandidateArchive was not supplied' }
  Invoke-LifecycleAudit `
    -Pacman $Pacman -Bsdtar $Bsdtar -TransactionRoot $TransactionRoot `
    -DependencyArchive $DependencyArchive -CandidateArchive $CandidateArchive `
    -ReportDirectory $ReportDirectory -PrivateBaseLocalDb $PrivateBaseLocalDb `
    -ExpectedBaseDbEntries $ExpectedBaseDbEntries `
    -ExpectedSharedDbEntries $ExpectedSharedDbEntries `
    -SharedDatabase $SharedDatabase -SharedLog $SharedLog
}

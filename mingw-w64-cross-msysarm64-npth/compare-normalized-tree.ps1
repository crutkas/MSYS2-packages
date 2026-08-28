<#
.SYNOPSIS
  Compare the inner trees of the npth candidate packages produced by two
  independent, deterministic build jobs and fail on any difference.

.DESCRIPTION
  The two build jobs upload their .pkg.tar.zst outputs as separate artifacts.
  This script discovers the package files common to both download directories,
  safely extracts each (reusing the fail-closed preflight in safe-extract.ps1),
  requires identical archive SHA-256 values, safely extracts each (reusing the
  fail-closed preflight in safe-extract.ps1), and compares the extracted trees
  byte-for-byte including metadata.

  Both the complete package archive and every extracted member - including the
  compressed .MTREE, .PKGINFO and .BUILDINFO - are compared as raw bytes. Any
  archive, missing-member, extra-member, or content difference fails.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $BuildA,
  [Parameter(Mandatory)] [string] $BuildB,
  [string] $Filter = '*.pkg.tar.*',
  [string] $Bsdtar = 'bsdtar',
  [string] $WorkDir
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# Capture parameters that collide with safe-extract.ps1's own param block before
# dot-sourcing it (dot-sourcing re-runs that param block and would otherwise
# reset $Bsdtar to its default).
$BsdtarExe = $Bsdtar
. (Join-Path $PSScriptRoot 'safe-extract.ps1')

function Get-NormalizedBytes {
  param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Relative)
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  return [pscustomobject]@{ Kind = 'raw'; Bytes = $bytes }
}

function Get-Sha256Hex {
  param([Parameter(Mandatory)] [byte[]] $Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
  }
  finally { $sha.Dispose() }
}

function Get-PackageTreeManifest {
  param(
    [Parameter(Mandatory)] [string] $Package,
    [Parameter(Mandatory)] [string] $Destination,
    [Parameter(Mandatory)] [string] $Bsdtar
  )
  Invoke-SafeExtract -Archive $Package -Destination $Destination -Bsdtar $Bsdtar | Out-Null
  $root = (Resolve-Path -LiteralPath $Destination).Path
  $rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar

  $manifest = [ordered]@{}
  foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -Force -File | Sort-Object FullName) {
    $full = [IO.Path]::GetFullPath($file.FullName)
    $relative = $full.Substring($rootPrefix.Length) -replace '\\', '/'
    $normalized = Get-NormalizedBytes -Path $full -Relative $relative
    $manifest[$relative] = [pscustomobject]@{
      Kind   = $normalized.Kind
      Size   = $normalized.Bytes.Length
      Sha256 = Get-Sha256Hex -Bytes $normalized.Bytes
    }
  }
  return $manifest
}

function Compare-PackagePair {
  param(
    [Parameter(Mandatory)] [string] $Name,
    [Parameter(Mandatory)] [string] $PackageA,
    [Parameter(Mandatory)] [string] $PackageB,
    [Parameter(Mandatory)] [string] $WorkDir,
    [Parameter(Mandatory)] [string] $Bsdtar
  )
  $destA = Join-Path $WorkDir "$Name.a"
  $destB = Join-Path $WorkDir "$Name.b"
  $archiveShaA = (Get-FileHash -LiteralPath $PackageA -Algorithm SHA256).Hash.ToLowerInvariant()
  $archiveShaB = (Get-FileHash -LiteralPath $PackageB -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($archiveShaA -ne $archiveShaB) {
    return [pscustomobject]@{
      Name    = $Name
      Entries = 0
      Diffs   = [Collections.Generic.List[string]]@(
        "package archive differs (A=$archiveShaA B=$archiveShaB)"
      )
    }
  }
  $manifestA = Get-PackageTreeManifest -Package $PackageA -Destination $destA -Bsdtar $Bsdtar
  $manifestB = Get-PackageTreeManifest -Package $PackageB -Destination $destB -Bsdtar $Bsdtar

  $diffs = [System.Collections.Generic.List[string]]::new()
  foreach ($rel in $manifestA.Keys) {
    if (-not $manifestB.Contains($rel)) {
      $diffs.Add("only in build A: $rel")
      continue
    }
    $a = $manifestA[$rel]
    $b = $manifestB[$rel]
    if ($a.Sha256 -ne $b.Sha256 -or $a.Size -ne $b.Size -or $a.Kind -ne $b.Kind) {
      $diffs.Add("content differs: $rel (A=$($a.Kind)/$($a.Size)/$($a.Sha256) B=$($b.Kind)/$($b.Size)/$($b.Sha256))")
    }
  }
  foreach ($rel in $manifestB.Keys) {
    if (-not $manifestA.Contains($rel)) {
      $diffs.Add("only in build B: $rel")
    }
  }
  return [pscustomobject]@{
    Name    = $Name
    Entries = $manifestA.Count
    Diffs   = $diffs
  }
}

if (-not (Test-Path -LiteralPath $BuildA -PathType Container)) {
  throw "Build A directory not found: $BuildA"
}
if (-not (Test-Path -LiteralPath $BuildB -PathType Container)) {
  throw "Build B directory not found: $BuildB"
}
if (-not $WorkDir) {
  $parent = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
  $WorkDir = Join-Path $parent "npth-compare-$PID"
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$packagesA = Get-ChildItem -LiteralPath $BuildA -Recurse -File -Filter $Filter | Sort-Object Name
$packagesB = Get-ChildItem -LiteralPath $BuildB -Recurse -File -Filter $Filter | Sort-Object Name
$namesA = @($packagesA | ForEach-Object { $_.Name })
$namesB = @($packagesB | ForEach-Object { $_.Name })

if ($namesA.Count -eq 0) {
  throw "No packages matching '$Filter' found in build A: $BuildA"
}
if (Compare-Object -ReferenceObject $namesA -DifferenceObject $namesB) {
  throw "Build A and B produced different package file sets:`n  A: $($namesA -join ', ')`n  B: $($namesB -join ', ')"
}

$allDiffs = [System.Collections.Generic.List[string]]::new()
foreach ($name in $namesA) {
  $pkgA = ($packagesA | Where-Object { $_.Name -eq $name } | Select-Object -First 1).FullName
  $pkgB = ($packagesB | Where-Object { $_.Name -eq $name } | Select-Object -First 1).FullName
  $result = Compare-PackagePair -Name $name -PackageA $pkgA -PackageB $pkgB -WorkDir $WorkDir -Bsdtar $BsdtarExe
  if ($result.Diffs.Count -gt 0) {
    Write-Output "MISMATCH in ${name}:"
    $result.Diffs | ForEach-Object {
      Write-Output "    $_"
      $allDiffs.Add("${name}: $_")
    }
  }
  else {
    Write-Output "OK ${name}: $($result.Entries) normalized entries identical across both builds."
  }
}

if ($allDiffs.Count -gt 0) {
  throw "Package outputs are not byte-for-byte identical ($($allDiffs.Count) difference(s))."
}

Write-Output "Both independent builds produced byte-for-byte identical package archives and inner trees."

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$validator = Join-Path $PSScriptRoot 'validate-buildinfo-path.ps1'
$expectedRoot = '/usr/src/debug/mingw-w64-cross-msysarm64-npth-1.8'
$expectedBuild = "$expectedRoot/build"
$expectedStart = "$expectedRoot/recipe"
$tempParent = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$temp = Join-Path $tempParent "npth-buildinfo-test-$PID"
New-Item -ItemType Directory -Force $temp | Out-Null

function Write-Fixture {
  param([string] $Name, [string] $Extra)
  $path = Join-Path $temp "$Name.BUILDINFO"
  @(
    'format = 2',
    'pkgname = mingw-w64-cross-msysarm64-npth',
    'pkgver = 1.8-2',
    "builddir = $expectedBuild",
    "startdir = $expectedStart",
    $Extra
  ) | Set-Content -Encoding utf8 $path
  $path
}

function Assert-Rejected {
  param([string] $Name, [string] $Extra)
  $path = Write-Fixture $Name $Extra
  $rejected = $false
  try {
    & $validator -Path $path
  }
  catch {
    $rejected = $_.Exception.Message -match 'forbidden'
  }
  if (-not $rejected) {
    throw ".BUILDINFO fixture $Name was not rejected"
  }
}

try {
  $safe = Write-Fixture safe 'options = !strip'
  & $validator -Path $safe
  Assert-Rejected drive 'source = D:\a\MSYS2-packages\PKGBUILD'
  Assert-Rejected actions 'source = /d/a/MSYS2-packages/PKGBUILD'
  Assert-Rejected cygdrive 'source = /cygdrive/d/work/PKGBUILD'
  Assert-Rejected home 'source = /home/runner/work/PKGBUILD'
  Assert-Rejected unc 'source = \\server\share\PKGBUILD'
  Assert-Rejected posix-unc 'source = //server/share/PKGBUILD'

  $wrong = Join-Path $temp 'wrong.BUILDINFO'
  @(
    'builddir = /tmp/npth',
    "startdir = $expectedStart"
  ) | Set-Content -Encoding utf8 $wrong
  $wrongRejected = $false
  try {
    & $validator -Path $wrong
  }
  catch {
    $wrongRejected = $_.Exception.Message -match 'does not bind'
  }
  if (-not $wrongRejected) {
    throw '.BUILDINFO with a nondeterministic builddir was not rejected'
  }

  $duplicate = Join-Path $temp 'duplicate.BUILDINFO'
  @(
    "builddir = $expectedBuild",
    'builddir = /tmp/npth',
    "startdir = $expectedStart"
  ) | Set-Content -Encoding utf8 $duplicate
  $duplicateRejected = $false
  try {
    & $validator -Path $duplicate
  }
  catch {
    $duplicateRejected = $_.Exception.Message -match 'exactly one builddir'
  }
  if (-not $duplicateRejected) {
    throw '.BUILDINFO with duplicate builddir fields was not rejected'
  }
}
finally {
  Remove-Item -LiteralPath $temp -Recurse -Force
}

Write-Output '.BUILDINFO path negative fixtures passed.'

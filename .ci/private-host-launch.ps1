param(
  [ValidateSet('Test', 'Launch')]
  [string]$Mode = 'Test',
  [string]$LockPath = (Join-Path $PSScriptRoot 'private-host-lock.json'),
  [string]$PrivateRoot = $(if ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'msys2-private-host' } else { Join-Path $PSScriptRoot '.private-host-root' })
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-ForbiddenPrefix {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  if ($Path -match '^(?i)C:\\msys64(\\|$)') {
    throw "$Name resolves under forbidden shared root: $Path"
  }
}

function Assert-NullField {
  param(
    [AllowNull()]
    $Value,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  if ($null -ne $Value -and $Value -ne '') {
    throw "$Name must remain null until independently admitted"
  }
}

function Assert-PresentField {
  param(
    [AllowNull()]
    $Value,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  if ($null -eq $Value -or $Value -eq '') {
    throw "$Name must be supplied before launch"
  }
}

function Assert-AssetLockClosed {
  param(
    [Parameter(Mandatory = $true)]
    $Asset,
    [Parameter(Mandatory = $true)]
    [string]$Label
  )
  foreach ($field in 'url', 'name', 'version', 'bytes', 'sha256') {
    Assert-NullField -Value $Asset.package.$field -Name "$Label.package.$field"
  }
}

function Assert-AssetLockOpen {
  param(
    [Parameter(Mandatory = $true)]
    $Asset,
    [Parameter(Mandatory = $true)]
    [string]$Label
  )
  foreach ($field in 'url', 'name', 'version', 'bytes', 'sha256') {
    Assert-PresentField -Value $Asset.package.$field -Name "$Label.package.$field"
  }
  foreach ($field in 'url', 'name', 'version', 'sha256') {
    Assert-PresentField -Value $Asset.source.$field -Name "$Label.source.$field"
  }
}

function Get-ResolvedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $cmd = Get-Command $Name -ErrorAction Stop
  $source = $cmd.Source
  if ([string]::IsNullOrWhiteSpace($source)) {
    $source = $cmd.Path
  }
  Test-ForbiddenPrefix -Path $source -Name $Name
  [pscustomobject]@{
    name = $Name
    source = $source
  }
}

$lock = Get-Content -Raw -LiteralPath $LockPath | ConvertFrom-Json

if ($Mode -eq 'Test') {
  Assert-NullField -Value $lock.private_root.root -Name 'private_root.root'
  Assert-AssetLockClosed -Asset $lock.assets.host.git -Label 'assets.host.git'
  Assert-AssetLockClosed -Asset $lock.assets.host.bash -Label 'assets.host.bash'

  try {
    Test-ForbiddenPrefix -Path 'C:\msys64\usr\bin\bash.exe' -Name 'shared bash.exe'
    throw 'shared path fail check did not fail'
  } catch {
    if ($_.Exception.Message -notmatch 'forbidden shared root') {
      throw
    }
  }

  try {
    Test-ForbiddenPrefix -Path 'C:\msys64\usr\lib\git-core\git.exe' -Name 'shared git.exe'
    throw 'shared path fail check did not fail'
  } catch {
    if ($_.Exception.Message -notmatch 'forbidden shared root') {
      throw
    }
  }

  Write-Host 'Static fail-closed private-host tests passed.'
  exit 0
}

Assert-PresentField -Value $PrivateRoot -Name 'PrivateRoot'
Assert-AssetLockOpen -Asset $lock.assets.host.git -Label 'assets.host.git'
Assert-AssetLockOpen -Asset $lock.assets.host.bash -Label 'assets.host.bash'
$root = [System.IO.Path]::GetFullPath($PrivateRoot)
foreach ($segment in @(
  $lock.private_root.dbpath,
  $lock.private_root.cache,
  $lock.private_root.log,
  $lock.private_root.config,
  $lock.private_root.hooks,
  $lock.private_root.gpg
)) {
  if ([string]::IsNullOrWhiteSpace($segment)) {
    throw 'private root path contract contains an unresolved segment'
  }
}

$privatePaths = [ordered]@{
  root = $root
  dbpath = Join-Path $root $lock.private_root.dbpath
  cache = Join-Path $root $lock.private_root.cache
  log = Join-Path $root $lock.private_root.log
  config = Join-Path $root $lock.private_root.config
  hooks = Join-Path $root $lock.private_root.hooks
  gpg = Join-Path $root $lock.private_root.gpg
}

foreach ($entry in $privatePaths.GetEnumerator()) {
  Test-ForbiddenPrefix -Path $entry.Value -Name $entry.Key
  New-Item -ItemType Directory -Force -Path $entry.Value | Out-Null
}

$bashExe = Join-Path $privatePaths.root 'usr\bin\bash.exe'
Test-ForbiddenPrefix -Path $bashExe -Name 'private bash.exe'

$provenance = foreach ($tool in $lock.provenance.tools) {
  Get-ResolvedCommand -Name $tool
}

$provenance | ConvertTo-Json -Depth 4 | Write-Host
Write-Host "Private launch root: $($privatePaths.root)"
Write-Host "Private bash.exe: $bashExe"
Write-Host "Private GIT_EXEC_PATH: $(Join-Path $privatePaths.root 'usr\lib\git-core')"

if ($lock.assets.host.git.package.url -eq $null -or $lock.assets.host.bash.package.url -eq $null) {
  throw 'private-host launch remains blocked until independently admitted git/bash package assets are supplied'
}

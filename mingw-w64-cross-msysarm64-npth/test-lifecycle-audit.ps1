$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$tarExe = 'C:\Windows\System32\tar.exe'
if (-not (Test-Path -LiteralPath $tarExe)) { $tarExe = 'bsdtar' }

# Load the pure helpers without executing the main lifecycle body.
$global:LifecycleDotSource = $true
try {
  . (Join-Path $PSScriptRoot 'lifecycle-audit.ps1')
}
finally {
  Remove-Variable -Name LifecycleDotSource -Scope Global -ErrorAction SilentlyContinue
}

$parent = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$root = Join-Path $parent "npth-lifecycle-test-$PID"
New-Item -ItemType Directory -Force $root | Out-Null

$failures = [System.Collections.Generic.List[string]]::new()
function Fail([string] $m) { $script:failures.Add($m) }
function Should-Throw([scriptblock] $Action, [string] $Because) {
  try { & $Action; Fail "did not fail: $Because" }
  catch { }
}

function New-Pkg {
  param([string] $PkgName, [string[]] $PkgInfoExtra, [hashtable] $Files)
  $payload = Join-Path $root ("pl-" + [Guid]::NewGuid().ToString('n'))
  New-Item -ItemType Directory -Force $payload | Out-Null
  $lines = @("pkgname = $PkgName", 'pkgver = 1.8-2', 'arch = x86_64') + $PkgInfoExtra
  $lines | Set-Content -Encoding ascii (Join-Path $payload '.PKGINFO')
  'format = 2' | Set-Content -Encoding ascii (Join-Path $payload '.BUILDINFO')
  $members = [System.Collections.Generic.List[string]]::new()
  $members.Add('.PKGINFO'); $members.Add('.BUILDINFO')
  foreach ($rel in ($Files.Keys | Sort-Object)) {
    $dest = Join-Path $payload $rel
    New-Item -ItemType Directory -Force (Split-Path -Parent $dest) | Out-Null
    [IO.File]::WriteAllBytes($dest, $Files[$rel])
    $members.Add($rel)
  }
  $archive = Join-Path $root "$PkgName-1.8-2-x86_64.pkg.tar.zst"
  Push-Location $payload
  try {
    & $tarExe -acf $archive @($members)
    if ($LASTEXITCODE -ne 0) { throw "failed to make $PkgName" }
  }
  finally { Pop-Location }
  return $archive
}

try {
  $scriptText = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'lifecycle-audit.ps1')
  if ($scriptText -notmatch "corrupt_qkk_exit" -or
      $scriptText -notmatch "recovered_qkk_exit" -or
      $scriptText -notmatch "'-Qkk'") {
    Fail 'lifecycle audit does not bind corruption detection and recovery evidence'
  }

  # --- Get-PackageInfo / Get-PackageFiles ----------------------------------
  $runtimePkg = New-Pkg -PkgName 'mingw-w64-cross-msysarm64-npth' -PkgInfoExtra @(
    'depend = aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21',
    'provides = aarch64-pc-msys-npth=1.8',
    'conflict = aarch64-pc-msys-npth'
  ) -Files @{ 'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = [byte[]](1..20) }

  $info = Get-PackageInfo -Archive $runtimePkg -Bsdtar $tarExe
  if (@($info['pkgname'])[0] -ne 'mingw-w64-cross-msysarm64-npth') { Fail 'Get-PackageInfo did not parse pkgname' }
  $files = @(Get-PackageFiles -Archive $runtimePkg -Bsdtar $tarExe)
  if ($files -contains '.PKGINFO' -or $files -contains '.BUILDINFO') { Fail 'Get-PackageFiles leaked metadata members' }
  if ($files.Count -ne 1) { Fail 'Get-PackageFiles returned an unexpected payload set' }

  # --- Test-CandidateMetadata (good runtime + devel) ------------------------
  if ((Test-CandidateMetadata -Info $info) -ne 'mingw-w64-cross-msysarm64-npth') { Fail 'valid runtime metadata rejected' }

  $develPkg = New-Pkg -PkgName 'mingw-w64-cross-msysarm64-npth-devel' -PkgInfoExtra @(
    'depend = mingw-w64-cross-msysarm64-npth=1.8-2',
    'depend = aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21',
    'depend = aarch64-pc-msys-sysroot=3.6.10.r0.ga527ace21',
    'provides = aarch64-pc-msys-npth-devel=1.8',
    'conflict = aarch64-pc-msys-npth-devel'
  ) -Files @{ 'opt/aarch64-pc-msys/usr/lib/libnpth.a' = [byte[]](1..40) }
  $develInfo = Get-PackageInfo -Archive $develPkg -Bsdtar $tarExe
  if ((Test-CandidateMetadata -Info $develInfo) -ne 'mingw-w64-cross-msysarm64-npth-devel') { Fail 'valid devel metadata rejected' }

  # --- Test-CandidateMetadata negatives ------------------------------------
  $badVersion = @{ pkgname = @('mingw-w64-cross-msysarm64-npth'); pkgver = @('1.8-1');
    depend = @('aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21'); provides = @('aarch64-pc-msys-npth=1.8'); conflict = @('aarch64-pc-msys-npth') }
  Should-Throw { Test-CandidateMetadata -Info $badVersion } 'wrong pkgrel accepted'

  $badDep = @{ pkgname = @('mingw-w64-cross-msysarm64-npth'); pkgver = @('1.8-2');
    depend = @('aarch64-pc-msys-runtime=9.9'); provides = @('aarch64-pc-msys-npth=1.8'); conflict = @('aarch64-pc-msys-npth') }
  Should-Throw { Test-CandidateMetadata -Info $badDep } 'wrong dependency version accepted'

  $extraDep = @{ pkgname = @('mingw-w64-cross-msysarm64-npth'); pkgver = @('1.8-2');
    depend = @('aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21', 'bash'); provides = @('aarch64-pc-msys-npth=1.8'); conflict = @('aarch64-pc-msys-npth') }
  Should-Throw { Test-CandidateMetadata -Info $extraDep } 'extra dependency accepted'

  $badProvide = @{ pkgname = @('mingw-w64-cross-msysarm64-npth'); pkgver = @('1.8-2');
    depend = @('aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21'); provides = @('aarch64-pc-msys-npth=9.9'); conflict = @('aarch64-pc-msys-npth') }
  Should-Throw { Test-CandidateMetadata -Info $badProvide } 'wrong provides accepted'

  $badConflict = @{ pkgname = @('mingw-w64-cross-msysarm64-npth'); pkgver = @('1.8-2');
    depend = @('aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21'); provides = @('aarch64-pc-msys-npth=1.8'); conflict = @('something-else') }
  Should-Throw { Test-CandidateMetadata -Info $badConflict } 'wrong conflict accepted'

  $unknownName = @{ pkgname = @('mingw-w64-cross-msysarm64-evil'); pkgver = @('1.8-2');
    depend = @(); provides = @('x=1.8'); conflict = @('x') }
  Should-Throw { Test-CandidateMetadata -Info $unknownName } 'unknown package name accepted'

  # --- Get-CandidateOwnership ----------------------------------------------
  $goodOwners = Get-CandidateOwnership -FilesByPackage ([ordered]@{
      'mingw-w64-cross-msysarm64-npth'       = @('opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll')
      'mingw-w64-cross-msysarm64-npth-devel' = @('opt/aarch64-pc-msys/usr/lib/libnpth.a', 'usr/share/licenses/mingw-w64-cross-msysarm64-npth-devel/COPYING.LIB')
    })
  if ($goodOwners.Count -ne 3) { Fail 'ownership map has the wrong size' }

  Should-Throw {
    Get-CandidateOwnership -FilesByPackage ([ordered]@{
        'mingw-w64-cross-msysarm64-npth'       = @('opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll')
        'mingw-w64-cross-msysarm64-npth-devel' = @('opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll')
      })
  } 'ownership collision accepted'

  Should-Throw {
    Get-CandidateOwnership -FilesByPackage ([ordered]@{
        'mingw-w64-cross-msysarm64-npth' = @('windows/system32/evil.dll')
      })
  } 'out-of-prefix ownership accepted'

  # --- Get-TreeSeal restoration semantics ----------------------------------
  $tree = Join-Path $root 'tree'
  New-Item -ItemType Directory -Force (Join-Path $tree 'sub') | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $tree 'sub\a.bin'), [byte[]](1..10))
  $seal1 = Get-TreeSeal -Path $tree
  $added = Join-Path $tree 'sub\b.bin'
  [IO.File]::WriteAllBytes($added, [byte[]](1..5))
  if ((Get-TreeSeal -Path $tree) -eq $seal1) { Fail 'tree seal ignored an added file' }
  Remove-Item -LiteralPath $added -Force
  if ((Get-TreeSeal -Path $tree) -ne $seal1) { Fail 'tree seal did not confirm restoration after removal' }

  # --- Get-LocalDbEntryCount -----------------------------------------------
  $ldb = Join-Path $root 'localdb'
  New-Item -ItemType Directory -Force $ldb | Out-Null
  'x' | Set-Content -Encoding ascii (Join-Path $ldb 'ALPM_DB_VERSION')
  1..7 | ForEach-Object {
    $d = Join-Path $ldb "pkg$_-1.0-1"
    New-Item -ItemType Directory -Force $d | Out-Null
    "pkgname = pkg$_" | Set-Content -Encoding ascii (Join-Path $d 'desc')
  }
  New-Item -ItemType Directory -Force (Join-Path $ldb 'not-a-package') | Out-Null
  if ((Get-LocalDbEntryCount -LocalDbPath $ldb) -ne 7) { Fail 'local DB entry count is wrong' }
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force
}

if ($failures.Count -gt 0) {
  Write-Output 'lifecycle-audit fixtures FAILED:'
  $failures | ForEach-Object { Write-Output "  - $_" }
  exit 1
}

Write-Output 'lifecycle-audit fixtures passed (metadata contract, ownership, tree restoration, and DB entry counting all validated).'

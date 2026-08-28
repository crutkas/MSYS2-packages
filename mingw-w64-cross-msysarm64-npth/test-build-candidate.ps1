<#
  Offline unit test for build-candidate.ps1 pure helpers. Validates the explicit
  pacman argument construction (fails closed against --nodeps / --assume-installed),
  the install plan derived from the real manifest (complete closure, no faked
  dependency, deny-list awareness), and the package sealing logic against a
  synthetic .pkg.tar.zst. No network and no ARM64 runner required.
#>
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$global:BuildCandidateDotSource = $true
. (Join-Path $PSScriptRoot 'build-candidate.ps1')
Remove-Variable -Name BuildCandidateDotSource -Scope Global -ErrorAction SilentlyContinue

$failures = [Collections.Generic.List[string]]::new()
function Assert($condition, $message) {
  if (-not $condition) { $script:failures.Add($message) }
}

$tar = 'C:\Windows\System32\tar.exe'
$tmp = Join-Path $PSScriptRoot '.build-test-tmp'
if (Test-Path -LiteralPath $tmp) { Remove-Item -Recurse -Force -LiteralPath $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
  $scriptText = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'build-candidate.ps1')
  Assert (-not ($scriptText -match '(?m)(?:--login|\s-lc\s)')) `
    'private build shell must never run login initialization'

  $buildRoot = Join-Path $tmp 'build-root'
  $smokeFixture = Join-Path $buildRoot 'pkgbase\src\smoke'
  New-Item -ItemType Directory -Force $smokeFixture | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $smokeFixture 'npth-dynamic-smoke.exe'), [byte[]](1..4))
  [IO.File]::WriteAllBytes((Join-Path $smokeFixture 'npth-static-smoke.exe'), [byte[]](5..8))
  Assert ((Get-NativeSmokeDirectory -BuildRoot $buildRoot) -eq $smokeFixture) `
    'native smoke discovery must use the deterministic build root'

  # --- New-PacmanCommonArgs: explicit paths, no forbidden flags ---
  $common = New-PacmanCommonArgs -Root $tmp -Config (Join-Path $tmp 'pacman-build.conf')
  foreach ($flag in @('--root', '--dbpath', '--cachedir', '--logfile', '--config', '--hookdir', '--gpgdir', '--noconfirm')) {
    Assert ($common -contains $flag) "common args missing $flag"
  }
  $joined = $common -join ' '
  Assert (-not ($joined -match '--nodeps')) 'common args must not contain --nodeps'
  Assert (-not ($joined -match '--assume-installed')) 'common args must not contain --assume-installed'
  Assert (-not ($joined -match 'msys64')) 'common args must not reference a shared client'

  # --- Get-InstallPlan: complete closure from the real manifest ---
  $manifestObj = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'input-manifest.json') | ConvertFrom-Json
  $plan = Get-InstallPlan -ManifestObject $manifestObj
  Assert ($plan.host.Count -ge 2) 'install plan host closure is too small'
  Assert ($plan.target.Count -ge 12) 'install plan target closure is too small'
  Assert ($plan.target -contains 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst') `
    'plan must include the real cygwin libstdc++ headers'
  Assert ($plan.host -contains 'make-4.4.1-2-x86_64.pkg.tar.zst') 'plan host missing make'
  Assert ($plan.host -contains 'pkgconf-2.5.1-1-x86_64.pkg.tar.zst') 'plan host missing pkgconf'
  Assert ($plan.denyPrefixes.Count -ge 2) 'plan did not surface deny-list prefixes'

  # No deny-listed artifact may appear as an installable filename.
  foreach ($name in @($plan.host + $plan.target)) {
    Assert ($name -like '*.pkg.tar.zst') "plan entry is not a package archive: $name"
  }

  # A manifest that drops the cygwin headers must be rejected (fail closed).
  $broken = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'input-manifest.json') | ConvertFrom-Json
  $broken.targetInputs = @($broken.targetInputs | Where-Object {
      $_.name -ne 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
    })
  $threw = $false
  try { Get-InstallPlan -ManifestObject $broken } catch { $threw = $true }
  Assert $threw 'Get-InstallPlan must reject a closure missing the cygwin libstdc++ headers'

  # --- Get-PackageSeal: extract + hash metadata from a synthetic package ---
  $stage = Join-Path $tmp 'pkgroot'
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  Set-Content -LiteralPath (Join-Path $stage '.PKGINFO') -Value "pkgname = demo`npkgver = 1.8-2`n" -Encoding ascii
  Set-Content -LiteralPath (Join-Path $stage '.BUILDINFO') -Value "format = 2`nbuilddir = /build`n" -Encoding ascii
  Set-Content -LiteralPath (Join-Path $stage '.MTREE') -Value "#mtree`n./usr type=dir`n" -Encoding ascii
  $pkg = Join-Path $tmp 'demo-1.8-2-x86_64.pkg.tar.zst'
  & $tar -c --zstd -f $pkg -C $stage '.PKGINFO' '.BUILDINFO' '.MTREE'
  Assert ($LASTEXITCODE -eq 0) 'failed to build synthetic package archive'

  $metaDir = Join-Path $tmp 'demo.metadata'
  $seal = Get-PackageSeal -Archive $pkg -Bsdtar $tar -MetadataDir $metaDir
  Assert ($seal.package -eq 'demo-1.8-2-x86_64.pkg.tar.zst') 'seal package name wrong'
  Assert ($seal.package_sha256.Length -eq 64) 'seal package hash wrong length'
  foreach ($member in @('.PKGINFO', '.BUILDINFO', '.MTREE')) {
    Assert ($seal.metadata.Contains($member)) "seal missing $member"
    Assert ($seal.metadata[$member].sha256.Length -eq 64) "seal $member hash wrong length"
    Assert ($seal.metadata[$member].bytes -gt 0) "seal $member has zero bytes"
  }
  Assert (Test-Path -LiteralPath (Join-Path $metaDir 'PKGINFO')) 'extracted PKGINFO not written'
  Assert (Test-Path -LiteralPath (Join-Path $metaDir 'MTREE')) 'extracted MTREE not written'

  # The extracted member bytes must hash to the sealed value.
  $reHash = (Get-FileHash -LiteralPath (Join-Path $metaDir 'PKGINFO') -Algorithm SHA256).Hash.ToLowerInvariant()
  Assert ($reHash -eq $seal.metadata['.PKGINFO'].sha256) 'extracted PKGINFO hash mismatch vs seal'
}
finally {
  Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
  Write-Error ("build-candidate unit test FAILED:`n - " + ($failures -join "`n - "))
  exit 1
}
Write-Output 'build-candidate unit test passed (explicit pacman args, complete install plan, fail-closed closure, package sealing).'

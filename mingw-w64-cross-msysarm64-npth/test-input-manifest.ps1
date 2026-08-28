$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$manifestPath = Join-Path $PSScriptRoot 'input-manifest.json'
$pkgbuildPath = Join-Path $PSScriptRoot 'PKGBUILD'

$failures = [System.Collections.Generic.List[string]]::new()
function Assert([bool] $Condition, [string] $Message) {
  if (-not $Condition) { $script:failures.Add($Message) }
}

$hex64 = '^[0-9a-f]{64}$'
$hex40 = '^[0-9a-f]{40}$'

if (-not (Test-Path -LiteralPath $manifestPath)) {
  throw "input-manifest.json not found at $manifestPath"
}

$raw = Get-Content -LiteralPath $manifestPath -Raw
$manifest = $raw | ConvertFrom-Json

Assert ($manifest.schema -eq 1) 'schema must be 1'
Assert ($manifest.disposition.status -eq 'diagnostic-only') 'a527 outputs must remain diagnostic-only'
Assert ($manifest.disposition.publish -eq $false) 'a527 outputs must never be publishable'
Assert ($manifest.disposition.canonicalRebuildBlockedOn -eq 'corrected ARM64 MSYS runtime') `
  'canonical rebuild blocker must be explicit'

# --- source binding -------------------------------------------------------
Assert ($manifest.source.repository -eq 'crutkas/MSYS2-packages') 'source.repository mismatch'
Assert ($manifest.source.branch -eq 'crutkas-finalize-arm64-npth-admission') 'source.branch mismatch'
Assert ($manifest.source.expectedParent -match $hex40) 'expectedParent must be a 40-char sha'
Assert ($manifest.source.expectedParent -eq '9efb4cb79a6921f405c8a6dabc7cc0b55c6f8cd4') 'expectedParent must be the stacked base head'
Assert ($manifest.source.parentBinding -eq 'ancestor') 'parentBinding must be ancestor so future commits stay possible'

# --- package --------------------------------------------------------------
Assert ($manifest.package.pkgbase -eq 'mingw-w64-cross-msysarm64-npth') 'pkgbase mismatch'
Assert ($manifest.package.pkgver -eq '1.8') 'pkgver mismatch'
Assert ($manifest.package.pkgrel -eq 2) 'pkgrel must be 2'
Assert ($manifest.package.sourceDateEpoch -is [int64] -or $manifest.package.sourceDateEpoch -is [int]) 'sourceDateEpoch must be an integer'
Assert ($manifest.package.sourceDateEpoch -gt 0) 'sourceDateEpoch must be positive'
Assert ($manifest.package.runtimePackage -eq 'mingw-w64-cross-msysarm64-npth-1.8-2-x86_64.pkg.tar.zst') 'runtimePackage name mismatch'
Assert ($manifest.package.develPackage -eq 'mingw-w64-cross-msysarm64-npth-devel-1.8-2-x86_64.pkg.tar.zst') 'develPackage name mismatch'

# --- helper for a downloadable content-addressed entry --------------------
function Test-Entry($entry, [string] $label, [bool] $UrlEndsWithName = $true) {
  Assert (-not [string]::IsNullOrWhiteSpace($entry.name)) "$label missing name"
  Assert ($entry.url -match '^https://') "$label url must be https"
  if ($UrlEndsWithName) {
    Assert ($entry.url.EndsWith($entry.name)) "$label url must end with its file name"
  }
  Assert ($entry.bytes -gt 0) "$label bytes must be positive"
  Assert ($entry.sha256 -match $hex64) "$label sha256 must be 64 hex chars"
}

Test-Entry $manifest.npthSource.tarball 'npthSource.tarball'
Test-Entry $manifest.npthSource.signature 'npthSource.signature'
Test-Entry $manifest.privateBase.archive 'privateBase.archive'
Test-Entry $manifest.privateBase.signature 'privateBase.signature'
Assert ($manifest.privateBase.signerKey.repositoryPath -eq 'mingw-w64-cross-msysarm64-npth/msys2-base-signer.asc') `
  'privateBase.signerKey repository path mismatch'
Assert ($manifest.privateBase.signerKey.bytes -eq 5393) 'privateBase.signerKey size mismatch'
Assert ($manifest.privateBase.signerKey.sha256 -match $hex64) 'privateBase.signerKey hash malformed'

Assert ($manifest.privateBase.archive.bytes -eq 53555380) 'privateBase archive size mismatch'
Assert ($manifest.privateBase.archive.sha256 -eq 'a2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221') 'privateBase archive sha mismatch'
Assert ($manifest.privateBase.signature.bytes -eq 566) 'privateBase signature size mismatch'
Assert ($manifest.privateBase.signer -eq 'E0AA0F031DBD80FFBA57B06D5A62D0CAB6264964') 'privateBase signer mismatch'
Assert ($manifest.privateBase.localDbPackageCount -eq 90) 'privateBase localDbPackageCount must match the immutable base'
Assert ($manifest.privateBase.sharedDbReferenceFileCount -eq 1178) 'shared DB reference file count must remain bound'

# --- scanner --------------------------------------------------------------
Assert ($manifest.scanner.commit -match $hex40) 'scanner commit must be a 40-char sha'
Assert ($manifest.scanner.commit -eq '3356eec1411983cc252b04afac32bca5f3b8d824') 'scanner commit mismatch'
Assert ($manifest.scanner.sha256 -eq '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') 'scanner sha mismatch'
Assert ($manifest.scanner.url.Contains($manifest.scanner.commit)) 'scanner url must pin the immutable commit'

# --- target + host inputs -------------------------------------------------
$requiredRoles = @(
  'runtime-headers', 'runtime', 'runtime-devel', 'sysroot', 'windows-default-manifest',
  'gcc', 'gcc-libs', 'libstdc++-headers', 'w32api-runtime', 'fixed-binutils',
  'cygwin-gcc-stage1', 'cygwin-gcc-libs-stage1'
)
$seenRoles = @($manifest.targetInputs | ForEach-Object { $_.role })
foreach ($role in $requiredRoles) {
  Assert ($seenRoles -contains $role) "targetInputs missing role $role"
}
foreach ($entry in $manifest.targetInputs) {
  Test-Entry $entry "targetInputs[$($entry.role)]"
  Assert (-not [string]::IsNullOrWhiteSpace($entry.releaseTag)) "targetInputs[$($entry.role)] missing releaseTag"
}
foreach ($entry in $manifest.hostPackages) {
  Test-Entry $entry "hostPackages[$($entry.role)]"
}

# Spot-check a couple of pinned sizes/hashes to catch transcription drift.
$binutils = $manifest.targetInputs | Where-Object { $_.role -eq 'fixed-binutils' }
Assert ($binutils.bytes -eq 6545114) 'fixed-binutils size mismatch'
Assert ($binutils.sha256 -eq '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b') 'fixed-binutils sha mismatch'
$runtime = $manifest.targetInputs | Where-Object { $_.role -eq 'runtime' }
Assert ($runtime.bytes -eq 9893043) 'runtime size mismatch'

# --- deny-list ------------------------------------------------------------
Assert ($manifest.denyList.revoked.Count -eq 2) 'deny-list must revoke both hand-built packages'
foreach ($entry in $manifest.denyList.revoked) {
  Assert ($entry.sha256Prefix -match '^[0-9a-f]{6,}$') "revoked entry $($entry.role) needs a hex sha256Prefix"
  Assert ($entry.bytes -gt 0) "revoked entry $($entry.role) needs a byte size"
  Assert (-not [string]::IsNullOrWhiteSpace($entry.reason)) "revoked entry $($entry.role) needs a reason"
}
$revokedPrefixes = @($manifest.denyList.revoked | ForEach-Object { $_.sha256Prefix })
Assert ($revokedPrefixes -contains '97237a') 'deny-list missing revoked runtime prefix 97237a'
Assert ($revokedPrefixes -contains '1145de') 'deny-list missing revoked devel prefix 1145de'
$revokedSizes = @($manifest.denyList.revoked | ForEach-Object { $_.bytes })
Assert ($revokedSizes -contains 13629) 'deny-list missing revoked runtime size 13629'
Assert ($revokedSizes -contains 13865) 'deny-list missing revoked devel size 13865'

Assert ($manifest.denyList.historicalOnly.Count -eq 2) 'deny-list must record both historical-only artifacts'
foreach ($entry in $manifest.denyList.historicalOnly) {
  Assert ($entry.sha256 -match $hex64) "historical entry $($entry.role) needs a 64-char sha256"
}

# The deny-listed and historical artifacts must never appear among real inputs.
$inputHashes = [System.Collections.Generic.HashSet[string]]::new()
foreach ($h in @(
    $manifest.npthSource.tarball.sha256,
    $manifest.npthSource.signature.sha256,
    $manifest.privateBase.archive.sha256,
    $manifest.privateBase.signerKey.sha256,
    $manifest.scanner.sha256
  ) + @($manifest.targetInputs | ForEach-Object { $_.sha256 }) + @($manifest.hostPackages | ForEach-Object { $_.sha256 })) {
  [void]$inputHashes.Add($h)
}
foreach ($entry in $manifest.denyList.historicalOnly) {
  Assert (-not $inputHashes.Contains($entry.sha256)) "historical hash $($entry.sha256) must not be an admission input"
}
foreach ($entry in $manifest.denyList.revoked) {
  foreach ($h in $inputHashes) {
    Assert (-not $h.StartsWith($entry.sha256Prefix)) "input hash $h collides with revoked prefix $($entry.sha256Prefix)"
  }
}

# --- action pins ----------------------------------------------------------
Assert ($manifest.actionPins.checkout -eq 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262') 'checkout pin mismatch'
Assert ($manifest.actionPins.uploadArtifact -eq 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02') 'upload pin mismatch'
Assert ($manifest.actionPins.downloadArtifact -eq 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093') 'download pin mismatch'
foreach ($pin in @($manifest.actionPins.checkout, $manifest.actionPins.uploadArtifact, $manifest.actionPins.downloadArtifact)) {
  Assert (($pin -split '@')[-1] -match $hex40) "action pin $pin must reference a 40-char sha"
}

# --- cross-check against PKGBUILD ----------------------------------------
if (Test-Path -LiteralPath $pkgbuildPath) {
  $pkgbuild = Get-Content -LiteralPath $pkgbuildPath -Raw
  Assert ($pkgbuild.Contains($manifest.npthSource.tarball.sha256)) 'PKGBUILD must pin the manifest npth tarball sha256'
  $expectedSums = "(?s)sha256sums=\(\s*'$($manifest.npthSource.tarball.sha256)'\s*'SKIP'\s*'dfe9fa551f7e44508466158099f85b93997a14fc3f5cf7da7c768909ddac08e1'\s*'1cf63874ee38b53132f0c7676b45839e2227136a49f61badc597a27c7727465f'\s*'5eec9c3423f6ee7ea3f354ea06b9ee6f40af88425a8e5294c6a4f6db085cb008'\s*\)"
  Assert ($pkgbuild -match $expectedSums) 'PKGBUILD source checksum order must match source() order'
  Assert ($pkgbuild.Contains('"mingw-w64-cross-msysarm64-npth=${pkgver}-${pkgrel}"')) `
    'devel package must require the exact runtime package release'
  Assert ($pkgbuild -match "pkgver=1\.8") 'PKGBUILD pkgver must be 1.8'
  Assert ($pkgbuild -match "pkgrel=2") 'PKGBUILD pkgrel must be 2'
}

if ($failures.Count -gt 0) {
  Write-Output "input-manifest validation FAILED:"
  $failures | ForEach-Object { Write-Output "  - $_" }
  exit 1
}

Write-Output "input-manifest.json validated: $($manifest.targetInputs.Count) target inputs, $($manifest.hostPackages.Count) host packages, deny-list and action pins wired."

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$validator = Join-Path $PSScriptRoot 'validate-dependency-lock.ps1'
$lockPath = Join-Path $PSScriptRoot 'dependency-lock.json'
$rejected = @(
  '0b8a6c6fd865ca09858f8f5f130233910c17d58dddb41719cecf1722a3964645',
  '3af7e6c7f9735554f39a601cd42b5a9cc379646318c63e613105908743ed6f2c',
  '5a3e2de75383e8d4a6c8431297f2740cf4a0976f1bc4da0fcb2a5271874a8d94',
  '5b7ea5ca6902094dbee157d138c22a8c76483da3ed1530c50e316d5a2574190e',
  '78e9cc98b8d38ff2f60c0ec5d9bc4f173f488ace93826bb90aef27ad69f195ee',
  '8004cc674d8735f453e4a000740a157605e1abc17ec90bd95ed79626b63981b2',
  '8921cee568ab0757e5211bce3a8c9ff49e27446c74a6940126f3ae778830aa2c',
  '9006b7594982d3aed3290de0c7b5707a08770ae2250a4f2572428a3c475bda0a',
  '9f3eb872e514b6be3d78001b1f25b089e9c2378128992241cc759fc66c42c708',
  'a1eb6396150d4233aff9ce80add334029721a55a7ee311f7516330d9e892005f',
  'd6914993d2d2bb2c51a6d46c9dd9f2e5149a8da30736a01cbcfd57854c65fd1f'
)

function Assert-Equal {
  param([object] $Actual, [object] $Expected, [string] $Name)
  if ($Actual -cne $Expected) {
    throw "$Name is not the coordinator-admitted value"
  }
}

& $validator -LockPath $lockPath -RequireApproved
$checkedInLock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
Assert-Equal $checkedInLock.admission.releaseId ([long] 378064013) 'releaseId'
Assert-Equal $checkedInLock.admission.releaseTag `
  'msysarm64-libgpg-error-pr16-06ae2f9-20260827' 'releaseTag'
Assert-Equal $checkedInLock.admission.tagObject `
  '0bbfd4a6d689df90ee88f3199161fc2e287c9baa' 'tagObject'
Assert-Equal $checkedInLock.admission.producerCommit `
  '06ae2f9c2ad5d69e736e4d056772a7be1546a076' 'producerCommit'
foreach ($role in @(
    @('evidence', 532755292, 938654,
      '728303c5c96e38dfd6edae3e6df6871f3d16d08f0279527bf8c1a49d66005068'),
    @('runtime', 532755293, 125720,
      'ca9c377b91896f3286071fd456389006ade6e297e7dd21efb06ab572ccb55d34'),
    @('devel', 532755294, 123170,
      '642880ad8fc5498fa7b755825b30008d466dbefa0dd07de80f5f5516b7968a2a'))) {
  $asset = $checkedInLock.admission.($role[0])
  Assert-Equal $asset.assetId ([long] $role[1]) "$($role[0]).assetId"
  Assert-Equal $asset.bytes ([long] $role[2]) "$($role[0]).bytes"
  Assert-Equal $asset.sha256 $role[3] "$($role[0]).sha256"
}
Assert-Equal $checkedInLock.admission.evidence.manifestSha256 `
  'b97366ac3866c7c716c671c3609ba0ce9e4406e67fa940b8cf0058927651645b' `
  'evidence.manifestSha256'
Assert-Equal $checkedInLock.admission.publicAudit.manifestSha256 `
  'e7eb01c6efd66a4b2692a365d3bb0bfcb63f552651474425a583e211ed0a558c' `
  'publicAudit.manifestSha256'
Assert-Equal $checkedInLock.admission.publicAudit.reportSha256 `
  '13dd8feac84996bb0c090f8741180fa8c36c852a3951690d76076f88c74de740' `
  'publicAudit.reportSha256'
if (@($checkedInLock.rejectedSha256).Count -ne 11) {
  throw 'The checked-in lock must retain exactly 11 historical rejected hashes'
}
foreach ($hash in $rejected) {
  if ($hash -notin $checkedInLock.rejectedSha256) {
    throw "The checked-in lock does not deny $hash"
  }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) "libassuan-lock-test-$PID"
New-Item -ItemType Directory -Force $temp | Out-Null
try {
  $mutatedPath = Join-Path $temp 'mutated-lock.json'
  $mutated = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
  $mutated.rejectedSha256[0] =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  $mutated | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $mutatedPath
  $deniedMutation = $false
  try {
    & $validator -LockPath $mutatedPath
  }
  catch {
    $deniedMutation = $_.Exception.Message -match 'rejectedSha256'
  }
  if (-not $deniedMutation) {
    throw 'The lock validator accepted a mutated rejection set'
  }

  $revokedPath = Join-Path $temp 'revoked-lock.json'
  $revoked = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
  $revoked.admission.runtime.sha256 = $rejected[9]
  $revoked | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $revokedPath
  $deniedRevoked = $false
  try {
    & $validator -LockPath $revokedPath
  }
  catch {
    $deniedRevoked = $_.Exception.Message -match 'revoked, rehearsal, or provisional'
  }
  if (-not $deniedRevoked) {
    throw 'The lock validator accepted a revoked package hash'
  }

  $duplicatePath = Join-Path $temp 'duplicate-lock.json'
  $raw = Get-Content -Raw -LiteralPath $lockPath
  $raw = $raw -replace '"approved": true,', '"approved": true, "approved": false,'
  Set-Content -Encoding utf8 -LiteralPath $duplicatePath -Value $raw
  $deniedDuplicate = $false
  try {
    & $validator -LockPath $duplicatePath
  }
  catch {
    $deniedDuplicate = $_.Exception.Message -match 'duplicate JSON property'
  }
  if (-not $deniedDuplicate) {
    throw 'The lock validator accepted duplicate JSON properties'
  }

  $tag = 'synthetic-fixed-linker-20260827'
  $runtime = [ordered]@{
    assetId = [long] 101
    bytes = [long] 1001
    filename = 'mingw-w64-cross-msysarm64-libgpg-error-1.56-1-x86_64.pkg.tar.zst'
    sha256 = '1111111111111111111111111111111111111111111111111111111111111111'
    url = "https://github.com/crutkas/MSYS2-packages/releases/download/$tag/mingw-w64-cross-msysarm64-libgpg-error-1.56-1-x86_64.pkg.tar.zst"
    pkgname = 'mingw-w64-cross-msysarm64-libgpg-error'
    pkgver = '1.56-1'
    arch = 'x86_64'
    provides = @('aarch64-pc-msys-libgpg-error=1.56')
    depends = @('aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21')
  }
  $devel = [ordered]@{
    assetId = [long] 102
    bytes = [long] 1002
    filename = 'mingw-w64-cross-msysarm64-libgpg-error-devel-1.56-1-x86_64.pkg.tar.zst'
    sha256 = '2222222222222222222222222222222222222222222222222222222222222222'
    url = "https://github.com/crutkas/MSYS2-packages/releases/download/$tag/mingw-w64-cross-msysarm64-libgpg-error-devel-1.56-1-x86_64.pkg.tar.zst"
    pkgname = 'mingw-w64-cross-msysarm64-libgpg-error-devel'
    pkgver = '1.56-1'
    arch = 'x86_64'
    provides = @('aarch64-pc-msys-libgpg-error-devel=1.56')
    depends = @(
      'aarch64-pc-msys-libgpg-error=1.56',
      'aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21'
    )
  }
  $packageInfos = @{}
  foreach ($package in @($runtime, $devel)) {
    $payload = Join-Path $temp "$($package.pkgname)-payload"
    New-Item -ItemType Directory -Force $payload | Out-Null
    $pkgInfoLines = @(
      "pkgname = $($package.pkgname)",
      "pkgver = $($package.pkgver)",
      "arch = $($package.arch)"
    )
    $pkgInfoLines += $package.depends | ForEach-Object { "depend = $_" }
    $pkgInfoLines += $package.provides | ForEach-Object { "provides = $_" }
    $pkgInfo = Join-Path $payload '.PKGINFO'
    $pkgInfoLines | Set-Content -Encoding ascii $pkgInfo
    $packageInfos[$package.pkgname] = $pkgInfo
    $archive = Join-Path $temp $package.filename
    & 'C:\Windows\System32\tar.exe' -acf $archive -C $payload .PKGINFO
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to create synthetic package $($package.pkgname)"
    }
    $archiveItem = Get-Item -LiteralPath $archive
    $package.bytes = [long] $archiveItem.Length
    $package.sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).
      Hash.ToLowerInvariant()
  }

  $evidenceRootName = 'synthetic-admission'
  $evidenceRoot = Join-Path $temp $evidenceRootName
  $evidencePackages = Join-Path $evidenceRoot 'ci\pr-packages'
  $evidenceMetadata = Join-Path $evidenceRoot 'evidence'
  New-Item -ItemType Directory -Force $evidencePackages, $evidenceMetadata |
    Out-Null
  Copy-Item (Join-Path $temp $runtime.filename) $evidencePackages
  Copy-Item (Join-Path $temp $devel.filename) $evidencePackages
  Copy-Item $packageInfos[$runtime.pkgname] `
    (Join-Path $evidenceMetadata 'runtime-final.PKGINFO')
  Copy-Item $packageInfos[$devel.pkgname] `
    (Join-Path $evidenceMetadata 'devel-final.PKGINFO')

  $manifestLines = [Collections.Generic.List[string]]::new()
  foreach ($relative in @(
      "ci\pr-packages\$($runtime.filename)",
      "ci\pr-packages\$($devel.filename)",
      'evidence\runtime-final.PKGINFO',
      'evidence\devel-final.PKGINFO')) {
    $file = Get-Item -LiteralPath (Join-Path $evidenceRoot $relative)
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).
      Hash.ToLowerInvariant()
    $manifestLines.Add("$hash  $($file.Length)  $relative")
  }
  $manifestPath = Join-Path $evidenceRoot 'MANIFEST.sha256'
  $manifestLines | Set-Content -Encoding ascii $manifestPath
  $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
  "$manifestHash  MANIFEST.sha256  STATUS=PASS  COMMIT=3333333333333333333333333333333333333333" |
    Set-Content -Encoding ascii (Join-Path $evidenceRoot 'SEAL.sha256')
  $evidenceArchive = Join-Path $temp 'synthetic-evidence.tar.zst'
  & 'C:\Windows\System32\tar.exe' -acf $evidenceArchive -C $temp $evidenceRootName
  if ($LASTEXITCODE -ne 0) {
    throw 'Unable to create synthetic evidence archive'
  }
  $evidenceItem = Get-Item -LiteralPath $evidenceArchive
  $archiveEntries = @(
    & 'C:\Windows\System32\tar.exe' -tf $evidenceArchive
  ).Count

  $approvedPath = Join-Path $temp 'approved-lock.json'
  [ordered]@{
    schemaVersion = 2
    approved = $true
    dependency = 'libgpg-error'
    requiredVersion = '1.56-1'
    repository = 'crutkas/MSYS2-packages'
    admission = [ordered]@{
      releaseId = [long] 100
      releaseTag = $tag
      tagObject = '4444444444444444444444444444444444444444'
      producerCommit = '3333333333333333333333333333333333333333'
      evidence = [ordered]@{
        assetId = [long] 103
        bytes = [long] $evidenceItem.Length
        filename = $evidenceItem.Name
        sha256 = (Get-FileHash -LiteralPath $evidenceArchive -Algorithm SHA256).
          Hash.ToLowerInvariant()
        url = "https://github.com/crutkas/MSYS2-packages/releases/download/$tag/$($evidenceItem.Name)"
        rootDirectory = $evidenceRootName
        archiveEntries = [long] $archiveEntries
        regularFiles = [long] 6
        manifestSha256 = $manifestHash
        manifestEntries = [long] 4
        sealStatus = 'PASS'
      }
      publicAudit = [ordered]@{
        manifestBytes = [long] 1
        manifestSha256 =
          '5555555555555555555555555555555555555555555555555555555555555555'
        reportBytes = [long] 1
        reportSha256 =
          '6666666666666666666666666666666666666666666666666666666666666666'
        result = 'PASS'
      }
      runtime = $runtime
      devel = $devel
    }
    rejectedSha256 = $rejected
  } | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $approvedPath
  & $validator `
    -LockPath $approvedPath `
    -EvidencePath $evidenceArchive `
    -PackageDirectory $temp `
    -Bsdtar 'C:\Windows\System32\tar.exe' `
    -RequireApproved
}
finally {
  Remove-Item -LiteralPath $temp -Recurse -Force
}

Write-Output 'Dependency lock and evidence-seal fixtures passed.'

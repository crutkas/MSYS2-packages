$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$validator = Join-Path $PSScriptRoot 'validate-dependency-lock.ps1'
$lockPath = Join-Path $PSScriptRoot 'dependency-lock.json'

& $validator -LockPath $lockPath
if ($LASTEXITCODE -ne 0) {
  throw 'The checked-in closed admission lock is invalid'
}
$checkedInLock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
foreach ($newlyDenied in @(
    '78e9cc98b8d38ff2f60c0ec5d9bc4f173f488ace93826bb90aef27ad69f195ee',
    '8004cc674d8735f453e4a000740a157605e1abc17ec90bd95ed79626b63981b2',
    'a1eb6396150d4233aff9ce80add334029721a55a7ee311f7516330d9e892005f')) {
  if ($newlyDenied -notin $checkedInLock.rejectedSha256) {
    throw "The checked-in lock does not deny $newlyDenied"
  }
}

$failedClosed = $false
try {
  & $validator -LockPath $lockPath -RequireApproved
}
catch {
  $failedClosed = $_.Exception.Message -match 'admission is closed'
}
if (-not $failedClosed) {
  throw 'The checked-in admission lock did not fail closed'
}

$temp = Join-Path ([IO.Path]::GetTempPath()) "libassuan-lock-test-$PID"
New-Item -ItemType Directory -Force $temp | Out-Null
try {
  $mutatedPath = Join-Path $temp 'mutated-lock.json'
  $mutated = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
  $mutated.rejectedSha256[0] = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
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

  $duplicatePath = Join-Path $temp 'duplicate-lock.json'
  $raw = Get-Content -Raw -LiteralPath $lockPath
  $raw = $raw -replace '"approved": false,', '"approved": false, "approved": true,'
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
    depends = @('aarch64-pc-msys-libgpg-error=1.56')
  }
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
    $pkgInfoLines | Set-Content -Encoding ascii (Join-Path $payload '.PKGINFO')
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
  $sealPath = Join-Path $temp 'synthetic-seal.json'
  [ordered]@{
    schemaVersion = 1
    repository = 'crutkas/MSYS2-packages'
    releaseTag = $tag
    producerCommit = '3333333333333333333333333333333333333333'
    packages = @($runtime, $devel)
  } | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $sealPath
  $sealItem = Get-Item -LiteralPath $sealPath
  $sealName = $sealItem.Name
  $approvedPath = Join-Path $temp 'approved-lock.json'
  [ordered]@{
    schemaVersion = 1
    approved = $true
    dependency = 'libgpg-error'
    requiredVersion = '1.56-1'
    repository = 'crutkas/MSYS2-packages'
    admission = [ordered]@{
      releaseTag = $tag
      producerCommit = '3333333333333333333333333333333333333333'
      seal = [ordered]@{
        assetId = [long] 103
        bytes = [long] $sealItem.Length
        filename = $sealName
        sha256 = (Get-FileHash -LiteralPath $sealPath -Algorithm SHA256).
          Hash.ToLowerInvariant()
        url = "https://github.com/crutkas/MSYS2-packages/releases/download/$tag/$sealName"
      }
      runtime = $runtime
      devel = $devel
    }
    rejectedSha256 = @(
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
  } | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $approvedPath
  & $validator `
    -LockPath $approvedPath `
    -SealPath $sealPath `
    -PackageDirectory $temp `
    -Bsdtar 'C:\Windows\System32\tar.exe' `
    -RequireApproved
  if ($LASTEXITCODE -ne 0) {
    throw 'The validator rejected a structurally valid bound admission seal'
  }
}
finally {
  Remove-Item -LiteralPath $temp -Recurse -Force
}

Write-Output 'Dependency lock negative fixtures passed.'

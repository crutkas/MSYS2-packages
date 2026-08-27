[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string] $LockPath,

  [string] $SealPath,

  [string] $PackageDirectory,

  [string] $Bsdtar,

  [switch] $RequireApproved
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$requiredRejectedHashes = @(
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

function Assert-ExactProperties {
  param(
    [Parameter(Mandatory)] [object] $Value,
    [Parameter(Mandatory)] [string[]] $Expected,
    [Parameter(Mandatory)] [string] $Name
  )

  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $wanted = @($Expected | Sort-Object)
  if (Compare-Object $wanted $actual) {
    throw "$Name has an unexpected property set (expected: $($wanted -join ', '); actual: $($actual -join ', '))"
  }
}

function Assert-HexSha256 {
  param([string] $Value, [string] $Name)
  if ($Value -cnotmatch '^[0-9a-f]{64}$') {
    throw "$Name is not a lowercase SHA-256"
  }
}

function Assert-NonEmptyString {
  param([object] $Value, [string] $Name)
  if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
    throw "$Name must be a nonempty string"
  }
}

function Assert-ExactStringArray {
  param([object[]] $Actual, [string[]] $Expected, [string] $Name)
  $actualSorted = @($Actual | ForEach-Object {
      Assert-NonEmptyString $_ "$Name entry"
      [string] $_
    } | Sort-Object)
  $expectedSorted = @($Expected | Sort-Object)
  if (Compare-Object $expectedSorted $actualSorted) {
    throw "$Name does not match its admitted value"
  }
}

function Assert-NoDuplicateProperties {
  param(
    [System.Text.Json.JsonElement] $Element,
    [string] $Path = '$'
  )

  switch ($Element.ValueKind) {
    ([System.Text.Json.JsonValueKind]::Object) {
      $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
      foreach ($property in $Element.EnumerateObject()) {
        if (-not $seen.Add($property.Name)) {
          throw "$Path contains duplicate JSON property '$($property.Name)'"
        }
        Assert-NoDuplicateProperties $property.Value "$Path.$($property.Name)"
      }
      break
    }
    ([System.Text.Json.JsonValueKind]::Array) {
      $index = 0
      foreach ($item in $Element.EnumerateArray()) {
        Assert-NoDuplicateProperties $item "$Path[$index]"
        $index++
      }
      break
    }
  }
}

function Read-StrictJson {
  param([string] $Path, [string] $Name)
  $resolved = (Resolve-Path -LiteralPath $Path).Path
  $text = [IO.File]::ReadAllText($resolved)
  $document = [System.Text.Json.JsonDocument]::Parse($text)
  try {
    Assert-NoDuplicateProperties $document.RootElement
  }
  finally {
    $document.Dispose()
  }
  $text | ConvertFrom-Json
}

function Assert-Asset {
  param(
    [object] $Asset,
    [string] $Name,
    [string] $ReleaseTag,
    [switch] $PackageFields
  )
  $properties = @('assetId', 'bytes', 'filename', 'sha256', 'url')
  if ($PackageFields) {
    $properties += @('arch', 'depends', 'pkgname', 'pkgver', 'provides')
  }
  Assert-ExactProperties $Asset $properties $Name
  if ($Asset.assetId -isnot [long] -or $Asset.assetId -le 0) {
    throw "$Name.assetId must be a positive integer"
  }
  if ($Asset.bytes -isnot [long] -or $Asset.bytes -le 0) {
    throw "$Name.bytes must be a positive integer"
  }
  Assert-NonEmptyString $Asset.filename "$Name.filename"
  if ([IO.Path]::GetFileName($Asset.filename) -cne $Asset.filename) {
    throw "$Name.filename must not contain a path"
  }
  Assert-HexSha256 $Asset.sha256 "$Name.sha256"
  $escapedTag = [Uri]::EscapeDataString($ReleaseTag)
  $escapedName = [Uri]::EscapeDataString($Asset.filename)
  $expectedUrl = "https://github.com/crutkas/MSYS2-packages/releases/download/$escapedTag/$escapedName"
  if ($Asset.url -cne $expectedUrl) {
    throw "$Name.url must be the immutable admitted GitHub release URL"
  }
}

function Assert-PackageAdmission {
  param([object] $Package, [string] $Name, [string] $ReleaseTag)
  Assert-ExactProperties $Package @(
    'arch', 'assetId', 'bytes', 'depends', 'filename', 'pkgname',
    'pkgver', 'provides', 'sha256', 'url'
  ) $Name
  Assert-Asset $Package $Name $ReleaseTag -PackageFields
  foreach ($property in @('pkgname', 'pkgver', 'arch')) {
    Assert-NonEmptyString $Package.$property "$Name.$property"
  }
  if ($Package.arch -cne 'x86_64') {
    throw "$Name.arch must be x86_64"
  }
  foreach ($property in @('depends', 'provides')) {
    if ($Package.$property -isnot [object[]] -or $Package.$property.Count -eq 0) {
      throw "$Name.$property must be a nonempty array"
    }
    foreach ($entry in $Package.$property) {
      Assert-NonEmptyString $entry "$Name.$property entry"
    }
  }
}

function Read-PkgInfo {
  param([string] $Archive, [string] $Tool)
  $lines = @(& $Tool -xOf $Archive .PKGINFO)
  if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) {
    throw "Unable to extract .PKGINFO from $Archive"
  }
  $fields = @{}
  foreach ($line in $lines) {
    if ($line -match '^([^#][^ ]*) = (.*)$') {
      if (-not $fields.ContainsKey($Matches[1])) {
        $fields[$Matches[1]] = [Collections.Generic.List[string]]::new()
      }
      $fields[$Matches[1]].Add($Matches[2])
    }
  }
  $fields
}

$lock = Read-StrictJson $LockPath 'dependency lock'
Assert-ExactProperties $lock @(
  'admission', 'approved', 'dependency', 'rejectedSha256', 'repository',
  'requiredVersion', 'schemaVersion'
) 'dependency lock'
if ($lock.schemaVersion -ne 1 -or
    $lock.dependency -cne 'libgpg-error' -or
    $lock.requiredVersion -cne '1.56-1' -or
    $lock.repository -cne 'crutkas/MSYS2-packages') {
  throw 'Dependency lock identity is invalid'
}
if ($lock.approved -isnot [bool]) {
  throw 'Dependency lock approved must be a Boolean'
}
Assert-ExactStringArray $lock.rejectedSha256 $requiredRejectedHashes 'rejectedSha256'
foreach ($hash in $lock.rejectedSha256) {
  Assert-HexSha256 $hash 'rejectedSha256 entry'
}

if (-not $lock.approved) {
  if ($null -ne $lock.admission) {
    throw 'An unapproved dependency lock must have a null admission'
  }
  if ($RequireApproved -or $SealPath -or $PackageDirectory -or $Bsdtar) {
    throw 'libgpg-error admission is closed; final fixed-linker coordinates are not approved'
  }
  Write-Output 'Dependency lock is structurally valid and intentionally unapproved.'
  exit 0
}

if ($null -eq $lock.admission) {
  throw 'An approved dependency lock must contain an admission'
}
Assert-ExactProperties $lock.admission @(
  'devel', 'producerCommit', 'releaseTag', 'runtime', 'seal'
) 'admission'
Assert-NonEmptyString $lock.admission.releaseTag 'admission.releaseTag'
if ($lock.admission.producerCommit -cnotmatch '^[0-9a-f]{40}$') {
  throw 'admission.producerCommit must be a lowercase full commit SHA'
}
Assert-Asset $lock.admission.seal 'admission.seal' $lock.admission.releaseTag
Assert-PackageAdmission $lock.admission.runtime 'admission.runtime' $lock.admission.releaseTag
Assert-PackageAdmission $lock.admission.devel 'admission.devel' $lock.admission.releaseTag

$allAdmissionHashes = @(
  $lock.admission.seal.sha256,
  $lock.admission.runtime.sha256,
  $lock.admission.devel.sha256
)
foreach ($hash in $allAdmissionHashes) {
  if ($hash -in $requiredRejectedHashes) {
    throw "Admission contains revoked, rehearsal, or provisional SHA-256 $hash"
  }
}
if ($lock.admission.runtime.pkgname -cne
    'mingw-w64-cross-msysarm64-libgpg-error' -or
    $lock.admission.devel.pkgname -cne
    'mingw-w64-cross-msysarm64-libgpg-error-devel') {
  throw 'Admission package names do not identify the required sibling pair'
}
foreach ($package in @($lock.admission.runtime, $lock.admission.devel)) {
  if ($package.pkgver -cne $lock.requiredVersion) {
    throw "$($package.pkgname) version is not $($lock.requiredVersion)"
  }
}

if ($SealPath) {
  $sealFile = Get-Item -LiteralPath $SealPath
  if ($sealFile.Name -cne $lock.admission.seal.filename -or
      $sealFile.Length -ne $lock.admission.seal.bytes -or
      (Get-FileHash -LiteralPath $sealFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne
      $lock.admission.seal.sha256) {
    throw 'Downloaded dependency seal does not match its admitted asset'
  }
  $seal = Read-StrictJson $sealFile.FullName 'dependency seal'
  Assert-ExactProperties $seal @(
    'packages', 'producerCommit', 'releaseTag', 'repository', 'schemaVersion'
  ) 'dependency seal'
  if ($seal.schemaVersion -ne 1 -or
      $seal.repository -cne $lock.repository -or
      $seal.releaseTag -cne $lock.admission.releaseTag -or
      $seal.producerCommit -cne $lock.admission.producerCommit) {
    throw 'Dependency seal identity does not match the admission lock'
  }
  if ($seal.packages -isnot [object[]] -or $seal.packages.Count -ne 2) {
    throw 'Dependency seal must bind exactly two package assets'
  }
  $sealedPackages = @($seal.packages | Sort-Object pkgname)
  $lockedPackages = @(
    $lock.admission.runtime,
    $lock.admission.devel
  ) | Sort-Object pkgname
  for ($index = 0; $index -lt 2; $index++) {
    Assert-PackageAdmission $sealedPackages[$index] "seal.packages[$index]" $seal.releaseTag
    foreach ($property in @(
        'arch', 'assetId', 'bytes', 'filename', 'pkgname', 'pkgver',
        'sha256', 'url')) {
      if ($sealedPackages[$index].$property -cne $lockedPackages[$index].$property) {
        throw "Dependency seal package $property does not match the admission lock"
      }
    }
    foreach ($property in @('depends', 'provides')) {
      Assert-ExactStringArray $sealedPackages[$index].$property `
        $lockedPackages[$index].$property "seal package $property"
    }
  }
}
elseif ($PackageDirectory -or $Bsdtar) {
  throw 'Package validation requires the admitted seal'
}

if ($PackageDirectory -or $Bsdtar) {
  if (-not $PackageDirectory -or -not $Bsdtar) {
    throw 'PackageDirectory and Bsdtar must be supplied together'
  }
  foreach ($package in @($lock.admission.runtime, $lock.admission.devel)) {
    $archive = Join-Path $PackageDirectory $package.filename
    $file = Get-Item -LiteralPath $archive
    if ($file.Length -ne $package.bytes -or
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $package.sha256) {
      throw "$($package.pkgname) bytes do not match the admission lock"
    }
    $pkginfo = Read-PkgInfo $archive $Bsdtar
    foreach ($field in @('pkgname', 'pkgver', 'arch')) {
      if ($pkginfo[$field].Count -ne 1 -or
          $pkginfo[$field][0] -cne $package.$field) {
        throw "$($package.pkgname) .PKGINFO $field does not match the admission lock"
      }
    }
    Assert-ExactStringArray $pkginfo['depend'] $package.depends `
      "$($package.pkgname) .PKGINFO depends"
    Assert-ExactStringArray $pkginfo['provides'] $package.provides `
      "$($package.pkgname) .PKGINFO provides"
  }
}

Write-Output 'Dependency admission lock, seal, and supplied package metadata are valid.'

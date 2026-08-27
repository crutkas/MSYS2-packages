[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string] $LockPath,

  [string] $EvidencePath,

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

function Assert-PositiveInteger {
  param([object] $Value, [string] $Name)
  if ($Value -isnot [long] -or $Value -le 0) {
    throw "$Name must be a positive integer"
  }
}

function Assert-ExactStringArray {
  param([object] $Actual, [string[]] $Expected, [string] $Name)
  $actualSorted = @(@($Actual) | ForEach-Object {
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
  param([string] $Path)
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

function Assert-AssetFields {
  param([object] $Asset, [string] $Name, [string] $ReleaseTag)
  Assert-PositiveInteger $Asset.assetId "$Name.assetId"
  Assert-PositiveInteger $Asset.bytes "$Name.bytes"
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
  Assert-AssetFields $Package $Name $ReleaseTag
  foreach ($property in @('pkgname', 'pkgver', 'arch')) {
    Assert-NonEmptyString $Package.$property "$Name.$property"
  }
  if ($Package.arch -cne 'x86_64') {
    throw "$Name.arch must be x86_64"
  }
  foreach ($property in @('depends', 'provides')) {
    if (@($Package.$property).Count -eq 0) {
      throw "$Name.$property must be a nonempty array"
    }
    foreach ($entry in @($Package.$property)) {
      Assert-NonEmptyString $entry "$Name.$property entry"
    }
  }
}

function Read-PkgInfoLines {
  param([string[]] $Lines, [string] $Name)
  if ($Lines.Count -eq 0) {
    throw "$Name is empty"
  }
  $fields = @{}
  foreach ($line in $Lines) {
    if ($line -match '^([^#][^ ]*) = (.*)$') {
      if (-not $fields.ContainsKey($Matches[1])) {
        $fields[$Matches[1]] = [Collections.Generic.List[string]]::new()
      }
      $fields[$Matches[1]].Add($Matches[2])
    }
  }
  $fields
}

function Read-PackageInfo {
  param([string] $Archive, [string] $Tool)
  $lines = @(& $Tool -xOf $Archive .PKGINFO)
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to extract .PKGINFO from $Archive"
  }
  Read-PkgInfoLines $lines "$Archive .PKGINFO"
}

function Assert-PkgInfo {
  param([hashtable] $PkgInfo, [object] $Package, [string] $Name)
  foreach ($field in @('pkgname', 'pkgver', 'arch')) {
    if (-not $PkgInfo.ContainsKey($field) -or
        $PkgInfo[$field].Count -ne 1 -or
        $PkgInfo[$field][0] -cne $Package.$field) {
      throw "$Name $field does not match the admission lock"
    }
  }
  Assert-ExactStringArray $PkgInfo['depend'] $Package.depends "$Name depends"
  Assert-ExactStringArray $PkgInfo['provides'] $Package.provides "$Name provides"
}

function ConvertTo-SafeManifestPath {
  param([string] $Value, [string] $Name)
  Assert-NonEmptyString $Value $Name
  $normalized = $Value.Replace('\', '/')
  if ($normalized -match '(^/|^[A-Za-z]:|^//|(^|/)\.\.(/|$)|(^|/)\.(/|$)|//)') {
    throw "$Name contains an unsafe path: $Value"
  }
  $normalized
}

function Join-ManifestPath {
  param([string] $Root, [string] $Relative)
  $result = $Root
  foreach ($segment in $Relative.Split('/')) {
    $result = Join-Path $result $segment
  }
  $result
}

function Test-EvidenceArchive {
  param(
    [object] $Admission,
    [string] $Archive,
    [string] $Tool
  )

  $evidence = $Admission.evidence
  $file = Get-Item -LiteralPath $Archive
  if ($file.Name -cne $evidence.filename -or
      $file.Length -ne $evidence.bytes -or
      (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.
        ToLowerInvariant() -cne $evidence.sha256) {
    throw 'Downloaded dependency evidence does not match its admitted asset'
  }

  $entries = @(& $Tool -tf $file.FullName)
  if ($LASTEXITCODE -ne 0 -or $entries.Count -ne $evidence.archiveEntries) {
    throw 'Dependency evidence archive entry count is invalid'
  }
  $rootPrefix = "$($evidence.rootDirectory)/"
  foreach ($entry in $entries) {
    $safe = ConvertTo-SafeManifestPath $entry 'evidence archive entry'
    if ($safe -cne $evidence.rootDirectory -and
        -not $safe.StartsWith($rootPrefix, [StringComparison]::Ordinal)) {
      throw "Dependency evidence archive escapes its admitted root: $entry"
    }
  }

  $temp = Join-Path ([IO.Path]::GetTempPath()) "libassuan-evidence-$PID-$([Guid]::NewGuid())"
  New-Item -ItemType Directory -Force $temp | Out-Null
  try {
    & $Tool -xf $file.FullName -C $temp
    if ($LASTEXITCODE -ne 0) {
      throw 'Unable to extract dependency evidence archive'
    }
    $root = Join-Path $temp $evidence.rootDirectory
    $manifestPath = Join-Path $root 'MANIFEST.sha256'
    $sealPath = Join-Path $root 'SEAL.sha256'
    $manifest = Get-Item -LiteralPath $manifestPath
    if ((Get-FileHash -LiteralPath $manifest.FullName -Algorithm SHA256).Hash.
        ToLowerInvariant() -cne $evidence.manifestSha256) {
      throw 'Dependency evidence manifest hash is invalid'
    }
    $expectedSeal = "$($evidence.manifestSha256)  MANIFEST.sha256  STATUS=$($evidence.sealStatus)  COMMIT=$($Admission.producerCommit)"
    $actualSeal = [IO.File]::ReadAllText($sealPath).TrimEnd("`r", "`n")
    if ($actualSeal -cne $expectedSeal) {
      throw 'Dependency evidence seal does not bind the admitted manifest and producer'
    }

    $records = [Collections.Generic.List[object]]::new()
    $recordPaths = [Collections.Generic.HashSet[string]]::new(
      [StringComparer]::Ordinal)
    foreach ($line in [IO.File]::ReadAllLines($manifest.FullName)) {
      if ($line -cnotmatch '^([0-9a-f]{64})  ([0-9]+)  (.+)$') {
        throw "Malformed dependency evidence manifest line: $line"
      }
      $relative = ConvertTo-SafeManifestPath $Matches[3] 'evidence manifest entry'
      if (-not $recordPaths.Add($relative)) {
        throw "Duplicate dependency evidence manifest path: $relative"
      }
      $record = [ordered]@{
        sha256 = $Matches[1]
        bytes = [long] $Matches[2]
        path = $relative
      }
      $payload = Get-Item -LiteralPath (Join-ManifestPath $root $relative)
      if ($payload.Length -ne $record.bytes -or
          (Get-FileHash -LiteralPath $payload.FullName -Algorithm SHA256).Hash.
            ToLowerInvariant() -cne $record.sha256) {
        throw "Dependency evidence payload does not match its manifest: $relative"
      }
      $records.Add([pscustomobject] $record)
    }
    if ($records.Count -ne $evidence.manifestEntries) {
      throw 'Dependency evidence manifest entry count is invalid'
    }

    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File)
    if ($files.Count -ne $evidence.regularFiles) {
      throw 'Dependency evidence regular-file count is invalid'
    }
    foreach ($payload in $files) {
      $relative = $payload.FullName.Substring($root.Length + 1).Replace('\', '/')
      if ($relative -notin @('MANIFEST.sha256', 'SEAL.sha256') -and
          -not $recordPaths.Contains($relative)) {
        throw "Unmanifested dependency evidence payload: $relative"
      }
    }

    foreach ($packageRole in @('runtime', 'devel')) {
      $package = $Admission.$packageRole
      $packageRelative = "ci/pr-packages/$($package.filename)"
      $record = @($records | Where-Object path -CEQ $packageRelative)
      if ($record.Count -ne 1 -or
          $record[0].bytes -ne $package.bytes -or
          $record[0].sha256 -cne $package.sha256) {
        throw "Dependency evidence manifest does not bind the $packageRole package"
      }
      $internalArchive = Join-ManifestPath $root $packageRelative
      Assert-PkgInfo (Read-PackageInfo $internalArchive $Tool) $package `
        "evidence $packageRole package .PKGINFO"

      $pkgInfoRelative = "evidence/$packageRole-final.PKGINFO"
      if (-not $recordPaths.Contains($pkgInfoRelative)) {
        throw "Dependency evidence does not bind $pkgInfoRelative"
      }
      $pkgInfoPath = Join-ManifestPath $root $pkgInfoRelative
      Assert-PkgInfo (Read-PkgInfoLines @(
          [IO.File]::ReadAllLines($pkgInfoPath)
        ) $pkgInfoRelative) $package "evidence $pkgInfoRelative"
    }
  }
  finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
  }
}

$lock = Read-StrictJson $LockPath
Assert-ExactProperties $lock @(
  'admission', 'approved', 'dependency', 'rejectedSha256', 'repository',
  'requiredVersion', 'schemaVersion'
) 'dependency lock'
if ($lock.schemaVersion -ne 2 -or
    $lock.dependency -cne 'libgpg-error' -or
    $lock.requiredVersion -cne '1.56-1' -or
    $lock.repository -cne 'crutkas/MSYS2-packages') {
  throw 'Dependency lock identity is invalid'
}
if ($lock.approved -isnot [bool]) {
  throw 'Dependency lock approved must be a Boolean'
}
Assert-ExactStringArray $lock.rejectedSha256 $requiredRejectedHashes 'rejectedSha256'
foreach ($hash in @($lock.rejectedSha256)) {
  Assert-HexSha256 $hash 'rejectedSha256 entry'
}

if (-not $lock.approved) {
  if ($null -ne $lock.admission) {
    throw 'An unapproved dependency lock must have a null admission'
  }
  if ($RequireApproved -or $EvidencePath -or $PackageDirectory -or $Bsdtar) {
    throw 'libgpg-error admission is closed; final fixed-linker coordinates are not approved'
  }
  Write-Output 'Dependency lock is structurally valid and intentionally unapproved.'
  exit 0
}

if ($null -eq $lock.admission) {
  throw 'An approved dependency lock must contain an admission'
}
Assert-ExactProperties $lock.admission @(
  'devel', 'evidence', 'producerCommit', 'publicAudit', 'releaseId',
  'releaseTag', 'runtime', 'tagObject'
) 'admission'
Assert-PositiveInteger $lock.admission.releaseId 'admission.releaseId'
Assert-NonEmptyString $lock.admission.releaseTag 'admission.releaseTag'
foreach ($property in @('producerCommit', 'tagObject')) {
  if ($lock.admission.$property -cnotmatch '^[0-9a-f]{40}$') {
    throw "admission.$property must be a lowercase full commit SHA"
  }
}

Assert-ExactProperties $lock.admission.evidence @(
  'archiveEntries', 'assetId', 'bytes', 'filename', 'manifestEntries',
  'manifestSha256', 'regularFiles', 'rootDirectory', 'sealStatus',
  'sha256', 'url'
) 'admission.evidence'
Assert-AssetFields $lock.admission.evidence 'admission.evidence' `
  $lock.admission.releaseTag
foreach ($property in @('archiveEntries', 'manifestEntries', 'regularFiles')) {
  Assert-PositiveInteger $lock.admission.evidence.$property "admission.evidence.$property"
}
foreach ($property in @('rootDirectory', 'sealStatus')) {
  Assert-NonEmptyString $lock.admission.evidence.$property "admission.evidence.$property"
}
Assert-HexSha256 $lock.admission.evidence.manifestSha256 `
  'admission.evidence.manifestSha256'

Assert-ExactProperties $lock.admission.publicAudit @(
  'manifestBytes', 'manifestSha256', 'reportBytes', 'reportSha256', 'result'
) 'admission.publicAudit'
foreach ($property in @('manifestBytes', 'reportBytes')) {
  Assert-PositiveInteger $lock.admission.publicAudit.$property `
    "admission.publicAudit.$property"
}
foreach ($property in @('manifestSha256', 'reportSha256')) {
  Assert-HexSha256 $lock.admission.publicAudit.$property `
    "admission.publicAudit.$property"
}
if ($lock.admission.publicAudit.result -cne 'PASS') {
  throw 'admission.publicAudit.result must be PASS'
}

Assert-PackageAdmission $lock.admission.runtime 'admission.runtime' `
  $lock.admission.releaseTag
Assert-PackageAdmission $lock.admission.devel 'admission.devel' `
  $lock.admission.releaseTag

$allAdmissionHashes = @(
  $lock.admission.evidence.sha256,
  $lock.admission.evidence.manifestSha256,
  $lock.admission.publicAudit.manifestSha256,
  $lock.admission.publicAudit.reportSha256,
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

if ($EvidencePath) {
  if (-not $Bsdtar) {
    throw 'Evidence validation requires Bsdtar'
  }
  Test-EvidenceArchive $lock.admission $EvidencePath $Bsdtar
}
elseif ($PackageDirectory -or $Bsdtar) {
  throw 'Package or archive validation requires the admitted evidence archive'
}

if ($PackageDirectory) {
  foreach ($package in @($lock.admission.runtime, $lock.admission.devel)) {
    $archive = Join-Path $PackageDirectory $package.filename
    $file = Get-Item -LiteralPath $archive
    if ($file.Length -ne $package.bytes -or
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.
          ToLowerInvariant() -cne $package.sha256) {
      throw "$($package.pkgname) bytes do not match the admission lock"
    }
    Assert-PkgInfo (Read-PackageInfo $archive $Bsdtar) $package `
      "$($package.pkgname) .PKGINFO"
  }
}

Write-Output 'Dependency admission lock, evidence seal, and supplied package metadata are valid.'

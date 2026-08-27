param(
  [ValidateSet('Test', 'Launch')]
  [string]$Mode = 'Test',
  [string]$LockPath = (Join-Path $PSScriptRoot 'private-host-lock.json'),
  [string]$PrivateRoot = $(if ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'msys2-private-host' } else { Join-Path $PSScriptRoot '.private-host-root' }),
  [string]$TrustedParent = $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $PSScriptRoot }),
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
  [string]$BashCommand = "cd '$RepoRoot' && ./.ci/ci-build.sh",
  [string[]]$BashArguments,
  [switch]$AllowFixturePackages,
  [string]$CurlPath,
  [string]$TarPath
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
  if ($Path -match '^(?i)(\\\\\?\\|\\\\\.\\|\\\\)') {
    throw "$Name uses a forbidden UNC/device prefix: $Path"
  }
}

function Assert-PathCandidate {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  Test-ForbiddenPrefix -Path $Path -Name $Name
  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full -notmatch '^[A-Za-z]:\\') {
    throw "$Name must resolve to a local drive path: $full"
  }
  $drive = Get-PSDrive -Name $full.Substring(0, 1) -ErrorAction Stop
  if ($null -ne $drive.DisplayRoot -and $drive.DisplayRoot -ne '') {
    throw "$Name resolves on a mapped or network drive: $($drive.DisplayRoot)"
  }
  $full
}

function Assert-PrivateRootIdentity {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $full = Assert-PathCandidate -Path $Path -Name $Name
  $forbidden = [System.IO.Path]::GetFullPath('C:\msys64').TrimEnd('\') + '\'
  if ($full -ieq $forbidden.TrimEnd('\')) {
    throw "$Name resolves to the forbidden shared root: $full"
  }
  if ($full.StartsWith($forbidden, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Name resolves beneath the forbidden shared root: $full"
  }
  $full
}

function Assert-PhysicalChain {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $current = Assert-PathIdentity -Path $Path -Name $Name
  while ($true) {
    $parent = Split-Path -Path $current -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
      break
    }
    $parent = Assert-PathIdentity -Path $parent -Name "$Name parent"
    $current = $parent
  }
}

function Assert-PathIdentity {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $full = Assert-PathCandidate -Path $Path -Name $Name
  if (-not (Test-Path -LiteralPath $full)) {
    throw "$Name does not exist: $full"
  }
  $item = Get-Item -LiteralPath $full -Force
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Name is a reparse point: $full"
  }
  $resolved = (Resolve-Path -LiteralPath $full).Path
  if ($resolved -ne $full) {
    throw "$Name resolved to unexpected identity: $resolved"
  }
  $cursor = $full
  while ($true) {
    $parent = Split-Path -Path $cursor -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
      break
    }
    $parentItem = Get-Item -LiteralPath $parent -Force
    if (($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Name parent is a reparse point: $parent"
    }
    $parentResolved = (Resolve-Path -LiteralPath $parent).Path
    if ($parentResolved -ne $parent) {
      throw "$Name parent resolved to unexpected identity: $parentResolved"
    }
    $cursor = $parent
  }
  $full
}

function Assert-NoAmbientShellFallback {
  foreach ($name in 'BASH_ENV', 'ENV') {
    $value = [System.Environment]::GetEnvironmentVariable($name)
    if (-not [string]::IsNullOrWhiteSpace($value)) {
      throw "$name must be unset for the private shell launch"
    }
  }
}

function Assert-LockSchema {
  param(
    [Parameter(Mandatory = $true)]$Lock,
    [Parameter(Mandatory = $true)][bool]$AllowFixturePackages
  )

  if ([int]$Lock.schema_version -ne 1) {
    throw "unsupported private-host lock schema version: $($Lock.schema_version)"
  }
  foreach ($field in 'kind', 'state', 'issued_by', 'issued_at', 'base_ref', 'head_ref', 'base_seed_sha256', 'canonical_lock_sha256', 'protected_context') {
    Assert-Field -Value $Lock.admission.$field -Name "admission.$field"
  }
  if ($Lock.admission.base_seed_sha256 -ne $Lock.base_seed.sha256) {
    throw 'admission.base_seed_sha256 must match the protected base seed'
  }
  if ($Lock.admission.canonical_lock_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'admission.canonical_lock_sha256 must be a lowercase SHA-256 hex string'
  }
  $kind = [string]$Lock.admission.kind
  if ($AllowFixturePackages) {
    if ($kind -ne 'fixture') {
      throw "fixture launch requires a fixture lock admission"
    }
  } else {
    if ($kind -ne 'production') {
      throw "production launch requires an admitted production lock"
    }
  }
  if ($null -eq $Lock.repositories -or @($Lock.repositories).Count -lt 1) {
    throw 'at least one repository is required'
  }
  if ($null -eq $Lock.assets.tools -or @($Lock.assets.tools.PSObject.Properties.Name).Count -lt 1) {
    throw 'at least one private tool package is required'
  }
  foreach ($field in 'curl', 'tar') {
    Assert-Field -Value $Lock.bootstrap.$field.url -Name "bootstrap.$field.url"
    Assert-Field -Value $Lock.bootstrap.$field.name -Name "bootstrap.$field.name"
    Assert-Field -Value $Lock.bootstrap.$field.bytes -Name "bootstrap.$field.bytes"
    Assert-Field -Value $Lock.bootstrap.$field.sha256 -Name "bootstrap.$field.sha256"
    $bootstrapUri = [System.Uri]::new([string]$Lock.bootstrap.$field.url, [System.UriKind]::Absolute)
    if ($bootstrapUri.Scheme -ne 'https') {
      throw "bootstrap.$field.url must be https"
    }
    if ([System.IO.Path]::GetFileName($bootstrapUri.AbsolutePath) -ne [string]$Lock.bootstrap.$field.name) {
      throw "bootstrap.$field.name must match the URL leaf name"
    }
    if ([string]$Lock.bootstrap.$field.sha256 -notmatch '^[0-9a-f]{64}$') {
      throw "bootstrap.$field.sha256 must be a lowercase SHA-256 hex string"
    }
  }
  Assert-Field -Value $Lock.ci.base_repository -Name 'ci.base_repository'
  Assert-Field -Value $Lock.ci.base_ref -Name 'ci.base_ref'
  Assert-Field -Value $Lock.ci.base_rev -Name 'ci.base_rev'
  Assert-Field -Value $Lock.ci.run_check -Name 'ci.run_check'
  Assert-Field -Value $Lock.ci.canonicalize_packages -Name 'ci.canonicalize_packages'
  Assert-Field -Value $Lock.ci.package_prefixes -Name 'ci.package_prefixes'
  Assert-Field -Value $Lock.ci.carch -Name 'ci.carch'
  Assert-Field -Value $Lock.ci.chost -Name 'ci.chost'
  Assert-Field -Value $Lock.ci.msystem_carch -Name 'ci.msystem_carch'
  Assert-Field -Value $Lock.ci.msystem_chost -Name 'ci.msystem_chost'
  Assert-Field -Value $Lock.ci.source_date_epoch -Name 'ci.source_date_epoch'
  foreach ($repo in @($Lock.repositories)) {
    Assert-Field -Value $repo.name -Name 'repositories.name'
    Assert-Field -Value $repo.server -Name 'repositories.server'
    Assert-Field -Value $repo.siglevel -Name 'repositories.siglevel'
  }
}

function Assert-PackageAsset {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][bool]$AllowFixturePackages
  )

  foreach ($field in 'url', 'name', 'version', 'bytes', 'sha256') {
    Assert-Field -Value $Asset.package.$field -Name "$Name.package.$field"
  }
  foreach ($field in 'pkgname', 'pkgver', 'pkgdesc', 'arch', 'depends', 'provides', 'conflicts') {
    Assert-Field -Value $Asset.metadata.$field -Name "$Name.metadata.$field"
  }

  $uri = [System.Uri]::new([string]$Asset.package.url, [System.UriKind]::Absolute)
  if (-not $AllowFixturePackages -and $uri.Scheme -ne 'https') {
    throw "$Name.package.url must use https in production"
  }
  if ([System.IO.Path]::GetFileName($uri.AbsolutePath) -ne [string]$Asset.package.name) {
    throw "$Name.package.name must match the URL leaf name"
  }
  if ($uri.AbsolutePath.EndsWith('/')) {
    throw "$Name.package.url must point to a leaf file"
  }
  if ([string]$Asset.package.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw "$Name.package.sha256 must be a lowercase SHA-256 hex string"
  }
  if ([int64]$Asset.package.bytes -le 0) {
    throw "$Name.package.bytes must be a positive integer"
  }
}

function Assert-Contained {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Parent,
    [Parameter(Mandatory = $true)]
    [string]$Child,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $parentFull = Assert-PrivateRootIdentity -Path $Parent -Name "$Name parent"
  $childFull = Assert-PathCandidate -Path $Child -Name $Name
  $prefix = $parentFull.TrimEnd('\') + '\'
  if (-not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Name escapes trusted root: $childFull"
  }
  if (-not $childFull.StartsWith((Resolve-Path -LiteralPath $parentFull).Path.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Name does not remain contained after canonicalization: $childFull"
  }
  $childFull
}

function New-ExclusiveDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $full = Assert-PrivateRootIdentity -Path $Path -Name $Name
  $parent = Split-Path -Path $full -Parent
  if ($parent) {
    Assert-PhysicalChain -Path $parent -Name "$Name parent"
  }
  if (Test-Path -LiteralPath $full) {
    throw "$Name already exists and cannot be reused: $full"
  }
  New-Item -ItemType Directory -Path $full -ErrorAction Stop | Out-Null
  Assert-PathIdentity -Path $full -Name $Name | Out-Null
  $full
}

function New-ExclusiveFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [string]$Content = ''
  )

  $full = Assert-PrivateRootIdentity -Path $Path -Name $Name
  $parent = Split-Path -Path $full -Parent
  if (Test-Path -LiteralPath $parent) {
    Assert-PhysicalChain -Path $parent -Name "$Name parent"
  }
  if (-not (Test-Path -LiteralPath $parent)) {
    New-ExclusiveDirectory -Path $parent -Name "$Name parent" | Out-Null
  }
  if (Test-Path -LiteralPath $full) {
    throw "$Name already exists and cannot be reused: $full"
  }
  $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try {
    if ($Content.Length -gt 0) {
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
      $stream.Write($bytes, 0, $bytes.Length)
    }
  } finally {
    $stream.Dispose()
  }
  Assert-PathIdentity -Path $full -Name $Name | Out-Null
  $full
}

function Read-PkgInfo {
  param([Parameter(Mandatory = $true)][string]$Path)
  $map = [ordered]@{}
  foreach ($line in Get-Content -LiteralPath $Path) {
    if ($line -match '^\s*([^=]+?)\s*=\s*(.*)\s*$') {
      $key = $Matches[1].Trim()
      $value = $Matches[2]
      if (-not $map.Contains($key)) {
        $map[$key] = @()
      }
      $map[$key] += $value
    }
  }
  $map
}

function Assert-Field {
  param(
    [AllowNull()]
    $Value,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  if ($null -eq $Value -or $Value -eq '') {
    throw "$Name is required"
  }
}

function Assert-Sequence {
  param(
    [Parameter(Mandatory = $true)]
    [object[]]$Actual,
    [Parameter(Mandatory = $true)]
    [object[]]$Expected,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $actualText = @($Actual) -join "`n"
  $expectedText = @($Expected) -join "`n"
  if ($actualText -ne $expectedText) {
    throw "$Name mismatch. Expected: [$expectedText] Actual: [$actualText]"
  }
}

function Assert-AssetReady {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][bool]$AllowFixturePackages
  )

  Assert-PackageAsset -Asset $Asset -Name $Name -AllowFixturePackages $AllowFixturePackages
}

function Download-Asset {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][string]$CurlPath,
    [Parameter(Mandatory = $true)][bool]$AllowFixturePackages
  )
  Assert-PathIdentity -Path $CurlPath -Name 'curl.exe' | Out-Null
  $curlArgs = @('--fail', '--location', '--retry', '5', '--silent', '--show-error')
  if (-not $AllowFixturePackages) {
    $curlArgs += @('--proto', '=https', '--proto-redir', '=https')
  }
  $curlArgs += @('--output', $Destination, $Asset.package.url)
  & $CurlPath @curlArgs
  if ($LASTEXITCODE -ne 0) {
    throw "download failed for $($Asset.package.url)"
  }
  $length = (Get-Item -LiteralPath $Destination).Length
  if ($length -ne [int64]$Asset.package.bytes) {
    throw "size mismatch for ${Destination}: expected $($Asset.package.bytes) got $length"
  }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
  if ($hash -ne $Asset.package.sha256.ToLowerInvariant()) {
    throw "sha256 mismatch for $Destination"
  }
}

function Extract-Archive {
  param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][string]$TarPath
  )
  if (-not (Test-Path -LiteralPath $Destination)) {
    throw "extract destination does not exist: $Destination"
  }
  Assert-PathIdentity -Path $TarPath -Name 'tar.exe' | Out-Null
  & $TarPath -xf $Archive -C $Destination
  if ($LASTEXITCODE -ne 0) {
    throw "archive extraction failed for $Archive"
  }
}

function Install-ArchiveTree {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Stage,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][bool]$AllowFixturePackages,
    [Parameter(Mandatory = $true)][string]$CurlPath,
    [Parameter(Mandatory = $true)][string]$TarPath
  )
  $downloadsRoot = Assert-PathIdentity -Path (Join-Path $Stage 'downloads') -Name 'downloads root'
  $extractRoot = Assert-PathIdentity -Path (Join-Path $Stage 'extract') -Name 'extract root'
  $downloads = New-ExclusiveDirectory -Path (Join-Path $downloadsRoot $Name) -Name "$Name downloads"
  $extracted = New-ExclusiveDirectory -Path (Join-Path $extractRoot $Name) -Name "$Name extract"
  $archive = Join-Path $downloads $Asset.package.name
  Download-Asset -Asset $Asset -Destination $archive -CurlPath $CurlPath -AllowFixturePackages $AllowFixturePackages
  Extract-Archive -Archive $archive -Destination $extracted -TarPath $TarPath

  $pkgInfoPath = Join-Path $extracted '.PKGINFO'
  if (-not (Test-Path -LiteralPath $pkgInfoPath)) {
    throw "$Name archive missing .PKGINFO"
  }
  $pkgInfo = Read-PkgInfo -Path $pkgInfoPath
  Assert-Sequence -Actual $pkgInfo['pkgname'] -Expected @($Asset.metadata.pkgname) -Name "$Name pkgname"
  Assert-Sequence -Actual $pkgInfo['pkgver'] -Expected @($Asset.metadata.pkgver) -Name "$Name pkgver"
  Assert-Sequence -Actual $pkgInfo['pkgdesc'] -Expected @($Asset.metadata.pkgdesc) -Name "$Name pkgdesc"
  Assert-Sequence -Actual $pkgInfo['arch'] -Expected @($Asset.metadata.arch) -Name "$Name arch"
  foreach ($dep in @($Asset.metadata.depends)) {
    if ($dep -and ($pkgInfo['depend'] -notcontains $dep)) {
      throw "$Name missing dependency $dep"
    }
  }
  foreach ($provide in @($Asset.metadata.provides)) {
    if ($provide -and ($pkgInfo['provide'] -notcontains $provide)) {
      throw "$Name missing provide $provide"
    }
  }
  foreach ($conflict in @($Asset.metadata.conflicts)) {
    if ($conflict -and ($pkgInfo['conflict'] -notcontains $conflict)) {
      throw "$Name missing conflict $conflict"
    }
  }
  foreach ($item in Get-ChildItem -LiteralPath $extracted -Force -Recurse) {
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Name archive extracted a reparse point: $($item.FullName)"
    }
    $relative = $item.FullName.Substring($extracted.Length).TrimStart('\')
    if ([string]::IsNullOrWhiteSpace($relative)) {
      continue
    }
    if ([System.IO.Path]::GetFileName($relative).StartsWith('.')) {
      continue
    }
    $target = Join-Path $Root $relative
    $targetParent = Split-Path -Path $target -Parent
    if (-not (Test-Path -LiteralPath $targetParent)) {
      New-Item -ItemType Directory -Path $targetParent -ErrorAction Stop | Out-Null
    }
    if ($item.PSIsContainer) {
      if (-not (Test-Path -LiteralPath $target)) {
        New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
      }
      Assert-PathIdentity -Path $target -Name "$Name extracted directory" | Out-Null
    } else {
      if (Test-Path -LiteralPath $target) {
        $existingHash = Get-FileHash -Algorithm SHA256 -LiteralPath $target
        $sourceHash = Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName
        if ($existingHash.Hash -ne $sourceHash.Hash) {
          throw "$Name archive collision at $target"
        }
        continue
      }
      Copy-Item -LiteralPath $item.FullName -Destination $target -Force
      Assert-PathIdentity -Path $target -Name "$Name extracted file" | Out-Null
    }
  }
}

function Resolve-PrivateTool {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$RelativePath,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $candidate = Join-Path $Root $RelativePath
  Assert-PathIdentity -Path $candidate -Name $Name | Out-Null
  $candidate
}

function Build-MinimalEnvironment {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)]$Lock,
    [Parameter(Mandatory = $true)][string]$GitExecPath
  )

  $homePath = Join-Path $Root 'home'
  $tmpPath = Join-Path $Root 'tmp'
  foreach ($pair in @(
    @{ Path = $homePath; Name = 'home' },
    @{ Path = $tmpPath; Name = 'tmp' }
  )) {
    if (-not (Test-Path -LiteralPath $pair.Path)) {
      New-Item -ItemType Directory -Path $pair.Path -ErrorAction Stop | Out-Null
    }
    Assert-PathIdentity -Path $pair.Path -Name $pair.Name | Out-Null
  }
  [ordered]@{
    PATH = ($Root + '\usr\bin')
    GIT_EXEC_PATH = $GitExecPath
    HOME = $homePath
    TEMP = $tmpPath
    TMP = $tmpPath
    MSYSTEM = 'MSYS'
    MSYS2_PATH_TYPE = 'inherit'
    CHERE_INVOKING = '1'
    LANG = 'C.UTF-8'
    LC_ALL = 'C.UTF-8'
    CI_BASE_REPOSITORY = [string]$Lock.ci.base_repository
    CI_BASE_REF = [string]$Lock.ci.base_ref
    CI_BASE_REV = [string]$Lock.ci.base_rev
    CI_RUN_CHECK = [string]$Lock.ci.run_check
    CI_CANONICALIZE_PACKAGES = [string]$Lock.ci.canonicalize_packages
    CI_PACKAGE_PREFIXES = [string]$Lock.ci.package_prefixes
    CARCH = [string]$Lock.ci.carch
    CHOST = [string]$Lock.ci.chost
    MSYSTEM_CARCH = [string]$Lock.ci.msystem_carch
    MSYSTEM_CHOST = [string]$Lock.ci.msystem_chost
    SOURCE_DATE_EPOCH = [string]$Lock.ci.source_date_epoch
  }
}

function Invoke-PrivateHostLaunch {
  param(
    [Parameter(Mandatory = $true)]$Lock,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$TrustedParent,
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$BashCommand,
    [string[]]$BashArguments,
    [Parameter(Mandatory = $true)][bool]$AllowFixturePackages,
    [Parameter(Mandatory = $true)][string]$CurlPath,
    [string]$TarPath
  )

  Assert-LockSchema -Lock $Lock -AllowFixturePackages $AllowFixturePackages
  Assert-NoAmbientShellFallback
  if (-not $AllowFixturePackages) {
    Assert-Field -Value $CurlPath -Name 'bootstrap.curl.path'
    Assert-Field -Value $TarPath -Name 'bootstrap.tar.path'
  }

  foreach ($assetName in 'git', 'bash') {
    Assert-AssetReady -Asset $Lock.assets.host.$assetName -Name "assets.host.$assetName" -AllowFixturePackages $AllowFixturePackages
  }
  foreach ($toolName in @($Lock.assets.tools.PSObject.Properties.Name)) {
    Assert-AssetReady -Asset $Lock.assets.tools.PSObject.Properties[$toolName].Value -Name "assets.tools.$toolName" -AllowFixturePackages $AllowFixturePackages
  }

  $rootPath = Assert-Contained -Parent $TrustedParent -Child $Root -Name 'private root'
  if (Test-Path -LiteralPath $rootPath) {
    throw "private root already exists and cannot be reused: $rootPath"
  }
  $rootPath = New-ExclusiveDirectory -Path $rootPath -Name 'private root'
  foreach ($subdir in @('usr', 'var', 'etc', 'home', 'stage', 'tmp')) {
    New-ExclusiveDirectory -Path (Join-Path $rootPath $subdir) -Name $subdir | Out-Null
  }
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\log') -Name 'var\log' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\lib') -Name 'var\lib' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\cache') -Name 'var\cache' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\lib\pacman') -Name 'var\lib\pacman' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\cache\pacman') -Name 'var\cache\pacman' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'etc\pacman.d') -Name 'etc\pacman.d' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'stage\downloads') -Name 'downloads root' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'stage\extract') -Name 'extract root' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\cache\pacman\pkg') -Name 'var\cache\pacman\pkg' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'var\lib\pacman\sync') -Name 'var\lib\pacman\sync' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'etc\pacman.d\gnupg') -Name 'etc\pacman.d\gnupg' | Out-Null

  Install-ArchiveTree -Asset $Lock.assets.host.git -Root $rootPath -Stage (Join-Path $rootPath 'stage') -Name 'git' -AllowFixturePackages $AllowFixturePackages -CurlPath $CurlPath -TarPath $TarPath
  Install-ArchiveTree -Asset $Lock.assets.host.bash -Root $rootPath -Stage (Join-Path $rootPath 'stage') -Name 'bash' -AllowFixturePackages $AllowFixturePackages -CurlPath $CurlPath -TarPath $TarPath
  foreach ($toolName in @($Lock.assets.tools.PSObject.Properties.Name)) {
    Install-ArchiveTree -Asset $Lock.assets.tools.PSObject.Properties[$toolName].Value -Root $rootPath -Stage (Join-Path $rootPath 'stage') -Name $toolName -AllowFixturePackages $AllowFixturePackages -CurlPath $CurlPath -TarPath $TarPath
  }

  $pacmanConf = New-ExclusiveFile -Path (Join-Path $rootPath 'etc\pacman.conf') -Name 'pacman.conf'
  $pacmanLog = New-ExclusiveFile -Path (Join-Path $rootPath 'var\log\pacman.log') -Name 'pacman.log'
  $pacmanLines = @(
    '[options]',
    "RootDir = $rootPath",
    "DBPath = $($Lock.private_root.dbpath)",
    "CacheDir = $($Lock.private_root.cache)",
    "LogFile = $pacmanLog",
    "HookDir = $($Lock.private_root.hooks)",
    "GPGDir = $($Lock.private_root.gpg)",
    'Architecture = aarch64',
    'SigLevel = Required DatabaseOptional'
  )
  foreach ($repo in @($Lock.repositories)) {
    $pacmanLines += ''
    $pacmanLines += "[$($repo.name)]"
    $pacmanLines += "Server = $($repo.server)"
    $pacmanLines += "SigLevel = $($repo.siglevel)"
  }
  Set-Content -LiteralPath $pacmanConf -Value $pacmanLines

  $bashExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\bash.exe' -Name 'bash.exe'
  $gitExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\git.exe' -Name 'git.exe'
  $pacmanExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\pacman.exe' -Name 'pacman.exe'
  $cygpathExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\cygpath.exe' -Name 'cygpath.exe'
  $objdumpExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\objdump.exe' -Name 'objdump.exe'
  $nmExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\nm.exe' -Name 'nm.exe'
  $tarExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\tar.exe' -Name 'tar.exe'
  $gitExecPath = Assert-PathIdentity -Path (Join-Path $rootPath 'usr\lib\git-core') -Name 'GIT_EXEC_PATH'
  $tempPath = Assert-PathIdentity -Path (Join-Path $rootPath 'tmp') -Name 'TMP'
  $homePath = Assert-PathIdentity -Path (Join-Path $rootPath 'home') -Name 'HOME'

  [pscustomobject]@{
   bash = $bashExe
   git = $gitExe
   pacman = $pacmanExe
   cygpath = $cygpathExe
   objdump = $objdumpExe
   nm = $nmExe
   tar = $tarExe
   git_exec_path = $gitExecPath
  } | ConvertTo-Json -Depth 4 | Write-Host

  $childEnv = Build-MinimalEnvironment -Root $rootPath -Lock $Lock -GitExecPath $gitExecPath
  $arguments = if ($null -ne $BashArguments -and $BashArguments.Count -gt 0) {
   @($BashArguments)
  } else {
   @('--noprofile', '--norc', '-lc', $BashCommand)
  }
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $bashExe
  $psi.WorkingDirectory = $RepoRoot
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $false
  $psi.RedirectStandardError = $false
  $psi.Environment.Clear()
  foreach ($entry in $childEnv.GetEnumerator()) {
   if ($null -ne $entry.Value -and $entry.Value -ne '') {
     $psi.Environment[$entry.Key] = [string]$entry.Value
   }
  }
  foreach ($argument in @($arguments)) {
   [void]$psi.ArgumentList.Add([string]$argument)
  }
  $proc = [System.Diagnostics.Process]::Start($psi)
  if ($null -eq $proc) {
   throw 'bash launch did not produce a process handle'
  }
  $proc.WaitForExit()
  return $proc.ExitCode
}

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json

if ($Mode -eq 'Test') {
  & (Join-Path $PSScriptRoot 'private-host-test.ps1') -LauncherPath $PSCommandPath -LockPath $LockPath
  exit $LASTEXITCODE
}

$exitCode = Invoke-PrivateHostLaunch -Lock $lock -Root $PrivateRoot -TrustedParent $TrustedParent -RepoRoot $RepoRoot -BashCommand $BashCommand -BashArguments $BashArguments -AllowFixturePackages ([bool]$AllowFixturePackages) -CurlPath $CurlPath -TarPath $TarPath
exit $exitCode

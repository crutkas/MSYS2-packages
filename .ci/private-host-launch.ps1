param(
  [ValidateSet('Test', 'Launch')]
  [string]$Mode = 'Test',
  [string]$LockPath = (Join-Path $PSScriptRoot 'private-host-lock.json'),
  [string]$PrivateRoot = $(if ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'msys2-private-host' } else { Join-Path $PSScriptRoot '.private-host-root' }),
  [string]$TrustedParent = $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $PSScriptRoot }),
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
  [string]$BashCommand = "cd '$RepoRoot' && ./.ci/ci-build.sh",
  [string[]]$BashArguments
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
  $full
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

  $parentFull = Assert-PathIdentity -Path $Parent -Name "$Name parent"
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

  $full = Assert-PathCandidate -Path $Path -Name $Name
  $parent = Split-Path -Path $full -Parent
  if ($parent) {
    Assert-PathIdentity -Path $parent -Name "$Name parent" | Out-Null
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

  $full = Assert-PathCandidate -Path $Path -Name $Name
  $parent = Split-Path -Path $full -Parent
  if (Test-Path -LiteralPath $parent) {
    Assert-PathIdentity -Path $parent -Name "$Name parent" | Out-Null
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
    [Parameter(Mandatory = $true)][string]$Name
  )

  foreach ($field in 'url', 'name', 'version', 'bytes', 'sha256') {
    Assert-Field -Value $Asset.package.$field -Name "$Name.package.$field"
  }
  foreach ($field in 'pkgname', 'pkgver', 'pkgrel', 'pkgdesc') {
    Assert-Field -Value $Asset.metadata.$field -Name "$Name.metadata.$field"
  }
  foreach ($field in 'arch', 'depends', 'provides', 'conflicts') {
    Assert-Field -Value $Asset.metadata.$field -Name "$Name.metadata.$field"
  }
}

function Download-Asset {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$Destination
  )
  & curl.exe --fail --location --retry 5 --silent --show-error --output $Destination $Asset.package.url
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
    [Parameter(Mandatory = $true)][string]$Destination
  )
  if (-not (Test-Path -LiteralPath $Destination)) {
    throw "extract destination does not exist: $Destination"
  }
  & tar.exe -xf $Archive -C $Destination
  if ($LASTEXITCODE -ne 0) {
    throw "archive extraction failed for $Archive"
  }
}

function Install-ArchiveTree {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Stage,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $downloadsRoot = Assert-PathIdentity -Path (Join-Path $Stage 'downloads') -Name 'downloads root'
  $extractRoot = Assert-PathIdentity -Path (Join-Path $Stage 'extract') -Name 'extract root'
  $downloads = New-ExclusiveDirectory -Path (Join-Path $downloadsRoot $Name) -Name "$Name downloads"
  $extracted = New-ExclusiveDirectory -Path (Join-Path $extractRoot $Name) -Name "$Name extract"
  $archive = Join-Path $downloads $Asset.package.name
  Download-Asset -Asset $Asset -Destination $archive
  Extract-Archive -Archive $archive -Destination $extracted

  $pkgInfoPath = Join-Path $extracted '.PKGINFO'
  if (-not (Test-Path -LiteralPath $pkgInfoPath)) {
    throw "$Name archive missing .PKGINFO"
  }
  $pkgInfo = Read-PkgInfo -Path $pkgInfoPath
  Assert-Sequence -Actual $pkgInfo['pkgname'] -Expected @($Asset.metadata.pkgname) -Name "$Name pkgname"
  Assert-Sequence -Actual $pkgInfo['pkgver'] -Expected @($Asset.metadata.pkgver) -Name "$Name pkgver"
  Assert-Sequence -Actual $pkgInfo['pkgrel'] -Expected @($Asset.metadata.pkgrel) -Name "$Name pkgrel"
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

  Copy-Item -Path (Join-Path $extracted '*') -Destination $Root -Recurse -Force
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
  }
}

function Invoke-PrivateHostLaunch {
  param(
    [Parameter(Mandatory = $true)]$Lock,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$TrustedParent,
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$BashCommand,
    [string[]]$BashArguments
  )

  foreach ($assetName in 'git', 'bash') {
    Assert-AssetReady -Asset $Lock.assets.host.$assetName -Name "assets.host.$assetName"
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
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'etc\pacman.d') -Name 'etc\pacman.d' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'stage\downloads') -Name 'downloads root' | Out-Null
  New-ExclusiveDirectory -Path (Join-Path $rootPath 'stage\extract') -Name 'extract root' | Out-Null

  Install-ArchiveTree -Asset $Lock.assets.host.git -Root $rootPath -Stage (Join-Path $rootPath 'stage') -Name 'git'
  Install-ArchiveTree -Asset $Lock.assets.host.bash -Root $rootPath -Stage (Join-Path $rootPath 'stage') -Name 'bash'

  $pacmanConf = New-ExclusiveFile -Path (Join-Path $rootPath 'etc\pacman.conf') -Name 'pacman.conf'
  $pacmanLog = New-ExclusiveFile -Path (Join-Path $rootPath 'var\log\pacman.log') -Name 'pacman.log'
  Set-Content -LiteralPath $pacmanConf -Value "[options]`nLogFile = $pacmanLog`n"

  $bashExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\bash.exe' -Name 'bash.exe'
  $gitExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\git.exe' -Name 'git.exe'
  $pacmanExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\pacman.exe' -Name 'pacman.exe'
  $cygpathExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\cygpath.exe' -Name 'cygpath.exe'
  $objdumpExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\objdump.exe' -Name 'objdump.exe'
  $nmExe = Resolve-PrivateTool -Root $rootPath -RelativePath 'usr\bin\nm.exe' -Name 'nm.exe'
  $gitExecPath = Assert-PathIdentity -Path (Join-Path $rootPath 'usr\lib\git-core') -Name 'GIT_EXEC_PATH'

  [pscustomobject]@{
    bash = $bashExe
    git = $gitExe
    pacman = $pacmanExe
    cygpath = $cygpathExe
    objdump = $objdumpExe
    nm = $nmExe
    git_exec_path = $gitExecPath
  } | ConvertTo-Json -Depth 4 | Write-Host

  $childEnv = Build-MinimalEnvironment -Root $rootPath -GitExecPath $gitExecPath
  $arguments = if ($null -ne $BashArguments -and $BashArguments.Count -gt 0) {
   @($BashArguments)
  } else {
    @('--noprofile', '--norc', '-lc', $BashCommand)
  }
  $proc = Start-Process -FilePath $bashExe -ArgumentList @($arguments) -WorkingDirectory $RepoRoot -NoNewWindow -PassThru -Wait -Environment $childEnv
  if ($null -eq $proc) {
    throw 'bash launch did not produce a process handle'
  }
  return $proc.ExitCode
}

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json

if ($Mode -eq 'Test') {
  & (Join-Path $PSScriptRoot 'private-host-test.ps1') -LauncherPath $PSCommandPath -LockPath $LockPath
  exit $LASTEXITCODE
}

$exitCode = Invoke-PrivateHostLaunch -Lock $lock -Root $PrivateRoot -TrustedParent $TrustedParent -RepoRoot $RepoRoot -BashCommand $BashCommand -BashArguments $BashArguments
exit $exitCode

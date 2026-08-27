param(
  [string]$LauncherPath = (Join-Path $PSScriptRoot 'private-host-launch.ps1'),
  [string]$LockPath = (Join-Path $PSScriptRoot 'private-host-lock.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Fails {
  param(
    [Parameter(Mandatory = $true)]
    [scriptblock]$Script,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $failed = $false
  try {
    & $Script
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
      $failed = $true
    }
  } catch {
    $failed = $true
  }

  if (-not $failed) {
    throw "$Name did not fail"
  }
}

function New-FixtureHostPublish {
  param(
    [Parameter(Mandatory = $true)]
    [string]$OutDir,
    [Parameter(Mandatory = $true)]
    [string]$AssemblyName
  )

  $projectDir = Join-Path $OutDir $AssemblyName
  New-Item -ItemType Directory -Force -Path $projectDir | Out-Null
  @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $projectDir 'fixture.csproj')
  @'
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;

var exe = Process.GetCurrentProcess().MainModule!.FileName!;
var marker = exe + ".env.txt";
var payload = new
{
    EXE = exe,
    ARGS = Environment.GetCommandLineArgs().Skip(1).ToArray(),
    PATH = Environment.GetEnvironmentVariable("PATH"),
    GIT_EXEC_PATH = Environment.GetEnvironmentVariable("GIT_EXEC_PATH"),
    MSYSTEM = Environment.GetEnvironmentVariable("MSYSTEM"),
    MSYS2_PATH_TYPE = Environment.GetEnvironmentVariable("MSYS2_PATH_TYPE"),
    HOME = Environment.GetEnvironmentVariable("HOME"),
    TEMP = Environment.GetEnvironmentVariable("TEMP"),
    BASH_ENV = Environment.GetEnvironmentVariable("BASH_ENV"),
    ENV = Environment.GetEnvironmentVariable("ENV")
};
File.WriteAllText(marker, JsonSerializer.Serialize(payload));
return 37;
'@ | Set-Content -LiteralPath (Join-Path $projectDir 'Program.cs')

  $publishDir = Join-Path $projectDir 'publish'
  & dotnet.exe publish (Join-Path $projectDir 'fixture.csproj') -c Release -o $publishDir -p:AssemblyName=$AssemblyName --nologo | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "failed to publish fixture console host: $AssemblyName"
  }
  return $publishDir
}

function New-ArchiveFromTree {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [Parameter(Mandatory = $true)]
    [string]$TarPath
  )

  & $TarPath -cf $ArchivePath -C $SourceDir .
  if ($LASTEXITCODE -ne 0) {
    throw "failed to create fixture archive: $ArchivePath"
  }
}

function Start-FixtureServer {
  param(
    [Parameter(Mandatory = $true)]
    [string]$MapFile,
    [Parameter(Mandatory = $true)]
    [int]$Port
  )

  $jobScript = {
    param($MapFile, $Port)
    $map = Get-Content -LiteralPath $MapFile -Raw | ConvertFrom-Json -AsHashtable
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    $listener.Start()
    try {
      while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $name = [System.IO.Path]::GetFileName($ctx.Request.Url.AbsolutePath)
        if ($map.ContainsKey($name)) {
          $file = $map[$name]
          [byte[]]$bytes = [System.IO.File]::ReadAllBytes($file)
          $ctx.Response.ContentLength64 = $bytes.Length
          $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
          $ctx.Response.OutputStream.Close()
        } else {
          $ctx.Response.StatusCode = 404
          $ctx.Response.Close()
        }
      }
    } finally {
      $listener.Stop()
    }
  }

  Start-Job -ScriptBlock $jobScript -ArgumentList $MapFile, $Port
}

function New-FixturePackageTree {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [Parameter(Mandatory = $true)]
    [string]$Role,
    [Parameter(Mandatory = $true)]
    [string]$HostRoot,
    [Parameter(Mandatory = $true)]
    [string]$TarPath
  )

  $pkgRoot = Join-Path $Root $Role
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\bin') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\lib\git-core') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\share\man\man1') | Out-Null

  if ($Role -eq 'bash') {
    foreach ($tool in @('bash', 'sh', 'pacman', 'cygpath', 'objdump', 'nm', 'tar')) {
      $publishDir = New-FixtureHostPublish -OutDir (Join-Path $HostRoot $tool) -AssemblyName $tool
      foreach ($suffix in 'exe', 'dll', 'deps.json', 'runtimeconfig.json', 'pdb') {
        Copy-Item -LiteralPath (Join-Path $publishDir "$tool.$suffix") -Destination (Join-Path $pkgRoot "usr\bin\$tool.$suffix") -Force
      }
    }
  } else {
    $publishDir = New-FixtureHostPublish -OutDir (Join-Path $HostRoot 'git') -AssemblyName 'git'
    foreach ($suffix in 'exe', 'dll', 'deps.json', 'runtimeconfig.json', 'pdb') {
      Copy-Item -LiteralPath (Join-Path $publishDir "git.$suffix") -Destination (Join-Path $pkgRoot "usr\bin\git.$suffix") -Force
    }
  }

  if ($Role -eq 'git') {
    Set-Content -LiteralPath (Join-Path $pkgRoot 'usr\lib\git-core\git-core-marker.txt') -Value 'git-core' -NoNewline
  } else {
    Set-Content -LiteralPath (Join-Path $pkgRoot 'usr\share\man\man1\bash.1') -Value '.so man1/bash.1' -NoNewline
  }

  $pkginfo = if ($Role -eq 'git') {
    @(
      'pkgname = git',
      'pkgver = 2.50.1-1',
      'pkgdesc = The fast distributed version control system',
      'arch = x86_64',
      'depend = curl',
      'depend = libpcre2_8',
      'depend = libexpat',
      'depend = libintl',
      'depend = nano',
      'depend = openssh',
      'depend = openssl',
      'depend = perl-Error',
      'depend = perl>=5.14.0',
      'depend = perl-Authen-SASL',
      'depend = perl-libwww',
      'depend = perl-MIME-tools',
      'depend = perl-Net-SMTP-SSL',
      'depend = perl-TermReadKey',
      'provide = git-core',
      'conflict = git-core'
    )
  } else {
    @(
      'pkgname = bash',
      'pkgver = 5.2.037-3',
      'pkgdesc = The GNU Bourne Again shell',
      'arch = aarch64',
      'provide = sh'
    )
  }
  $pkginfo | Set-Content -LiteralPath (Join-Path $pkgRoot '.PKGINFO')
  $archive = Join-Path $Root "$Role.pkg.tar"
  New-ArchiveFromTree -SourceDir $pkgRoot -ArchivePath $archive -TarPath $TarPath
  return $archive
}

function New-FixtureToolPackage {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [Parameter(Mandatory = $true)]
    [string]$HostRoot,
    [Parameter(Mandatory = $true)]
    [string]$TarPath,
    [Parameter(Mandatory = $true)]
    [string]$PkgName,
    [Parameter(Mandatory = $true)]
    [string]$PkgVer,
    [Parameter(Mandatory = $true)]
    [string]$PkgDesc,
    [Parameter(Mandatory = $true)]
    [string]$Arch,
    [string[]]$AssemblyNames = @(),
    [string[]]$Provides = @(),
    [string[]]$Depends = @(),
    [string[]]$Conflicts = @()
  )

  $pkgRoot = Join-Path $Root $PkgName
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\bin') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\share\man\man1') | Out-Null

  foreach ($assemblyName in $AssemblyNames) {
    $publishDir = New-FixtureHostPublish -OutDir (Join-Path $HostRoot $assemblyName) -AssemblyName $assemblyName
    foreach ($suffix in 'exe', 'dll', 'deps.json', 'runtimeconfig.json', 'pdb') {
      Copy-Item -LiteralPath (Join-Path $publishDir "$assemblyName.$suffix") -Destination (Join-Path $pkgRoot "usr\bin\$assemblyName.$suffix") -Force
    }
  }

  $pkginfo = @(
    "pkgname = $PkgName",
    "pkgver = $PkgVer",
    "pkgdesc = $PkgDesc",
    "arch = $Arch"
  )
  foreach ($dep in $Depends) { $pkginfo += "depend = $dep" }
  foreach ($provide in $Provides) { $pkginfo += "provide = $provide" }
  foreach ($conflict in $Conflicts) { $pkginfo += "conflict = $conflict" }
  $pkginfo | Set-Content -LiteralPath (Join-Path $pkgRoot '.PKGINFO')
  $archive = Join-Path $Root "$PkgName.pkg.tar"
  New-ArchiveFromTree -SourceDir $pkgRoot -ArchivePath $archive -TarPath $TarPath
  return $archive
}

function New-FixtureLock {
  param(
    [Parameter(Mandatory = $true)]
    [string]$BaseLockPath,
    [Parameter(Mandatory = $true)]
    [string]$GitArchive,
    [Parameter(Mandatory = $true)]
    [string]$BashArchive,
    [Parameter(Mandatory = $true)]
    [hashtable]$ToolArchives,
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl
  )

  $lock = Get-Content -LiteralPath $BaseLockPath -Raw | ConvertFrom-Json
  $gitBytes = [System.IO.File]::ReadAllBytes($GitArchive).Length
  $bashBytes = [System.IO.File]::ReadAllBytes($BashArchive).Length
  $gitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $GitArchive).Hash.ToLowerInvariant()
  $bashHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BashArchive).Hash.ToLowerInvariant()

  $lock.schema_version = 1
  $lock.admission = [pscustomobject]@{
    kind = 'fixture'
    state = 'admitted'
    issued_by = 'fixture-harness'
    issued_at = '2026-08-27T00:00:00Z'
    base_ref = 'crutkas-native-arm64-readline'
    head_ref = 'a98dd4ff'
    base_seed_sha256 = $lock.base_seed.sha256
    canonical_lock_sha256 = ('0' * 64)
    protected_context = 'private-host-contract'
  }
  $lock.bootstrap = [pscustomobject]@{
    curl = [pscustomobject]@{
      url = "https://example.invalid/bootstrap/curl.exe"
      name = (Split-Path -Leaf (Get-Command curl.exe).Source)
      bytes = (Get-Item (Get-Command curl.exe).Source).Length
      sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Get-Command curl.exe).Source).Hash.ToLowerInvariant()
    }
    tar = [pscustomobject]@{
      url = "https://example.invalid/bootstrap/tar.exe"
      name = (Split-Path -Leaf (Get-Command tar.exe).Source)
      bytes = (Get-Item (Get-Command tar.exe).Source).Length
      sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Get-Command tar.exe).Source).Hash.ToLowerInvariant()
    }
  }
  $lock.ci = [pscustomobject]@{
    base_repository = 'https://github.com/crutkas/MSYS2-packages.git'
    base_ref = 'crutkas-native-arm64-readline'
    base_rev = 'fixture'
    run_check = '1'
    canonicalize_packages = '1'
    package_prefixes = 'mingw-w64-cross-cygwinarm64- mingw-w64-cross-msysarm64-'
    carch = 'aarch64'
    chost = 'aarch64-pc-cygwin'
    msystem_carch = 'aarch64'
    msystem_chost = 'aarch64-pc-cygwin'
    source_date_epoch = '1786817435'
  }
  $lock.repositories = @(
    [pscustomobject]@{
      name = 'ci'
      server = "$BaseUrl/repo/"
      siglevel = 'Never'
    }
  )

  $lock.assets.host.git.package = [pscustomobject]@{
    url = "$BaseUrl/git.pkg.tar"
    name = 'git.pkg.tar'
    version = '2.50.1-1'
    bytes = $gitBytes
    sha256 = $gitHash
  }
  $lock.assets.host.git.metadata = [pscustomobject]@{
    pkgname = 'git'
    pkgver = '2.50.1-1'
    pkgdesc = 'The fast distributed version control system'
    arch = @('x86_64')
    depends = @('curl', 'libpcre2_8', 'libexpat', 'libintl', 'nano', 'openssh', 'openssl', 'perl-Error', 'perl>=5.14.0', 'perl-Authen-SASL', 'perl-libwww', 'perl-MIME-tools', 'perl-Net-SMTP-SSL', 'perl-TermReadKey')
    provides = @('git-core')
    conflicts = @('git-core')
  }
  $lock.assets.host.bash.package = [pscustomobject]@{
    url = "$BaseUrl/bash.pkg.tar"
    name = 'bash.pkg.tar'
    version = '5.2.037-3'
    bytes = $bashBytes
    sha256 = $bashHash
  }
  $lock.assets.host.bash.metadata = [pscustomobject]@{
    pkgname = 'bash'
    pkgver = '5.2.037-3'
    pkgdesc = 'The GNU Bourne Again shell'
    arch = @('aarch64')
    depends = @()
    provides = @('sh')
    conflicts = @()
  }

  $lock.assets.tools = [pscustomobject]@{}
  foreach ($entry in $ToolArchives.GetEnumerator()) {
    $name = $entry.Key
    $archive = $entry.Value
    $lock.assets.tools | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{
      package = [pscustomobject]@{
        url = "$BaseUrl/$name.pkg.tar"
        name = "$name.pkg.tar"
        version = '1.0.0-1'
        bytes = [System.IO.File]::ReadAllBytes($archive).Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
      }
      metadata = [pscustomobject]@{
        pkgname = $name
        pkgver = '1.0.0-1'
        pkgdesc = "Fixture package for $name"
        arch = @('x86_64')
        depends = @()
        provides = @()
        conflicts = @()
      }
    })
  }

  $fixtureLock = Join-Path ([System.IO.Path]::GetDirectoryName($BaseLockPath)) 'private-host-lock.fixture.json'
  $lock | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fixtureLock
  return $fixtureLock
}

$root = Join-Path $env:TEMP 'private-host-fixture'
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null

$curlPath = (Get-Command curl.exe -ErrorAction Stop).Source
$tarPath = (Get-Command tar.exe -ErrorAction Stop).Source
$hostRoot = Join-Path $root 'hosts'
New-Item -ItemType Directory -Force -Path $hostRoot | Out-Null

$toolArchives = [ordered]@{}
$toolArchives.curl = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'curl' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for curl' -Arch 'x86_64' -AssemblyNames @('curl')
$toolArchives.pacman = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'pacman' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for pacman' -Arch 'x86_64' -AssemblyNames @('pacman')
$toolArchives.cygpath = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'cygpath' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for cygpath' -Arch 'x86_64' -AssemblyNames @('cygpath')
$toolArchives.tar = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'tar' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for tar' -Arch 'x86_64' -AssemblyNames @('tar')
$toolArchives.objdump = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'objdump' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for objdump' -Arch 'x86_64' -AssemblyNames @('objdump')
$toolArchives.nm = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'nm' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for nm' -Arch 'x86_64' -AssemblyNames @('nm')
$toolArchives.makepkg = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'makepkg' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for makepkg' -Arch 'x86_64' -AssemblyNames @('makepkg')
$toolArchives.'base-devel' = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'base-devel' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for base-devel' -Arch 'x86_64'
$toolArchives.readline = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'readline' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for readline' -Arch 'x86_64'
$toolArchives.ncurses = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'ncurses' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for ncurses' -Arch 'x86_64'
$toolArchives.'libiconv' = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'libiconv' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for libiconv' -Arch 'x86_64'
$toolArchives.'libintl' = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'libintl' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for libintl' -Arch 'x86_64'
$toolArchives.zlib = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'zlib' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for zlib' -Arch 'x86_64'
$toolArchives.zstd = New-FixtureToolPackage -Root $root -HostRoot $hostRoot -TarPath $tarPath -PkgName 'zstd' -PkgVer '1.0.0-1' -PkgDesc 'Fixture package for zstd' -Arch 'x86_64'

$bashTar = New-FixturePackageTree -Root $root -Role bash -HostRoot $hostRoot -TarPath $tarPath
$gitTar = New-FixturePackageTree -Root $root -Role git -HostRoot $hostRoot -TarPath $tarPath

$mapFile = Join-Path $root 'server-map.json'
$serverMap = [ordered]@{
  'bash.pkg.tar' = $bashTar
  'git.pkg.tar' = $gitTar
}
foreach ($entry in $toolArchives.GetEnumerator()) {
  $serverMap["$($entry.Key).pkg.tar"] = $entry.Value
}
$serverMap | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $mapFile

$port = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$port.Start()
$listenPort = ([System.Net.IPEndPoint]$port.LocalEndpoint).Port
$port.Stop()
$server = Start-FixtureServer -MapFile $mapFile -Port $listenPort
Start-Sleep -Milliseconds 500

$fixtureLock = New-FixtureLock -BaseLockPath $LockPath -GitArchive $gitTar -BashArchive $bashTar -ToolArchives $toolArchives -BaseUrl "http://127.0.0.1:$listenPort"
$privateRoot = Join-Path $root 'private-root'

$baseLock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
if ($baseLock.schema_version -ne 1) { throw 'fixture base lock schema version mismatch' }
foreach ($field in 'kind', 'state', 'issued_by', 'issued_at', 'base_ref', 'head_ref', 'base_seed_sha256', 'canonical_lock_sha256', 'protected_context') {
  if ($null -ne $baseLock.admission.$field) {
    throw "expected fail-closed null admission field: $field"
  }
}
foreach ($field in 'curl', 'tar') {
  foreach ($subfield in 'url', 'name', 'bytes', 'sha256') {
    if ($null -ne $baseLock.bootstrap.$field.$subfield) {
      throw "expected fail-closed null bootstrap field: $field.$subfield"
    }
  }
}
foreach ($field in 'base_repository', 'base_ref', 'base_rev', 'run_check', 'canonicalize_packages', 'package_prefixes', 'carch', 'chost', 'msystem_carch', 'msystem_chost', 'source_date_epoch') {
  if ($null -ne $baseLock.ci.$field) {
    throw "expected fail-closed null ci field: $field"
  }
}
if (($baseLock.repositories | Measure-Object).Count -ne 0) {
  throw 'expected fail-closed empty repository list'
}
if (($baseLock.assets.tools.PSObject.Properties | Measure-Object).Count -ne 0) {
  throw 'expected fail-closed empty tool closure'
}
foreach ($tool in 'git', 'bash') {
  foreach ($field in 'url', 'name', 'version', 'bytes', 'sha256') {
    if ($null -ne $baseLock.assets.host.$tool.package.$field) {
      throw "expected fail-closed null $tool package field: $field"
    }
  }
}

$tempParent = Join-Path $root 'trusted-parent'
New-Item -ItemType Directory -Force -Path $tempParent | Out-Null
$jTarget = Join-Path $root 'junction-target'
New-Item -ItemType Directory -Force -Path $jTarget | Out-Null
$jRoot = Join-Path $tempParent 'junction-root'
try {
  New-Item -ItemType Junction -Path $jRoot -Target $jTarget | Out-Null
  Assert-Fails -Name 'junction root rejected' -Script {
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $jRoot -TrustedParent $tempParent -BashCommand 'echo should-not-run' -AllowFixturePackages -CurlPath $curlPath -TarPath $tarPath
  }
} finally {
  Remove-Item -LiteralPath $jRoot -Force -Recurse -ErrorAction SilentlyContinue
}

Assert-Fails -Name 'quoted device path rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot '\\?\C:\msys64' -TrustedParent $tempParent -BashCommand 'echo should-not-run' -AllowFixturePackages -CurlPath $curlPath -TarPath $tarPath
}

Assert-Fails -Name 'UNC path rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot '\\localhost\c$\msys64' -TrustedParent $tempParent -BashCommand 'echo should-not-run' -AllowFixturePackages -CurlPath $curlPath -TarPath $tarPath
}

$env:BASH_ENV = 'C:\msys64\etc\bash.bashrc'
Assert-Fails -Name 'ambient bash env rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $privateRoot -TrustedParent $root -BashCommand "printf 'hello world'" -AllowFixturePackages -CurlPath $curlPath -TarPath $tarPath
}
Remove-Item Env:\BASH_ENV -ErrorAction SilentlyContinue

$null = & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $privateRoot -TrustedParent $root -BashCommand "printf 'hello world'" -AllowFixturePackages -CurlPath $curlPath -TarPath $tarPath
if ($LASTEXITCODE -ne 37) {
  Stop-Job $server | Out-Null
  throw "expected launch exit 37, got $LASTEXITCODE"
}

$marker = Get-Content -LiteralPath (Join-Path $privateRoot 'usr\bin\bash.exe.env.txt') -Raw | ConvertFrom-Json
if ($marker.PATH -match 'C:\\msys64') { throw 'shared root leaked into private child environment' }
if ($marker.GIT_EXEC_PATH -match 'C:\\msys64') { throw 'shared git exec path leaked into private child environment' }
if ($marker.EXE -notmatch [regex]::Escape($privateRoot)) { throw 'private root not present in child environment' }
if ($marker.BASH_ENV) { throw 'ambient BASH_ENV leaked into private child environment' }
if ($marker.ENV) { throw 'ambient ENV leaked into private child environment' }
if ((@($marker.ARGS) -join "`n") -ne (@('--noprofile', '--norc', '-lc', "printf 'hello world'") -join "`n")) {
  throw 'default bash -lc argv was not preserved'
}

Stop-Job $server | Out-Null
Remove-Job $server | Out-Null
Write-Host 'Fixture-based private-host launch test passed.'

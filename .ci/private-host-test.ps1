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
  return $true
}

function New-FixtureHostPublish {
  param(
    [Parameter(Mandatory = $true)]
    [string]$OutDir,
    [Parameter(Mandatory = $true)]
    [string]$AssemblyName
  )
  $projectDir = Join-Path $OutDir 'fixture-host'
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
using System.Text.Json;

var exe = Process.GetCurrentProcess().MainModule!.FileName!;
var marker = exe + ".env.txt";
var payload = new
{
    EXE = exe,
    PATH = Environment.GetEnvironmentVariable("PATH"),
    GIT_EXEC_PATH = Environment.GetEnvironmentVariable("GIT_EXEC_PATH"),
    MSYSTEM = Environment.GetEnvironmentVariable("MSYSTEM"),
    MSYS2_PATH_TYPE = Environment.GetEnvironmentVariable("MSYS2_PATH_TYPE"),
    HOME = Environment.GetEnvironmentVariable("HOME"),
    TEMP = Environment.GetEnvironmentVariable("TEMP")
};
File.WriteAllText(marker, JsonSerializer.Serialize(payload));
return 37;
'@ | Set-Content -LiteralPath (Join-Path $projectDir 'Program.cs')
  $publishDir = Join-Path $projectDir 'publish'
& dotnet.exe publish (Join-Path $projectDir 'fixture.csproj') -c Release -o $publishDir -p:AssemblyName=$AssemblyName --nologo | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw 'failed to publish fixture console host'
  }
  return $publishDir
}

function Copy-PublishedConsoleHost {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,
    [Parameter(Mandatory = $true)]
    [string]$DestinationDir,
    [Parameter(Mandatory = $true)]
    [string]$AssemblyName,
    [string[]]$ExtraExeNames = @()
  )

  foreach ($suffix in 'exe', 'dll', 'deps.json', 'runtimeconfig.json', 'pdb') {
    $source = Join-Path $SourceDir "$AssemblyName.$suffix"
    if (-not (Test-Path -LiteralPath $source)) {
      throw "missing published fixture file: $source"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $DestinationDir "$AssemblyName.$suffix") -Force
  }

  foreach ($extra in $ExtraExeNames) {
    Copy-Item -LiteralPath (Join-Path $DestinationDir "$AssemblyName.exe") -Destination (Join-Path $DestinationDir $extra) -Force
  }
}

function New-ArchiveFromTree {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath
  )

  & tar.exe -cf $ArchivePath -C $SourceDir . | Out-Null
}

function Read-PkgInfo {
  param([Parameter(Mandatory = $true)][string]$Path)
  $map = [ordered]@{}
  foreach ($line in Get-Content -LiteralPath $Path) {
    if ($line -match '^\s*([^=]+?)\s*=\s*(.*)\s*$') {
      $key = $Matches[1].Trim()
      $value = $Matches[2]
      if (-not $map.Contains($key)) { $map[$key] = @() }
      $map[$key] += $value
    }
  }
  $map
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

function New-TempPort {
  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
  $listener.Stop()
  $port
}

function New-FixturePackageTree {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [Parameter(Mandatory = $true)]
    [string]$Role,
    [Parameter(Mandatory = $true)]
    [string]$PublishedDir
  )

  $pkgRoot = Join-Path $Root $Role
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\bin') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\lib\git-core') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $pkgRoot 'usr\share\man\man1') | Out-Null

  if ($Role -eq 'bash') {
    Copy-PublishedConsoleHost -SourceDir $PublishedDir -DestinationDir (Join-Path $pkgRoot 'usr\bin') -AssemblyName 'bash' -ExtraExeNames @('sh.exe', 'pacman.exe', 'cygpath.exe', 'objdump.exe', 'nm.exe')
  } else {
    Copy-PublishedConsoleHost -SourceDir $PublishedDir -DestinationDir (Join-Path $pkgRoot 'usr\bin') -AssemblyName 'git'
  }

  if ($Role -eq 'git') {
    Set-Content -LiteralPath (Join-Path $pkgRoot 'usr\lib\git-core\git-core-marker.txt') -Value 'git-core' -NoNewline
  } else {
    Set-Content -LiteralPath (Join-Path $pkgRoot 'usr\share\man\man1\bash.1') -Value '.so man1/bash.1' -NoNewline
  }

  $pkginfo = @(
    "%NAME%",
    "%VERSION%",
    "%DESC%",
    "%ARCH%",
    "%DEPENDS%",
    "%PROVIDES%",
    "%CONFLICTS%"
  )
  if ($Role -eq 'git') {
    $pkginfo = @(
      'pkgname = git',
      'pkgver = 2.50.1-1',
      'pkgrel = 1',
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
    $pkginfo = @(
      'pkgname = bash',
      'pkgver = 5.2.037-3',
      'pkgrel = 3',
      'pkgdesc = The GNU Bourne Again shell',
      'arch = aarch64',
      'provide = sh'
    )
  }
  $pkginfo | Set-Content -LiteralPath (Join-Path $pkgRoot '.PKGINFO')
  $archive = Join-Path $Root "$Role.pkg.tar"
  New-ArchiveFromTree -SourceDir $pkgRoot -ArchivePath $archive
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
    [string]$BaseUrl
  )

  $lock = Get-Content -LiteralPath $BaseLockPath -Raw | ConvertFrom-Json
  $gitBytes = [System.IO.File]::ReadAllBytes($GitArchive).Length
  $bashBytes = [System.IO.File]::ReadAllBytes($BashArchive).Length
  $gitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $GitArchive).Hash.ToLowerInvariant()
  $bashHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BashArchive).Hash.ToLowerInvariant()

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
    pkgrel = '1'
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
    pkgrel = '3'
    pkgdesc = 'The GNU Bourne Again shell'
    arch = @('aarch64')
    depends = @()
    provides = @('sh')
    conflicts = @()
  }
  $fixtureLock = Join-Path ([System.IO.Path]::GetDirectoryName($BaseLockPath)) 'private-host-lock.fixture.json'
  $lock | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fixtureLock
  return $fixtureLock
}

$root = Join-Path $env:TEMP 'private-host-fixture'
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null

$bashPublish = New-FixtureHostPublish -OutDir (Join-Path $root 'bash-host') -AssemblyName 'bash'
$gitPublish = New-FixtureHostPublish -OutDir (Join-Path $root 'git-host') -AssemblyName 'git'

$bashTar = New-FixturePackageTree -Root $root -Role bash -PublishedDir $bashPublish
$gitTar = New-FixturePackageTree -Root $root -Role git -PublishedDir $gitPublish

$mapFile = Join-Path $root 'server-map.json'
@{
  'bash.pkg.tar' = $bashTar
  'git.pkg.tar' = $gitTar
} | ConvertTo-Json | Set-Content -LiteralPath $mapFile

$port = New-TempPort
$server = Start-FixtureServer -MapFile $mapFile -Port $port
Start-Sleep -Milliseconds 500

$fixtureLock = New-FixtureLock -BaseLockPath $LockPath -GitArchive $gitTar -BashArchive $bashTar -BaseUrl "http://127.0.0.1:$port"
$privateRoot = Join-Path $root 'private-root'

$baseLock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
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
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $jRoot -TrustedParent $tempParent -BashCommand 'echo should-not-run'
  }
} finally {
  Remove-Item -LiteralPath $jRoot -Force -Recurse -ErrorAction SilentlyContinue
}

Assert-Fails -Name 'quoted device path rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot '\\?\C:\msys64' -TrustedParent $tempParent -BashCommand 'echo should-not-run'
}

Assert-Fails -Name 'UNC path rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot '\\localhost\c$\msys64' -TrustedParent $tempParent -BashCommand 'echo should-not-run'
}

$bashScript = Join-Path $root 'bash-fixture.ps1'
@'
$exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$marker = "$exe.env.txt"
$content = [ordered]@{
  EXE = $exe
  PATH = $env:PATH
  GIT_EXEC_PATH = $env:GIT_EXEC_PATH
  MSYSTEM = $env:MSYSTEM
  MSYS2_PATH_TYPE = $env:MSYS2_PATH_TYPE
  HOME = $env:HOME
  TEMP = $env:TEMP
}
$content | ConvertTo-Json -Depth 2 | Set-Content -LiteralPath $marker
exit 37
'@ | Set-Content -LiteralPath $bashScript
$result = & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $privateRoot -TrustedParent $root -BashArguments @('-NoProfile', '-File', $bashScript)
if ($LASTEXITCODE -ne 37) {
  Stop-Job $server | Out-Null
  throw "expected launch exit 37, got $LASTEXITCODE"
}

$marker = Get-Content -LiteralPath (Join-Path $privateRoot 'usr\bin\bash.exe.env.txt') -Raw | ConvertFrom-Json
if ($marker.PATH -match 'C:\\msys64') { throw 'shared root leaked into private child environment' }
if ($marker.GIT_EXEC_PATH -match 'C:\\msys64') { throw 'shared git exec path leaked into private child environment' }
if ($marker.EXE -notmatch [regex]::Escape($privateRoot)) { throw 'private root not present in child environment' }

Stop-Job $server | Out-Null
Remove-Job $server | Out-Null
Write-Host 'Fixture-based private-host launch test passed.'

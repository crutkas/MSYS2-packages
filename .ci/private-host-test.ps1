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

  $lock.schema_version = 1
  $lock.admission = [pscustomobject]@{
    kind = 'fixture'
    state = 'admitted'
    issued_by = 'fixture-harness'
    issued_at = '2026-08-27T00:00:00Z'
  }

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

  $fixtureLock = Join-Path ([System.IO.Path]::GetDirectoryName($BaseLockPath)) 'private-host-lock.fixture.json'
  $lock | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fixtureLock
  return $fixtureLock
}

$root = Join-Path $env:TEMP 'private-host-fixture'
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null

$tarPath = (Get-Command tar.exe -ErrorAction Stop).Source
$hostRoot = Join-Path $root 'hosts'
New-Item -ItemType Directory -Force -Path $hostRoot | Out-Null

$bashTar = New-FixturePackageTree -Root $root -Role bash -HostRoot $hostRoot -TarPath $tarPath
$gitTar = New-FixturePackageTree -Root $root -Role git -HostRoot $hostRoot -TarPath $tarPath

$mapFile = Join-Path $root 'server-map.json'
@{
  'bash.pkg.tar' = $bashTar
  'git.pkg.tar' = $gitTar
} | ConvertTo-Json | Set-Content -LiteralPath $mapFile

$port = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$port.Start()
$listenPort = ([System.Net.IPEndPoint]$port.LocalEndpoint).Port
$port.Stop()
$server = Start-FixtureServer -MapFile $mapFile -Port $listenPort
Start-Sleep -Milliseconds 500

$fixtureLock = New-FixtureLock -BaseLockPath $LockPath -GitArchive $gitTar -BashArchive $bashTar -BaseUrl "http://127.0.0.1:$listenPort"
$privateRoot = Join-Path $root 'private-root'

$baseLock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
if ($baseLock.schema_version -ne 1) { throw 'fixture base lock schema version mismatch' }
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
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $jRoot -TrustedParent $tempParent -BashCommand 'echo should-not-run' -AllowFixturePackages -TarPath $tarPath
  }
} finally {
  Remove-Item -LiteralPath $jRoot -Force -Recurse -ErrorAction SilentlyContinue
}

Assert-Fails -Name 'quoted device path rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot '\\?\C:\msys64' -TrustedParent $tempParent -BashCommand 'echo should-not-run' -AllowFixturePackages -TarPath $tarPath
}

Assert-Fails -Name 'UNC path rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot '\\localhost\c$\msys64' -TrustedParent $tempParent -BashCommand 'echo should-not-run' -AllowFixturePackages -TarPath $tarPath
}

$env:BASH_ENV = 'C:\msys64\etc\bash.bashrc'
Assert-Fails -Name 'ambient bash env rejected' -Script {
  & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $privateRoot -TrustedParent $root -BashCommand "printf 'hello world'" -AllowFixturePackages -TarPath $tarPath
}
Remove-Item Env:\BASH_ENV -ErrorAction SilentlyContinue

$null = & pwsh -NoProfile -ExecutionPolicy Bypass -File $LauncherPath -Mode Launch -LockPath $fixtureLock -PrivateRoot $privateRoot -TrustedParent $root -BashCommand "printf 'hello world'" -AllowFixturePackages -TarPath $tarPath
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

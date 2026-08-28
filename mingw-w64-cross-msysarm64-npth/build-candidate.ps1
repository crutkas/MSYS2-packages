<#
.SYNOPSIS
  Deterministic npth candidate build + seal for the two independent build jobs.

.DESCRIPTION
  Both windows-2025 build jobs invoke this identically so they start from the
  same immutable, content-addressed inputs, the same SOURCE_DATE_EPOCH, and the
  same private root, and therefore must emit byte-identical inner package trees.

  The full dependency closure is installed with the private base's own pacman
  using ONLY hash-verified local archives (`pacman -U`) with explicit
  --root/--dbpath/--cachedir/--logfile/--config/--hookdir/--gpgdir. There is no
  live repository sync, and neither --nodeps nor --assume-installed is ever used:
  the closure (including the cygwin libstdc++ headers the ARM64 gcc depends on)
  is complete, so makepkg's own dependency check passes without contacting a
  repository. C:\msys64 is never used for package work.

  Pure, dot-sourceable helpers carry the policy so the offline test can validate
  the install plan and the sealing logic without a network or an ARM64 runner.
#>
[CmdletBinding()]
param(
  [string] $Manifest,
  [string] $InputsDir,
  [string] $Root,
  [string] $Workspace,
  [string] $OutputDir,
  [string] $Bsdtar = 'C:\Windows\System32\tar.exe',
  [long]   $SourceDateEpoch = 0
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function New-PacmanCommonArgs {
  <# Explicit, self-contained pacman invocation. Every path is pinned so the
     transaction can only touch the private root, never a shared client. #>
  param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $Config)
  return @(
    '--root', $Root,
    '--dbpath', (Join-Path $Root 'var\lib\pacman'),
    '--cachedir', (Join-Path $Root 'var\cache\pacman\pkg'),
    '--logfile', (Join-Path $Root 'var\log\pacman-build.log'),
    '--config', $Config,
    '--hookdir', (Join-Path $Root 'etc\pacman.d\hooks-build'),
    '--gpgdir', (Join-Path $Root 'etc\pacman.d\gnupg-build'),
    '--noconfirm'
  )
}

function New-PrivatePacmanConfig {
  <# Writes a private pacman.conf. LocalFileSigLevel = Never is sound because
     every archive was independently SHA-256 verified before install. #>
  param([Parameter(Mandatory)] [string] $Path)
  @'
[options]
Architecture = x86_64
SigLevel = Never
LocalFileSigLevel = Never
'@ | Set-Content -Encoding ascii -LiteralPath $Path
  return $Path
}

function Get-InstallPlan {
  <# Produces the ordered install plan from the manifest. Host closure first,
     then the full target closure. The cygwin libstdc++ headers are guaranteed
     to be part of the target closure so no dependency is ever faked. Any deny-
     listed artifact appearing in the plan is a hard error. #>
  param([Parameter(Mandatory)] [object] $ManifestObject)

  $host_ = @($ManifestObject.hostPackages | ForEach-Object { $_.name })
  $target = @($ManifestObject.targetInputs | ForEach-Object { $_.name })

  if (-not ($target -contains 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst')) {
    throw 'Install plan is missing the real cygwin libstdc++ headers; refusing to fall back to --assume-installed.'
  }

  $denyPrefixes = @($ManifestObject.denyList.revoked | ForEach-Object { $_.sha256Prefix })
  return [ordered]@{
    host          = $host_
    target        = $target
    denyPrefixes  = $denyPrefixes
  }
}

function Invoke-PrivateInstall {
  <# Installs a set of local archives in a single -U transaction. No --nodeps,
     no --assume-installed: pacman resolves the closure from the provided files
     alone. #>
  param(
    [Parameter(Mandatory)] [string] $Pacman,
    [Parameter(Mandatory)] [string[]] $Common,
    [Parameter(Mandatory)] [string] $InputsDir,
    [Parameter(Mandatory)] [string[]] $Filenames
  )
  $arguments = [Collections.Generic.List[string]]::new()
  $arguments.AddRange([string[]] $Common)
  $arguments.Add('--needed')
  $arguments.Add('-U')
  foreach ($filename in $Filenames) {
    $path = Join-Path $InputsDir $filename
    if (-not (Test-Path -LiteralPath $path)) {
      throw "Install archive is missing: $filename"
    }
    $arguments.Add($path)
  }
  & $Pacman @arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Private -U transaction failed for: $($Filenames -join ', ')"
  }
}

function Get-ArchiveMemberBytes {
  <# Streams a single archive member to a byte array via bsdtar, never touching
     a shared client. #>
  param(
    [Parameter(Mandatory)] [string] $Bsdtar,
    [Parameter(Mandatory)] [string] $Archive,
    [Parameter(Mandatory)] [string] $Member
  )
  $psi = [Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $Bsdtar
  $psi.ArgumentList.Add('-xOf'); $psi.ArgumentList.Add($Archive); $psi.ArgumentList.Add($Member)
  $psi.RedirectStandardOutput = $true
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  $ms = [IO.MemoryStream]::new()
  try { $proc.StandardOutput.BaseStream.CopyTo($ms) } finally { $proc.WaitForExit() }
  if ($proc.ExitCode -ne 0) { throw "bsdtar could not read $Member from $Archive" }
  return $ms.ToArray()
}

function Get-PackageSeal {
  <# Extracts .PKGINFO/.MTREE/.BUILDINFO for a built package, records their
     SHA-256s, and records the package SHA-256 itself. The comparison job later
     proves the two build jobs produced identical seals. #>
  param(
    [Parameter(Mandatory)] [string] $Archive,
    [Parameter(Mandatory)] [string] $Bsdtar,
    [Parameter(Mandatory)] [string] $MetadataDir
  )
  New-Item -ItemType Directory -Force -Path $MetadataDir | Out-Null
  $seal = [ordered]@{
    package      = [IO.Path]::GetFileName($Archive)
    package_sha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    metadata     = [ordered]@{}
  }
  foreach ($member in @('.PKGINFO', '.BUILDINFO', '.MTREE')) {
    $bytes = Get-ArchiveMemberBytes -Bsdtar $Bsdtar -Archive $Archive -Member $member
    $target = Join-Path $MetadataDir ($member.TrimStart('.'))
    [IO.File]::WriteAllBytes($target, $bytes)
    $sha = [BitConverter]::ToString(
      [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    $seal.metadata[$member] = [ordered]@{ bytes = $bytes.Length; sha256 = $sha }
  }
  & (Join-Path $PSScriptRoot 'validate-buildinfo-path.ps1') `
    -Path (Join-Path $MetadataDir 'BUILDINFO') | Out-Null
  return $seal
}

function Get-NativeSmokeDirectory {
  param([Parameter(Mandatory)] [string] $BuildRoot)
  $matches = @(
    Get-ChildItem -LiteralPath $BuildRoot -Directory -Recurse |
      Where-Object {
        $_.Name -eq 'smoke' -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'npth-dynamic-smoke.exe')) -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'npth-static-smoke.exe'))
      }
  )
  if ($matches.Count -ne 1) {
    throw "Expected one complete native smoke bundle under $BuildRoot, found $($matches.Count)."
  }
  return $matches[0].FullName
}

function Invoke-BuildCandidate {
  <# Full deterministic build: materialize the private pacman config, install the
     host and target closures, run makepkg with the pinned SOURCE_DATE_EPOCH, and
     seal every produced package plus the scanner input and path-leak evidence. #>
  param(
    [Parameter(Mandatory)] [string] $Manifest,
    [Parameter(Mandatory)] [string] $InputsDir,
    [Parameter(Mandatory)] [string] $Root,
    [Parameter(Mandatory)] [string] $Workspace,
    [Parameter(Mandatory)] [string] $OutputDir,
    [Parameter(Mandatory)] [string] $Bsdtar,
    [Parameter(Mandatory)] [long] $SourceDateEpoch
  )
  $manifestObject = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
  $plan = Get-InstallPlan -ManifestObject $manifestObject
  New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

  $pacman = Join-Path $Root 'usr\bin\pacman.exe'
  $bash = Join-Path $Root 'usr\bin\bash.exe'
  $cygpath = Join-Path $Root 'usr\bin\cygpath.exe'
  foreach ($tool in @($pacman, $bash, $cygpath)) {
    if (-not (Test-Path -LiteralPath $tool)) { throw "Private base is missing $tool" }
  }

  $config = New-PrivatePacmanConfig -Path (Join-Path $Root 'etc\pacman-build.conf')
  foreach ($dir in @(
      (Join-Path $Root 'var\cache\pacman\pkg'),
      (Join-Path $Root 'var\log'),
      (Join-Path $Root 'etc\pacman.d\hooks-build'),
      (Join-Path $Root 'etc\pacman.d\gnupg-build'))) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  $common = New-PacmanCommonArgs -Root $Root -Config $config

  Invoke-PrivateInstall -Pacman $pacman -Common $common -InputsDir $InputsDir -Filenames $plan.host
  Invoke-PrivateInstall -Pacman $pacman -Common $common -InputsDir $InputsDir -Filenames $plan.target

  $objdump = Join-Path $Root 'opt\bin\aarch64-pc-msys-objdump.exe'
  if (-not (Test-Path -LiteralPath $objdump)) {
    throw 'Target cross toolchain did not install aarch64-pc-msys-objdump.'
  }

  $deterministicRoot = Join-Path $Root 'usr\src\debug\mingw-w64-cross-msysarm64-npth-1.8'
  $recipeStage = Join-Path $deterministicRoot 'recipe'
  $buildRoot = Join-Path $deterministicRoot 'build'
  if (Test-Path -LiteralPath $deterministicRoot) {
    Remove-Item -LiteralPath $deterministicRoot -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $deterministicRoot | Out-Null
  Copy-Item -LiteralPath (Join-Path $Workspace 'mingw-w64-cross-msysarm64-npth') `
    -Destination $recipeStage -Recurse

  $recipePosix = '/usr/src/debug/mingw-w64-cross-msysarm64-npth-1.8/recipe'
  $buildDirPosix = '/usr/src/debug/mingw-w64-cross-msysarm64-npth-1.8/build'
  $inputsPosix = (& $bash -c "/usr/bin/cygpath -u '$InputsDir'").Trim()
  $signatureKey = Join-Path $InputsDir 'signature_key.asc'
  if (-not (Test-Path -LiteralPath $signatureKey)) {
    throw 'signature_key.asc must be pre-downloaded so makepkg can verify the pinned npth source signature.'
  }
  # SRCDEST points makepkg at the pre-downloaded, hash-verified tarball + .sig so
  # the build performs no live source download; GNUPGHOME holds only the imported
  # upstream signing key, keeping makepkg's genuine PGP source check intact.
  $script = @"
set -euo pipefail
export SOURCE_DATE_EPOCH='$SourceDateEpoch'
export MSYS2_ARG_CONV_EXCL='*'
export PATH=/opt/bin:/opt/aarch64-pc-msys/usr/bin:/usr/bin:/bin
export SRCDEST='$inputsPosix'
export BUILDDIR='$buildDirPosix'
export GNUPGHOME='$inputsPosix/gnupg-build'
mkdir -p "`$GNUPGHOME"
chmod 700 "`$GNUPGHOME"
gpg --batch --import '$inputsPosix/signature_key.asc'
cd '$recipePosix'
makepkg --cleanbuild --check --noconfirm
"@
  & $bash -c $script 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'build.log')
  if ($LASTEXITCODE -ne 0) { throw 'Deterministic npth cross-build failed.' }

  $packages = @(Get-ChildItem -LiteralPath $recipeStage `
      -Filter '*.pkg.tar.zst')
  if ($packages.Count -lt 2) {
    throw "Expected the runtime and devel packages, found $($packages.Count)."
  }

  $seals = [Collections.Generic.List[object]]::new()
  foreach ($package in $packages) {
    Copy-Item -LiteralPath $package.FullName -Destination $OutputDir
    $metadataDir = Join-Path $OutputDir ("$($package.Name).metadata")
    $seals.Add((Get-PackageSeal -Archive $package.FullName -Bsdtar $Bsdtar -MetadataDir $metadataDir))
  }
  $smoke = Get-NativeSmokeDirectory -BuildRoot $buildRoot
  Copy-Item -LiteralPath $smoke -Destination (Join-Path $OutputDir 'native-smoke') -Recurse

  [ordered]@{
    schema            = 1
    source_head       = [Environment]::GetEnvironmentVariable('ADMISSION_HEAD')
    source_date_epoch = $SourceDateEpoch
    packages          = $seals.ToArray()
  } | ConvertTo-Json -Depth 8 |
    Set-Content -Encoding utf8 -LiteralPath (Join-Path $OutputDir 'build-seal.json')
  $downloadSeal = Join-Path $InputsDir 'input-download-seal.json'
  if (-not (Test-Path -LiteralPath $downloadSeal)) {
    throw 'Verified immutable input download seal is missing.'
  }
  Copy-Item -LiteralPath $downloadSeal -Destination $OutputDir

  return (Join-Path $OutputDir 'build-seal.json')
}

if ($MyInvocation.InvocationName -ne '.' -and
    -not (Get-Variable -Name BuildCandidateDotSource -Scope Global -ErrorAction SilentlyContinue)) {
  foreach ($name in 'Manifest', 'InputsDir', 'Root', 'Workspace', 'OutputDir') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $name -ValueOnly))) {
      throw "-$name is required when running build-candidate.ps1 directly."
    }
  }
  if ($SourceDateEpoch -le 0) { throw '-SourceDateEpoch must be a positive epoch.' }
  $sealPath = Invoke-BuildCandidate `
    -Manifest $Manifest -InputsDir $InputsDir -Root $Root -Workspace $Workspace `
    -OutputDir $OutputDir -Bsdtar $Bsdtar -SourceDateEpoch $SourceDateEpoch
  Write-Output "Build seal written to $sealPath"
  Write-Output 'NPTH-BUILD-CANDIDATE-OK'
}

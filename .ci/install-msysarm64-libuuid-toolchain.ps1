[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

$repository = $env:GITHUB_REPOSITORY
$branchCandidates = @($env:GITHUB_REF_NAME, $env:GITHUB_HEAD_REF) |
    Where-Object { $_ }
if ($repository -ne 'crutkas/MSYS2-packages') {
    throw "Refusing fork-only root materialization in $repository"
}
if ($branchCandidates -notcontains 'crutkas-arm64-msys-libuuid') {
    throw "Refusing libuuid root for refs: $($branchCandidates -join ', ')"
}
if ($env:RUNNER_ARCH -ne 'X64') {
    throw "The private build requires an X64 runner, not $env:RUNNER_ARCH"
}
if (Test-Path -LiteralPath $RootPath) {
    throw "Private root already exists: $RootPath"
}

$systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $systemTar -PathType Leaf)) {
    throw "Missing Windows archive tool: $systemTar"
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    [IO.File]::WriteAllLines(
        $Path,
        $Lines,
        [Text.UTF8Encoding]::new($false))
}

function Invoke-Download {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    & curl.exe --fail --location --retry 5 --retry-all-errors `
        --retry-delay 2 --silent --show-error `
        --output $Path $Uri
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed: $Uri"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) {
        throw "SHA-256 mismatch for $([IO.Path]::GetFileName($Path)): $actual"
    }
}

function Assert-SafeArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [string]$RequiredPrefix
    )

    $entries = @(& $script:systemTar -tf $Archive)
    if ($LASTEXITCODE -ne 0 -or $entries.Count -eq 0) {
        throw "Cannot list archive safely: $Archive"
    }
    foreach ($entry in $entries) {
        $normalized = $entry.Replace('\', '/')
        if (-not $normalized -or
            $normalized.StartsWith('/') -or
            $normalized -match '^[A-Za-z]:' -or
            $normalized.Split('/') -contains '..') {
            throw "Unsafe archive entry in $Archive`: $entry"
        }
        if ($RequiredPrefix -and
            $normalized -ne $RequiredPrefix.TrimEnd('/') -and
            -not $normalized.StartsWith($RequiredPrefix)) {
            throw "Archive entry escapes required prefix in $Archive`: $entry"
        }
    }
    foreach ($line in @(& $script:systemTar -tvf $Archive |
        Where-Object { $_ -match '^[lh]' })) {
        if ($line.StartsWith('h')) {
            if ($line -notmatch '\s(?<path>\S+)\s+link to\s+(?<target>\S+)$') {
                throw "Unparseable archive hardlink in $Archive`: $line"
            }
            $target = $Matches.target.Replace('\', '/')
            if ($target.StartsWith('/') -or
                $target -match '^[A-Za-z]:' -or
                $target.Split('/') -contains '..') {
                throw "Unsafe archive hardlink in $Archive`: $line"
            }
            if ($RequiredPrefix -and
                $target -ne $RequiredPrefix.TrimEnd('/') -and
                -not $target.StartsWith($RequiredPrefix)) {
                throw "Archive hardlink escapes required prefix: $line"
            }
            continue
        }
        if ($line -notmatch '\s(?<path>\S+)\s+->\s+(?<target>\S+)$') {
            throw "Unparseable archive symlink in $Archive`: $line"
        }
        $linkPath = $Matches.path.Replace('\', '/')
        $target = $Matches.target.Replace('\', '/')
        if ($target.StartsWith('/') -or $target -match '^[A-Za-z]:') {
            throw "Unsafe archive symlink in $Archive`: $line"
        }
        $linkParts = $linkPath.Split('/')
        $segments = [Collections.Generic.List[string]]::new()
        if ($linkParts.Count -gt 1) {
            foreach ($segment in $linkParts[0..($linkParts.Count - 2)]) {
                if ($segment) {
                    $segments.Add($segment)
                }
            }
        }
        foreach ($segment in $target.Split('/')) {
            if (-not $segment -or $segment -eq '.') {
                continue
            }
            if ($segment -eq '..') {
                if ($segments.Count -eq 0) {
                    throw "Archive symlink escapes root in $Archive`: $line"
                }
                $segments.RemoveAt($segments.Count - 1)
            }
            else {
                $segments.Add($segment)
            }
        }
        $resolvedArchivePath = $segments -join '/'
        if ($RequiredPrefix -and
            $resolvedArchivePath -ne $RequiredPrefix.TrimEnd('/') -and
            -not $resolvedArchivePath.StartsWith($RequiredPrefix)) {
            throw "Archive symlink escapes required prefix: $line"
        }
    }
}

function Invoke-PrivateBash {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    $bash = Join-Path $script:RootPath 'usr\bin\bash.exe'
    $oldMsystem = $env:MSYSTEM
    $oldChere = $env:CHERE_INVOKING
    $oldPathType = $env:MSYS2_PATH_TYPE
    try {
        $env:MSYSTEM = 'MSYS'
        $env:CHERE_INVOKING = '1'
        $env:MSYS2_PATH_TYPE = 'inherit'
        $output = @(& $bash --noprofile --norc -c $Script 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $env:MSYSTEM = $oldMsystem
        $env:CHERE_INVOKING = $oldChere
        $env:MSYS2_PATH_TYPE = $oldPathType
    }
    Write-Utf8NoBom -Path $LogPath -Lines @($output | ForEach-Object {
        $_.ToString()
    })
    if ($exitCode -ne 0) {
        throw "Private MSYS command failed with exit code $exitCode"
    }
    if ($output -match 'command failed to execute correctly') {
        throw 'Private package transaction reported a failed install script'
    }
    return $output
}

$baseAsset = [pscustomobject]@{
    Name = 'msys2-base-x86_64-20260611.tar.zst'
    Uri = 'https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260611.tar.zst'
    Size = 54503668
    Sha256 = 'ace898d250d7302a24259a0288d69354649365af9cc64c8bcc2f219bc1e28374'
}

$targetAssets = @(
    [pscustomobject]@{
        Name = 'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/cygwinarm64-binutils-pr21-3356eec-20260827/mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        Sha256 = '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/cygwinarm64-libstdcxx-headers-pr7-20260815/mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
        Sha256 = '1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/cygwinarm64-gcc-static-runtime-20260815/mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
        Sha256 = '17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/cygwinarm64-gcc-static-runtime-20260815/mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
        Sha256 = '063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = '263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = '33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = 'e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = 'c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-gcc-pr13-support-20260826/mingw-w64-cross-msysarm64-libstdc%2B%2B-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
        Sha256 = '9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-gcc-pr13-support-20260826/mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
        Sha256 = '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-gcc-pr13-20260826/mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-gcc-pr13-20260826/mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
        Sha256 = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'
    }
)

$sourceAssets = @(
    [pscustomobject]@{
        Name = 'util-linux-2.40.2.tar.xz'
        Uri = 'https://www.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-2.40.2.tar.xz'
        Sha256 = 'd78b37a66f5922d70edf3bdfb01a6b33d34ed3c3cafd6628203b2a2b67c8e8b3'
    },
    [pscustomobject]@{
        Name = 'check-aarch64-pseudo-relocs-3356eec.ps1'
        Uri = 'https://raw.githubusercontent.com/crutkas/MSYS2-packages/3356eec1411983cc252b04afac32bca5f3b8d824/.ci/check-aarch64-pseudo-relocs.ps1'
        Sha256 = '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
    }
)

$inputRoot = Join-Path (Split-Path -Parent $RootPath) 'libuuid-private-inputs'
$hostDirectory = Join-Path $inputRoot 'host'
$targetDirectory = Join-Path $inputRoot 'target'
$sourceDirectory = Join-Path $inputRoot 'source'
foreach ($path in @($inputRoot, $EvidenceDirectory)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
New-Item -ItemType Directory -Force -Path `
    $hostDirectory, $targetDirectory, $sourceDirectory, $EvidenceDirectory |
    Out-Null

$basePath = Join-Path $inputRoot $baseAsset.Name
Invoke-Download -Uri $baseAsset.Uri -Path $basePath -Sha256 $baseAsset.Sha256
if ((Get-Item -LiteralPath $basePath).Length -ne $baseAsset.Size) {
    throw 'Immutable MSYS base size mismatch'
}
Assert-SafeArchive -Archive $basePath -RequiredPrefix 'msys64/'

$hostManifestPath = Join-Path $PSScriptRoot 'msysarm64-libuuid-host-packages.sha256'
$hostRecords = @()
foreach ($line in Get-Content -LiteralPath $hostManifestPath) {
    if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9+_.~-]+\.pkg\.tar\.(?:zst|xz))$') {
        throw "Invalid host manifest line: $line"
    }
    $hostRecords += [pscustomobject]@{
        Sha256 = $Matches[1]
        Name = $Matches[2]
    }
}
if ($hostRecords.Count -ne 138 -or
    @($hostRecords.Name | Sort-Object -Unique).Count -ne 138) {
    throw 'Host package manifest must contain 138 unique records'
}

$curlArguments = @(
    '--parallel',
    '--parallel-max', '8',
    '--fail',
    '--retry', '5',
    '--retry-all-errors',
    '--retry-delay', '2',
    '--silent',
    '--show-error',
    '--output-dir', $hostDirectory
)
foreach ($record in $hostRecords) {
    $curlArguments += '--remote-name'
    $curlArguments += "https://repo.msys2.org/msys/x86_64/$($record.Name)"
}
& curl.exe @curlArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Host package download failed'
}
foreach ($record in $hostRecords) {
    $path = Join-Path $hostDirectory $record.Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing host package: $($record.Name)"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
    if ($actual -ne $record.Sha256) {
        throw "Host package SHA-256 mismatch: $($record.Name)"
    }
    Assert-SafeArchive -Archive $path
}

foreach ($asset in $targetAssets) {
    $path = Join-Path $targetDirectory $asset.Name
    Invoke-Download -Uri $asset.Uri -Path $path -Sha256 $asset.Sha256
    Assert-SafeArchive -Archive $path
}
foreach ($asset in $sourceAssets) {
    $path = Join-Path $sourceDirectory $asset.Name
    Invoke-Download -Uri $asset.Uri -Path $path -Sha256 $asset.Sha256
}

$fixedBinutils = Join-Path $targetDirectory $targetAssets[0].Name
$fixedListing = @(& $systemTar -tvf $fixedBinutils |
    Where-Object { $_ -match 'opt/bin/aarch64-pc-msys-' })
if ($fixedListing.Count -ne 20) {
    throw "Expected 20 fixed-binutils aliases, found $($fixedListing.Count)"
}
foreach ($line in $fixedListing) {
    if ($line -notmatch ' -> aarch64-pc-cygwin-[A-Za-z0-9+.~-]+\.exe$') {
        throw "Unsafe or unexpected fixed-binutils alias: $line"
    }
}

$extractParent = "$RootPath.extract"
if (Test-Path -LiteralPath $extractParent) {
    Remove-Item -LiteralPath $extractParent -Recurse -Force
}
New-Item -ItemType Directory -Path $extractParent | Out-Null
& $systemTar -xf $basePath -C $extractParent
if ($LASTEXITCODE -ne 0) {
    throw 'Immutable MSYS base extraction failed'
}
$extractedRoot = Join-Path $extractParent 'msys64'
if (-not (Test-Path -LiteralPath (Join-Path $extractedRoot 'usr\bin\bash.exe'))) {
    throw 'Immutable MSYS base did not produce the expected root'
}
$allowedExtractedRoot = [IO.Path]::GetFullPath($extractedRoot).
    TrimEnd('\') + '\'
foreach ($link in Get-ChildItem -LiteralPath $extractedRoot -Recurse -Force |
    Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    }) {
    foreach ($target in @($link.Target)) {
        if ([IO.Path]::IsPathRooted($target)) {
            throw "Base archive produced an absolute link: $($link.FullName)"
        }
        $resolved = [IO.Path]::GetFullPath(
            (Join-Path $link.DirectoryName $target))
        if (-not $resolved.StartsWith(
            $allowedExtractedRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
            throw "Base archive link escapes private root: $($link.FullName)"
        }
    }
}
Move-Item -LiteralPath $extractedRoot -Destination $RootPath
Remove-Item -LiteralPath $extractParent -Force

$hostCache = Join-Path $RootPath 'var\cache\pacman\pkg\host'
$targetCache = Join-Path $RootPath 'var\cache\pacman\pkg\target'
$emptyHooks = Join-Path $RootPath 'var\empty-hooks'
New-Item -ItemType Directory -Force -Path $hostCache, $targetCache, $emptyHooks |
    Out-Null
Get-ChildItem -LiteralPath $hostDirectory -File | Copy-Item -Destination $hostCache
Get-ChildItem -LiteralPath $targetDirectory -File | Copy-Item -Destination $targetCache

$syncDatabase = Join-Path $RootPath 'var\lib\pacman\sync'
if (Test-Path -LiteralPath $syncDatabase) {
    Remove-Item -LiteralPath $syncDatabase -Recurse -Force
}
$privateConfig = @(
    '[options]',
    'RootDir = /',
    'DBPath = /var/lib/pacman/',
    'CacheDir = /var/cache/pacman/pkg/',
    'LogFile = /var/log/pacman.log',
    'GPGDir = /etc/pacman.d/gnupg/',
    'Architecture = x86_64',
    'SigLevel = Never',
    'LocalFileSigLevel = Never'
)
Write-Utf8NoBom -Path (Join-Path $RootPath 'etc\pacman.conf') `
    -Lines $privateConfig
$privatePacmanLog = Join-Path $RootPath 'var\log\pacman.log'
$basePacmanLogSha256 = (
    Get-FileHash -Algorithm SHA256 $privatePacmanLog
).Hash.ToLowerInvariant()
Write-Utf8NoBom -Path $privatePacmanLog -Lines @()

$hostUpgrade = @'
set -euo pipefail
export PATH=/usr/bin
MSYS='winsymlinks:sys' pacman \
  --noconfirm \
  --hookdir /var/empty-hooks \
  -U /var/cache/pacman/pkg/host/*.pkg.tar.zst
'@
Invoke-PrivateBash -Script $hostUpgrade `
    -LogPath (Join-Path $EvidenceDirectory 'host-upgrade.log') |
    Out-Null

$targetInstall = @'
set -euo pipefail
export PATH=/usr/bin
MSYS='winsymlinks:sys' pacman \
  --noconfirm \
  --hookdir /var/empty-hooks \
  -U /var/cache/pacman/pkg/target/*.pkg.tar.zst
'@
Invoke-PrivateBash -Script $targetInstall `
    -LogPath (Join-Path $EvidenceDirectory 'target-install.log') |
    Out-Null

$verifyRoot = @'
set -euo pipefail
export PATH=/opt/bin:/usr/bin
expected=(
  'mingw-w64-cross-cygwinarm64-binutils 2.44.50-2'
  'mingw-w64-cross-cygwinarm64-libstdc++-headers 15.0.1dev-1'
  'mingw-w64-cross-cygwinarm64-gcc-libs-stage1 15.0.1dev-2'
  'mingw-w64-cross-cygwinarm64-gcc-stage1 15.0.1dev-2'
  'mingw-w64-cross-msysarm64-headers 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-windows-default-manifest 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-sysroot 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-runtime 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-runtime-devel 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-w32api-runtime 14.0.0.r0.g9b3dd0125-1'
  'mingw-w64-cross-msysarm64-libstdc++-headers 15.0.1dev-1'
  'mingw-w64-cross-msysarm64-gcc-libs 15.0.1dev-1'
  'mingw-w64-cross-msysarm64-gcc 15.0.1dev-1'
)
for identity in "${expected[@]}"; do
  package=${identity% *}
  test "$(pacman -Q "$package")" = "$identity"
  pacman -Qk "$package"
done
for tool in \
  addr2line ar as c++filt dlltool dllwrap elfedit gprof ld ld.bfd nm \
  objcopy objdump ranlib readelf size strings strip windmc windres
do
  alias_path="/opt/bin/aarch64-pc-msys-$tool.exe"
  test -L "$alias_path"
  test "$(readlink "$alias_path")" = "aarch64-pc-cygwin-$tool.exe"
  test "$(pacman -Qoq "$alias_path")" = \
    mingw-w64-cross-cygwinarm64-binutils
done
test "$(sha256sum /opt/bin/aarch64-pc-msys-ld.exe | awk '{ print $1 }')" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
for tool in ar nm ranlib; do
  test "$(pacman -Qoq "/opt/aarch64-pc-msys/bin/$tool.exe")" = \
    mingw-w64-cross-msysarm64-gcc
done
test "$(aarch64-pc-msys-gcc -dumpmachine)" = aarch64-pc-msys
pacman -Q | LC_ALL=C sort
'@
$packageState = Invoke-PrivateBash -Script $verifyRoot `
    -LogPath (Join-Path $EvidenceDirectory 'root-verification.log')
Write-Utf8NoBom -Path (Join-Path $EvidenceDirectory 'package-state.txt') `
    -Lines @($packageState | Where-Object { $_ -match '^[A-Za-z0-9+_.~-]+ ' })

Copy-Item -LiteralPath $hostManifestPath `
    -Destination (Join-Path $EvidenceDirectory 'host-packages.sha256')
Write-Utf8NoBom -Path (Join-Path $EvidenceDirectory 'target-packages.sha256') `
    -Lines @($targetAssets | Sort-Object Name | ForEach-Object {
        "$($_.Sha256)  $($_.Name)"
    })
Write-Utf8NoBom -Path (Join-Path $EvidenceDirectory 'source-inputs.sha256') `
    -Lines @($sourceAssets | Sort-Object Name | ForEach-Object {
        "$($_.Sha256)  $($_.Name)"
    })
Write-Utf8NoBom -Path (Join-Path $EvidenceDirectory 'base-input.sha256') `
    -Lines @("$($baseAsset.Sha256)  $($baseAsset.Name)")
Copy-Item -LiteralPath $privatePacmanLog `
    -Destination (Join-Path $EvidenceDirectory 'pacman.log')

$pathScanner = Join-Path `
    $PSScriptRoot 'scan-msysarm64-libuuid-private-paths.ps1'
$heldPathRegression = Join-Path `
    $PSScriptRoot 'test-msysarm64-libuuid-held-path-leaks.ps1'
& $heldPathRegression `
    -ScannerPath $pathScanner `
    -EvidencePath (Join-Path `
        $EvidenceDirectory 'held-release-path-regression.json')

$summary = [ordered]@{
    schema = 1
    base_name = $baseAsset.Name
    base_size = $baseAsset.Size
    base_sha256 = $baseAsset.Sha256
    base_pacman_log_sha256 = $basePacmanLogSha256
    host_package_count = $hostRecords.Count
    target_package_count = $targetAssets.Count
    source_input_count = $sourceAssets.Count
    fixed_linker_sha256 =
        '075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f'
    shared_root_used = $false
    private_config_sha256 = (
        Get-FileHash -Algorithm SHA256 (Join-Path $RootPath 'etc\pacman.conf')
    ).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText(
    (Join-Path $EvidenceDirectory 'root-summary.json'),
    ($summary | ConvertTo-Json -Depth 4),
    [Text.UTF8Encoding]::new($false))

& $pathScanner -SelfTest
& $pathScanner `
    -Paths @($EvidenceDirectory) `
    -ForbiddenPaths @(
        $RootPath,
        $inputRoot,
        $EvidenceDirectory,
        $env:RUNNER_TEMP
    ) `
    -OutputPath (Join-Path $EvidenceDirectory 'path-scan.json')

$manifestPath = Join-Path $EvidenceDirectory 'evidence-manifest.sha256'
$sealPath = Join-Path $EvidenceDirectory 'evidence.seal'
$manifestLines = Get-ChildItem -LiteralPath $EvidenceDirectory -File |
    Where-Object { $_.FullName -notin @($manifestPath, $sealPath) } |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).
            Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
Write-Utf8NoBom -Path $manifestPath -Lines @($manifestLines)
$seal = (Get-FileHash -Algorithm SHA256 $manifestPath).Hash.ToLowerInvariant()
Write-Utf8NoBom -Path $sealPath `
    -Lines @("$seal  evidence-manifest.sha256")

if ($env:GITHUB_ENV) {
    "LIBUUID_PRIVATE_ROOT=$RootPath" >> $env:GITHUB_ENV
    "MSYSARM64_TOOLCHAIN_DIR=$targetDirectory" >> $env:GITHUB_ENV
    "LIBUUID_SOURCE_INPUT_DIR=$sourceDirectory" >> $env:GITHUB_ENV
    "LIBUUID_ROOT_EVIDENCE=$EvidenceDirectory" >> $env:GITHUB_ENV
}

[pscustomobject]@{
    Root = $RootPath
    EvidenceSeal = $seal
    HostPackages = $hostRecords.Count
    TargetPackages = $targetAssets.Count
}

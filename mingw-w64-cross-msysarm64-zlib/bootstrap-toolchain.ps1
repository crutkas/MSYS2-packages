[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Destination,

    [Parameter(Mandatory = $true)]
    [string] $MsysRoot,

    [string[]] $AdditionalPackages = @(),

    [switch] $Install
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repository = 'crutkas/MSYS2-packages'
$utf8 = [Text.UTF8Encoding]::new($false)
$expected = [ordered]@{
    'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst' = @{
        Tag = 'cygwinarm64-binutils-pr21-3356eec-20260827'
        Size = 6545114L
        Sha256 = '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b'
    }
    'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst' = @{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Size = 43966034L
        Sha256 = '063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e'
    }
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst' = @{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Size = 357954L
        Sha256 = '17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c'
    }
    'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' = @{
        Tag = 'cygwinarm64-libstdcxx-headers-pr7-20260815'
        Size = 2184212L
        Sha256 = '1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6'
    }
    'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 9319013L
        Sha256 = '263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21'
    }
    'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 4743L
        Sha256 = '33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f'
    }
    'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 86822L
        Sha256 = 'e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca'
    }
    'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Size = 2349635L
        Sha256 = '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24'
    }
    'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 9893043L
        Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
    }
    'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 4426157L
        Sha256 = 'c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1'
    }
    'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Size = 1520166L
        Sha256 = '9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08'
    }
    'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Size = 4963824L
        Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
    }
    'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst' = @{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Size = 83876291L
        Sha256 = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Get-Release {
    param([Parameter(Mandatory = $true)][string] $Tag)

    $headers = @{
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'msysarm64-zlib-private-bootstrap'
    }
    if ($env:GITHUB_TOKEN) {
        $headers.Authorization = "Bearer $($env:GITHUB_TOKEN)"
    }
    return Invoke-RestMethod `
        -Uri "https://api.github.com/repos/$repository/releases/tags/$Tag" `
        -Headers $headers
}

function Download-InputSet {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)]
        [ValidateSet('webrequest', 'httpclient')]
        [string] $Method
    )

    if (Test-Path -LiteralPath $Directory) {
        throw "Download destination already exists: $Directory"
    }
    New-Item -ItemType Directory -Path $Directory | Out-Null

    $releaseCache = @{}
    $hashes = [ordered]@{}
    $client = if ($Method -eq 'httpclient') {
        [Net.Http.HttpClient]::new()
    }
    else {
        $null
    }
    try {
        foreach ($entry in $expected.GetEnumerator()) {
            $name = $entry.Key
            $identity = $entry.Value
            if (-not $releaseCache.ContainsKey($identity.Tag)) {
                $releaseCache[$identity.Tag] = Get-Release -Tag $identity.Tag
            }
            $published = @(
                $releaseCache[$identity.Tag].assets |
                    Where-Object name -EQ $name
            )
            if ($published.Count -ne 1) {
                throw "Expected one release asset: $name"
            }
            if ($published[0].size -ne $identity.Size) {
                throw "Published size mismatch: $name"
            }
            if ($published[0].digest -ne "sha256:$($identity.Sha256)") {
                throw "Published digest mismatch: $name"
            }

            $path = Join-Path $Directory $name
            if ($Method -eq 'webrequest') {
                Invoke-WebRequest `
                    -Uri $published[0].browser_download_url `
                    -OutFile $path
            }
            else {
                $bytes = $client.GetByteArrayAsync(
                    [Uri] $published[0].browser_download_url
                ).GetAwaiter().GetResult()
                [IO.File]::WriteAllBytes($path, $bytes)
            }

            $item = Get-Item -LiteralPath $path
            $hash = Get-Sha256 -Path $path
            if ($item.Length -ne $identity.Size -or
                $hash -ne $identity.Sha256) {
                throw "Downloaded identity mismatch: $name"
            }
            $hashes[$name] = $hash
        }
    }
    finally {
        if ($client) {
            $client.Dispose()
        }
    }
    return $hashes
}

if (Test-Path -LiteralPath $Destination) {
    throw "Destination must be fresh: $Destination"
}
$Destination = [IO.Path]::GetFullPath($Destination)
$MsysRoot = [IO.Path]::GetFullPath($MsysRoot)
if ($MsysRoot.TrimEnd('\') -ieq 'C:\msys64') {
    throw 'The hosted C:\msys64 root is forbidden'
}

$primaryDirectory = Join-Path $Destination 'primary'
$redownloadDirectory = Join-Path $Destination 'independent-redownload'
$primaryHashes = Download-InputSet `
    -Directory $primaryDirectory `
    -Method webrequest
$redownloadHashes = Download-InputSet `
    -Directory $redownloadDirectory `
    -Method httpclient

$manifest = @("source`tmethods`tasset`tbytes`tsha256")
foreach ($name in $expected.Keys) {
    if ($primaryHashes[$name] -ne $redownloadHashes[$name]) {
        throw "Independent redownload mismatch: $name"
    }
    $identity = $expected[$name]
    $manifest += @(
        "release:$($identity.Tag)`tInvoke-WebRequest+HttpClient`t$name`t" +
        "$($identity.Size)`t$($identity.Sha256)"
    )
}
[IO.File]::WriteAllText(
    (Join-Path $Destination 'toolchain-inputs.tsv'),
    (($manifest -join "`n") + "`n"),
    $utf8
)

if (-not $Install) {
    exit 0
}

$pacman = Join-Path $MsysRoot 'usr\bin\pacman.exe'
$bash = Join-Path $MsysRoot 'usr\bin\bash.exe'
$cygpath = Join-Path $MsysRoot 'usr\bin\cygpath.exe'
foreach ($path in @($pacman, $bash, $cygpath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Private root executable is missing: $path"
    }
}
foreach ($relative in @(
    'var\lib\pacman',
    'var\cache\pacman\pkg',
    'var\log',
    'etc\pacman.d\hooks',
    'etc\pacman.d\gnupg'
)) {
    New-Item -ItemType Directory -Force -Path (
        Join-Path $MsysRoot $relative
    ) | Out-Null
}

$config = Join-Path $Destination 'private-pacman.conf'
[IO.File]::WriteAllText(
    $config,
    @"
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional
"@,
    $utf8
)

$packageNames = @(
    'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
    'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
    'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
    'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
)
$windowsPackages = @(
    $AdditionalPackages
    $packageNames | ForEach-Object { Join-Path $primaryDirectory $_ }
)
foreach ($path in $windowsPackages) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Private transaction input is missing: $path"
    }
}
$posixPackages = @(
    foreach ($path in $windowsPackages) {
        (& $cygpath -u $path | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "cygpath failed: $path"
        }
    }
)
$configPosix = (& $cygpath -u $config | Select-Object -Last 1).Trim()

$env:MSYS = 'winsymlinks:sys'
$hookMask = @'
set -euo pipefail
export PATH=/usr/bin
/usr/bin/mkdir -p /etc/pacman.d/hooks
for hook in texinfo-install.hook texinfo-remove.hook; do
  /usr/bin/rm -f "/etc/pacman.d/hooks/$hook"
  MSYS=winsymlinks:sys /usr/bin/ln -s /dev/null \
    "/etc/pacman.d/hooks/$hook"
done
'@
& $bash --noprofile --norc -c $hookMask
if ($LASTEXITCODE -ne 0) {
    throw "Private hook masking failed: $LASTEXITCODE"
}

$pacmanBaseArguments = @(
    '--root', '/',
    '--dbpath', '/var/lib/pacman',
    '--cachedir', '/var/cache/pacman/pkg',
    '--logfile', '/var/log/zlib-private-pacman.log',
    '--config', $configPosix,
    '--hookdir', '/etc/pacman.d/hooks',
    '--gpgdir', '/etc/pacman.d/gnupg'
)
$pacmanArguments = $pacmanBaseArguments + @(
    '--noconfirm',
    '-U',
    '--'
) + $posixPackages
& $pacman @pacmanArguments
if ($LASTEXITCODE -ne 0) {
    throw "Private atomic transaction failed: $LASTEXITCODE"
}
Copy-Item `
    -LiteralPath $config `
    -Destination (Join-Path $MsysRoot 'etc\pacman.conf') `
    -Force

$preflight = @'
set -euo pipefail
export PATH=/opt/bin:/usr/bin
pacman_private=(
  /usr/bin/pacman
  --root /
  --dbpath /var/lib/pacman
  --cachedir /var/cache/pacman/pkg
  --logfile /var/log/zlib-private-pacman.log
  --config "$1"
  --hookdir /etc/pacman.d/hooks
  --gpgdir /etc/pacman.d/gnupg
)
test "$(/opt/bin/aarch64-pc-msys-gcc.exe -dumpmachine)" = aarch64-pc-msys
test "$(/opt/bin/aarch64-pc-msys-gcc.exe -dumpversion)" = 15.0.1
test "$("${pacman_private[@]}" -Q mingw-w64-cross-cygwinarm64-binutils)" = \
  "mingw-w64-cross-cygwinarm64-binutils 2.44.50-2"
test "$(/usr/bin/sha256sum /opt/bin/aarch64-pc-cygwin-ld.exe |
  /usr/bin/cut -d" " -f1)" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
tools=(
  addr2line ar as c++filt dlltool dllwrap elfedit gprof ld ld.bfd
  nm objcopy objdump ranlib readelf size strings strip windmc windres
)
for tool in "${tools[@]}"; do
  alias="/opt/bin/aarch64-pc-msys-${tool}.exe"
  test -L "$alias"
  test "$(/usr/bin/readlink "$alias")" = "aarch64-pc-cygwin-${tool}.exe"
  test "$("${pacman_private[@]}" -Qoq "$alias")" = \
    mingw-w64-cross-cygwinarm64-binutils
done
'@
& $bash --noprofile --norc -c $preflight -- $configPosix
if ($LASTEXITCODE -ne 0) {
    throw "Private toolchain preflight failed: $LASTEXITCODE"
}

$installed = @(
    'diffutils',
    'isl',
    'make',
    'mpc',
    'patch',
    'mingw-w64-cross-cygwinarm64-binutils',
    'mingw-w64-cross-cygwinarm64-gcc-stage1',
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1',
    'mingw-w64-cross-cygwinarm64-libstdc++-headers',
    'mingw-w64-cross-msysarm64-headers',
    'mingw-w64-cross-msysarm64-windows-default-manifest',
    'mingw-w64-cross-msysarm64-sysroot',
    'mingw-w64-cross-msysarm64-w32api-runtime',
    'mingw-w64-cross-msysarm64-runtime',
    'mingw-w64-cross-msysarm64-runtime-devel',
    'mingw-w64-cross-msysarm64-libstdc++-headers',
    'mingw-w64-cross-msysarm64-gcc-libs',
    'mingw-w64-cross-msysarm64-gcc'
)
$installedLines = @("package`tversion")
foreach ($name in $installed) {
    $query = & $pacman @pacmanBaseArguments -Q $name
    if ($LASTEXITCODE -ne 0) {
        throw "Private installed-package query failed: $name"
    }
    $installedLines += ($query -replace ' ', "`t")
}
[IO.File]::WriteAllText(
    (Join-Path $Destination 'installed-toolchain.tsv'),
    (($installedLines -join "`n") + "`n"),
    $utf8
)

$toolPaths = @(
    (Join-Path $MsysRoot 'usr\bin\bash.exe'),
    (Join-Path $MsysRoot 'usr\bin\make.exe'),
    (Join-Path $MsysRoot 'usr\bin\makepkg'),
    (Join-Path $MsysRoot 'usr\bin\patch.exe'),
    (Join-Path $MsysRoot 'usr\bin\pacman.exe'),
    (Join-Path $MsysRoot 'usr\bin\bsdtar.exe'),
    (Join-Path $MsysRoot 'usr\bin\zstd.exe'),
    (Join-Path $MsysRoot 'opt\bin\aarch64-pc-msys-gcc.exe'),
    (Join-Path $MsysRoot 'opt\bin\aarch64-pc-msys-g++.exe'),
    (Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-ld.exe'),
    (Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-objdump.exe'),
    (Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-nm.exe')
)
$toolLines = @("path`tbytes`tsha256")
foreach ($path in $toolPaths) {
    $item = Get-Item -LiteralPath $path
    $relative = $path.Substring($MsysRoot.Length).Replace('\', '/')
    $toolLines += "$relative`t$($item.Length)`t$(Get-Sha256 -Path $path)"
}
[IO.File]::WriteAllText(
    (Join-Path $Destination 'private-tools.tsv'),
    (($toolLines -join "`n") + "`n"),
    $utf8
)

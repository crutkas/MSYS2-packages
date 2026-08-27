param(
    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [string]$MsysRoot = 'C:\msys64',

    [switch]$Install
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = 'crutkas/MSYS2-packages'

$expected = [ordered]@{
    'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-binutils-pr21-3356eec-20260827'
        Size = 6545114L
        Sha256 = '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b'
    }
    'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Size = 43966034L
        Sha256 = '063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e'
    }
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Size = 357954L
        Sha256 = '17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c'
    }
    'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-libstdcxx-headers-pr7-20260815'
        Size = 2184212L
        Sha256 = '1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6'
    }
    'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 9319013L
        Sha256 = '263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21'
    }
    'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 4743L
        Sha256 = '33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f'
    }
    'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 86822L
        Sha256 = 'e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca'
    }
    'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Size = 2349635L
        Sha256 = '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24'
    }
    'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 9893043L
        Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
    }
    'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 4426157L
        Sha256 = 'c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1'
    }
    'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Size = 1520166L
        Sha256 = '9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08'
    }
    'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Size = 4963824L
        Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
    }
    'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Size = 83876291L
        Sha256 = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'
    }
}

function Download-InputSet {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)]
        [ValidateSet('gh', 'curl')]
        [string]$Method
    )

    if (Test-Path -LiteralPath $Directory) {
        throw "download destination already exists: $Directory"
    }
    New-Item -ItemType Directory -Path $Directory | Out-Null

    $releaseCache = @{}
    $hashes = [ordered]@{}
    foreach ($entry in $expected.GetEnumerator()) {
        $name = $entry.Key
        $asset = $entry.Value
        if (-not $releaseCache.ContainsKey($asset.Tag)) {
            $releaseJson = & gh api `
                "repos/$repository/releases/tags/$($asset.Tag)"
            if ($LASTEXITCODE -ne 0) {
                throw "release lookup failed: $($asset.Tag)"
            }
            $releaseCache[$asset.Tag] = $releaseJson | ConvertFrom-Json
        }

        $published = @(
            $releaseCache[$asset.Tag].assets |
                Where-Object Name -EQ $name
        )
        if ($published.Count -ne 1) {
            throw "expected one published release asset: $name"
        }
        if ($published[0].size -ne $asset.Size) {
            throw "published size mismatch for $name"
        }
        if ($published[0].digest -ne "sha256:$($asset.Sha256)") {
            throw "published digest mismatch for $name"
        }

        $path = Join-Path $Directory $name
        if ($Method -eq 'gh') {
            & gh release download $asset.Tag `
                --repo $repository `
                --pattern $name `
                --dir $Directory
            if ($LASTEXITCODE -ne 0) {
                throw "primary gh download failed: $name"
            }
        }
        else {
            $encodedName = [Uri]::EscapeDataString($name)
            $url = "https://github.com/$repository/releases/download/$($asset.Tag)/$encodedName"
            & curl.exe --fail --location --retry 3 `
                --silent --show-error `
                --output $path $url
            if ($LASTEXITCODE -ne 0) {
                throw "independent curl download failed: $name"
            }
        }

        $item = Get-Item -LiteralPath $path
        if ($item.Length -ne $asset.Size) {
            throw "downloaded size mismatch for $name"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $asset.Sha256) {
            throw "SHA-256 mismatch for $name`: expected $($asset.Sha256), got $hash"
        }
        $hashes[$name] = $hash
    }

    $actualNames = @(
        Get-ChildItem -LiteralPath $Directory -File -Filter '*.pkg.tar.zst' |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedNames = @($expected.Keys | Sort-Object)
    if (Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames) {
        throw 'downloaded package set does not exactly match the pinned input set'
    }

    return $hashes
}

if (-not $env:GH_TOKEN) {
    throw 'GH_TOKEN is required'
}
if (Test-Path -LiteralPath $Destination) {
    throw "destination already exists: $Destination"
}

$primaryDirectory = Join-Path $Destination 'primary'
$redownloadDirectory = Join-Path $Destination 'independent-redownload'
$primaryHashes = Download-InputSet -Directory $primaryDirectory -Method gh
$redownloadHashes = Download-InputSet -Directory $redownloadDirectory -Method curl

foreach ($name in $expected.Keys) {
    if ($primaryHashes[$name] -ne $redownloadHashes[$name]) {
        throw "independent redownload mismatch for $name"
    }
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$hashReport = Join-Path $Destination 'toolchain-inputs.tsv'
@(
    "source`tidentity`tasset`tsha256"
    foreach ($name in $expected.Keys) {
        $source = "release:$($expected[$name].Tag)"
        "$source`tgh+curl`t$name`t$($primaryHashes[$name])"
    }
) | Set-Content -LiteralPath $hashReport -Encoding utf8NoBOM

if (-not $Install) {
    exit 0
}

$installOrder = @(
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
$packagePaths = @($installOrder | ForEach-Object { Join-Path $primaryDirectory $_ })
$pacman = Join-Path $MsysRoot 'usr\bin\pacman.exe'
$bash = Join-Path $MsysRoot 'usr\bin\bash.exe'
if (-not (Test-Path -LiteralPath $pacman -PathType Leaf)) {
    throw "pacman is missing: $pacman"
}
if (-not (Test-Path -LiteralPath $bash -PathType Leaf)) {
    throw "bash is missing: $bash"
}

$env:MSYS = 'winsymlinks:sys'
& $pacman --noconfirm -U -- @packagePaths
if ($LASTEXITCODE -ne 0) {
    throw "atomic toolchain transaction failed with exit code $LASTEXITCODE"
}

$preflight = @'
set -euo pipefail
export PATH=/usr/bin:/opt/bin:/mingw64/bin:$PATH
test "$(aarch64-pc-msys-gcc -dumpmachine)" = aarch64-pc-msys
test "$(aarch64-pc-msys-gcc -dumpversion)" = 15.0.1
test "$(pacman -Q mingw-w64-cross-cygwinarm64-binutils)" = \
  "mingw-w64-cross-cygwinarm64-binutils 2.44.50-2"
test "$(pacman -Qoq /opt/bin/aarch64-pc-msys-gcc.exe)" = mingw-w64-cross-msysarm64-gcc
test "$(pacman -Qoq /opt/bin/aarch64-pc-cygwin-ar.exe)" = mingw-w64-cross-cygwinarm64-binutils
test "$(pacman -Qoq /opt/bin/aarch64-pc-msys-ld.exe)" = mingw-w64-cross-cygwinarm64-binutils
test "$(sha256sum /opt/bin/aarch64-pc-cygwin-ld.exe | cut -d" " -f1)" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
tools=(
  addr2line ar as c++filt dlltool dllwrap elfedit gprof ld ld.bfd
  nm objcopy objdump ranlib readelf size strings strip windmc windres
)
for tool in "${tools[@]}"; do
  alias="/opt/bin/aarch64-pc-msys-${tool}.exe"
  test -L "$alias"
  test "$(readlink "$alias")" = "aarch64-pc-cygwin-${tool}.exe"
  test "$(pacman -Qoq "$alias")" = \
    mingw-w64-cross-cygwinarm64-binutils
done
test -L /opt/aarch64-pc-msys/bin/ar.exe
test "$(readlink /opt/aarch64-pc-msys/bin/ar.exe)" = ../../aarch64-pc-cygwin/bin/ar.exe
test -f /opt/aarch64-pc-msys/bin/msys-2.0.dll
test -f /opt/aarch64-pc-msys/lib/libmsys-2.0.a
test -f /opt/aarch64-pc-msys/usr/lib/libkernel32.a
'@
& $bash --noprofile --norc -c $preflight
if ($LASTEXITCODE -ne 0) {
    throw "installed compiler preflight failed with exit code $LASTEXITCODE"
}

$installedReport = Join-Path $Destination 'installed-toolchain.tsv'
$installedNames = @(
    'mingw-w64-cross-cygwinarm64-binutils'
    'mingw-w64-cross-cygwinarm64-gcc-stage1'
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1'
    'mingw-w64-cross-cygwinarm64-libstdc++-headers'
    'mingw-w64-cross-msysarm64-headers'
    'mingw-w64-cross-msysarm64-windows-default-manifest'
    'mingw-w64-cross-msysarm64-sysroot'
    'mingw-w64-cross-msysarm64-w32api-runtime'
    'mingw-w64-cross-msysarm64-runtime'
    'mingw-w64-cross-msysarm64-runtime-devel'
    'mingw-w64-cross-msysarm64-libstdc++-headers'
    'mingw-w64-cross-msysarm64-gcc-libs'
    'mingw-w64-cross-msysarm64-gcc'
)
@(
    "package`tversion"
    foreach ($name in $installedNames) {
        $query = & $pacman -Q $name
        if ($LASTEXITCODE -ne 0) {
            throw "installed package query failed: $name"
        }
        ($query -replace ' ', "`t")
    }
) | Set-Content -LiteralPath $installedReport -Encoding utf8NoBOM

param(
    [switch]$DownloadOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = $env:GITHUB_REPOSITORY
$branchCandidates = @($env:GITHUB_REF_NAME, $env:GITHUB_HEAD_REF) |
    Where-Object { $_ }
if ($repository -ne 'crutkas/MSYS2-packages') {
    throw "Refusing fork-only toolchain install in $repository"
}
if ($branchCandidates -notcontains 'crutkas-arm64-msys-libuuid') {
    throw "Refusing libuuid toolchain install for refs: $($branchCandidates -join ', ')"
}
if ($env:RUNNER_ARCH -ne 'X64') {
    throw "The cross-build job requires an X64 runner, not $env:RUNNER_ARCH"
}

$destination = Join-Path $env:RUNNER_TEMP 'msysarm64-libuuid-toolchain'
New-Item -ItemType Directory -Force -Path $destination | Out-Null

$releaseAssets = @(
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

foreach ($asset in $releaseAssets) {
    $path = Join-Path $destination $asset.Name
    & curl.exe --fail --location --retry 5 --silent --show-error `
        --output $path $asset.Uri
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed: $($asset.Uri)"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
    if ($actual -ne $asset.Sha256) {
        throw "SHA-256 mismatch for $($asset.Name): $actual"
    }
}
if ($DownloadOnly) {
    $releaseAssets | ForEach-Object {
        $path = Join-Path $destination $_.Name
        [pscustomobject]@{
            Name = $_.Name
            Size = (Get-Item -LiteralPath $path).Length
            Sha256 = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
        }
    }
    return
}
"MSYSARM64_TOOLCHAIN_DIR=$destination" >> $env:GITHUB_ENV

$expectedPackages = @(
    'mingw-w64-cross-cygwinarm64-binutils',
    'mingw-w64-cross-cygwinarm64-libstdc++-headers',
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1',
    'mingw-w64-cross-cygwinarm64-gcc-stage1',
    'mingw-w64-cross-msysarm64-headers',
    'mingw-w64-cross-msysarm64-windows-default-manifest',
    'mingw-w64-cross-msysarm64-sysroot',
    'mingw-w64-cross-msysarm64-runtime',
    'mingw-w64-cross-msysarm64-runtime-devel',
    'mingw-w64-cross-msysarm64-w32api-runtime',
    'mingw-w64-cross-msysarm64-libstdc++-headers',
    'mingw-w64-cross-msysarm64-gcc-libs',
    'mingw-w64-cross-msysarm64-gcc'
)
$pacman = 'C:\msys64\usr\bin\pacman.exe'
foreach ($package in $expectedPackages) {
    & $pacman -Q $package *> $null
    if ($LASTEXITCODE -eq 0) {
        throw "Toolchain package unexpectedly preinstalled: $package"
    }
}

$packagePaths = @()
$packagePaths += $releaseAssets | ForEach-Object {
    Join-Path $destination $_.Name
}

$oldMsys = $env:MSYS
try {
    $env:MSYS = 'winsymlinks:sys'
    & $pacman --noconfirm -U @packagePaths
    if ($LASTEXITCODE -ne 0) {
        throw 'Atomic AArch64 MSYS toolchain installation failed'
    }
}
finally {
    $env:MSYS = $oldMsys
}

$bash = 'C:\msys64\usr\bin\bash.exe'
$preflight = @'
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
done
test -L /opt/aarch64-pc-msys/bin/ar.exe
test -L /opt/aarch64-pc-msys/bin/nm.exe
test -L /opt/aarch64-pc-msys/bin/ranlib.exe
test "$(aarch64-pc-msys-gcc -dumpmachine)" = aarch64-pc-msys
for tool in gcc g++ ar as dlltool ld nm objcopy objdump ranlib readelf strip windres; do
  test "$(type -P "aarch64-pc-msys-$tool")" = "/opt/bin/aarch64-pc-msys-$tool"
  case "$tool" in
    gcc|g++)
      test "$(pacman -Qoq "/opt/bin/aarch64-pc-msys-$tool.exe")" = \
        mingw-w64-cross-msysarm64-gcc
      ;;
    *)
      test -L "/opt/bin/aarch64-pc-msys-$tool.exe"
      test "$(readlink "/opt/bin/aarch64-pc-msys-$tool.exe")" = \
        "aarch64-pc-cygwin-$tool.exe"
      test "$(pacman -Qoq "/opt/bin/aarch64-pc-msys-$tool.exe")" = \
        mingw-w64-cross-cygwinarm64-binutils
      test "$(pacman -Qoq "$(realpath "/opt/bin/aarch64-pc-msys-$tool.exe")")" = \
        mingw-w64-cross-cygwinarm64-binutils
      ;;
  esac
done
test "$(sha256sum /opt/bin/aarch64-pc-msys-ld.exe | awk '{ print $1 }')" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
for tool in ar nm ranlib; do
  test "$(pacman -Qoq "/opt/aarch64-pc-msys/bin/$tool.exe")" = \
    mingw-w64-cross-msysarm64-gcc
done
for input in libmsys-2.0.a libkernel32.a libgcc.a; do
  path=$(aarch64-pc-msys-gcc -print-file-name="$input")
  test -f "$path"
  aarch64-pc-msys-objdump -f "$path" | grep -F 'architecture: aarch64'
done
macros=$(aarch64-pc-msys-gcc -dM -E - < /dev/null)
for macro in __aarch64__ __CYGWIN__ __MSYS__ _WIN64; do
  grep -Eq "^#define $macro([[:space:]]|$)" <<< "$macros"
done
! grep -Eq '^#define (__x86_64__|_M_X64)([[:space:]]|$)' <<< "$macros"
'@
& $bash -lc $preflight
if ($LASTEXITCODE -ne 0) {
    throw 'Installed AArch64 MSYS toolchain preflight failed'
}

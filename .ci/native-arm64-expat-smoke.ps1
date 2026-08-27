[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $MsysRoot,

    [Parameter(Mandatory = $true)]
    [string] $PackageDir,

    [Parameter(Mandatory = $true)]
    [string] $ReportRoot,

    [Parameter(Mandatory = $true)]
    [string] $BinutilsReleaseTag,

    [Parameter(Mandatory = $true)]
    [string] $BinutilsAssetName,

    [Parameter(Mandatory = $true)]
    [string] $BinutilsSha256,

    [Parameter(Mandatory = $true)]
    [string] $BinutilsVersion,

    [string] $GitHubToken = $env:GITHUB_TOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Group
    )

    Write-Host "::group::$Group"
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Group failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Write-Host '::endgroup::'
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw "Not an MZ executable: $Path"
        }
        [void] $stream.Seek(0x3c, [System.IO.SeekOrigin]::Begin)
        $peOffset = $reader.ReadInt32()
        [void] $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin)
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Missing PE signature: $Path"
        }
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Get-MsysPath {
    param(
        [Parameter(Mandatory = $true)][string] $Cygpath,
        [Parameter(Mandatory = $true)][string] $WindowsPath
    )

    $result = & $Cygpath -u $WindowsPath
    if ($LASTEXITCODE -ne 0) {
        throw "cygpath failed for $WindowsPath"
    }
    return ($result | Select-Object -Last 1).Trim()
}

if (-not $GitHubToken) {
    throw 'GITHUB_TOKEN is required'
}

$MsysRoot = [System.IO.Path]::GetFullPath($MsysRoot)
$PackageDir = [System.IO.Path]::GetFullPath($PackageDir)
$ReportRoot = [System.IO.Path]::GetFullPath($ReportRoot)
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'Arm64') {
    throw "Native ARM64 Windows is required: $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
}
if (-not (Test-Path -LiteralPath $MsysRoot -PathType Container)) {
    throw "MSYS2 root does not exist: $MsysRoot"
}
if (-not (Test-Path -LiteralPath $PackageDir -PathType Container)) {
    throw "Package directory does not exist: $PackageDir"
}
if (Test-Path -LiteralPath $ReportRoot) {
    throw "Report directory must be fresh: $ReportRoot"
}

New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$hostArchitecture = [ordered]@{
    os_architecture =
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    process_architecture =
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    processor_architecture = $env:PROCESSOR_ARCHITECTURE
    processor_architew6432 = $env:PROCESSOR_ARCHITEW6432
}
$hostArchitecture |
    ConvertTo-Json |
    Set-Content -Encoding utf8NoBOM (Join-Path $ReportRoot 'host-architecture.json')
$inputDir = Join-Path $ReportRoot 'inputs'
$validationDir = Join-Path $ReportRoot 'validation'
New-Item -ItemType Directory -Path $inputDir, $validationDir | Out-Null

$env:GH_TOKEN = $GitHubToken
$releaseGroups = @(
    @{
        Tag = $BinutilsReleaseTag
        Assets = @(
            @{ Name = $BinutilsAssetName; Sha256 = $BinutilsSha256 }
        )
    },
    @{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
                Sha256 = '063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e'
            },
            @{
                Name = 'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
                Sha256 = '17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c'
            }
        )
    },
    @{
        Tag = 'cygwinarm64-sysroot-pr3-20260813'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-cygwinarm64-headers-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst'
                Sha256 = '5266346cc10b142f871704ce4277699b1a5daa3121dc869990b4bedce69c0611'
            },
            @{
                Name = 'mingw-w64-cross-cygwinarm64-windows-default-manifest-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst'
                Sha256 = 'cc089511fede6042a25f83fcb5903fddeede89ddd9655360741513ee9015e3dc'
            },
            @{
                Name = 'mingw-w64-cross-cygwinarm64-sysroot-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst'
                Sha256 = '4ed8a30f592317bf7e4def6f3c773139f2565b0f8afaedd820f7ee46d33cad20'
            }
        )
    },
    @{
        Tag = 'cygwinarm64-w32api-20260813'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-cygwinarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
                Sha256 = '53478f9a60e2fdad7d3b4357fa4fb937a1afab16af16a55e5a25ae9fac308fa7'
            }
        )
    },
    @{
        Tag = 'cygwinarm64-libstdcxx-headers-pr7-20260815'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
                Sha256 = '1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6'
            }
        )
    },
    @{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                Sha256 = '263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21'
            },
            @{
                Name = 'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                Sha256 = '33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f'
            },
            @{
                Name = 'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                Sha256 = 'e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca'
            },
            @{
                Name = 'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
            },
            @{
                Name = 'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                Sha256 = 'c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1'
            }
        )
    },
    @{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
                Sha256 = '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24'
            },
            @{
                Name = 'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
                Sha256 = '9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08'
            }
        )
    },
    @{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Assets = @(
            @{
                Name = 'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
                Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
            },
            @{
                Name = 'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
                Sha256 = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'
            }
        )
    }
)

$inputAssets = [System.Collections.Generic.List[object]]::new()
foreach ($group in $releaseGroups) {
    $arguments = @(
        'release', 'download', $group.Tag,
        '--repo', 'crutkas/MSYS2-packages',
        '--dir', $inputDir
    )
    foreach ($asset in $group.Assets) {
        $arguments += @('--pattern', $asset.Name)
        $inputAssets.Add($asset)
    }
    Invoke-External -FilePath 'gh' -Arguments $arguments -Group "Download $($group.Tag)"
}

foreach ($asset in $inputAssets) {
    $path = Join-Path $inputDir $asset.Name
    $actual = Get-Sha256 -Path $path
    if ($actual -ne $asset.Sha256) {
        throw "SHA-256 mismatch for $($asset.Name): $actual"
    }
}
$prerequisiteManifest = foreach ($asset in $inputAssets) {
    '{0}  {1}' -f $asset.Sha256, $asset.Name
}
$prerequisiteManifest |
    Set-Content -Encoding ascii (Join-Path $ReportRoot 'prerequisite-sha256.txt')

$expatPackages = @(
    Get-ChildItem -LiteralPath $PackageDir -File |
        Where-Object { $_.Name -like 'mingw-w64-cross-msysarm64-*expat*-2.7.1-1-x86_64.pkg.tar.zst' } |
        Sort-Object Name
)
if ($expatPackages.Count -ne 3) {
    throw "Expected three Expat package archives, found $($expatPackages.Count)"
}

$packageManifest = foreach ($package in $expatPackages) {
    '{0}  {1}' -f (Get-Sha256 -Path $package.FullName), $package.Name
}
$packageManifest | Set-Content -Encoding ascii (Join-Path $ReportRoot 'expat-package-sha256.txt')

$pacman = Join-Path $MsysRoot 'usr\bin\pacman.exe'
$cygpath = Join-Path $MsysRoot 'usr\bin\cygpath.exe'
$bash = Join-Path $MsysRoot 'usr\bin\bash.exe'
$bootstrapNames = @(
    $BinutilsAssetName,
    'mingw-w64-cross-cygwinarm64-headers-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-cygwinarm64-windows-default-manifest-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-cygwinarm64-sysroot-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-cygwinarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst',
    'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
)
$finalNames = @(
    'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
)

$savedMsys = $env:MSYS
try {
    $env:MSYS = 'winsymlinks:sys'
    Invoke-External -FilePath $pacman `
        -Arguments (@('--noconfirm', '-U') + @($bootstrapNames | ForEach-Object { Join-Path $inputDir $_ })) `
        -Group 'Install bootstrap toolchain'
    Invoke-External -FilePath $pacman `
        -Arguments (@('--noconfirm', '-U') + @($finalNames | ForEach-Object { Join-Path $inputDir $_ })) `
        -Group 'Install final toolchain atomically'
    Invoke-External -FilePath $pacman `
        -Arguments (@('--noconfirm', '-U') + @($expatPackages.FullName)) `
        -Group 'Install Expat packages atomically'
}
finally {
    $env:MSYS = $savedMsys
}

$expectedPackages = [ordered]@{
    'mingw-w64-cross-cygwinarm64-binutils' = $BinutilsVersion
    'mingw-w64-cross-msysarm64-runtime' = '3.6.10.r0.ga527ace21-1'
    'mingw-w64-cross-msysarm64-runtime-devel' = '3.6.10.r0.ga527ace21-1'
    'mingw-w64-cross-msysarm64-sysroot' = '3.6.10.r0.ga527ace21-1'
    'mingw-w64-cross-msysarm64-gcc-libs' = '15.0.1dev-1'
    'mingw-w64-cross-msysarm64-gcc' = '15.0.1dev-1'
    'mingw-w64-cross-msysarm64-expat' = '2.7.1-1'
    'mingw-w64-cross-msysarm64-libexpat' = '2.7.1-1'
    'mingw-w64-cross-msysarm64-libexpat-devel' = '2.7.1-1'
}
$installed = foreach ($entry in $expectedPackages.GetEnumerator()) {
    $actual = (& $pacman -Q $entry.Key) -join ''
    if ($LASTEXITCODE -ne 0 -or $actual -ne "$($entry.Key) $($entry.Value)") {
        throw "Package identity mismatch: expected $($entry.Key) $($entry.Value), got $actual"
    }
    $actual
}
$installed | Set-Content -Encoding ascii (Join-Path $ReportRoot 'installed-packages.txt')
$integrity = foreach ($entry in $expectedPackages.GetEnumerator()) {
    $output = & $pacman -Qk $entry.Key
    if ($LASTEXITCODE -ne 0) {
        throw "Package integrity check failed: $($entry.Key)"
    }
    $output
}
$integrity | Set-Content -Encoding ascii (Join-Path $ReportRoot 'package-integrity.txt')
$linker = Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-ld.exe'
if ((Get-Sha256 -Path $linker) -ne '075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f') {
    throw 'Installed fixed linker identity mismatch'
}
Remove-Item -LiteralPath $inputDir -Recurse -Force

$targetRoot = Join-Path $MsysRoot 'opt\aarch64-pc-msys'
$expatDll = Join-Path $targetRoot 'usr\bin\msys-expat-1.dll'
$xmlwf = Join-Path $targetRoot 'usr\bin\xmlwf.exe'
$scanner = Join-Path $targetRoot `
    'share\doc\mingw-w64-cross-msysarm64-expat\check-aarch64-pseudo-relocs.ps1'
if ((Get-Sha256 -Path $scanner) -ne '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') {
    throw 'Installed canonical pseudo-reloc scanner identity mismatch'
}
foreach ($path in @($expatDll, $xmlwf)) {
    $machine = Get-PeMachine -Path $path
    if ($machine -ne 0xaa64) {
        throw "Expected AA64 PE machine for $path, got $('0x{0:x4}' -f $machine)"
    }
}

$validationMsys = Get-MsysPath -Cygpath $cygpath -WindowsPath $validationDir
$env:MSYSTEM = 'MSYS'
$env:MSYS2_PATH_TYPE = 'inherit'
$validator = @"
set -euo pipefail
export PATH=/usr/bin:/opt/bin:`$PATH
EXPECTED_VERSION=2.7.1 RUN_NATIVE=1 NATIVE_HOST_ARCH=arm64 \
  bash /opt/aarch64-pc-msys/share/doc/mingw-w64-cross-msysarm64-expat/validate-expat.sh \
    /opt/aarch64-pc-msys '$validationMsys'
"@
Invoke-External -FilePath $bash -Arguments @('--login', '-lc', $validator) `
    -Group 'Run native Expat validator'

$nativeReport = Get-Content -LiteralPath (Join-Path $validationDir 'native-execution.txt')
if (
    @($nativeReport | Where-Object { $_ -match '^dynamic\s+expat-xml-smoke-ok$' }).Count -ne 1 -or
    @($nativeReport | Where-Object { $_ -match '^static\s+expat-xml-smoke-ok$' }).Count -ne 1 -or
    @($nativeReport | Where-Object { $_ -match '^status\s+executed$' }).Count -ne 1
) {
    throw "Native XML API smoke did not execute successfully: $nativeReport"
}
$pseudoReport = Get-Content -LiteralPath (Join-Path $validationDir 'pseudo-relocations.txt')
if (@($pseudoReport | Where-Object { $_ -notmatch "`tempty$" }).Count -ne 0) {
    throw "A non-empty pseudo-relocation list was reported: $pseudoReport"
}

$sample = Join-Path $ReportRoot 'xmlwf-native-smoke.xml'
'<root><child value="native-arm64"/></root>' |
    Set-Content -Encoding ascii -LiteralPath $sample
$sampleMsys = Get-MsysPath -Cygpath $cygpath -WindowsPath $sample
$xmlwfSmoke = @"
set -euo pipefail
export PATH=/opt/aarch64-pc-msys/usr/bin:/opt/aarch64-pc-msys/bin:`$PATH
/opt/aarch64-pc-msys/usr/bin/xmlwf.exe '$sampleMsys'
printf 'xmlwf-native-ok\n'
"@
$xmlwfOutput = & $bash --login -lc $xmlwfSmoke
if ($LASTEXITCODE -ne 0 -or $xmlwfOutput -notcontains 'xmlwf-native-ok') {
    throw "Native xmlwf smoke failed: $xmlwfOutput"
}
$xmlwfOutput | Set-Content -Encoding ascii (Join-Path $ReportRoot 'xmlwf-native-smoke.txt')

$manifestPath = Join-Path $ReportRoot 'evidence-sha256.txt'
$manifest = Get-ChildItem -LiteralPath $ReportRoot -Recurse -File |
    Where-Object { $_.FullName -ne $manifestPath } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($ReportRoot.Length + 1).Replace('\', '/')
        '{0}  {1}' -f (Get-Sha256 -Path $_.FullName), $relative
    }
$manifest | Set-Content -Encoding ascii $manifestPath
$seal = Get-Sha256 -Path $manifestPath
"$seal  evidence-sha256.txt" |
    Set-Content -Encoding ascii (Join-Path $ReportRoot 'evidence-seal.txt')
Write-Host "Native ARM64 Expat evidence seal: $seal"

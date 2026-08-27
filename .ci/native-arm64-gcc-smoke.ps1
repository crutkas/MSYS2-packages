[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $MsysRoot,

    [Parameter(Mandatory = $true)]
    [string] $ReportRoot,

    [string] $GitHubToken = $env:GITHUB_TOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-FileIdentity {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $Size,
        [Parameter(Mandatory = $true)][string] $Sha256
    )

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Size) {
        throw "Size mismatch for $($item.Name): expected $Size, got $($item.Length)"
    }

    $actualHash = Get-Sha256 -Path $Path
    if ($actualHash -ne $Sha256) {
        throw "SHA-256 mismatch for $($item.Name): expected $Sha256, got $actualHash"
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Group
    )

    Write-Host "::group::$Group"
    $exitCode = -1
    try {
        & $FilePath @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        Write-Host '::endgroup::'
    }

    if ($exitCode -ne 0) {
        throw "$Group failed with exit code $exitCode"
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
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
    throw 'GITHUB_TOKEN is required to read the pinned prerequisite artifact'
}

$MsysRoot = [System.IO.Path]::GetFullPath($MsysRoot)
$ReportRoot = [System.IO.Path]::GetFullPath($ReportRoot)
if (-not (Test-Path -LiteralPath $MsysRoot -PathType Container)) {
    throw "MSYS2 root does not exist: $MsysRoot"
}
if (Test-Path -LiteralPath $ReportRoot) {
    throw "Report directory must be fresh: $ReportRoot"
}

New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$transcriptPath = Join-Path $ReportRoot 'powershell-transcript.txt'
$transcriptStarted = $false
Start-Transcript -Path $transcriptPath | Out-Null
$transcriptStarted = $true

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NativeArchitecture {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine);
}
'@

    [uint16] $processMachine = 0
    [uint16] $nativeMachine = 0
    $architectureCall = [NativeArchitecture]::IsWow64Process2(
        [System.Diagnostics.Process]::GetCurrentProcess().Handle,
        [ref] $processMachine,
        [ref] $nativeMachine
    )
    if (-not $architectureCall) {
        throw "IsWow64Process2 failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $osArchitecture =
        [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processorArchitectures = @(
        Get-CimInstance -ClassName Win32_Processor |
            ForEach-Object { [int] $_.Architecture }
    )
    $architecture = [ordered]@{
        PROCESSOR_ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE
        PROCESSOR_ARCHITEW6432 = $env:PROCESSOR_ARCHITEW6432
        runtime_os_architecture = $osArchitecture
        process_machine = ('0x{0:x4}' -f $processMachine)
        native_machine = ('0x{0:x4}' -f $nativeMachine)
        cim_processor_architectures = $processorArchitectures
    }
    $architecture |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $ReportRoot 'host-architecture.json')
    $architecture | Format-List | Out-String | Write-Host

    if ($nativeMachine -ne 0xaa64 -or $osArchitecture -ne 'Arm64') {
        throw "The runner is not native ARM64: native=$('0x{0:x4}' -f $nativeMachine), OS=$osArchitecture"
    }
    if (
        $processorArchitectures.Count -eq 0 -or
        @($processorArchitectures | Where-Object { $_ -ne 12 }).Count -ne 0
    ) {
        throw "Win32_Processor did not report ARM64 architecture 12: $processorArchitectures"
    }

    $releaseGroups = @(
        @{
            Tag = 'cygwinarm64-gcc-static-runtime-20260815'
            Assets = @(
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-binutils-2.44.50-1-x86_64.pkg.tar.zst'
                    Size = 6525338L
                    Sha256 = '8908cb690952788153b60bc4fb659826bbd8a03a26c1073f76c0be7ed6f97518'
                },
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
                    Size = 357954L
                    Sha256 = '17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c'
                },
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
                    Size = 43966034L
                    Sha256 = '063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e'
                }
            )
        },
        @{
            Tag = 'cygwinarm64-sysroot-pr3-20260813'
            Assets = @(
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-headers-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst'
                    Size = 9319165L
                    Sha256 = '5266346cc10b142f871704ce4277699b1a5daa3121dc869990b4bedce69c0611'
                },
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-sysroot-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst'
                    Size = 87021L
                    Sha256 = '4ed8a30f592317bf7e4def6f3c773139f2565b0f8afaedd820f7ee46d33cad20'
                },
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-windows-default-manifest-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst'
                    Size = 4841L
                    Sha256 = 'cc089511fede6042a25f83fcb5903fddeede89ddd9655360741513ee9015e3dc'
                }
            )
        },
        @{
            Tag = 'cygwinarm64-w32api-20260813'
            Assets = @(
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
                    Size = 4186012L
                    Sha256 = '53478f9a60e2fdad7d3b4357fa4fb937a1afab16af16a55e5a25ae9fac308fa7'
                }
            )
        },
        @{
            Tag = 'cygwinarm64-libstdcxx-headers-pr7-20260815'
            Assets = @(
                @{
                    Name = 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
                    Size = 2184212L
                    Sha256 = '1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6'
                }
            )
        },
        @{
            Tag = 'msysarm64-runtime-pr10-a527-20260824'
            Assets = @(
                @{
                    Name = 'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                    Size = 9319013L
                    Sha256 = '263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                    Size = 9893043L
                    Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                    Size = 4426157L
                    Sha256 = 'c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                    Size = 86822L
                    Sha256 = 'e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
                    Size = 4743L
                    Sha256 = '33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f'
                }
            )
        },
        @{
            Tag = 'msysarm64-gcc-pr13-20260826'
            Assets = @(
                @{
                    Name = 'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
                    Size = 83876291L
                    Sha256 = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
                    Size = 4963824L
                    Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
                    Size = 1519710L
                    Sha256 = '3c49988d2540c5dafb1aae8c8702b944c8c02171ceafdad65f4f2a8194d00087'
                },
                @{
                    Name = 'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
                    Size = 2349635L
                    Sha256 = '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24'
                }
            )
        }
    )

    $apiHeaders = @{
        Accept = 'application/vnd.github+json'
        Authorization = "Bearer $GitHubToken"
        'User-Agent' = 'native-arm64-gcc-smoke'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    $downloadRoot = Join-Path $env:RUNNER_TEMP "native-arm64-gcc-$([guid]::NewGuid().ToString('N'))"
    $releaseRoot = Join-Path $downloadRoot 'release-assets'
    New-Item -ItemType Directory -Path $releaseRoot | Out-Null

    $assetPaths = @{}
    $downloadEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $releaseGroups) {
        $tag = [string] $group.Tag
        $releaseUri =
            "https://api.github.com/repos/crutkas/MSYS2-packages/releases/tags/$tag"
        $release = Invoke-RestMethod -Uri $releaseUri -Headers $apiHeaders
        if ($release.tag_name -ne $tag -or $release.draft) {
            throw "Release identity mismatch for $tag"
        }

        $expectedNames = @($group.Assets | ForEach-Object { $_.Name } | Sort-Object)
        $packageAssets = @(
            $release.assets |
                Where-Object { $_.name.EndsWith('.pkg.tar.zst') }
        )
        $actualNames = @($packageAssets | ForEach-Object { $_.name } | Sort-Object)
        $nameDifference = @(
            Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames
        )
        if ($nameDifference.Count -ne 0) {
            throw "Package asset set changed for $tag`: $($nameDifference | Out-String)"
        }

        foreach ($expected in $group.Assets) {
            $matching = @($packageAssets | Where-Object { $_.name -eq $expected.Name })
            if ($matching.Count -ne 1) {
                throw "Expected one release asset named $($expected.Name), got $($matching.Count)"
            }
            $remote = $matching[0]
            if ([long] $remote.size -ne [long] $expected.Size) {
                throw "Release metadata size mismatch for $($expected.Name)"
            }

            $destination = Join-Path $releaseRoot $expected.Name
            Invoke-WebRequest -Uri $remote.browser_download_url -OutFile $destination
            Assert-FileIdentity `
                -Path $destination `
                -Size $expected.Size `
                -Sha256 $expected.Sha256
            $assetPaths[$expected.Name] = $destination
            $downloadEvidence.Add([ordered]@{
                source = "release:$tag"
                name = $expected.Name
                bytes = [long] $expected.Size
                sha256 = $expected.Sha256
                url = $remote.browser_download_url
            })
        }
    }

    $downloadEvidence |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $ReportRoot 'download-evidence.json')

    $targetRoot = Join-Path $MsysRoot 'opt\aarch64-pc-msys'
    $cygwinTargetRoot = Join-Path $MsysRoot 'opt\aarch64-pc-cygwin'
    if (
        (Test-Path -LiteralPath $targetRoot) -or
        (Test-Path -LiteralPath $cygwinTargetRoot)
    ) {
        throw 'The MSYS2 installation is not fresh: an ARM64 target prefix already exists'
    }

    $pacman = Join-Path $MsysRoot 'usr\bin\pacman.exe'
    if (-not (Test-Path -LiteralPath $pacman -PathType Leaf)) {
        throw "pacman is missing: $pacman"
    }
    $env:MSYS = 'winsymlinks:sys'
    $env:MSYSTEM = 'MSYS'

    function Install-Transaction {
        param(
            [Parameter(Mandatory = $true)][string] $Name,
            [Parameter(Mandatory = $true)][string[]] $Packages
        )

        $paths = @(
            foreach ($package in $Packages) {
                if (-not $assetPaths.ContainsKey($package)) {
                    throw "No verified download for $package"
                }
                $assetPaths[$package]
            }
        )
        Invoke-External `
            -FilePath $pacman `
            -Arguments (@('--noconfirm', '--noprogressbar', '-U') + $paths) `
            -Group $Name
    }

    Install-Transaction -Name 'Install Cygwin ARM64 bootstrap atomically' -Packages @(
        'mingw-w64-cross-cygwinarm64-binutils-2.44.50-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-headers-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-windows-default-manifest-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-sysroot-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst',
        'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
    )

    Install-Transaction -Name 'Install final ARM64 MSYS runtime stack atomically' -Packages @(
        'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
    )

    Install-Transaction -Name 'Install final ARM64 MSYS GCC split atomically' -Packages @(
        'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst',
        'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
    )

    $bash = Join-Path $MsysRoot 'usr\bin\bash.exe'
    $cygpath = Join-Path $MsysRoot 'usr\bin\cygpath.exe'
    $bashHarness = Join-Path $PSScriptRoot 'native-arm64-gcc-smoke.sh'
    $bashHarnessUnix = Get-MsysPath -Cygpath $cygpath -WindowsPath $bashHarness
    $reportUnix = Get-MsysPath -Cygpath $cygpath -WindowsPath $ReportRoot
    Invoke-External `
        -FilePath $bash `
        -Arguments @('--noprofile', '--norc', $bashHarnessUnix, $reportUnix) `
        -Group 'Verify packages, compile, link, and audit ARM64 outputs'

    $compiler = Join-Path $MsysRoot 'opt\bin\aarch64-pc-msys-gcc.exe'
    $compilerMachine = Get-PeMachine -Path $compiler
    if ($compilerMachine -ne 0x8664) {
        throw "Expected the released host compiler to be x86-64 (0x8664), got $('0x{0:x4}' -f $compilerMachine)"
    }
    [ordered]@{
        path = $compiler
        machine = ('0x{0:x4}' -f $compilerMachine)
        execution = 'Windows ARM64 x86-64 emulation'
    } |
        ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $ReportRoot 'host-compiler-architecture.json')

    $nativeRun = Join-Path $ReportRoot 'native-run'
    New-Item -ItemType Directory -Path $nativeRun | Out-Null
    $binaryExpectations = [ordered]@{
        'basic-c.exe' = 'basic-c-ok'
        'cxx-runtime.exe' = 'cxx-runtime-ok'
        'thread-runtime.exe' = 'thread-runtime-ok'
        'process-runtime.exe' = 'process-runtime-ok'
        'lto-bridge.exe' = 'lto-bridge-ok'
    }
    foreach ($binaryName in $binaryExpectations.Keys) {
        Copy-Item `
            -LiteralPath (Join-Path $ReportRoot "binaries\$binaryName") `
            -Destination (Join-Path $nativeRun $binaryName)
    }

    $runtimeDlls = @(
        (Join-Path $MsysRoot 'opt\aarch64-pc-msys\bin\msys-2.0.dll'),
        (Join-Path $MsysRoot 'opt\lib\gcc\aarch64-pc-msys\msys-gcc_s-seh-1.dll'),
        (Join-Path $MsysRoot 'opt\lib\gcc\aarch64-pc-msys\15.0.1\msys-stdc++-6.dll')
    )
    foreach ($runtimeDll in $runtimeDlls) {
        Copy-Item -LiteralPath $runtimeDll -Destination $nativeRun
    }

    $nativeFiles = @(
        Get-ChildItem -LiteralPath $nativeRun -File |
            Where-Object { $_.Extension -in @('.exe', '.dll') }
    )
    $peEvidence = foreach ($file in $nativeFiles) {
        $machine = Get-PeMachine -Path $file.FullName
        if ($machine -ne 0xaa64) {
            throw "Native payload is not ARM64: $($file.Name) => $('0x{0:x4}' -f $machine)"
        }
        [ordered]@{
            name = $file.Name
            machine = ('0x{0:x4}' -f $machine)
            sha256 = Get-Sha256 -Path $file.FullName
        }
    }
    $peEvidence |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $ReportRoot 'native-pe-evidence.json')

    $env:MSYS = 'winsymlinks:sys'
    $env:MSYSTEM = 'MSYS'
    Push-Location $nativeRun
    try {
        foreach ($entry in $binaryExpectations.GetEnumerator()) {
            $outputPath = Join-Path $ReportRoot "$($entry.Key).stdout.txt"
            $output = @(& (Join-Path $nativeRun $entry.Key) 2>&1)
            $exitCode = $LASTEXITCODE
            $output | ForEach-Object { $_.ToString() } | Set-Content -LiteralPath $outputPath
            $output | ForEach-Object { Write-Host $_ }
            if ($exitCode -ne 0) {
                throw "$($entry.Key) failed natively with exit code $exitCode"
            }
            if (@($output | ForEach-Object { $_.ToString() }) -notcontains $entry.Value) {
                throw "$($entry.Key) did not emit required marker '$($entry.Value)'"
            }
        }
    }
    finally {
        Pop-Location
    }

    @(
        'runner-native-machine=0xaa64'
        'target-pe-machine=0xaa64'
        'target-format=pei-aarch64-little'
        'runtime-import=msys-2.0.dll'
        'windows-import=KERNEL32.dll'
        'native-tests=basic-c,cxx-runtime,thread-runtime,process-runtime,lto-bridge'
        'result=success'
    ) | Set-Content -LiteralPath (Join-Path $ReportRoot 'native-smoke-summary.txt')
}
finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}

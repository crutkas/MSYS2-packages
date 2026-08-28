[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHeadSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

$repository = $env:GITHUB_REPOSITORY
$branchCandidates = @($env:GITHUB_REF_NAME, $env:GITHUB_HEAD_REF) |
    Where-Object { $_ }
if ($repository -ne 'crutkas/MSYS2-packages') {
    throw "Refusing fork-only native smoke in $repository"
}
if ($branchCandidates -notcontains 'crutkas-arm64-msys-libuuid') {
    throw "Refusing libuuid native smoke for refs: $($branchCandidates -join ', ')"
}
$sourceRoot = Split-Path -Parent $PSScriptRoot
$actualHeadSha = (git -C $sourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHeadSha -ne $ExpectedHeadSha) {
    throw "Checked-out commit mismatch: expected=$ExpectedHeadSha actual=$actualHeadSha"
}

$arm64Processors = @(Get-CimInstance Win32_Processor |
    Where-Object { $_.Architecture -eq 12 })
if ($arm64Processors.Count -eq 0) {
    throw 'Native smoke requires an ARM64 Windows host'
}
$systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $systemTar -PathType Leaf)) {
    throw "Missing Windows archive tool: $systemTar"
}

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

    & curl.exe --fail --location --retry 5 --silent --show-error `
        --output $Path $Uri
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed: $Uri"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) {
        throw "SHA-256 mismatch for $([IO.Path]::GetFileName($Path)): $actual"
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64) {
        throw "Not a PE file: $Path"
    }
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3c)
    if ($peOffset + 6 -gt $bytes.Length) {
        throw "Invalid PE header offset: $Path"
    }
    if ($bytes[$peOffset] -ne 0x50 -or
        $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or
        $bytes[$peOffset + 3] -ne 0) {
        throw "Missing PE signature: $Path"
    }
    return [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

function Get-Wow64Attestation {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    [ushort]$processMachine = 0
    [ushort]$nativeMachine = 0
    if (-not [NativeArchitecture]::IsWow64Process2(
        $Process.Handle,
        [ref]$processMachine,
        [ref]$nativeMachine)) {
        throw "IsWow64Process2 failed for PID $($Process.Id): $(
            [Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $effectiveMachine = if ($processMachine -eq 0) {
        $nativeMachine
    }
    else {
        $processMachine
    }
    return [ordered]@{
        process_machine = '0x{0:x4}' -f $processMachine
        native_machine = '0x{0:x4}' -f $nativeMachine
        effective_machine = '0x{0:x4}' -f $effectiveMachine
    }
}

function Assert-SafeArchive {
    param([Parameter(Mandatory = $true)][string]$Archive)

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
    }
    $linkLines = @(& $script:systemTar -tvf $Archive |
        Where-Object { $_ -match '^[lh]' })
    foreach ($line in $linkLines) {
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
    }
    return [ordered]@{
        entries = $entries.Count
        links = $linkLines.Count
    }
}

function Expand-SafeArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $preflight = Assert-SafeArchive -Archive $Archive
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    & $script:systemTar -xf $Archive -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract $Archive"
    }
    $destinationRoot = [IO.Path]::GetFullPath($Destination).
        TrimEnd('\') + '\'
    foreach ($link in Get-ChildItem -LiteralPath $Destination -Recurse -Force |
        Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }) {
        foreach ($target in @($link.Target)) {
            if ([IO.Path]::IsPathRooted($target)) {
                throw "Extracted archive link is absolute: $($link.FullName)"
            }
            $resolved = [IO.Path]::GetFullPath(
                (Join-Path $link.DirectoryName $target))
            if (-not $resolved.StartsWith(
                $destinationRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
                throw "Extracted archive link escapes root: $($link.FullName)"
            }
        }
    }
    return $preflight
}

function Get-OnlyFile {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Filter
    )

    $files = @(Get-ChildItem -LiteralPath $Directory -Filter $Filter -File)
    if ($files.Count -ne 1) {
        throw "Expected one $Filter in $Directory, found $($files.Count)"
    }
    return $files[0].FullName
}

$work = Join-Path $env:RUNNER_TEMP 'msysarm64-libuuid-native-private'
$downloads = Join-Path $work 'downloads'
$evidenceDirectory = Join-Path $ArtifactDirectory 'native-smoke-evidence'
foreach ($path in @($work, $evidenceDirectory)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
New-Item -ItemType Directory -Force -Path $downloads, $evidenceDirectory |
    Out-Null

$hostToolAssets = @(
    [pscustomobject]@{
        Name = 'gcc-libs-15.3.0-1-x86_64.pkg.tar.zst'
        Uri = 'https://repo.msys2.org/msys/x86_64/gcc-libs-15.3.0-1-x86_64.pkg.tar.zst'
        Sha256 = '0d99a122c453c05ae21ba3dcea910f2e0d93d38ae067c677a112a315b0f3cec5'
    },
    [pscustomobject]@{
        Name = 'libiconv-1.19-1-x86_64.pkg.tar.zst'
        Uri = 'https://repo.msys2.org/msys/x86_64/libiconv-1.19-1-x86_64.pkg.tar.zst'
        Sha256 = '0fa55ea2a6ccf97cf8c58b24b2615815e15e16e6e4e888091c263c2c83c5313d'
    },
    [pscustomobject]@{
        Name = 'libintl-0.22.5-1-x86_64.pkg.tar.zst'
        Uri = 'https://repo.msys2.org/msys/x86_64/libintl-0.22.5-1-x86_64.pkg.tar.zst'
        Sha256 = '336d66b9d95cf9c1804958f8e260762a3e83bf158ed5981f783bc772a31073cf'
    },
    [pscustomobject]@{
        Name = 'msys2-runtime-3.6.10-3-x86_64.pkg.tar.zst'
        Uri = 'https://repo.msys2.org/msys/x86_64/msys2-runtime-3.6.10-3-x86_64.pkg.tar.zst'
        Sha256 = '4dfcff2f7bde98f30dbd5d3773320e2ce2b06d9175a53fee6a18621637e3f3d1'
    },
    [pscustomobject]@{
        Name = 'zlib-1.3.2-1-x86_64.pkg.tar.zst'
        Uri = 'https://repo.msys2.org/msys/x86_64/zlib-1.3.2-1-x86_64.pkg.tar.zst'
        Sha256 = 'a04aa79996c57f0db936be66cf94326d7e67e9cd8dbffe4cf6e97693d0a1d9ef'
    }
)
$publishedAssets = @(
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-gcc-pr13-20260826/mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/cygwinarm64-binutils-pr21-3356eec-20260827/mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        Sha256 = '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b'
    }
)

$inputRecords = @($hostToolAssets) + @($publishedAssets)
foreach ($asset in $inputRecords) {
    $path = Join-Path $downloads $asset.Name
    Invoke-Download -Uri $asset.Uri -Path $path -Sha256 $asset.Sha256
}

$runtimePackage = Get-OnlyFile `
    -Directory $ArtifactDirectory `
    -Filter 'mingw-w64-cross-msysarm64-libuuid-2.40.2-2-x86_64.pkg.tar.*'
$develPackage = Get-OnlyFile `
    -Directory $ArtifactDirectory `
    -Filter 'mingw-w64-cross-msysarm64-libuuid-devel-2.40.2-2-x86_64.pkg.tar.*'

$toolRoot = Join-Path $work 'tool-root'
$runtimeRoot = Join-Path $work 'runtime'
$gccRoot = Join-Path $work 'gcc-libs'
$libuuidRoot = Join-Path $work 'libuuid'
$develRoot = Join-Path $work 'libuuid-devel'
$preflightLines = [Collections.Generic.List[string]]::new()
foreach ($asset in $hostToolAssets) {
    $archive = Join-Path $downloads $asset.Name
    $preflight = Expand-SafeArchive -Archive $archive -Destination $toolRoot
    $preflightLines.Add(
        "$($asset.Name)`t$($preflight.entries)`t$($preflight.links)`tpass")
}
$fixedPreflight = Expand-SafeArchive `
    -Archive (Join-Path $downloads $publishedAssets[2].Name) `
    -Destination $toolRoot
$preflightLines.Add(
    "$($publishedAssets[2].Name)`t$($fixedPreflight.entries)`t$(
        $fixedPreflight.links)`tpass")
$runtimePreflight = Expand-SafeArchive `
    -Archive (Join-Path $downloads $publishedAssets[0].Name) `
    -Destination $runtimeRoot
$preflightLines.Add(
    "$($publishedAssets[0].Name)`t$($runtimePreflight.entries)`t$(
        $runtimePreflight.links)`tpass")
$gccPreflight = Expand-SafeArchive `
    -Archive (Join-Path $downloads $publishedAssets[1].Name) `
    -Destination $gccRoot
$preflightLines.Add(
    "$($publishedAssets[1].Name)`t$($gccPreflight.entries)`t$(
        $gccPreflight.links)`tpass")
$runtimeOutputPreflight = Expand-SafeArchive `
    -Archive $runtimePackage `
    -Destination $libuuidRoot
$preflightLines.Add(
    "$([IO.Path]::GetFileName($runtimePackage))`t$(
        $runtimeOutputPreflight.entries)`t$(
        $runtimeOutputPreflight.links)`tpass")
$develOutputPreflight = Expand-SafeArchive `
    -Archive $develPackage `
    -Destination $develRoot
$preflightLines.Add(
    "$([IO.Path]::GetFileName($develPackage))`t$(
        $develOutputPreflight.entries)`t$(
        $develOutputPreflight.links)`tpass")
Write-Utf8NoBom `
    -Path (Join-Path $evidenceDirectory 'archive-preflight.tsv') `
    -Lines (@("archive`tentries`tlinks`tresult") + @($preflightLines))

$scanner = Join-Path $develRoot `
    'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\check-aarch64-pseudo-relocs-3356eec.ps1'
$objdump = Join-Path $toolRoot 'opt\bin\aarch64-pc-cygwin-objdump.exe'
$nm = Join-Path $toolRoot 'opt\bin\aarch64-pc-cygwin-nm.exe'
$linker = Join-Path $toolRoot 'opt\bin\aarch64-pc-cygwin-ld.exe'
$toolBindings = [ordered]@{
    scanner = (Get-FileHash -Algorithm SHA256 $scanner).
        Hash.ToLowerInvariant()
    objdump = (Get-FileHash -Algorithm SHA256 $objdump).
        Hash.ToLowerInvariant()
    nm = (Get-FileHash -Algorithm SHA256 $nm).Hash.ToLowerInvariant()
    linker = (Get-FileHash -Algorithm SHA256 $linker).Hash.ToLowerInvariant()
}
if ($toolBindings.scanner -ne
    '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') {
    throw 'Canonical pseudo-reloc scanner hash mismatch'
}
if ($toolBindings.linker -ne
    '075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f') {
    throw 'Canonical linker hash mismatch'
}
[IO.File]::WriteAllText(
    (Join-Path $evidenceDirectory 'scanner-tools.json'),
    ($toolBindings | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false))

$bin = Join-Path $work 'native-root\usr\bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$nativeFiles = @(
    (Join-Path $runtimeRoot 'opt\aarch64-pc-msys\bin\msys-2.0.dll'),
    (Join-Path $gccRoot 'opt\lib\gcc\aarch64-pc-msys\msys-gcc_s-seh-1.dll'),
    (Join-Path $libuuidRoot 'opt\aarch64-pc-msys\bin\msys-uuid-1.dll'),
    (Join-Path $develRoot 'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\validation\libuuid-smoke.exe'),
    (Join-Path $develRoot 'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\validation\libuuid-static-smoke.exe')
)
$nativeHashes = [ordered]@{}
$toolBin = Join-Path $toolRoot 'usr\bin'
$originalPath = $env:PATH
$env:PATH = "$toolBin;$originalPath"
foreach ($path in $nativeFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing native smoke input: $path"
    }
    if ((Get-PeMachine -Path $path) -ne 0xaa64) {
        throw "Non-ARM64 PE input: $path"
    }
    $name = [IO.Path]::GetFileName($path)
    $nativeHashes[$name] = (
        Get-FileHash -Algorithm SHA256 $path
    ).Hash.ToLowerInvariant()
    $scanOutput = Join-Path $evidenceDirectory "$name.pseudo-relocs.json"
    & (Get-Process -Id $PID).Path `
        -NoLogo `
        -NoProfile `
        -File $scanner `
        -PePath $path `
        -OutputPath $scanOutput `
        -Objdump $objdump `
        -Nm $nm
    if ($LASTEXITCODE -ne 0) {
        throw "Canonical pseudo-reloc scan failed: $path"
    }
    $scanText = Get-Content -LiteralPath $scanOutput -Raw
    $scanText = [regex]::Replace(
        $scanText,
        '"input_path"\s*:\s*"[^"]*"',
        '"input_path": "<audited-pe>"')
    [IO.File]::WriteAllText(
        $scanOutput,
        $scanText,
        [Text.UTF8Encoding]::new($false))
    $scan = $scanText | ConvertFrom-Json
    if ($scan.result -ne 'pass' -or
        @($scan.flags | Where-Object {
            $_ -notin @(8, 16, 32, 64)
        }).Count -ne 0) {
        throw "Rejected pseudo-reloc scan result: $path"
    }
    Copy-Item -LiteralPath $path -Destination $bin
}

$currentProcess = Get-Process -Id $PID
$controllerAttestation = Get-Wow64Attestation -Process $currentProcess
$controller = [ordered]@{
    os_architecture = [Runtime.InteropServices.RuntimeInformation]::
        OSArchitecture.ToString()
    process_architecture = [Runtime.InteropServices.RuntimeInformation]::
        ProcessArchitecture.ToString()
    is_wow64_process2 = $controllerAttestation
}

$moduleLines = [Collections.Generic.List[string]]::new()
$processRecords = [Collections.Generic.List[object]]::new()
$oldMsystem = $env:MSYSTEM
$oldAttest = $env:LIBUUID_SMOKE_ATTEST
try {
    $env:MSYSTEM = 'MSYS'
    $env:LIBUUID_SMOKE_ATTEST = '1'
    $env:PATH = "$bin;$toolBin;$originalPath"
    foreach ($smokeName in @(
        'libuuid-smoke.exe',
        'libuuid-static-smoke.exe'
    )) {
        $smoke = Join-Path $bin $smokeName
        $stdout = Join-Path $evidenceDirectory "$smokeName.stdout.txt"
        $stderr = Join-Path $evidenceDirectory "$smokeName.stderr.txt"
        $process = Start-Process `
            -FilePath $smoke `
            -WorkingDirectory $bin `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -NoNewWindow `
            -PassThru
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (-not $process.HasExited -and
            (-not (Test-Path -LiteralPath $stdout) -or
             (Get-Item -LiteralPath $stdout).Length -eq 0) -and
            [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
            $process.Refresh()
        }
        $process.Refresh()
        if ($process.HasExited) {
            throw "$smokeName exited before process attestation"
        }
        $wow64 = Get-Wow64Attestation -Process $process
        if ($wow64.effective_machine -ne '0xaa64') {
            throw "$smokeName did not execute as native ARM64"
        }

        $moduleNames = [Collections.Generic.List[string]]::new()
        $loadedCustom = @{}
        foreach ($module in (Get-Process -Id $process.Id -Module |
            Sort-Object ModuleName)) {
            $modulePath = $module.FileName
            $moduleName = $module.ModuleName.ToLowerInvariant()
            $machine = Get-PeMachine -Path $modulePath
            $hash = (Get-FileHash -Algorithm SHA256 $modulePath).
                Hash.ToLowerInvariant()
            $machineText = '0x{0:x4}' -f $machine
            $moduleNames.Add($moduleName)
            $moduleLines.Add(
                "$smokeName`t$moduleName`t$machineText`t$hash")
            if ($nativeHashes.Contains($moduleName)) {
                $loadedCustom[$moduleName] = [ordered]@{
                    path = [IO.Path]::GetFullPath($modulePath)
                    machine = $machineText
                    sha256 = $hash
                }
            }
        }
        foreach ($required in @(
            $smokeName,
            'msys-2.0.dll',
            'msys-gcc_s-seh-1.dll'
        )) {
            if (-not $moduleNames.Contains($required.ToLowerInvariant())) {
                throw "$smokeName did not load $required"
            }
        }
        if ($smokeName -eq 'libuuid-smoke.exe' -and
            -not $moduleNames.Contains('msys-uuid-1.dll')) {
            throw 'Dynamic smoke did not load msys-uuid-1.dll'
        }
        if ($smokeName -eq 'libuuid-static-smoke.exe' -and
            $moduleNames.Contains('msys-uuid-1.dll')) {
            throw 'Static smoke loaded msys-uuid-1.dll'
        }
        $expectedCustom = if ($smokeName -eq 'libuuid-smoke.exe') {
            @(
                'libuuid-smoke.exe',
                'msys-2.0.dll',
                'msys-gcc_s-seh-1.dll',
                'msys-uuid-1.dll'
            )
        }
        else {
            @(
                'libuuid-static-smoke.exe',
                'msys-2.0.dll',
                'msys-gcc_s-seh-1.dll'
            )
        }
        if ((@($loadedCustom.Keys | Sort-Object) -join "`n") -ne
            (@($expectedCustom | Sort-Object) -join "`n")) {
            throw "Loaded custom module set changed for $smokeName"
        }
        foreach ($custom in $expectedCustom) {
            $expectedPath = [IO.Path]::GetFullPath((Join-Path $bin $custom))
            $actual = $loadedCustom[$custom]
            if ($actual.path -ne $expectedPath -or
                $actual.machine -ne '0xaa64' -or
                $actual.sha256 -ne $nativeHashes[$custom]) {
                throw "Loaded custom module identity changed: $custom"
            }
        }

        if (-not $process.WaitForExit(30000)) {
            throw "$smokeName did not exit after attestation"
        }
        if ($process.ExitCode -ne 0) {
            throw "$smokeName failed with exit code $($process.ExitCode)"
        }
        $text = (Get-Content -LiteralPath $stdout -Raw).Trim()
        if ($text -notmatch
            '^libuuid-smoke:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            throw "Unexpected $smokeName output: $text"
        }
        if ((Get-Item -LiteralPath $stderr).Length -ne 0) {
            throw "$smokeName wrote to stderr"
        }
        $processRecords.Add([ordered]@{
            name = $smokeName
            exit_code = $process.ExitCode
            output = $text
            is_wow64_process2 = $wow64
            module_count = $moduleNames.Count
        })
    }
}
finally {
    $env:MSYSTEM = $oldMsystem
    $env:LIBUUID_SMOKE_ATTEST = $oldAttest
    $env:PATH = $originalPath
}

Write-Utf8NoBom `
    -Path (Join-Path $evidenceDirectory 'loaded-modules.tsv') `
    -Lines (@("process`tmodule`tmachine`tsha256") + @($moduleLines))
$attestation = [ordered]@{
    schema = 1
    repository = $repository
    commit = $actualHeadSha
    runner = $env:RUNNER_NAME
    processor = $arm64Processors[0].Name
    controller = $controller
    processes = @($processRecords)
    native_inputs = $nativeHashes
    scanner_tools = $toolBindings
}
[IO.File]::WriteAllText(
    (Join-Path $evidenceDirectory 'process-attestation.json'),
    ($attestation | ConvertTo-Json -Depth 8),
    [Text.UTF8Encoding]::new($false))

$inputManifest = @()
foreach ($asset in $inputRecords) {
    $inputManifest += "$($asset.Sha256)  $($asset.Name)"
}
$inputManifest += "$(
    (Get-FileHash -Algorithm SHA256 $runtimePackage).Hash.ToLowerInvariant()
)  $([IO.Path]::GetFileName($runtimePackage))"
$inputManifest += "$(
    (Get-FileHash -Algorithm SHA256 $develPackage).Hash.ToLowerInvariant()
)  $([IO.Path]::GetFileName($develPackage))"
Write-Utf8NoBom `
    -Path (Join-Path $evidenceDirectory 'input-snapshot.sha256') `
    -Lines @($inputManifest | Sort-Object)

$privatePattern = '(?im)([A-Za-z]:[\\/](?:a|Users)[\\/]|/(?:tmp|cygdrive)/|/[a-z]/a/)'
foreach ($file in Get-ChildItem -LiteralPath $evidenceDirectory -File) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes -contains 0) {
        continue
    }
    if ([Text.Encoding]::UTF8.GetString($bytes) -match $privatePattern) {
        throw "Private path leaked into native evidence: $($file.Name)"
    }
}
Write-Utf8NoBom `
    -Path (Join-Path $evidenceDirectory 'path-scan.tsv') `
    -Lines @("private-path-leaks`t0")

$manifestPath = Join-Path $evidenceDirectory 'evidence-manifest.sha256'
$sealPath = Join-Path $evidenceDirectory 'evidence.seal'
$manifest = Get-ChildItem -LiteralPath $evidenceDirectory -File |
    Where-Object { $_.FullName -notin @($manifestPath, $sealPath) } |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).
            Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
Write-Utf8NoBom -Path $manifestPath -Lines @($manifest)
$seal = (Get-FileHash -Algorithm SHA256 $manifestPath).
    Hash.ToLowerInvariant()
Write-Utf8NoBom -Path $sealPath `
    -Lines @("$seal  evidence-manifest.sha256")

$attestation

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackagesDirectory,

    [Parameter(Mandatory = $true)]
    [string] $NativeInputsDirectory,

    [Parameter(Mandatory = $true)]
    [string] $ValidationDirectory,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = [Text.UTF8Encoding]::new($false)

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ZlibNativeArchitecture {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine);
}
'@

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite
    )
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw "Missing MZ header: $Path"
        }
        [void] $stream.Seek(0x3c, [IO.SeekOrigin]::Begin)
        $peOffset = $reader.ReadInt32()
        [void] $stream.Seek($peOffset, [IO.SeekOrigin]::Begin)
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

function Get-Wow64Evidence {
    param([Parameter(Mandatory = $true)][Diagnostics.Process] $Process)

    [uint16] $processMachine = 0
    [uint16] $nativeMachine = 0
    $ok = [ZlibNativeArchitecture]::IsWow64Process2(
        $Process.Handle,
        [ref] $processMachine,
        [ref] $nativeMachine
    )
    if (-not $ok) {
        throw "IsWow64Process2 failed for PID $($Process.Id): $(
            [Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    return [ordered]@{
        process_machine = ('0x{0:x4}' -f $processMachine)
        native_machine = ('0x{0:x4}' -f $nativeMachine)
        native = ($processMachine -eq 0 -and $nativeMachine -eq 0xaa64)
    }
}

function Get-ModuleEvidence {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process] $Process,
        [Parameter(Mandatory = $true)][string] $PayloadRoot
    )

    $Process.Refresh()
    $modules = @()
    foreach ($module in @($Process.Modules)) {
        $path = $module.FileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Loaded module path is unavailable: $path"
        }
        $machine = Get-PeMachine -Path $path
        if ($machine -ne 0xaa64) {
            throw "Loaded module is not AA64: $path => $('0x{0:x4}' -f $machine)"
        }
        $scope = if ($path.StartsWith(
                $PayloadRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            'payload'
        }
        else {
            'system'
        }
        $modules += [ordered]@{
            scope = $scope
            name = [IO.Path]::GetFileName($path)
            machine = '0xaa64'
            bytes = (Get-Item -LiteralPath $path).Length
            sha256 = Get-Sha256 -Path $path
        }
    }
    if ($modules.Count -eq 0) {
        throw "No loaded modules were enumerated for PID $($Process.Id)"
    }
    return @($modules | Sort-Object scope, name)
}

function Start-BinaryProcess {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [string] $Arguments = '',
        [switch] $Hold
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Path
    $start.Arguments = $Arguments
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['MSYSTEM'] = 'MSYS'
    if ($Hold) {
        $start.Environment['MSYS_ZLIB_NATIVE_HOLD'] = '1'
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "Failed to start $Path"
    }
    return $process
}

function Write-Json {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Path
    )

    [IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 16) + "`n"),
        $utf8
    )
}

foreach ($path in @(
    $PackagesDirectory,
    $NativeInputsDirectory,
    $ValidationDirectory
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Required native input directory is missing: $path"
    }
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Native output directory must be fresh: $OutputDirectory"
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null

$hostProcess = Get-Process -Id $PID
$hostArchitecture = [ordered]@{
    os_architecture = [Runtime.InteropServices.RuntimeInformation]::
        OSArchitecture.ToString()
    process_architecture = [Runtime.InteropServices.RuntimeInformation]::
        ProcessArchitecture.ToString()
    iswow64process2 = Get-Wow64Evidence -Process $hostProcess
    cim = @(
        Get-CimInstance -ClassName Win32_Processor |
            ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    architecture = [int] $_.Architecture
                }
            }
    )
}
if ($hostArchitecture.os_architecture -ne 'Arm64' -or
    $hostArchitecture.process_architecture -ne 'Arm64' -or
    -not $hostArchitecture.iswow64process2.native -or
    @($hostArchitecture.cim | Where-Object { $_.architecture -ne 12 }).Count) {
    throw "Runner is not native ARM64: $($hostArchitecture | ConvertTo-Json)"
}

$expectedPackages = [ordered]@{
    'mingw-w64-cross-msysarm64-zlib-1.3.1-1-x86_64.pkg.tar.zst' = $null
    'mingw-w64-cross-msysarm64-zlib-devel-1.3.1-1-x86_64.pkg.tar.zst' = $null
    'mingw-w64-cross-msysarm64-zlib-minigzip-1.3.1-1-x86_64.pkg.tar.zst' = $null
}
$checksumPath = Join-Path $PackagesDirectory 'release-SHA256SUMS'
foreach ($line in Get-Content -LiteralPath $checksumPath) {
    if ($line -notmatch '^([0-9a-f]{64}) [ *](?:\./)?(.+)$') {
        throw "Malformed package checksum line: $line"
    }
    if (-not $expectedPackages.Contains($Matches[2])) {
        throw "Unexpected package checksum entry: $($Matches[2])"
    }
    $expectedPackages[$Matches[2]] = $Matches[1]
}
foreach ($entry in $expectedPackages.GetEnumerator()) {
    $path = Join-Path $PackagesDirectory $entry.Key
    if ((Get-Sha256 -Path $path) -ne $entry.Value) {
        throw "Package checksum mismatch: $($entry.Key)"
    }
}

$nativeManifest = Join-Path $NativeInputsDirectory 'SHA256SUMS.tsv'
$nativeRecords = @(Import-Csv -LiteralPath $nativeManifest -Delimiter "`t")
if ($nativeRecords.Count -eq 0) {
    throw 'Native input manifest is empty'
}
foreach ($record in $nativeRecords) {
    $path = Join-Path $NativeInputsDirectory $record.path
    $item = Get-Item -LiteralPath $path
    if ($item.Length -ne [long] $record.bytes -or
        (Get-Sha256 -Path $path) -ne $record.sha256) {
        throw "Native input checksum mismatch: $($record.path)"
    }
}

$runtimeName =
    'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
$runtimePath = Join-Path $OutputDirectory $runtimeName
$runtimeUrl = "https://github.com/crutkas/MSYS2-packages/releases/download/" +
    "msysarm64-runtime-pr10-a527-20260824/$runtimeName"
Invoke-WebRequest -Uri $runtimeUrl -OutFile $runtimePath
if ((Get-Item $runtimePath).Length -ne 9893043 -or
    (Get-Sha256 -Path $runtimePath) -ne
        '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e') {
    throw 'Native runtime package identity mismatch'
}

$tar = 'C:\Windows\System32\tar.exe'
$stage = Join-Path $OutputDirectory 'stage'
$installationRoot = Join-Path $OutputDirectory 'native-root'
$bin = Join-Path $installationRoot 'usr\bin'
New-Item -ItemType Directory -Path $stage, $bin | Out-Null
$extractPackages = @(
    $runtimePath
    (Join-Path $PackagesDirectory (
        'mingw-w64-cross-msysarm64-zlib-1.3.1-1-x86_64.pkg.tar.zst'))
    (Join-Path $PackagesDirectory (
        'mingw-w64-cross-msysarm64-zlib-minigzip-1.3.1-1-x86_64.pkg.tar.zst'))
)
foreach ($package in $extractPackages) {
    & $tar -xf $package -C $stage
    if ($LASTEXITCODE -ne 0) {
        throw "Native package extraction failed: $package"
    }
}

$payload = [ordered]@{
    'msys-2.0.dll' = Join-Path $stage 'opt\aarch64-pc-msys\bin\msys-2.0.dll'
    'msys-z.dll' = Join-Path $stage 'opt\aarch64-pc-msys\usr\bin\msys-z.dll'
    'minigzip.exe' = Join-Path $stage (
        'opt\aarch64-pc-msys\usr\bin\minigzip.exe')
    'pseudo-reloc-cxx.exe' = Join-Path $NativeInputsDirectory (
        'pseudo-reloc-cxx.exe')
    'msys-gcc_s-seh-1.dll' = Join-Path $NativeInputsDirectory (
        'msys-gcc_s-seh-1.dll')
    'msys-stdc++-6.dll' = Join-Path $NativeInputsDirectory (
        'msys-stdc++-6.dll')
}
foreach ($entry in $payload.GetEnumerator()) {
    if ((Get-PeMachine -Path $entry.Value) -ne 0xaa64) {
        throw "Native payload is not AA64: $($entry.Key)"
    }
    Copy-Item -LiteralPath $entry.Value -Destination (
        Join-Path $bin $entry.Key)
}

$boundScanPath = Join-Path `
    $NativeInputsDirectory `
    'pseudo-reloc-cxx.pseudo-relocs.json'
if (-not (Test-Path -LiteralPath $boundScanPath -PathType Leaf)) {
    throw 'Bound C++ pseudo-reloc scan is missing'
}
$scan = Get-Content -LiteralPath $boundScanPath -Raw | ConvertFrom-Json
$cxxPath = Join-Path $bin 'pseudo-reloc-cxx.exe'
if ($scan.input.sha256 -ne (Get-Sha256 -Path $cxxPath) -or
    $scan.scanner_result.result -ne 'pass') {
    throw 'C++ native input is not bound to a passing scanner report'
}

$inputBytes = $utf8.GetBytes(("native ARM64 MSYS zlib roundtrip`n" * 256))
$compress = Start-BinaryProcess `
    -Path (Join-Path $bin 'minigzip.exe') `
    -WorkingDirectory $bin
Start-Sleep -Milliseconds 500
$compressEvidence = [ordered]@{
    label = 'minigzip-compress'
    executable_sha256 = Get-Sha256 -Path $compress.StartInfo.FileName
    process = Get-Wow64Evidence -Process $compress
    modules = Get-ModuleEvidence -Process $compress -PayloadRoot $bin
}
$compress.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
$compress.StandardInput.Close()
$compressed = [IO.MemoryStream]::new()
$compress.StandardOutput.BaseStream.CopyTo($compressed)
$compressError = $compress.StandardError.ReadToEnd()
$compress.WaitForExit()
if ($compress.ExitCode -ne 0) {
    throw "Native compression failed: $compressError"
}

$decompress = Start-BinaryProcess `
    -Path (Join-Path $bin 'minigzip.exe') `
    -WorkingDirectory $bin `
    -Arguments '-d'
Start-Sleep -Milliseconds 500
$decompressEvidence = [ordered]@{
    label = 'minigzip-decompress'
    executable_sha256 = Get-Sha256 -Path $decompress.StartInfo.FileName
    process = Get-Wow64Evidence -Process $decompress
    modules = Get-ModuleEvidence -Process $decompress -PayloadRoot $bin
}
$compressedBytes = $compressed.ToArray()
$decompress.StandardInput.BaseStream.Write(
    $compressedBytes,
    0,
    $compressedBytes.Length
)
$decompress.StandardInput.Close()
$roundtrip = [IO.MemoryStream]::new()
$decompress.StandardOutput.BaseStream.CopyTo($roundtrip)
$decompressError = $decompress.StandardError.ReadToEnd()
$decompress.WaitForExit()
if ($decompress.ExitCode -ne 0) {
    throw "Native decompression failed: $decompressError"
}
$outputBytes = $roundtrip.ToArray()
$inputHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($inputBytes)
).ToLowerInvariant()
$outputHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($outputBytes)
).ToLowerInvariant()
if ($inputBytes.Length -ne $outputBytes.Length -or
    $inputHash -ne $outputHash) {
    throw 'Native compression roundtrip mismatch'
}

$cxx = Start-BinaryProcess `
    -Path $cxxPath `
    -WorkingDirectory $bin `
    -Hold
Start-Sleep -Milliseconds 500
$cxxEvidence = [ordered]@{
    label = 'pseudo-reloc-cxx'
    executable_sha256 = Get-Sha256 -Path $cxxPath
    bound_scanner_report_sha256 = Get-Sha256 -Path $boundScanPath
    process = Get-Wow64Evidence -Process $cxx
    modules = Get-ModuleEvidence -Process $cxx -PayloadRoot $bin
}
$cxx.StandardInput.WriteLine('')
$cxx.StandardInput.Close()
$cxxOutput = $cxx.StandardOutput.ReadToEnd()
$cxxError = $cxx.StandardError.ReadToEnd()
$cxx.WaitForExit()
if ($cxx.ExitCode -ne 0 -or $cxxOutput -notmatch 'cxx-runtime-ok') {
    throw "Native C++ probe failed: output=$cxxOutput error=$cxxError"
}

$attestation = [ordered]@{
    schema = 'msysarm64-zlib-native-attestation/v1'
    host = $hostArchitecture
    installation_layout = [ordered]@{
        root = $installationRoot
        usr_bin = $bin
    }
    payload = @(
        foreach ($entry in $payload.GetEnumerator()) {
            $path = Join-Path $bin $entry.Key
            [ordered]@{
                name = $entry.Key
                machine = '0xaa64'
                bytes = (Get-Item $path).Length
                sha256 = Get-Sha256 -Path $path
            }
        }
    )
    executions = @(
        $compressEvidence
        $decompressEvidence
        $cxxEvidence
    )
    roundtrip = [ordered]@{
        input_sha256 = $inputHash
        output_sha256 = $outputHash
        compressed_bytes = $compressedBytes.Length
    }
    cxx_stdout = $cxxOutput.Trim()
    result = 'pass'
}
Write-Json `
    -Value $attestation `
    -Path (Join-Path $OutputDirectory 'native-attestation.json')

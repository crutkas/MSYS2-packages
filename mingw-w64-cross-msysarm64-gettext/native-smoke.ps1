param(
    [Parameter(Mandatory = $true)]
    [string] $TargetRoot,
    [Parameter(Mandatory = $true)]
    [string] $SmokeRoot,
    [Parameter(Mandatory = $true)]
    [string] $ReportPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64') {
    throw 'Native smoke requires Windows ARM64'
}

$target = (Resolve-Path $TargetRoot).Path
$smoke = (Resolve-Path $SmokeRoot).Path
$runtime = Join-Path $target 'bin\msys-intl-8.dll'
$libiconv = Join-Path $target 'bin\msys-iconv-2.dll'
$gettext = Join-Path $target 'bin\gettext.exe'
$msgfmt = Join-Path $target 'bin\msgfmt.exe'
$header = Join-Path $target 'include\libintl.h'
$importLibrary = Join-Path $target 'lib\libintl.dll.a'
$staticLibrary = Join-Path $target 'lib\libintl.a'

foreach ($path in @(
        $runtime,
        $libiconv,
        $gettext,
        $msgfmt,
        $header,
        $importLibrary,
        $staticLibrary,
        (Join-Path $smoke 'dynamic-consumer.exe'),
        (Join-Path $smoke 'static-consumer.exe'),
        (Join-Path $smoke 'locale\C.UTF-8\LC_MESSAGES\arm64-gettext-smoke.mo')
    )) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required native smoke input is absent: $path"
    }
}

function Get-PeMachine([string] $Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw "Not an MZ image: $Path"
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Not a PE image: $Path"
        }
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

$peFiles = @(
    Get-ChildItem (Join-Path $target 'bin') -File |
        Where-Object { $_.Extension -in @('.dll', '.exe') }
    Get-ChildItem $smoke -File -Filter '*-consumer.exe'
)
if ($peFiles.Count -lt 12) {
    throw "Expected at least 12 target PE files, got $($peFiles.Count)"
}
foreach ($file in $peFiles) {
    $machine = Get-PeMachine $file.FullName
    if ($machine -ne 0xaa64) {
        throw "Non-AA64 PE payload: $($file.FullName) machine=0x$($machine.ToString('x4'))"
    }
}

$runRoot = Join-Path $env:RUNNER_TEMP 'gettext-native-smoke'
if (Test-Path $runRoot) {
    Remove-Item -LiteralPath $runRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $runRoot | Out-Null
Copy-Item (Join-Path $smoke 'dynamic-consumer.exe') $runRoot
Copy-Item (Join-Path $smoke 'static-consumer.exe') $runRoot
Copy-Item (Join-Path $smoke 'locale') $runRoot -Recurse

$oldPath = $env:PATH
$env:PATH = "$(Join-Path $target 'bin');$oldPath"
try {
    $results = foreach ($name in @('dynamic-consumer.exe', 'static-consumer.exe')) {
        $stdout = Join-Path $runRoot "$name.stdout"
        $stderr = Join-Path $runRoot "$name.stderr"
        $process = Start-Process `
            -FilePath (Join-Path $runRoot $name) `
            -WorkingDirectory $runRoot `
            -NoNewWindow `
            -PassThru `
            -Wait `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr
        if ($process.ExitCode -ne 0) {
            $errorText = Get-Content $stderr -Raw
            throw "$name failed with exit code $($process.ExitCode): $errorText"
        }
        [pscustomobject]@{
            Name = $name
            ExitCode = $process.ExitCode
            Sha256 = (Get-FileHash (Join-Path $runRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}
finally {
    $env:PATH = $oldPath
}

$report = @(
    'package=gettext-0.22.5-1'
    'target=aarch64-pc-msys'
    'personality=MSYS'
    'abi=LP64/AAPCS64/SEH'
    'coverage=native locale/domain/thread/module smoke'
    'catalog_encoding=UTF-8'
    "pe_count=$($peFiles.Count)"
    "runtime_sha256=$((Get-FileHash $runtime -Algorithm SHA256).Hash.ToLowerInvariant())"
)
foreach ($result in $results) {
    $report += "consumer=$($result.Name) exit=$($result.ExitCode) sha256=$($result.Sha256)"
}
$report += 'Fork/argv-dependent CLI execution is intentionally blocked by the current ARM64 MSYS runtime defect.'
$report | Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM

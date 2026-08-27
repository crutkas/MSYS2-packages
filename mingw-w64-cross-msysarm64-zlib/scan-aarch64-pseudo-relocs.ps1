[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string] $Label,

    [Parameter(Mandatory = $true)]
    [string] $ScannerPath,

    [Parameter(Mandatory = $true)]
    [string] $Objdump,

    [Parameter(Mandatory = $true)]
    [string] $Nm,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(Mandatory = $true)]
    [string] $RetainedInputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $SummaryPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedScanner = '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
$expectedObjdump = 'bb0d53db4128aff7f6b20c46be4e3625b1d82134476d7b03e58ed22015136e6e'
$expectedNm = '80b4716108b362ba05f48cd9228d20a4193897b4a5eeb8eb19e80f4c83e3e90a'
$utf8 = [Text.UTF8Encoding]::new($false)

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

foreach ($path in @($PePath, $ScannerPath, $Objdump, $Nm)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required scanner input is missing: $path"
    }
}

$scannerHash = Get-Sha256 -Path $ScannerPath
$objdumpHash = Get-Sha256 -Path $Objdump
$nmHash = Get-Sha256 -Path $Nm
if ($scannerHash -ne $expectedScanner) {
    throw "Scanner hash mismatch: $scannerHash"
}
if ($objdumpHash -ne $expectedObjdump) {
    throw "objdump hash mismatch: $objdumpHash"
}
if ($nmHash -ne $expectedNm) {
    throw "nm hash mismatch: $nmHash"
}

New-Item -ItemType Directory -Force -Path $RetainedInputDirectory | Out-Null
$extension = [IO.Path]::GetExtension($PePath).ToLowerInvariant()
$retainedName = "$Label$extension"
$retainedPath = Join-Path $RetainedInputDirectory $retainedName
if (Test-Path -LiteralPath $retainedPath) {
    throw "Retained scanner input already exists: $retainedPath"
}
Copy-Item -LiteralPath $PePath -Destination $retainedPath

$rawOutput = "$OutputPath.raw"
$pwsh = (Get-Process -Id $PID).Path
& $pwsh -NoLogo -NoProfile -NonInteractive `
    -File $ScannerPath `
    -PePath $retainedPath `
    -OutputPath $rawOutput `
    -Objdump $Objdump `
    -Nm $Nm
if ($LASTEXITCODE -ne 0) {
    throw "Canonical pseudo-reloc scanner failed with exit code $LASTEXITCODE"
}

$scannerResult = Get-Content -LiteralPath $rawOutput -Raw |
    ConvertFrom-Json -Depth 16
$scannerResult.input_path = "scanner-inputs/$retainedName"
if ($scannerResult.result -ne 'pass') {
    throw "Canonical scanner result is not pass: $($scannerResult.result)"
}
$violations = @($scannerResult.policy_violations)
$flags = @($scannerResult.flags)
if ($violations.Count -ne 0) {
    throw "Canonical scanner reported policy violations: $violations"
}
if (@($flags | Where-Object { $_ -notin @(8, 16, 32, 64) }).Count -ne 0) {
    throw "Canonical scanner reported unsupported flags: $flags"
}
if (@($flags | Where-Object { $_ -in @(12, 21) }).Count -ne 0) {
    throw "Canonical scanner reported ambiguous flags: $flags"
}

$inputItem = Get-Item -LiteralPath $retainedPath
$report = [ordered]@{
    schema = 'msysarm64-zlib-pseudo-reloc-binding/v1'
    label = $Label
    input = [ordered]@{
        file = "scanner-inputs/$retainedName"
        bytes = $inputItem.Length
        sha256 = Get-Sha256 -Path $retainedPath
    }
    tools = [ordered]@{
        scanner = [ordered]@{
            file = '.ci/check-aarch64-pseudo-relocs.ps1'
            sha256 = $scannerHash
        }
        objdump = [ordered]@{
            file = '/opt/bin/aarch64-pc-cygwin-objdump.exe'
            sha256 = $objdumpHash
        }
        nm = [ordered]@{
            file = '/opt/bin/aarch64-pc-cygwin-nm.exe'
            sha256 = $nmHash
        }
    }
    scanner_result = $scannerResult
    encoding = 'utf-8-no-bom'
}

$parent = Split-Path -Parent $OutputPath
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
[IO.File]::WriteAllText(
    $OutputPath,
    (($report | ConvertTo-Json -Depth 16) + "`n"),
    $utf8
)

$outputHash = Get-Sha256 -Path $OutputPath
$flagText = if ($flags.Count -eq 0) { 'none' } else { $flags -join ',' }
$summaryLine = @(
    $Label
    $report.input.sha256
    $scannerHash
    $objdumpHash
    $nmHash
    $scannerResult.table_format
    $scannerResult.record_count
    $flagText
    $outputHash
    'pass'
) -join "`t"
[IO.File]::AppendAllText($SummaryPath, "$summaryLine`n", $utf8)

Remove-Item -LiteralPath $rawOutput

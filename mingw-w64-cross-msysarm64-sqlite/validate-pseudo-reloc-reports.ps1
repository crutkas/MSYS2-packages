[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ReportDirectory,

    [Parameter(Mandatory = $true)]
    [string] $PePath,

    [Parameter(Mandatory = $true)]
    [string] $ScannerPath,

    [Parameter(Mandatory = $true)]
    [string] $ObjdumpPath,

    [Parameter(Mandatory = $true)]
    [string] $NmPath,

    [Parameter(Mandatory = $true)]
    [string] $ExpectedScannerSha256,

    [Parameter(Mandatory = $true)]
    [string] $ExpectedObjdumpSha256,

    [Parameter(Mandatory = $true)]
    [string] $ExpectedNmSha256,

    [Parameter(Mandatory = $true)]
    [string] $SummaryPath,

    [switch] $AppendSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).
        Hash.ToLowerInvariant()
}

$scanner = (Resolve-Path -LiteralPath $ScannerPath).Path
$objdump = (Resolve-Path -LiteralPath $ObjdumpPath).Path
$nm = (Resolve-Path -LiteralPath $NmPath).Path
$scannerSha256 = Get-Sha256 -Path $scanner
$objdumpSha256 = Get-Sha256 -Path $objdump
$nmSha256 = Get-Sha256 -Path $nm

if ($scannerSha256 -ne $ExpectedScannerSha256) {
    throw "scanner SHA-256 mismatch: $scannerSha256"
}
if ($objdumpSha256 -ne $ExpectedObjdumpSha256) {
    throw "objdump SHA-256 mismatch: $objdumpSha256"
}
if ($nmSha256 -ne $ExpectedNmSha256) {
    throw "nm SHA-256 mismatch: $nmSha256"
}

$summary = [System.Collections.Generic.List[string]]::new()
foreach ($input in @($PePath)) {
    $pe = (Resolve-Path -LiteralPath $input).Path
    $name = Split-Path -Leaf $pe
    $reportPath = Join-Path $ReportDirectory "$name.json"
    $report = Get-Content -LiteralPath $reportPath -Raw |
        ConvertFrom-Json
    $inputSha256 = Get-Sha256 -Path $pe
    $bindingProperty = $report.PSObject.Properties['binding']
    if ($null -eq $bindingProperty) {
        $reportedInput = (Resolve-Path -LiteralPath $report.input_path).Path
        if ($reportedInput -ne $pe) {
            throw "scanner input mismatch for ${name}: $reportedInput"
        }
    }
    else {
        if ($report.input_path -ne $name -or
            $report.binding.input_sha256 -ne $inputSha256 -or
            $report.binding.scanner_sha256 -ne $scannerSha256 -or
            $report.binding.objdump_sha256 -ne $objdumpSha256 -or
            $report.binding.nm_sha256 -ne $nmSha256) {
            throw "existing scanner binding mismatch for $name"
        }
    }

    $flags = @($report.flags | ForEach-Object { [uint32] $_ })
    $violations = @($report.policy_violations)
    if ($report.result -ne 'pass' -or $violations.Count -ne 0) {
        throw "pseudo-reloc policy failed for $name"
    }
    if (@($flags | Where-Object { $_ -notin @(8, 16, 32, 64) }).Count) {
        throw "unknown pseudo-reloc flag in $name"
    }
    if (@($flags | Where-Object { $_ -in @(12, 21) }).Count) {
        throw "rejected pseudo-reloc flag in $name"
    }

    $report.input_path = $name
    $report | Add-Member -Force -NotePropertyName binding -NotePropertyValue (
        [ordered]@{
            input_sha256 = $inputSha256
            scanner_name = Split-Path -Leaf $scanner
            scanner_sha256 = $scannerSha256
            objdump_name = Split-Path -Leaf $objdump
            objdump_sha256 = $objdumpSha256
            nm_name = Split-Path -Leaf $nm
            nm_sha256 = $nmSha256
        })
    $json = $report | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText(
        $reportPath,
        "$json`n",
        [Text.UTF8Encoding]::new($false))
    $summary.Add((
        "{0}`t{1}`t{2}`t{3}`t{4}" -f
            $name,
            $report.table_format,
            $report.record_count,
            ($flags -join ','),
            $report.binding.input_sha256))
}

$summaryText = ($summary -join "`n") + "`n"
if ($AppendSummary) {
    [IO.File]::AppendAllText(
        $SummaryPath,
        $summaryText,
        [Text.UTF8Encoding]::new($false))
}
else {
    [IO.File]::WriteAllText(
        $SummaryPath,
        $summaryText,
        [Text.UTF8Encoding]::new($false))
}

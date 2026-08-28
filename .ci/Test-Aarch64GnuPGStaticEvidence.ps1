[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $EvidencePath,

    [Parameter(Mandatory = $true)]
    [string] $Repository,

    [Parameter(Mandatory = $true)]
    [string] $BaseCommit,

    [Parameter(Mandatory = $true)]
    [string] $HeadCommit,

    [string] $LockPath = (Join-Path $PSScriptRoot '..\mingw-w64-cross-msysarm64-gnupg\dependencies.lock.json'),
    [string] $InventoryPath = (Join-Path $PSScriptRoot '..\mingw-w64-cross-msysarm64-gnupg\inventory.json'),
    [string] $ScannerPath = (Join-Path $PSScriptRoot 'check-aarch64-pseudo-relocs.ps1'),
    [string] $WorkflowPath = (Join-Path $PSScriptRoot '..\.github\workflows\aarch64-msys-gnupg.yml')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ExactProperties {
    param([object] $Object, [string[]] $Expected, [string] $Name)
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object @($Expected | Sort-Object) $actual) {
        throw "$Name does not match its closed schema"
    }
}

function Get-NormalizedSha256 {
    param([string] $Path)
    $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path)).Replace("`r`n", "`n")
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text))
    ).ToLowerInvariant()
}

$evidence = Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
Assert-ExactProperties $evidence @(
    'schema_version', 'evidence_type', 'repository', 'base_commit', 'head_commit',
    'tree', 'policy_hashes', 'action_pins', 'unresolved_dependencies', 'attempts'
) 'Static evidence'
Assert-ExactProperties $evidence.policy_hashes @(
    'lock_sha256', 'inventory_sha256', 'scanner_sha256'
) 'Policy hashes'
Assert-ExactProperties $evidence.attempts @(
    'setup_msys2', 'dependency_download', 'package_install', 'package_build', 'native_execution'
) 'Attempt counters'

if ($evidence.schema_version -ne 1 -or
    $evidence.evidence_type -ne 'aarch64-pc-msys-gnupg-static-policy' -or
    $evidence.repository -ne $Repository -or $evidence.base_commit -ne $BaseCommit -or
    $evidence.head_commit -ne $HeadCommit -or $evidence.tree -notmatch '^[0-9a-f]{40}$') {
    throw 'Static evidence identity binding failed'
}
$actualHead = (& git rev-parse HEAD).Trim()
$actualTree = (& git rev-parse "$HeadCommit`^{tree}").Trim()
$actualBase = (& git merge-base $BaseCommit $HeadCommit).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -ne $HeadCommit -or
    $actualTree -ne $evidence.tree -or $actualBase -ne $BaseCommit) {
    throw 'Static evidence Git object binding failed'
}
foreach ($counter in $evidence.attempts.PSObject.Properties) {
    if ($counter.Value -isnot [long] -or $counter.Value -ne 0) {
        throw "Static evidence attempt counter is not integer zero: $($counter.Name)"
    }
}
if ($evidence.policy_hashes.lock_sha256 -ne (Get-NormalizedSha256 $LockPath) -or
    $evidence.policy_hashes.inventory_sha256 -ne (Get-NormalizedSha256 $InventoryPath) -or
    $evidence.policy_hashes.scanner_sha256 -ne (Get-NormalizedSha256 $ScannerPath)) {
    throw 'Static evidence policy hash binding failed'
}

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$expectedUnresolved = @(
    $lock.dependencies |
        Where-Object { $_.required -and $_.status -eq 'unresolved' } |
        ForEach-Object id |
        Sort-Object
)
if (Compare-Object $expectedUnresolved @($evidence.unresolved_dependencies | Sort-Object)) {
    throw 'Static evidence unresolved dependency set is incomplete'
}

$workflowText = Get-Content -LiteralPath $WorkflowPath -Raw
$expectedPins = @(
    [regex]::Matches($workflowText, '(?m)^\s*-\s+uses:\s+(?<action>[^@\s]+)@(?<commit>[0-9a-f]{40})(?:\s|$)') |
        ForEach-Object { "$($_.Groups['action'].Value)@$($_.Groups['commit'].Value)" } |
        Sort-Object
)
$actualPins = @(
    foreach ($pin in $evidence.action_pins) {
        Assert-ExactProperties $pin @('action', 'commit') 'Action pin'
        "$($pin.action)@$($pin.commit)"
    }
) | Sort-Object
if (Compare-Object $expectedPins $actualPins) {
    throw 'Static evidence action pin set is incomplete'
}

[pscustomobject]@{
    result = 'pass'
    unresolved = $expectedUnresolved.Count
    action_pins = $expectedPins.Count
}

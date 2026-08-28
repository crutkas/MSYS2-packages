[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Repository,

    [Parameter(Mandatory = $true)]
    [string] $BaseCommit,

    [Parameter(Mandatory = $true)]
    [string] $HeadCommit,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [string] $LockPath = (Join-Path $PSScriptRoot '..\mingw-w64-cross-msysarm64-gnupg\dependencies.lock.json'),
    [string] $InventoryPath = (Join-Path $PSScriptRoot '..\mingw-w64-cross-msysarm64-gnupg\inventory.json'),
    [string] $ScannerPath = (Join-Path $PSScriptRoot 'check-aarch64-pseudo-relocs.ps1'),
    [string] $WorkflowPath = (Join-Path $PSScriptRoot '..\.github\workflows\aarch64-msys-gnupg.yml')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NormalizedSha256 {
    param([string] $Path)
    $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path)).Replace("`r`n", "`n")
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text))
    ).ToLowerInvariant()
}

if ($Repository -ne 'crutkas/MSYS2-packages' -or
    $BaseCommit -notmatch '^[0-9a-f]{40}$' -or
    $HeadCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Static evidence repository or commit binding is invalid'
}
if (@(& git status --porcelain).Count -ne 0) {
    throw 'Static evidence requires a clean checkout'
}
$actualHead = (& git rev-parse HEAD).Trim()
$tree = (& git rev-parse "$HeadCommit`^{tree}").Trim()
$mergeBase = (& git merge-base $BaseCommit $HeadCommit).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -ne $HeadCommit -or $mergeBase -ne $BaseCommit -or
    $tree -notmatch '^[0-9a-f]{40}$') {
    throw 'Static evidence Git binding failed'
}

$workflowText = Get-Content -LiteralPath $WorkflowPath -Raw
$actionPins = @(
    [regex]::Matches($workflowText, '(?m)^\s*-\s+uses:\s+(?<action>[^@\s]+)@(?<commit>[0-9a-f]{40})(?:\s|$)') |
        ForEach-Object {
            [ordered]@{
                action = $_.Groups['action'].Value
                commit = $_.Groups['commit'].Value
            }
        }
)
$allActionUses = @([regex]::Matches($workflowText, '(?m)^\s*-\s+uses:\s+\S+'))
if ($actionPins.Count -eq 0 -or $actionPins.Count -ne $allActionUses.Count) {
    throw 'Static evidence requires every action to use a full commit SHA'
}

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$unresolved = @(
    $lock.dependencies |
        Where-Object { $_.required -and $_.status -eq 'unresolved' } |
        ForEach-Object id |
        Sort-Object
)
if (@($lock.dependencies | Where-Object status -eq 'admitted').Count -ne 0 -or
    $unresolved.Count -eq 0) {
    throw 'Static evidence is only valid for the current zero-admission fail-closed state'
}

$evidence = [ordered]@{
    schema_version = 1
    evidence_type = 'aarch64-pc-msys-gnupg-static-policy'
    repository = $Repository
    base_commit = $BaseCommit
    head_commit = $HeadCommit
    tree = $tree
    policy_hashes = [ordered]@{
        lock_sha256 = Get-NormalizedSha256 $LockPath
        inventory_sha256 = Get-NormalizedSha256 $InventoryPath
        scanner_sha256 = Get-NormalizedSha256 $ScannerPath
    }
    action_pins = $actionPins
    unresolved_dependencies = $unresolved
    attempts = [ordered]@{
        setup_msys2 = 0
        dependency_download = 0
        package_install = 0
        package_build = 0
        native_execution = 0
    }
}
$json = ($evidence | ConvertTo-Json -Depth 8) + "`n"
$parent = Split-Path -Parent $OutputPath
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
[IO.File]::WriteAllText($OutputPath, $json.Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($false))

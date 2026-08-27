param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Capture', 'Verify')]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [string]$SharedRoot = 'C:\msys64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-SharedState {
    $database = Join-Path $SharedRoot 'var\lib\pacman'
    $log = Join-Path $SharedRoot 'var\log\pacman.log'
    $files = @()
    if (Test-Path -LiteralPath $database -PathType Container) {
        $files = @(
            Get-ChildItem -LiteralPath $database -File -Recurse |
                Sort-Object FullName |
                ForEach-Object {
                    $relative = [IO.Path]::GetRelativePath($database, $_.FullName)
                    $hash = (
                        Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
                    ).Hash.ToLowerInvariant()
                    [pscustomobject]@{
                        Path = $relative.Replace('\', '/')
                        Size = $_.Length
                        Sha256 = $hash
                    }
                }
        )
    }

    $logIdentity = [pscustomobject]@{
        Exists = Test-Path -LiteralPath $log -PathType Leaf
        Size = 0L
        Sha256 = ''
    }
    if ($logIdentity.Exists) {
        $logItem = Get-Item -LiteralPath $log
        $logIdentity.Size = $logItem.Length
        $logIdentity.Sha256 = (
            Get-FileHash -LiteralPath $log -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }

    [pscustomobject]@{
        Schema = 1
        DatabaseFiles = $files
        Log = $logIdentity
    }
}

New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$baseline = Join-Path $EvidenceDirectory 'shared-state-before.json'
$after = Join-Path $EvidenceDirectory 'shared-state-after.json'

if ($Action -eq 'Capture') {
    Get-SharedState |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $baseline -Encoding utf8NoBOM
    exit 0
}

if (-not (Test-Path -LiteralPath $baseline -PathType Leaf)) {
    throw "shared-state baseline is missing: $baseline"
}
Get-SharedState |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $after -Encoding utf8NoBOM
$beforeHash = (Get-FileHash -LiteralPath $baseline -Algorithm SHA256).Hash
$afterHash = (Get-FileHash -LiteralPath $after -Algorithm SHA256).Hash
if ($beforeHash -ne $afterHash) {
    throw 'shared MSYS2 package database or log changed during private build'
}
@(
    "shared-client-invoked`tno"
    "shared-state-unchanged`tyes"
    "shared-sentinel-sha256`t$($beforeHash.ToLowerInvariant())"
) | Set-Content `
    -LiteralPath (Join-Path $EvidenceDirectory 'shared-state-verdict.tsv') `
    -Encoding utf8NoBOM

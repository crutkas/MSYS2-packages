[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Before', 'After')]
    [string]$Phase,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_REPOSITORY -ne 'crutkas/MSYS2-packages') {
    throw "Refusing shared-root observation in $($env:GITHUB_REPOSITORY)"
}
$branchCandidates = @($env:GITHUB_REF_NAME, $env:GITHUB_HEAD_REF) |
    Where-Object { $_ }
if ($branchCandidates -notcontains 'crutkas-arm64-msys-libuuid') {
    throw "Refusing shared-root observation for refs: $($branchCandidates -join ', ')"
}

$sharedRoot = 'C:\msys64'
if (-not (Test-Path -LiteralPath $sharedRoot -PathType Container)) {
    throw "Expected runner MSYS root is absent: $sharedRoot"
}

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

function Write-TreeManifest {
    param(
        [Parameter(Mandatory = $true)][string]$TreeRoot,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $TreeRoot -PathType Container)) {
        Write-Utf8NoBom -Path $OutputPath -Lines @('<absent>')
        return
    }
    $records = [Collections.Generic.List[string]]::new()
    foreach ($item in Get-ChildItem -LiteralPath $TreeRoot -Recurse -Force |
        Sort-Object FullName) {
        $relative = $item.FullName.Substring($TreeRoot.Length).
            TrimStart('\').Replace('\', '/')
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $target = @($item.Target) -join ','
            $kind = if ($item.PSIsContainer) { 'LINKDIR' } else { 'LINK' }
            $records.Add("$kind  $relative  $target")
            continue
        }
        if ($item.PSIsContainer) {
            $records.Add("DIR  $relative")
            continue
        }
        $hash = (Get-FileHash -Algorithm SHA256 $item.FullName).
            Hash.ToLowerInvariant()
        $records.Add("$hash  $relative")
    }
    Write-Utf8NoBom -Path $OutputPath -Lines $records
}

if ($Phase -eq 'Before') {
    if (Test-Path -LiteralPath $EvidenceDirectory) {
        Remove-Item -LiteralPath $EvidenceDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
}
elseif (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    throw 'Shared-root before evidence is missing'
}

$prefix = $Phase.ToLowerInvariant()
$dbManifest = Join-Path $EvidenceDirectory "$prefix-db.sha256"
$optManifest = Join-Path $EvidenceDirectory "$prefix-opt.sha256"
$logManifest = Join-Path $EvidenceDirectory "$prefix-log.sha256"
Write-TreeManifest `
    -TreeRoot (Join-Path $sharedRoot 'var\lib\pacman') `
    -OutputPath $dbManifest
Write-TreeManifest `
    -TreeRoot (Join-Path $sharedRoot 'opt') `
    -OutputPath $optManifest
Write-TreeManifest `
    -TreeRoot (Join-Path $sharedRoot 'var\log') `
    -OutputPath $logManifest

$pacmanLog = Join-Path $sharedRoot 'var\log\pacman.log'
$pacmanExe = Join-Path $sharedRoot 'usr\bin\pacman.exe'
$snapshot = [ordered]@{
    schema = 1
    phase = $prefix
    db_manifest_sha256 = (
        Get-FileHash -Algorithm SHA256 $dbManifest
    ).Hash.ToLowerInvariant()
    db_records = @(Get-Content -LiteralPath $dbManifest).Count
    opt_manifest_sha256 = (
        Get-FileHash -Algorithm SHA256 $optManifest
    ).Hash.ToLowerInvariant()
    opt_records = @(Get-Content -LiteralPath $optManifest).Count
    log_manifest_sha256 = (
        Get-FileHash -Algorithm SHA256 $logManifest
    ).Hash.ToLowerInvariant()
    log_records = @(Get-Content -LiteralPath $logManifest).Count
    pacman_log_size = (Get-Item -LiteralPath $pacmanLog).Length
    pacman_log_sha256 = (
        Get-FileHash -Algorithm SHA256 $pacmanLog
    ).Hash.ToLowerInvariant()
    pacman_exe_sha256 = (
        Get-FileHash -Algorithm SHA256 $pacmanExe
    ).Hash.ToLowerInvariant()
}
$summaryPath = Join-Path $EvidenceDirectory "$prefix-summary.json"
[IO.File]::WriteAllText(
    $summaryPath,
    ($snapshot | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false))

if ($Phase -eq 'After') {
    $beforePath = Join-Path $EvidenceDirectory 'before-summary.json'
    $before = Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json
    $fields = @(
        'db_manifest_sha256',
        'db_records',
        'opt_manifest_sha256',
        'opt_records',
        'log_manifest_sha256',
        'log_records',
        'pacman_log_size',
        'pacman_log_sha256',
        'pacman_exe_sha256'
    )
    $differences = [Collections.Generic.List[string]]::new()
    foreach ($field in $fields) {
        if ($before.$field -ne $snapshot[$field]) {
            $differences.Add(
                "$field`: before=$($before.$field) after=$($snapshot[$field])")
        }
    }
    $comparison = [ordered]@{
        schema = 1
        stable = ($differences.Count -eq 0)
        differences = @($differences)
    }
    [IO.File]::WriteAllText(
        (Join-Path $EvidenceDirectory 'comparison.json'),
        ($comparison | ConvertTo-Json -Depth 3),
        [Text.UTF8Encoding]::new($false))
    if ($differences.Count -ne 0) {
        throw "Shared runner root changed: $($differences -join '; ')"
    }

    $manifestPath = Join-Path $EvidenceDirectory 'evidence-manifest.sha256'
    $sealPath = Join-Path $EvidenceDirectory 'evidence.seal'
    $manifest = Get-ChildItem -LiteralPath $EvidenceDirectory -File |
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
}

$snapshot

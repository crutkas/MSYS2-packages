[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [string[]]$ForbiddenPaths
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    throw "Private evidence directory is absent: $EvidenceDirectory"
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    return $Path.Substring($Root.Length + 1).Replace('\', '/')
}

function Assert-EvidenceSeal {
    param([Parameter(Mandatory = $true)][string]$SealPath)

    $componentRoot = Split-Path -Parent $SealPath
    $sealValue = (Get-Content -LiteralPath $SealPath -Raw).Trim()
    if ($sealValue -notmatch
        '^([0-9a-f]{64})(?:  | \*)evidence-manifest\.sha256$') {
        throw "Invalid component seal format: $SealPath"
    }
    $manifestPath = Join-Path $componentRoot 'evidence-manifest.sha256'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-FileHash -Algorithm SHA256 $manifestPath).
            Hash.ToLowerInvariant() -ne $Matches[1]) {
        throw "Component manifest seal mismatch: $SealPath"
    }

    $listedPaths = [Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        if ($line -notmatch '^([0-9a-f]{64})(?:  | \*)(.+)$') {
            throw "Invalid component manifest line: $line"
        }
        $expectedHash = $Matches[1]
        $relative = $Matches[2].Replace('/', '\')
        if ([IO.Path]::IsPathRooted($relative) -or
            $relative.Split('\') -contains '..') {
            throw "Unsafe component manifest path: $relative"
        }
        $path = [IO.Path]::GetFullPath((Join-Path $componentRoot $relative))
        $prefix = [IO.Path]::GetFullPath($componentRoot).TrimEnd('\') + '\'
        if (-not $path.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileHash -Algorithm SHA256 $path).
                Hash.ToLowerInvariant() -ne $expectedHash) {
            throw "Component manifest entry mismatch: $relative"
        }
        $canonicalRelative = $relative.Replace('\', '/')
        if ($listedPaths.Contains($canonicalRelative)) {
            throw "Duplicate component manifest entry: $canonicalRelative"
        }
        $listedPaths.Add($canonicalRelative)
    }
    $actualPaths = @(Get-ChildItem -LiteralPath $componentRoot -Recurse -File |
        Where-Object {
            $_.FullName -notin @($manifestPath, $SealPath)
        } |
        ForEach-Object {
            Get-RelativePath -Root $componentRoot -Path $_.FullName
        } |
        Sort-Object)
    if ((@($listedPaths | Sort-Object) -join "`n") -ne
        ($actualPaths -join "`n")) {
        throw "Component manifest does not enumerate every file: $SealPath"
    }
}

$requiredComponents = @('commit', 'root', 'build', 'shared')
$actualComponents = @(Get-ChildItem -LiteralPath $EvidenceDirectory -Directory |
    Sort-Object Name |
    Select-Object -ExpandProperty Name)
if (($actualComponents -join "`n") -ne
    (@($requiredComponents | Sort-Object) -join "`n")) {
    throw "Private evidence component set is not exact: $(
        $actualComponents -join ', ')"
}
foreach ($component in $requiredComponents) {
    $seal = Join-Path $EvidenceDirectory "$component\evidence.seal"
    if (-not (Test-Path -LiteralPath $seal -PathType Leaf)) {
        throw "Private evidence component is incomplete: $component"
    }
    Assert-EvidenceSeal -SealPath $seal
}

$pathScanner = Join-Path `
    $PSScriptRoot 'scan-msysarm64-libuuid-private-paths.ps1'
& $pathScanner -SelfTest
& $pathScanner `
    -Paths @($EvidenceDirectory) `
    -ForbiddenPaths $ForbiddenPaths `
    -OutputPath (Join-Path $EvidenceDirectory 'path-scan.json')

$manifestPath = Join-Path $EvidenceDirectory 'evidence-manifest.sha256'
$sealPath = Join-Path $EvidenceDirectory 'evidence.seal'
$manifest = Get-ChildItem -LiteralPath $EvidenceDirectory -Recurse -File |
    Where-Object { $_.FullName -notin @($manifestPath, $sealPath) } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($EvidenceDirectory.Length + 1).
            Replace('\', '/')
        $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).
            Hash.ToLowerInvariant()
        "$hash  $relative"
    }
[IO.File]::WriteAllLines(
    $manifestPath,
    @($manifest),
    [Text.UTF8Encoding]::new($false))
$manifestHash = (Get-FileHash -Algorithm SHA256 $manifestPath).
    Hash.ToLowerInvariant()
[IO.File]::WriteAllText(
    $sealPath,
    "$manifestHash  evidence-manifest.sha256`n",
    [Text.UTF8Encoding]::new($false))

[ordered]@{
    schema = 1
    component_count = $requiredComponents.Count
    manifest_sha256 = $manifestHash
}

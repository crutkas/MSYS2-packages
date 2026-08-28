[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BuildA,

    [Parameter(Mandatory = $true)]
    [string]$BuildB,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [string]$DependencyLock
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$lock = Get-Content -LiteralPath $DependencyLock -Raw | ConvertFrom-Json
if ($lock.canonical_runtime_admitted -ne $true -or
    $lock.canonical_runtime.admitted -ne $true -or
    $lock.build_classification.status -cne
        'canonical-runtime-admitted-build-enabled') {
    throw 'reproducibility comparison requires an admitted canonical runtime'
}
foreach ($record in $lock.package_candidates.records) {
    if ($record.admitted -ne $false -or
        $record.eligible_for_admission -ne $false -or
        $record.independent_redownload_verified -ne $false -or
        $null -ne $record.coordinator_admission_reference -or
        $null -ne $record.asset_name -or
        $null -ne $record.size -or
        $null -ne $record.sha256) {
        throw "candidate record was populated before comparison: $($record.package)"
    }
}
$candidatePackages = @(
    $lock.package_candidates.records.package | Sort-Object -Unique
)
if ($candidatePackages.Count -ne 2 -or
    @(
        Compare-Object `
            -ReferenceObject @(
                'mingw-w64-cross-msysarm64-gmp',
                'mingw-w64-cross-msysarm64-gmp-devel') `
            -DifferenceObject $candidatePackages
    ).Count -ne 0) {
    throw 'candidate package record set is not exact'
}
foreach ($directory in @($BuildA, $BuildB)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "build output directory is missing: $directory"
    }
}
if (Test-Path -LiteralPath $EvidenceDirectory) {
    throw "reproducibility evidence directory already exists: $EvidenceDirectory"
}
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null

$expectedPackages = @(
    'mingw-w64-cross-msysarm64-gmp',
    'mingw-w64-cross-msysarm64-gmp-devel'
)
$builds = @{
    A = [IO.Path]::GetFullPath($BuildA)
    B = [IO.Path]::GetFullPath($BuildB)
}
$archives = @{}
foreach ($label in @('A', 'B')) {
    $found = @(
        Get-ChildItem -LiteralPath $builds[$label] -File |
            Where-Object Name -Like '*.pkg.tar.zst' |
            Sort-Object Name
    )
    if ($found.Count -ne 2) {
        throw "build $label did not produce exactly two package archives"
    }
    $byPackage = @{}
    foreach ($archive in $found) {
        $package = if ($archive.Name -like
            'mingw-w64-cross-msysarm64-gmp-devel-6.3.0-2-*.pkg.tar.zst') {
            'mingw-w64-cross-msysarm64-gmp-devel'
        }
        elseif ($archive.Name -like
            'mingw-w64-cross-msysarm64-gmp-6.3.0-2-*.pkg.tar.zst') {
            'mingw-w64-cross-msysarm64-gmp'
        }
        else {
            throw "unexpected build $label archive: $($archive.Name)"
        }
        if ($byPackage.ContainsKey($package)) {
            throw "duplicate build $label package: $package"
        }
        $byPackage[$package] = $archive
    }
    foreach ($package in $expectedPackages) {
        if (-not $byPackage.ContainsKey($package)) {
            throw "build $label omitted $package"
        }
    }
    $archives[$label] = $byPackage
}

function Get-InnerSeal {
    param(
        [Parameter(Mandatory = $true)][IO.FileInfo]$Archive,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $extractRoot = Join-Path $EvidenceDirectory "extract-$Label"
    New-Item -ItemType Directory -Path $extractRoot | Out-Null
    & tar.exe -xf $Archive.FullName -C $extractRoot
    if ($LASTEXITCODE -ne 0) {
        throw "cannot extract package for inner seal: $($Archive.Name)"
    }
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($entry in Get-ChildItem -LiteralPath $extractRoot -Force -Recurse |
            Sort-Object FullName) {
        $relative = [IO.Path]::GetRelativePath(
            $extractRoot,
            $entry.FullName).Replace('\', '/')
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $rows.Add("link`t$relative`t$($entry.LinkTarget)")
        }
        elseif ($entry.PSIsContainer) {
            $rows.Add("dir`t$relative")
        }
        else {
            $hash = (
                Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $rows.Add("file`t$relative`t$($entry.Length)`t$hash")
        }
    }
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
    return @($rows)
}

$packageRows = [Collections.Generic.List[string]]::new()
foreach ($package in $expectedPackages) {
    $a = $archives.A[$package]
    $b = $archives.B[$package]
    if ($a.Name -cne $b.Name) {
        throw "$package archive names differ between builds"
    }
    $hashA = (Get-FileHash $a.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashB = (Get-FileHash $b.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($a.Length -ne $b.Length -or $hashA -cne $hashB) {
        throw "$package archive bytes differ between builds"
    }

    $sealA = Get-InnerSeal -Archive $a -Label "$package-A"
    $sealB = Get-InnerSeal -Archive $b -Label "$package-B"
    if (($sealA -join "`n") -cne ($sealB -join "`n")) {
        throw "$package inner trees differ between builds"
    }
    $sealA | Set-Content `
        -LiteralPath (Join-Path $EvidenceDirectory "$package.inner-tree.tsv") `
        -Encoding utf8NoBOM
    $packageRows.Add(
        "$package`t$($a.Name)`t$($a.Length)`t$hashA")
}
$packageRows | Set-Content `
    -LiteralPath (Join-Path $EvidenceDirectory 'packages.tsv') `
    -Encoding utf8NoBOM
@(
    'classification=canonical-build-candidate'
    'admissible=false'
    'archive-byte-equality=pass'
    'inner-tree-equality=pass'
) | Set-Content `
    -LiteralPath (Join-Path $EvidenceDirectory 'summary.txt') `
    -Encoding utf8NoBOM

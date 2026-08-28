[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BuildAPath,

    [Parameter(Mandatory = $true)]
    [string] $BuildBPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(Mandatory = $true)]
    [string] $EvidencePath,

    [Parameter(Mandatory = $true)]
    [string] $InventoryPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PackageRecords {
    param([string] $Path)
    $root = (Resolve-Path -LiteralPath $Path).Path
    $packages = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.pkg.tar.*')
    if ($packages.Count -eq 0) {
        throw "No packages found in independent build: $root"
    }
    $records = @(
        foreach ($package in $packages) {
            [pscustomobject]@{
                name = $package.Name
                path = $package.FullName
                bytes = $package.Length
                sha256 = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
    if (@($records.name | Sort-Object -Unique).Count -ne $records.Count) {
        throw "Independent build contains duplicate package names: $root"
    }
    return @($records | Sort-Object name)
}

function Get-SingleEvidence {
    param(
        [string] $Root,
        [string] $Name
    )
    $matches = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name)
    if ($matches.Count -ne 1) {
        throw "Independent build must contain exactly one ${Name}: $Root"
    }
    $evidence = Get-Content -LiteralPath $matches[0].FullName -Raw | ConvertFrom-Json
    if ($evidence.schema_version -ne 1 -or $evidence.result -ne 'pass') {
        throw "Independent build evidence did not pass: $($matches[0].FullName)"
    }
    return $evidence
}

function Get-BuildEvidenceIds {
    param(
        [string] $Root,
        [string] $ExpectedBuildId,
        [object[]] $Packages
    )
    $identity = Get-SingleEvidence $Root 'build-identity-evidence.json'
    if ($identity.build_id -ne $ExpectedBuildId -or -not $identity.source_signature_verified) {
        throw "Independent build identity or source-signature evidence is invalid: $Root"
    }

    $paths = Get-SingleEvidence $Root 'forbidden-path-evidence.json'
    if (@($paths.scanned_entries).Count -eq 0 -or
        (Compare-Object @('ascii', 'nul_rich', 'utf16be', 'utf16le') @($paths.encodings | Sort-Object))) {
        throw "Forbidden-path evidence is incomplete: $Root"
    }
    $scannedPackages = @(
        $paths.scanned_entries |
            ForEach-Object { Split-Path -Leaf $_.input } |
            Sort-Object -Unique
    )
    if (Compare-Object @($Packages.name | Sort-Object) $scannedPackages) {
        throw "Forbidden-path evidence does not cover every package: $Root"
    }
    $scanInputs = @($paths.inputs | Where-Object type -eq 'archive')
    if (Compare-Object @($Packages.name | Sort-Object) @(
        $scanInputs | ForEach-Object { Split-Path -Leaf $_.path } | Sort-Object
    )) {
        throw "Forbidden-path archive evidence does not cover every package: $Root"
    }
    foreach ($packageRecord in $Packages) {
        $scanInput = @(
            $scanInputs |
                Where-Object { (Split-Path -Leaf $_.path) -eq $packageRecord.name }
        )
        if ($scanInput.Count -ne 1 -or
            $scanInput[0].bytes -ne $packageRecord.bytes -or
            $scanInput[0].sha256 -ne $packageRecord.sha256) {
            throw "Forbidden-path evidence is not bound to package bytes: $($packageRecord.name)"
        }
    }

    $package = Get-SingleEvidence $Root 'package-evidence.json'
    if ($package.target -ne 'aarch64-pc-msys' -or $package.pe_count -le 0 -or
        @($package.pe | Where-Object { $_.pseudo_reloc.result -ne 'pass' }).Count -ne 0) {
        throw "Package architecture or pseudo-relocation evidence is incomplete: $Root"
    }

    $transaction = Get-SingleEvidence $Root 'candidate-transaction.json'
    $integrity = @($transaction.candidate_integrity)
    if ($integrity.Count -eq 0 -or
        @($integrity | Where-Object {
            [string]::IsNullOrWhiteSpace($_.archive) -or
            $null -eq $_.archive_bytes -or
            [string]::IsNullOrWhiteSpace($_.archive_sha256) -or
            -not $_.qkk_detected_corruption -or
            [string]::IsNullOrWhiteSpace($_.mtree_sha256) -or
            [string]::IsNullOrWhiteSpace($_.exact_reinstall_recovered_sha256) -or
            @($_.final_installed_manifest).Count -eq 0
        }).Count -ne 0) {
        throw "Ownership, MTREE, corruption or reinstall evidence is incomplete: $Root"
    }
    if (Compare-Object @($Packages.name | Sort-Object) @($integrity.archive | Sort-Object)) {
        throw "Lifecycle evidence does not cover every package: $Root"
    }
    foreach ($packageRecord in $Packages) {
        $packageIntegrity = @($integrity | Where-Object archive -eq $packageRecord.name)
        if ($packageIntegrity.Count -ne 1 -or
            $packageIntegrity[0].archive_bytes -ne $packageRecord.bytes -or
            $packageIntegrity[0].archive_sha256 -ne $packageRecord.sha256) {
            throw "Lifecycle evidence is not bound to package bytes: $($packageRecord.name)"
        }
    }

    return @(
        'source-signature-verification'
        "independent-build-$ExpectedBuildId"
        'complete-ownership-mtree'
        'corruption-detection-reinstall-recovery'
        'forbidden-path-binary-scan'
        'package-architecture-imports'
        'pseudo-relocations'
    )
}

$buildA = @(Get-PackageRecords $BuildAPath)
$buildB = @(Get-PackageRecords $BuildBPath)
if (Compare-Object $buildA.name $buildB.name) {
    throw 'Independent builds produced different package sets'
}

$matched = @()
foreach ($left in $buildA) {
    $right = @($buildB | Where-Object name -eq $left.name)
    if ($right.Count -ne 1 -or $left.bytes -ne $right[0].bytes -or $left.sha256 -ne $right[0].sha256) {
        throw "Independent builds are not byte-identical: $($left.name)"
    }
    $matched += [ordered]@{
        name = $left.name
        bytes = $left.bytes
        sha256 = $left.sha256
    }
}

$manifestLines = @($matched | ForEach-Object { "$($_.sha256)  $($_.name)" })
$manifest = ($manifestLines -join "`n") + "`n"
$buildEvidence = @(
    Get-BuildEvidenceIds $BuildAPath 'a' $buildA
    Get-BuildEvidenceIds $BuildBPath 'b' $buildB
    'byte-identical-packages'
) | Sort-Object -Unique
$declaredBuildEvidence = @(
    (Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json).required_build_evidence
)
if ($declaredBuildEvidence.Count -eq 0 -or
    @($declaredBuildEvidence | Sort-Object -Unique).Count -ne $declaredBuildEvidence.Count) {
    throw 'Inventory build-evidence requirements must be nonempty and unique'
}
$requiredBuildEvidence = @($declaredBuildEvidence | Sort-Object)
if (Compare-Object $requiredBuildEvidence $buildEvidence) {
    throw 'Build evidence does not exactly satisfy inventory requirements'
}

$destination = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) {
    throw "Reproducibility output already exists: $destination"
}
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($record in $buildA) {
    Copy-Item -LiteralPath $record.path -Destination (Join-Path $destination $record.name)
}
$manifestPath = Join-Path $destination 'SHA256SUMS'
[IO.File]::WriteAllText($manifestPath, $manifest, [Text.UTF8Encoding]::new($false))
$manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

$evidence = [ordered]@{
    schema_version = 1
    result = 'pass'
    independent_builds = 2
    comparison = 'byte-identical'
    packages = $matched
    package_manifest_sha256 = $manifestSha256
    completed_build_evidence = $buildEvidence
}
$parent = Split-Path -Parent $EvidencePath
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

[pscustomobject]@{
    result = 'pass'
    package_manifest_sha256 = $manifestSha256
    packages = $matched.Count
}

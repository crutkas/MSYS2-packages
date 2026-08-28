[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LockPath,

    [switch] $AllowUnresolved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
if ($lock.schema_version -ne 1) {
    throw "Unsupported lock schema: $($lock.schema_version)"
}
if ($lock.target.triplet -ne 'aarch64-pc-msys' -or
    $lock.target.object_format -ne 'pei-aarch64-little' -or
    $lock.target.abi -ne 'LP64/AAPCS64/SEH' -or
    $lock.target.runtime -ne 'msys-2.0.dll') {
    throw 'The dependency lock does not describe the required MSYS ARM64 ABI'
}

$expectedSource = @{
    archive_bytes = 8010244
    archive_sha256 = '7b24706e4da7e0e3b06ca068231027401f238102c41c909631349dcc3b85eb46'
    signature_bytes = 238
    signature_sha256 = '043bd2067efc5ad5837767fef556096dd42490f98bc12a47c6ef0e42fa552560'
}
foreach ($field in $expectedSource.Keys) {
    if ($lock.source.$field -ne $expectedSource[$field]) {
        throw "Source pin mismatch for $field"
    }
}

$expectedFoundations = @{
    'gcc' = @('msysarm64-gcc-pr13-20260826', 83876291, 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22', 'mingw-w64-cross-msysarm64-gcc', '15.0.1dev-1', 'c17cf6f65ebbf88cdc7cfa0cbf6f038eba955a67')
    'gcc-libs' = @('msysarm64-gcc-pr13-20260826', 4963824, '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438', 'mingw-w64-cross-msysarm64-gcc-libs', '15.0.1dev-1', 'c17cf6f65ebbf88cdc7cfa0cbf6f038eba955a67')
    'libstdcxx-headers' = @('msysarm64-gcc-pr13-support-20260826', 1520166, '9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08', 'mingw-w64-cross-msysarm64-libstdc++-headers', '15.0.1dev-1', '42f1fb808363203a83c7f6f935ab7e4bdffbe127')
    'w32api-runtime' = @('msysarm64-gcc-pr13-support-20260826', 2349635, '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24', 'mingw-w64-cross-msysarm64-w32api-runtime', '14.0.0.r0.g9b3dd0125-1', '42f1fb808363203a83c7f6f935ab7e4bdffbe127')
    'binutils' = @('cygwinarm64-binutils-pr21-3356eec-20260827', 6545114, '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b', 'mingw-w64-cross-cygwinarm64-binutils', '2.44.50-2', '3356eec1411983cc252b04afac32bca5f3b8d824')
}

$revokedReleases = @($lock.revoked_releases)
$revokedTags = @(
    $revokedReleases |
        ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_.release_tag) -or
                [string]::IsNullOrWhiteSpace($_.reason)) {
                throw 'Every revoked release requires a tag and reason'
            }
            $_.release_tag
        }
)
if (@($revokedTags | Sort-Object -Unique).Count -ne $revokedTags.Count) {
    throw 'Revoked release tags must be unique'
}
foreach ($dependency in $lock.dependencies) {
    if ($null -ne $dependency.release_tag -and $dependency.release_tag -in $revokedTags) {
        throw "Dependency $($dependency.id) references revoked release $($dependency.release_tag)"
    }
}

$quarantinedReleases = @($lock.quarantined_releases)
$quarantinedTags = @(
    $quarantinedReleases |
        ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_.release_tag) -or
                [string]::IsNullOrWhiteSpace($_.reason) -or
                $_.immutable -or -not $_.diagnostic_only) {
                throw 'Every quarantined release must be explicitly nonimmutable and diagnostic-only'
            }
            $_.release_tag
        }
)
if (@($quarantinedTags | Sort-Object -Unique).Count -ne $quarantinedTags.Count) {
    throw 'Quarantined release tags must be unique'
}
foreach ($dependency in $lock.dependencies) {
    if ($null -ne $dependency.release_tag -and $dependency.release_tag -in $quarantinedTags) {
        throw "Dependency $($dependency.id) references quarantined release $($dependency.release_tag)"
    }
}
$libgpgQuarantine = @(
    $quarantinedReleases |
        Where-Object release_tag -eq 'msysarm64-libgpg-error-pr16-06ae2f9-20260827'
)
if ($libgpgQuarantine.Count -ne 1 -or
    $libgpgQuarantine[0].release_id -ne 378064013 -or
    $libgpgQuarantine[0].producer_commit -ne '06ae2f9c2ad5d69e736e4d056772a7be1546a076') {
    throw 'The nonimmutable libgpg-error release requires one authoritative quarantine record'
}
$expectedLibgpgDiagnostics = @{
    'mingw-w64-cross-msysarm64-libgpg-error-1.56-1-x86_64.pkg.tar.zst' = @(
        125720,
        'ca9c377b91896f3286071fd456389006ade6e297e7dd21efb06ab572ccb55d34'
    )
    'mingw-w64-cross-msysarm64-libgpg-error-devel-1.56-1-x86_64.pkg.tar.zst' = @(
        123170,
        '642880ad8fc5498fa7b755825b30008d466dbefa0dd07de80f5f5516b7968a2a'
    )
}
$diagnostics = @($libgpgQuarantine[0].package_diagnostics)
if ($diagnostics.Count -ne $expectedLibgpgDiagnostics.Count) {
    throw 'The libgpg-error quarantine diagnostic package set changed'
}
foreach ($assetName in $expectedLibgpgDiagnostics.Keys) {
    $diagnostic = @($diagnostics | Where-Object asset_name -eq $assetName)
    $expected = $expectedLibgpgDiagnostics[$assetName]
    if ($diagnostic.Count -ne 1 -or
        $diagnostic[0].asset_bytes -ne $expected[0] -or
        $diagnostic[0].asset_sha256 -ne $expected[1]) {
        throw "The libgpg-error quarantine diagnostic identity changed: $assetName"
    }
}

$revokedRuntimeTag = 'msysarm64-runtime-pr10-a527-20260824'
$revocation = @($revokedReleases | Where-Object release_tag -eq $revokedRuntimeTag)
if ($revocation.Count -ne 1) {
    throw 'The revoked ARM64 runtime release must have one authoritative revocation record'
}

$ids = @($lock.dependencies | ForEach-Object { $_.id })
if (($ids | Sort-Object -Unique).Count -ne $ids.Count) {
    throw 'Dependency IDs must be unique'
}

$unresolved = @()
foreach ($dependency in $lock.dependencies) {
    if ($dependency.status -eq 'not-applicable') {
        if ($dependency.required) {
            throw "$($dependency.id) is required but marked not-applicable"
        }
        continue
    }
    if ($dependency.status -eq 'unresolved') {
        if (-not $dependency.required) {
            throw "$($dependency.id) is unresolved but not required"
        }
        foreach ($field in @('release_tag', 'asset_url', 'asset_name', 'asset_bytes', 'asset_sha256', 'producer_commit', 'package')) {
            if ($null -ne $dependency.$field) {
                throw "Unresolved dependency $($dependency.id) has provisional $field"
            }
        }
        $unresolved += $dependency.id
        continue
    }
    if ($dependency.status -ne 'admitted') {
        throw "Unknown dependency status for $($dependency.id): $($dependency.status)"
    }
    if ($dependency.asset_bytes -le 0 -or $dependency.asset_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid asset size or SHA-256 for $($dependency.id)"
    }
    if ([string]::IsNullOrWhiteSpace($dependency.release_tag) -or
        [string]::IsNullOrWhiteSpace($dependency.producer_commit) -or
        $null -eq $dependency.package -or
        [string]::IsNullOrWhiteSpace($dependency.package.name) -or
        [string]::IsNullOrWhiteSpace($dependency.package.version) -or
        @($dependency.package.provides).Count -eq 0 -or
        @($dependency.package.owned_files).Count -eq 0) {
        throw "Incomplete admitted metadata for $($dependency.id)"
    }
    $uri = [Uri] $dependency.asset_url
    $decodedPath = [Uri]::UnescapeDataString($uri.AbsolutePath)
    $expectedSuffix = "/releases/download/$($dependency.release_tag)/$($dependency.asset_name)"
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com' -or
        -not $decodedPath.StartsWith('/crutkas/MSYS2-packages/', [StringComparison]::Ordinal) -or
        -not $decodedPath.EndsWith($expectedSuffix, [StringComparison]::Ordinal)) {
        throw "Asset URL is not an immutable crutkas release URL for $($dependency.id)"
    }
}

foreach ($id in $expectedFoundations.Keys) {
    $dependency = @($lock.dependencies | Where-Object id -eq $id)
    if ($dependency.Count -ne 1 -or $dependency[0].status -ne 'admitted') {
        throw "Missing admitted immutable foundation: $id"
    }
    $expected = $expectedFoundations[$id]
    $actual = $dependency[0]
    if ($actual.release_tag -ne $expected[0] -or
        $actual.asset_bytes -ne $expected[1] -or
        $actual.asset_sha256 -ne $expected[2] -or
        $actual.package.name -ne $expected[3] -or
        $actual.package.version -ne $expected[4] -or
        $actual.producer_commit -ne $expected[5]) {
        throw "Immutable foundation mismatch: $id"
    }
}
if (Compare-Object @($expectedFoundations.Keys | Sort-Object) @(
    $lock.dependencies |
        Where-Object status -eq 'admitted' |
        ForEach-Object id |
        Sort-Object
)) {
    throw 'The lock admits an unexpected dependency; no crypto leaf is currently admitted'
}

$scanner = $lock.fixed_binutils_evidence.scanner
if ($scanner.commit -ne '3356eec1411983cc252b04afac32bca5f3b8d824' -or
    $scanner.path -ne '.ci/check-aarch64-pseudo-relocs.ps1' -or
    $scanner.sha256 -ne '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9' -or
    $scanner.package_contained) {
    throw 'Fixed-binutils scanner provenance mismatch'
}

if ($unresolved.Count -ne 0 -and -not $AllowUnresolved) {
    throw "Required dependencies are unresolved: $($unresolved -join ', ')"
}

[pscustomobject]@{
    result = 'pass'
    admitted = @($lock.dependencies | Where-Object status -eq 'admitted').Count
    unresolved = $unresolved
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LockPath,

    [string] $Repository = 'crutkas/MSYS2-packages',
    [string] $ResponseDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$unresolved = @($lock.dependencies | Where-Object { $_.required -and $_.status -ne 'admitted' })
if ($unresolved.Count -ne 0) {
    throw "Live release validation is forbidden until the lock is complete: $($unresolved.id -join ', ')"
}

$globallyQuarantinedReleaseIds = @(377908415)
$admitted = @($lock.dependencies | Where-Object status -eq 'admitted')
$releaseIds = @($admitted | ForEach-Object release_id | Sort-Object -Unique)
foreach ($releaseId in $releaseIds) {
    if ($releaseId -in $globallyQuarantinedReleaseIds) {
        throw "Globally quarantined release ID cannot be admitted: $releaseId"
    }

    if ($ResponseDirectory) {
        $responsePath = Join-Path $ResponseDirectory "$releaseId.json"
        $release = Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json
    }
    else {
        $headers = @{
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $release = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$Repository/releases/$releaseId" `
            -Headers $headers `
            -UserAgent 'crutkas-msysarm64-gnupg-admission'
    }

    if ('immutable' -notin @($release.PSObject.Properties.Name)) {
        throw "Release response omits immutable status: $releaseId"
    }
    if ($release.immutable -ne $true) {
        throw "Release is not immutable: $releaseId"
    }

    $dependencies = @($admitted | Where-Object release_id -eq $releaseId)
    $expectedTag = @($dependencies.release_tag | Sort-Object -Unique)
    if ($release.id -ne $releaseId -or $expectedTag.Count -ne 1 -or
        $release.tag_name -ne $expectedTag[0]) {
        throw "Release ID or tag drift: $releaseId"
    }

    foreach ($dependency in $dependencies) {
        $asset = @($release.assets | Where-Object id -eq $dependency.asset_id)
        if ($asset.Count -ne 1 -or
            $asset[0].name -ne $dependency.asset_name -or
            $asset[0].size -ne $dependency.asset_bytes -or
            $asset[0].digest -ne "sha256:$($dependency.asset_sha256)" -or
            $asset[0].browser_download_url -ne $dependency.asset_url) {
            throw "Release asset identity drift: $($dependency.id)"
        }
    }
}

[pscustomobject]@{
    result = 'pass'
    releases = $releaseIds.Count
    assets = $admitted.Count
}

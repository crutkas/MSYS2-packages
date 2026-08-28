[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Packages,

    [Parameter(Mandatory = $true)]
    [string] $InventoryPath,

    [string] $Bsdtar = 'C:\msys64\usr\bin\bsdtar.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
$expectedNames = @($inventory.packages.psobject.Properties.Name | Sort-Object)
$actualNames = @()
foreach ($archive in $Packages) {
    $info = @(& $Bsdtar -xOf $archive .PKGINFO)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read package metadata: $archive"
    }
    $nameLine = @($info | Where-Object { $_ -match '^pkgname = ' })
    if ($nameLine.Count -ne 1) {
        throw "Package has invalid pkgname metadata: $archive"
    }
    $name = $nameLine[0].Substring(10)
    if ($name -notin $expectedNames) {
        throw "Unexpected split package: $name"
    }
    $actualNames += $name
    $contract = $inventory.packages.$name
    $owned = @(
        & $Bsdtar -tf $archive |
            Where-Object { $_ -and $_ -notmatch '^\.|/$' }
    )
    if ($contract.requires_nonempty -and $owned.Count -eq 0) {
        throw "Split package is empty: $name"
    }
    foreach ($prefix in @($contract.path_prefixes)) {
        $prefixWithSlash = "$($prefix.TrimEnd('/'))/"
        if (@($owned | Where-Object { $_.StartsWith($prefixWithSlash, [StringComparison]::Ordinal) }).Count -eq 0) {
            throw "Split package $name has no owned file under $prefix"
        }
    }
    $allowedPrefixes = @($contract.path_prefixes | ForEach-Object { "$($_.TrimEnd('/'))/" })
    $unexpected = @(
        $owned | Where-Object {
            $path = $_
            -not $path.StartsWith('usr/share/licenses/', [StringComparison]::Ordinal) -and
            @($allowedPrefixes | Where-Object { $path.StartsWith($_, [StringComparison]::Ordinal) }).Count -eq 0
        }
    )
    if ($unexpected.Count -ne 0) {
        throw "Split package $name owns files outside its contract: $($unexpected -join ', ')"
    }
}

if (Compare-Object $expectedNames ($actualNames | Sort-Object)) {
    throw "Missing or duplicate split package. Expected: $($expectedNames -join ', '); actual: $($actualNames -join ', ')"
}

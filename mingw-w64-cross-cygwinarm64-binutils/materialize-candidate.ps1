[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SourceCommit,
    [Parameter(Mandatory = $true)]
    [string] $SourceArchiveSha256,
    [Parameter(Mandatory = $true)]
    [long] $SourceArchiveSize,
    [Parameter(Mandatory = $true)]
    [string] $SourceTree,
    [Parameter(Mandatory = $true)]
    [string] $PackageVersion,
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int] $PackageRelease,
    [Parameter(Mandatory = $true)]
    [switch] $PackageExactHeadCiAuthority,
    [string] $SourceRepository = 'crutkas/binutils-woarm64',
    [string] $TemplatePath = (Join-Path $PSScriptRoot 'PKGBUILD.fixed.in'),
    [string] $OutputPath = (Join-Path $PSScriptRoot 'PKGBUILD')
)

$ErrorActionPreference = 'Stop'
$FrozenSourceCommit = '3f05fc4d3e0eeab265f2157e3257a7067b6e7223'
$FrozenSourceTree = 'ecca625d45883e13128283a8c1750dac7997f729'
$FrozenSourceArchiveSize = 66204943
$FrozenSourceArchiveSha256 =
    'd11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e'
$FrozenPackageVersion = '2.44.50'
$FrozenPackageRelease = 2

$SourceCommit = $SourceCommit.ToLowerInvariant()
$SourceArchiveSha256 = $SourceArchiveSha256.ToLowerInvariant()
$SourceTree = $SourceTree.ToLowerInvariant()
if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'SourceCommit must be an exact 40-character lowercase hexadecimal commit.'
}
if ($SourceArchiveSha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'SourceArchiveSha256 must be an exact 64-character hexadecimal digest.'
}
if ($SourceTree -notmatch '^[0-9a-f]{40}$') {
    throw 'SourceTree must be an exact 40-character lowercase hexadecimal tree.'
}
if ($SourceArchiveSize -le 0) {
    throw 'SourceArchiveSize must be positive.'
}
if ($PackageVersion -notmatch '^[0-9][0-9A-Za-z._+]*$') {
    throw 'PackageVersion is not a valid source-derived pkgver.'
}
if ($PackageVersion -eq '2.44.50' -and $PackageRelease -lt 2) {
    throw 'The fixed 2.44.50 candidate must advance pkgrel beyond baseline 1.'
}
if (-not $PackageExactHeadCiAuthority) {
    throw 'Package exact-head CI authority must be explicitly admitted.'
}
if ($SourceCommit -ne $FrozenSourceCommit -or
    $SourceTree -ne $FrozenSourceTree -or
    $SourceArchiveSize -ne $FrozenSourceArchiveSize -or
    $SourceArchiveSha256 -ne $FrozenSourceArchiveSha256 -or
    $PackageVersion -ne $FrozenPackageVersion -or
    $PackageRelease -ne $FrozenPackageRelease) {
    throw 'Candidate inputs do not match the frozen reviewed source/package admission unit.'
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'gh is required to verify the immutable source commit and tree.'
}
$commit = gh api "repos/$SourceRepository/commits/$SourceCommit" |
    ConvertFrom-Json
if ($commit.sha -ne $SourceCommit -or $commit.commit.tree.sha -ne $SourceTree) {
    throw "Source commit/tree mismatch: $($commit.sha)/$($commit.commit.tree.sha)"
}

$archive = Join-Path ([System.IO.Path]::GetTempPath()) "$SourceCommit.tar.gz"
try {
    $archiveUrl = "https://github.com/$SourceRepository/archive/$SourceCommit.tar.gz"
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archive
    $actualArchiveSize = (Get-Item -LiteralPath $archive).Length
    if ($actualArchiveSize -ne $SourceArchiveSize) {
        throw "Source archive size mismatch: $actualArchiveSize"
    }
    $actualArchiveSha256 = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    if ($actualArchiveSha256 -ne $SourceArchiveSha256) {
        throw "Source archive SHA-256 mismatch: $actualArchiveSha256"
    }

    $content = Get-Content -LiteralPath $TemplatePath -Raw
    $replacements = [ordered]@{
        '@SOURCE_COMMIT@' = $SourceCommit
        '@SOURCE_TREE@' = $SourceTree
        '@SOURCE_ARCHIVE_SIZE@' = $SourceArchiveSize.ToString(
            [System.Globalization.CultureInfo]::InvariantCulture)
        '@SOURCE_ARCHIVE_SHA256@' = $SourceArchiveSha256
        '@PKGVER@' = $PackageVersion
        '@PKGREL@' = $PackageRelease.ToString(
            [System.Globalization.CultureInfo]::InvariantCulture)
    }
    foreach ($entry in $replacements.GetEnumerator()) {
        if (-not $content.Contains($entry.Key)) {
            throw "Candidate template is missing token $($entry.Key)."
        }
        $content = $content.Replace($entry.Key, $entry.Value)
    }
    if ($content -match '@[A-Z0-9_]+@') {
        throw 'Candidate template still contains unresolved admission tokens.'
    }
    [System.IO.File]::WriteAllText(
        $OutputPath,
        $content.Replace("`r`n", "`n"),
        [System.Text.UTF8Encoding]::new($false))
}
finally {
    Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    source_repository = $SourceRepository
    source_commit = $SourceCommit
    source_tree = $SourceTree
    source_archive_size = $SourceArchiveSize
    source_archive_sha256 = $SourceArchiveSha256
    source_ci_authority = 'package-exact-head'
    package_version = $PackageVersion
    package_release = $PackageRelease
    output = (Resolve-Path -LiteralPath $OutputPath).Path
} | ConvertTo-Json

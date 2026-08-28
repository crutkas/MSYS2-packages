[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ArchivePath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [string] $TarPath = 'tar.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-ArchivePath {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [string] $BasePath = ''
    )

    if (-not $Path -or
        $Path.StartsWith('/') -or
        $Path.StartsWith('\') -or
        $Path -match '^[A-Za-z]:' -or
        $Path.Contains('\')) {
        throw "unsafe archive path: $Path"
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($BasePath) {
        foreach ($part in $BasePath.Split('/')) {
            if ($part -and $part -ne '.') { $parts.Add($part) }
        }
    }
    foreach ($part in $Path.Split('/')) {
        switch ($part) {
            { -not $_ -or $_ -eq '.' } { continue }
            '..' {
                if ($parts.Count -eq 0) {
                    throw "archive path escapes root: $Path"
                }
                $parts.RemoveAt($parts.Count - 1)
            }
            default { $parts.Add($part) }
        }
    }
    return $parts -join '/'
}

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
if ($TarPath -eq 'tar.exe' -and (Test-Path -LiteralPath $systemTar)) {
    $TarPath = $systemTar
}
$entries = @(& $TarPath -tf $archive 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "archive listing failed: $($entries -join [Environment]::NewLine)"
}
$normalizedEntries = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($entry in $entries) {
    $normalized = Normalize-ArchivePath -Path $entry.TrimEnd('/')
    if ($normalized -and -not $normalizedEntries.Add($normalized)) {
        throw "duplicate normalized archive path: $normalized"
    }
}

$verbose = @(& $TarPath -tvf $archive 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "verbose archive listing failed: $($verbose -join [Environment]::NewLine)"
}
$links = [System.Collections.Generic.List[object]]::new()
$entriesByLength = @(
    $normalizedEntries |
        Sort-Object -Property Length -Descending
)
foreach ($line in $verbose) {
    $trimmed = $line.TrimStart()
    if (-not $trimmed -or $trimmed[0] -notin @('h', 'l')) { continue }

    $separator = if ($trimmed[0] -eq 'l') { ' -> ' } else { ' link to ' }
    $separatorIndex = $trimmed.LastIndexOf($separator)
    if ($separatorIndex -lt 0) {
        throw "unparseable archive link: $line"
    }
    $left = $trimmed.Substring(0, $separatorIndex)
    $target = $trimmed.Substring($separatorIndex + $separator.Length)
    $entry = @(
        $entriesByLength |
            Where-Object {
                $left.EndsWith(" $_", [StringComparison]::Ordinal)
            } |
            Select-Object -First 1
    )
    if ($entry.Count -ne 1) {
        throw "unable to bind archive link path: $line"
    }

    $base = if ($trimmed[0] -eq 'l') {
        Split-Path -Parent $entry[0] | ForEach-Object { $_ -replace '\\', '/' }
    }
    else {
        ''
    }
    $resolvedTarget = Normalize-ArchivePath -Path $target -BasePath $base
    $targetPresent = $normalizedEntries.Contains($resolvedTarget)
    if ($trimmed[0] -eq 'h' -and -not $targetPresent) {
        throw "archive link target is not contained: $($entry[0]) -> $target"
    }
    $links.Add([ordered]@{
        type = if ($trimmed[0] -eq 'l') { 'symlink' } else { 'hardlink' }
        path = $entry[0]
        target = $target
        resolved_target = $resolvedTarget
        target_in_archive = $targetPresent
    })
}

$result = [ordered]@{
    schema = 1
    archive = Split-Path -Leaf $archive
    archive_sha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $archive
    ).Hash.ToLowerInvariant()
    entry_count = $normalizedEntries.Count
    link_count = $links.Count
    links = $links
    result = 'pass'
}
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
[IO.File]::WriteAllText(
    $OutputPath,
    (($result | ConvertTo-Json -Depth 6) + "`n"),
    [Text.UTF8Encoding]::new($false))

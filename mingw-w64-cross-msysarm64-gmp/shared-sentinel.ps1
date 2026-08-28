[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Capture', 'Compare')]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [string]$SharedRoot = 'C:\msys64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sentinels = @(
    'var\lib\pacman',
    'var\cache\pacman',
    'var\log\pacman.log',
    'etc\pacman.conf',
    'etc\pacman.d\hooks',
    'etc\pacman.d\gnupg'
)

function Get-SentinelRows {
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in $sentinels) {
        $path = Join-Path $SharedRoot $relative
        if (-not (Test-Path -LiteralPath $path)) {
            $rows.Add("missing`t$relative")
            continue
        }
        $item = Get-Item -Force -LiteralPath $path
        $items = if ($item.PSIsContainer) {
            @($item) + @(Get-ChildItem -Force -Recurse -LiteralPath $path)
        }
        else {
            @($item)
        }
        foreach ($entry in $items) {
            $name = [IO.Path]::GetRelativePath($SharedRoot, $entry.FullName)
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $rows.Add("link`t$name`t$($entry.LinkTarget)")
            }
            elseif ($entry.PSIsContainer) {
                $rows.Add("dir`t$name")
            }
            else {
                $hash = (
                    Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                $rows.Add("file`t$name`t$($entry.Length)`t$hash")
            }
        }
    }
    return @($rows | Sort-Object -CaseSensitive)
}
$current = (Get-SentinelRows) -join "`n"
$current += "`n"
if ($Action -eq 'Capture') {
    $parent = Split-Path -Parent $ManifestPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText(
        $ManifestPath,
        $current,
        [Text.UTF8Encoding]::new($false))
    exit 0
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "shared-state baseline is missing: $ManifestPath"
}
$baseline = [IO.File]::ReadAllText($ManifestPath)
if ($current -cne $baseline) {
    $actual = "$ManifestPath.actual"
    [IO.File]::WriteAllText(
        $actual,
        $current,
        [Text.UTF8Encoding]::new($false))
    throw "shared MSYS2 state changed; compare $ManifestPath and $actual"
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $EvidenceRoot,

    [Parameter(Mandatory = $true)]
    [string[]] $SensitivePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$replacements = [System.Collections.Generic.List[object]]::new()
$index = 0
foreach ($sensitive in $SensitivePath) {
    if (-not $sensitive) { continue }
    $index++
    $token = "<private-root-$index>"
    $variants = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [void] $variants.Add($sensitive.TrimEnd('\', '/'))
    if (Test-Path -LiteralPath $sensitive) {
        [void] $variants.Add(
            (Resolve-Path -LiteralPath $sensitive).Path.TrimEnd('\', '/'))
    }
    foreach ($variant in @($variants)) {
        [void] $variants.Add($variant.Replace('\', '/'))
        if ($variant -match '^(?<drive>[A-Za-z]):[\\/](?<tail>.*)$') {
            $drive = $Matches.drive.ToLowerInvariant()
            $tail = $Matches.tail.Replace('\', '/')
            [void] $variants.Add("/$drive/$tail")
            [void] $variants.Add("/cygdrive/$drive/$tail")
        }
    }
    foreach ($variant in $variants) {
        if ($variant) {
            $replacements.Add([ordered]@{
                value = $variant
                token = $token
            })
        }
    }
}
$ordered = @($replacements | Sort-Object { $_.value.Length } -Descending)
$runnerRoots = @(
    [ordered]@{
        pattern = '[A-Za-z]:[\\/]a[\\/]'
        token = '<runner-root>/'
    },
    [ordered]@{
        pattern = '[A-Za-z]:[\\/]Users[\\/]runner[^\\/]*[\\/]'
        token = '<runner-home>/'
    },
    [ordered]@{
        pattern = '/home/runner/'
        token = '<runner-home>/'
    },
    [ordered]@{
        pattern = '/[cd]/a/'
        token = '<runner-root>/'
    }
)
$forbiddenRunnerPath =
    '([A-Za-z]:[\\/]a[\\/]|[A-Za-z]:[\\/]Users[\\/]runner|/home/runner/|/[cd]/a/)'

$binaryExtensions = @(
    '.a', '.dll', '.exe', '.gz', '.o', '.xz', '.zip', '.zst'
)
foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File) {
    if ($file.Extension.ToLowerInvariant() -in $binaryExtensions) { continue }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes -contains 0) { continue }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    foreach ($replacement in $ordered) {
        $text = $text.Replace(
            $replacement.value,
            $replacement.token,
            [StringComparison]::OrdinalIgnoreCase)
    }
    foreach ($runnerRoot in $runnerRoots) {
        $text = [regex]::Replace(
            $text,
            $runnerRoot.pattern,
            $runnerRoot.token,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    [IO.File]::WriteAllText(
        $file.FullName,
        $text,
        [Text.UTF8Encoding]::new($false))
}

foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File) {
    if ($file.Extension.ToLowerInvariant() -in $binaryExtensions) { continue }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes -contains 0) { continue }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    foreach ($replacement in $ordered) {
        if ($text.Contains(
                $replacement.value,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "unsanitized path in $($file.FullName)"
        }
    }
    if ([regex]::IsMatch(
            $text,
            $forbiddenRunnerPath,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        throw "forbidden runner path in $($file.FullName)"
    }
}

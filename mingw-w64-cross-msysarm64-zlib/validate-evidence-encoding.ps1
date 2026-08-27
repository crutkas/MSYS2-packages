[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Root,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$utf8 = [Text.UTF8Encoding]::new($false)
$textNames = @(
    '.BUILDINFO',
    '.PKGINFO',
    'release-SHA256SUMS'
)
$textExtensions = @(
    '.csv',
    '.conf',
    '.json',
    '.md',
    '.mtree',
    '.ps1',
    '.sha256',
    '.sh',
    '.tsv',
    '.txt'
)

$records = @()
foreach ($file in Get-ChildItem -LiteralPath $rootPath -Recurse -File |
        Sort-Object FullName) {
    if ($file.Name -eq '.MTREE') {
        continue
    }
    if (
        $file.Name -notin $textNames -and
        $file.Extension.ToLowerInvariant() -notin $textExtensions
    ) {
        continue
    }

    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $hasBom = (
        $bytes.Length -ge 3 -and
        $bytes[0] -eq 0xef -and
        $bytes[1] -eq 0xbb -and
        $bytes[2] -eq 0xbf
    )
    if ($hasBom) {
        throw "UTF-8 BOM is forbidden: $($file.FullName)"
    }
    if ($bytes -contains 0) {
        throw "NUL byte in text evidence: $($file.FullName)"
    }
    try {
        $text = $strictUtf8.GetString($bytes)
    }
    catch {
        throw "Invalid UTF-8 evidence file: $($file.FullName)"
    }

    $records += [ordered]@{
        path = $file.FullName.Substring($rootPath.Length + 1).
            Replace('\', '/')
        bytes = $bytes.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).
            Hash.ToLowerInvariant()
        encoding = 'utf-8-no-bom'
        crlf = ([regex]::Matches($text, "`r`n")).Count
        bare_cr = ([regex]::Matches($text, "`r(?!`n)")).Count
        lf = ([regex]::Matches($text, "(?<!`r)`n")).Count
    }
}

$result = [ordered]@{
    schema = 'msysarm64-zlib-evidence-encoding/v1'
    root = '.'
    files = $records
    result = 'pass'
}
[IO.File]::WriteAllText(
    $OutputPath,
    (($result | ConvertTo-Json -Depth 8) + "`n"),
    $utf8
)

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Root,

    [Parameter(Mandatory = $true)]
    [string] $ManifestPath,

    [Parameter(Mandatory = $true)]
    [string] $SealPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$utf8 = [Text.UTF8Encoding]::new($false)
$manifestFull = [IO.Path]::GetFullPath($ManifestPath)
$sealFull = [IO.Path]::GetFullPath($SealPath)
$rows = @("path`tbytes`tsha256")
foreach ($file in Get-ChildItem -LiteralPath $rootPath -Recurse -File |
        Sort-Object FullName) {
    if ($file.FullName -in @($manifestFull, $sealFull)) {
        continue
    }
    $relative = $file.FullName.Substring($rootPath.Length + 1).
        Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).
        Hash.ToLowerInvariant()
    $rows += "$relative`t$($file.Length)`t$hash"
}
[IO.File]::WriteAllText(
    $manifestFull,
    (($rows -join "`n") + "`n"),
    $utf8
)

$seal = [ordered]@{
    schema = 'msysarm64-zlib-evidence-seal/v1'
    repository = $env:GITHUB_REPOSITORY
    run_id = $env:GITHUB_RUN_ID
    run_attempt = $env:GITHUB_RUN_ATTEMPT
    event = $env:GITHUB_EVENT_NAME
    head_sha = $env:GITHUB_SHA
    manifest = [IO.Path]::GetFileName($manifestFull)
    files = $rows.Count - 1
    manifest_bytes = (Get-Item $manifestFull).Length
    manifest_sha256 = (
        Get-FileHash -LiteralPath $manifestFull -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText(
    $sealFull,
    (($seal | ConvertTo-Json -Depth 8) + "`n"),
    $utf8
)

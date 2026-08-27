[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('before', 'after')]
    [string] $Label,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [string] $SharedRoot = 'C:\msys64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-FileManifest {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $OutputPath
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        [IO.File]::WriteAllText(
            $OutputPath,
            "`"path`",`"length`",`"lastWriteUtc`",`"sha256`"`r`n",
            [Text.UTF8Encoding]::new($false)
        )
        return
    }
    $records = @(
        Get-ChildItem -LiteralPath $Root -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                path = $_.FullName.Substring($Root.Length + 1)
                length = $_.Length
                lastWriteUtc = $_.LastWriteTimeUtc.ToString('o')
                sha256 = (
                    Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
                ).Hash.ToLowerInvariant()
            }
        } |
        Write-Output
    )
    if ($records.Count -eq 0) {
        [IO.File]::WriteAllText(
            $OutputPath,
            "`"path`",`"length`",`"lastWriteUtc`",`"sha256`"`r`n",
            [Text.UTF8Encoding]::new($false)
        )
    }
    else {
        $records |
            Export-Csv $OutputPath -NoTypeInformation -Encoding utf8
    }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$databaseRoot = Join-Path $SharedRoot 'var\lib\pacman\local'
$gpgRoot = Join-Path $SharedRoot 'etc\pacman.d\gnupg'
$logPath = Join-Path $SharedRoot 'var\log\pacman.log'
$databaseManifest = Join-Path $OutputDirectory "shared-db-$Label.csv"
$gpgManifest = Join-Path $OutputDirectory "shared-gpg-$Label.csv"
Write-FileManifest -Root $databaseRoot -OutputPath $databaseManifest
Write-FileManifest -Root $gpgRoot -OutputPath $gpgManifest

$log = if (Test-Path -LiteralPath $logPath -PathType Leaf) {
    $item = Get-Item -LiteralPath $logPath
    [ordered]@{
        present = $true
        bytes = $item.Length
        last_write_utc = $item.LastWriteTimeUtc.ToString('o')
        sha256 = (
            Get-FileHash -LiteralPath $logPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
}
else {
    [ordered]@{
        present = $false
        bytes = 0
        last_write_utc = $null
        sha256 = $null
    }
}

$result = [ordered]@{
    schema = 'msysarm64-zlib-shared-state/v1'
    label = $Label
    shared_root = $SharedRoot
    database = [ordered]@{
        file_count = @(Import-Csv $databaseManifest).Count
        manifest = [IO.Path]::GetFileName($databaseManifest)
        manifest_bytes = (Get-Item $databaseManifest).Length
        manifest_sha256 = (
            Get-FileHash -LiteralPath $databaseManifest -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    gpg = [ordered]@{
        file_count = @(Import-Csv $gpgManifest).Count
        manifest = [IO.Path]::GetFileName($gpgManifest)
        manifest_bytes = (Get-Item $gpgManifest).Length
        manifest_sha256 = (
            Get-FileHash -LiteralPath $gpgManifest -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    pacman_log = $log
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText(
    (Join-Path $OutputDirectory "shared-state-$Label.json"),
    (($result | ConvertTo-Json -Depth 8) + "`n"),
    $utf8
)

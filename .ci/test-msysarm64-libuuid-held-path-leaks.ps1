[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScannerPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

$assets = @(
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-libuuid-2.40.2-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-libuuid-pr31-20260827/mingw-w64-cross-msysarm64-libuuid-2.40.2-1-x86_64.pkg.tar.zst'
        Size = 57059
        Sha256 = '425444b6744ee3897e44e1a7f2de1b1903506ff208fd40cd0a80c12589a885de'
        AssetId = 532799335
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-libuuid-devel-2.40.2-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-libuuid-pr31-20260827/mingw-w64-cross-msysarm64-libuuid-devel-2.40.2-1-x86_64.pkg.tar.zst'
        Size = 83353
        Sha256 = '9b4e044699ff8779373efc8a070b6b5ac029f09b3621ecf9cd7bf47a9955c0eb'
        AssetId = 532799336
    }
)
$expectedCounts = [ordered]@{
    'msys-uuid-1.dll' = 54
    'libuuid-smoke.exe' = 67
    'libuuid-static-smoke.exe' = 67
}
$systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
foreach ($requiredFile in @($ScannerPath, $systemTar)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Missing held-path regression input: $requiredFile"
    }
}

function Assert-SafePackageArchive {
    param([Parameter(Mandatory = $true)][string]$Path)

    $entries = @(& $script:systemTar -tf $Path)
    if ($LASTEXITCODE -ne 0 -or $entries.Count -eq 0) {
        throw "Cannot list held package archive: $Path"
    }
    foreach ($entry in $entries) {
        $normalized = $entry.Replace('\', '/')
        if (-not $normalized -or
            $normalized.StartsWith('/') -or
            $normalized -match '^[A-Za-z]:' -or
            $normalized.Split('/') -contains '..') {
            throw "Unsafe held package entry: $entry"
        }
    }
    $links = @(& $script:systemTar -tvf $Path |
        Where-Object { $_ -match '^[lh]' })
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot inspect held package links: $Path"
    }
    if ($links.Count -ne 0) {
        throw "Held package unexpectedly contains links: $Path"
    }
}

$temporaryBase = if ($env:RUNNER_TEMP) {
    $env:RUNNER_TEMP
}
else {
    [IO.Path]::GetTempPath()
}
$workRoot = Join-Path $temporaryBase `
    "libuuid-held-path-regression-$([Guid]::NewGuid().ToString('N'))"
$extractRoot = Join-Path $workRoot 'extracted'
$rawReport = Join-Path $workRoot 'path-scan.json'
try {
    New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null
    foreach ($asset in $assets) {
        $archive = Join-Path $workRoot $asset.Name
        & curl.exe --fail --location --retry 5 --retry-all-errors `
            --retry-delay 2 --silent --show-error `
            --output $archive $asset.Uri
        if ($LASTEXITCODE -ne 0) {
            throw "Held package download failed: $($asset.Uri)"
        }
        $file = Get-Item -LiteralPath $archive
        $sha256 = (Get-FileHash -Algorithm SHA256 $archive).
            Hash.ToLowerInvariant()
        if ($file.Length -ne $asset.Size -or $sha256 -ne $asset.Sha256) {
            throw "Held package identity mismatch: $($asset.Name)"
        }
        Assert-SafePackageArchive -Path $archive

        $destination = Join-Path $extractRoot $asset.AssetId
        New-Item -ItemType Directory -Path $destination | Out-Null
        & $systemTar -xf $archive -C $destination
        if ($LASTEXITCODE -ne 0) {
            throw "Held package extraction failed: $($asset.Name)"
        }
    }

    $rejected = $false
    try {
        & $ScannerPath -Paths @($extractRoot) -OutputPath $rawReport
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected -or
        -not (Test-Path -LiteralPath $rawReport -PathType Leaf)) {
        throw 'The scanner did not reject the exact held package pair'
    }

    $report = Get-Content -Raw -LiteralPath $rawReport | ConvertFrom-Json
    if ($report.result -ne 'fail' -or
        $report.files_enumerated -ne 45 -or
        $report.files_scanned -ne 45 -or
        $report.leak_count -ne 188 -or
        $report.unique_leak_values -ne 20) {
        throw 'Held package path findings do not match the denied audit'
    }
    $actualNames = @($report.findings.file | Sort-Object -Unique)
    if (Compare-Object @($expectedCounts.Keys) $actualNames) {
        throw 'Held package findings do not identify the three denied PEs'
    }
    foreach ($name in $expectedCounts.Keys) {
        if (@($report.findings | Where-Object file -eq $name).Count -ne
            $expectedCounts[$name]) {
            throw "Held package finding count changed for $name"
        }
    }

    $attestation = [ordered]@{
        schema = 1
        result = 'expected-rejection'
        held_release = 'msysarm64-libuuid-pr31-20260827'
        assets = @($assets | ForEach-Object {
            [ordered]@{
                name = $_.Name
                asset_id = $_.AssetId
                size = $_.Size
                sha256 = $_.Sha256
                url = $_.Uri
            }
        })
        scanner_sha256 = $report.scanner_sha256
        files_enumerated = $report.files_enumerated
        files_scanned = $report.files_scanned
        bytes_scanned = $report.bytes_scanned
        leak_count = $report.leak_count
        unique_leak_values = $report.unique_leak_values
        finding_counts = @($expectedCounts.GetEnumerator() | ForEach-Object {
            [ordered]@{
                file = $_.Key
                count = $_.Value
            }
        })
        value_sha256 = @($report.findings.value_sha256 |
            Sort-Object -Unique)
    }
    $parent = Split-Path -Parent $EvidencePath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText(
        $EvidencePath,
        ($attestation | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false))
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}

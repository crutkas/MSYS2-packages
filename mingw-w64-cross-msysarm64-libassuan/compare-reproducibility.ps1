param(
    [Parameter(Mandatory = $true)]
    [string]$LeftDirectory,

    [Parameter(Mandatory = $true)]
    [string]$RightDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
$expectedPackages = @(
    'mingw-w64-cross-msysarm64-libassuan-3.0.2-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-libassuan-devel-3.0.2-1-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-libassuan-tools-3.0.2-1-x86_64.pkg.tar.zst'
)
$expectedSources = @(
    [pscustomobject]@{
        name = 'libassuan-3.0.2.tar.bz2'
        bytes = 593917
        sha256 = 'd2931cdad266e633510f9970e1a2f346055e351bb19f9b78912475b8074c36f6'
    },
    [pscustomobject]@{
        name = 'libassuan-3.0.2.tar.bz2.sig'
        bytes = 238
        sha256 = '5aa3c5cea6f42bcb96be9e1dd922b33ccb05e2f0565e93674e85ddcf8cd78e86'
    }
)

function Get-FileRecord {
    param([string]$Path)

    $item = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        name = $item.Name
        bytes = $item.Length
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Assert-EqualRecord {
    param(
        [object]$Left,
        [object]$Right,
        [string]$Description
    )

    if ($Left.name -cne $Right.name -or
        $Left.bytes -ne $Right.bytes -or
        $Left.sha256 -cne $Right.sha256) {
        throw "$Description differs between independent builds"
    }
}

$leftPackages = Join-Path $LeftDirectory 'libassuan-candidate'
$rightPackages = Join-Path $RightDirectory 'libassuan-candidate'
$leftInputs = Join-Path $LeftDirectory 'libassuan-inputs'
$rightInputs = Join-Path $RightDirectory 'libassuan-inputs'
$actualLeftNames = @(Get-ChildItem -LiteralPath $leftPackages -File -Filter '*.pkg.tar.zst' |
    Select-Object -ExpandProperty Name | Sort-Object)
$actualRightNames = @(Get-ChildItem -LiteralPath $rightPackages -File -Filter '*.pkg.tar.zst' |
    Select-Object -ExpandProperty Name | Sort-Object)
if (($actualLeftNames -join "`n") -cne (($expectedPackages | Sort-Object) -join "`n") -or
    ($actualRightNames -join "`n") -cne (($expectedPackages | Sort-Object) -join "`n")) {
    throw 'Independent builds did not produce the exact expected package split'
}

$packageRecords = foreach ($name in $expectedPackages) {
    $left = Get-FileRecord -Path (Join-Path $leftPackages $name)
    $right = Get-FileRecord -Path (Join-Path $rightPackages $name)
    Assert-EqualRecord -Left $left -Right $right -Description $name
    $left
}
$sourceRecords = foreach ($expected in $expectedSources) {
    $left = Get-FileRecord -Path (Join-Path $leftInputs $expected.name)
    $right = Get-FileRecord -Path (Join-Path $rightInputs $expected.name)
    Assert-EqualRecord -Left $left -Right $right -Description $expected.name
    Assert-EqualRecord -Left $left -Right $expected -Description "$($expected.name) pin"
    $left
}

$reportDirectory = Split-Path -Parent $ReportPath
New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null
[ordered]@{
    status = 'PASS'
    comparison = 'byte-for-byte SHA-256 equality across independent fresh runners'
    packages = @($packageRecords)
    signedSources = @($sourceRecords)
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 -LiteralPath $ReportPath

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Scanner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedHash = '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
$actualHash = (Get-FileHash -LiteralPath $Scanner -Algorithm SHA256).
    Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "scanner hash mismatch: $actualHash"
}

$temp = Join-Path $env:TEMP "coreutils-scanner-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temp | Out-Null

function Write-Table {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [uint32[]] $Header = @(0, 0, 1),
        [uint32[]] $Flags = @(),
        [byte[]] $TrailingBytes = @()
    )

    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        foreach ($value in $Header) {
            $writer.Write([uint32]$value)
        }
        $index = 0
        foreach ($flag in $Flags) {
            $writer.Write([uint32](0x7000 + ($index * 8)))
            $writer.Write([uint32](0x1000 + ($index * 4)))
            $writer.Write([uint32]$flag)
            $index++
        }
        foreach ($value in $TrailingBytes) {
            $writer.Write([byte]$value)
        }
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function Invoke-Fixture {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [uint32[]] $Header = @(0, 0, 1),
        [uint32[]] $Flags = @(),
        [byte[]] $TrailingBytes = @(),
        [Parameter(Mandatory = $true)][int] $ExpectedExit,
        [Parameter(Mandatory = $true)][string] $ExpectedResult
    )

    $table = Join-Path $temp "$Name.bin"
    $output = Join-Path $temp "$Name.json"
    Write-Table -Path $table -Header $Header -Flags $Flags `
        -TrailingBytes $TrailingBytes
    & pwsh -NoProfile -File $Scanner -TablePath $table -OutputPath $output 2>$null
    if ($LASTEXITCODE -ne $ExpectedExit) {
        throw "$Name exit mismatch: $LASTEXITCODE"
    }
    $result = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    if ($result.result -ne $ExpectedResult) {
        throw "$Name result mismatch: $($result.result)"
    }
}

try {
    Invoke-Fixture -Name empty -ExpectedExit 0 -ExpectedResult pass
    Invoke-Fixture -Name allowed -Flags @(8, 16, 32, 64) `
        -ExpectedExit 0 -ExpectedResult pass
    Invoke-Fixture -Name rejected -Flags @(64, 12, 21) `
        -ExpectedExit 1 -ExpectedResult fail
    Invoke-Fixture -Name unknown -Flags @(7) `
        -ExpectedExit 1 -ExpectedResult fail
    Invoke-Fixture -Name malformed-header -Header @(0, 0, 2) `
        -ExpectedExit 2 -ExpectedResult error
    Invoke-Fixture -Name malformed-length -TrailingBytes @(255) `
        -ExpectedExit 2 -ExpectedResult error
    'coreutils pseudo-reloc scanner fixtures: PASS'
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Remove-Item -LiteralPath $temp -Recurse -Force
    }
}

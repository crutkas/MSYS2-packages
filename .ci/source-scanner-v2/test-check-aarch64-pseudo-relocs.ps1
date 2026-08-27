[CmdletBinding()]
param(
    [string] $NegativePePath,
    [string] $PositivePePath,
    [string] $Objdump = 'aarch64-pc-cygwin-objdump.exe',
    [string] $Nm = 'aarch64-pc-cygwin-nm.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$checker = Join-Path $PSScriptRoot 'check-aarch64-pseudo-relocs.ps1'
$fixtures = Get-Content (Join-Path $PSScriptRoot 'fixtures.json') -Raw | ConvertFrom-Json
$temp = Join-Path $env:TEMP "pseudo-reloc-decoder-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temp | Out-Null

function Write-Table {
    param(
        [Parameter(Mandatory = $true)] $Fixture,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        foreach ($value in $Fixture.header) {
            $writer.Write([uint32] $value)
        }
        $index = 1
        foreach ($flag in $Fixture.flags) {
            $writer.Write([uint32] (0x7000 + ($index * 8)))
            $writer.Write([uint32] (0x1000 + ($index * 4)))
            $writer.Write([uint32] $flag)
            $index++
        }
        if ($Fixture.PSObject.Properties.Name -contains 'trailing_bytes') {
            foreach ($value in $Fixture.trailing_bytes) {
                $writer.Write([byte] $value)
            }
        }
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function Invoke-Expected {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][int] $ExpectedExit,
        [Parameter(Mandatory = $true)][string] $ExpectedResult,
        [uint32[]] $ExpectedFlags = @()
    )

    $output = Join-Path $temp "$Name.json"
    & pwsh -NoProfile -File $checker @Arguments -OutputPath $output 2>$null
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne $ExpectedExit) {
        throw "$Name exit mismatch: expected $ExpectedExit, got $exitCode"
    }
    $result = Get-Content $output -Raw | ConvertFrom-Json
    if ($result.result -ne $ExpectedResult) {
        throw "$Name result mismatch: expected $ExpectedResult, got $($result.result)"
    }
    if ($ExpectedFlags.Count -ne 0) {
        $actual = @($result.flags | ForEach-Object { [uint32] $_ })
        if (($ExpectedFlags -join ',') -ne ($actual -join ',')) {
            throw "$Name flags mismatch: expected $ExpectedFlags, got $actual"
        }
    }
    return $result
}

try {
    foreach ($fixture in $fixtures) {
        $path = Join-Path $temp "$($fixture.name).bin"
        Write-Table -Fixture $fixture -Path $path
        $result = Invoke-Expected `
            -Name $fixture.name `
            -Arguments @('-TablePath', $path) `
            -ExpectedExit $fixture.expected_exit `
            -ExpectedResult $fixture.expected_result `
            -ExpectedFlags @($fixture.flags)
        if ($fixture.name -eq 'negative-64-21-12-21-12') {
            $violations = @($result.policy_violations | ForEach-Object { [uint32] $_ })
            if (@(Compare-Object @(12, 21) $violations).Count -ne 0) {
                throw "Negative fixture violations mismatch: $violations"
            }
        }
    }

    if ($NegativePePath) {
        $result = Invoke-Expected `
            -Name 'negative-pe' `
            -Arguments @('-PePath', $NegativePePath, '-Objdump', $Objdump, '-Nm', $Nm) `
            -ExpectedExit 1 `
            -ExpectedResult 'fail' `
            -ExpectedFlags @(64, 21, 12, 21, 12)
        if (@(Compare-Object @(12, 21) @($result.policy_violations)).Count -ne 0) {
            throw 'Negative PE did not report 12 and 21'
        }
    }

    if ($PositivePePath) {
        $result = Invoke-Expected `
            -Name 'positive-pe' `
            -Arguments @('-PePath', $PositivePePath, '-Objdump', $Objdump, '-Nm', $Nm) `
            -ExpectedExit 0 `
            -ExpectedResult 'pass'
        if (@($result.flags | Where-Object { $_ -in @(12, 21) }).Count -ne 0) {
            throw 'Positive PE contains rejected 12/21 records'
        }
    }

    'pseudo-reloc-decoder-tests	PASS'
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Remove-Item -LiteralPath $temp -Recurse -Force
    }
}

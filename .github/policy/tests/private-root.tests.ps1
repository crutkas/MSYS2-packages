[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = (Resolve-Path (Join-Path $PSScriptRoot '..\PrivateRoot.psm1')).Path
Import-Module $modulePath -Force -ErrorAction Stop

$script:assertions = 0

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool] $Condition,

        [Parameter(Mandatory)]
        [string] $Label
    )

    $script:assertions++
    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock] $Action,

        [Parameter(Mandatory)]
        [string] $Label
    )

    $script:assertions++
    $threw = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $threw = $true
    }
    if (-not $threw) {
        throw "Expected rejection: $Label"
    }
}

$canonicalTemp = (Get-Item -LiteralPath $env:TEMP -Force).FullName.TrimEnd('\')
$testRoot = Join-Path $canonicalTemp "policy-root-tests-$PID-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null

try {
    Assert-Throws -Label 'relative path' -Action {
        Assert-PolicyLexicalPath -Path 'relative\path' -Label 'test'
    }
    Assert-Throws -Label 'UNC path' -Action {
        Assert-PolicyLexicalPath -Path '\\server\share\root' -Label 'test'
    }
    Assert-Throws -Label 'device path' -Action {
        Assert-PolicyLexicalPath -Path '\\?\C:\root' -Label 'test'
    }
    Assert-Throws -Label 'dot traversal' -Action {
        Assert-PolicyLexicalPath -Path 'C:\safe\..\escape' -Label 'test'
    }
    Assert-Throws -Label 'forward slash' -Action {
        Assert-PolicyLexicalPath -Path 'C:\safe/path' -Label 'test'
    }
    Assert-Throws -Label 'non-NFC component' -Action {
        $decomposed = "C:\cafe$([char]0x0301)"
        Assert-PolicyLexicalPath -Path $decomposed -Label 'test'
    }
    Assert-Throws -Label 'synthetic 8.3 alias' -Action {
        Assert-PolicyExistingDirectory -Path 'C:\PROGRA~1' -Label 'test'
    }

    $lastComponent = Split-Path -Leaf $testRoot
    $wrongCase = Join-Path (Split-Path -Parent $testRoot) $lastComponent.ToUpperInvariant()
    if ($wrongCase -ceq $testRoot) {
        $wrongCase = Join-Path (Split-Path -Parent $testRoot) $lastComponent.ToLowerInvariant()
    }
    Assert-Throws -Label 'case alias' -Action {
        Assert-PolicyExistingDirectory -Path $wrongCase -Label 'test'
    }

    $physical = Join-Path $testRoot 'physical'
    $junction = Join-Path $testRoot 'junction'
    New-Item -ItemType Directory -Path $physical -ErrorAction Stop | Out-Null
    New-Item -ItemType Junction -Path $junction -Target $physical -ErrorAction Stop | Out-Null
    Assert-Throws -Label 'reparse point' -Action {
        Assert-PolicyExistingDirectory -Path $junction -Label 'test'
    }

    $matrixOne = Get-PolicyMatrixDigest -MatrixDiscriminator '{"arch":"arm64"}'
    $matrixTwo = Get-PolicyMatrixDigest -MatrixDiscriminator '{"arch":"x64"}'
    Assert-True -Condition ($matrixOne -cmatch '^[0-9a-f]{64}$') -Label 'matrix digest shape'
    Assert-True -Condition ($matrixOne -cne $matrixTwo) -Label 'matrix discriminator binding'

    $firstPath = Get-PolicyPrivateRootPath `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '1001' `
        -RunAttempt '1' `
        -JobName 'verify' `
        -MatrixDiscriminator '{"arch":"arm64"}'
    $jobPath = Get-PolicyPrivateRootPath `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '1001' `
        -RunAttempt '1' `
        -JobName 'verify_other' `
        -MatrixDiscriminator '{"arch":"arm64"}'
    $attemptPath = Get-PolicyPrivateRootPath `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '1001' `
        -RunAttempt '2' `
        -JobName 'verify' `
        -MatrixDiscriminator '{"arch":"arm64"}'
    Assert-True -Condition ($firstPath -cne $jobPath) -Label 'job binding'
    Assert-True -Condition ($firstPath -cne $attemptPath) -Label 'attempt binding'
    Assert-True -Condition ($firstPath.Contains('\run-1001\attempt-1\job-verify\matrix-')) -Label 'root dimensions'

    New-Item -ItemType Directory -Path $firstPath -Force -ErrorAction Stop | Out-Null
    Assert-Throws -Label 'preexisting root' -Action {
        New-PolicyPrivateRoot `
            -RunnerTemp $testRoot `
            -RepositoryId '1333319488' `
            -RunId '1001' `
            -RunAttempt '1' `
            -JobName 'verify' `
            -MatrixDiscriminator '{"arch":"arm64"}'
    }

    $created = New-PolicyPrivateRoot `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '2002' `
        -RunAttempt '3' `
        -JobName 'verify' `
        -MatrixDiscriminator 'none'
    Assert-True -Condition ([IO.Directory]::Exists($created)) -Label 'private root created'
    Assert-True -Condition ([IO.File]::Exists((Join-Path $created '.policy-root'))) -Label 'exclusive claim'
    Assert-True -Condition ($created.StartsWith("$testRoot\", [StringComparison]::Ordinal)) -Label 'runner.temp containment'
    Assert-Throws -Label 'same root cannot be reused' -Action {
        New-PolicyPrivateRoot `
            -RunnerTemp $testRoot `
            -RepositoryId '1333319488' `
            -RunId '2002' `
            -RunAttempt '3' `
            -JobName 'verify' `
            -MatrixDiscriminator 'none'
    }
}
finally {
    if ([IO.Directory]::Exists($testRoot)) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
    }
}

Write-Output "Private-root assertions passed: $script:assertions"

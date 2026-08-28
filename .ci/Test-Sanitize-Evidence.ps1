[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'sqlite-evidence-sanitizer-' + [guid]::NewGuid().ToString('N'))
$evidenceRoot = Join-Path $fixtureRoot 'complete-evidence'
$transactionRoot = Join-Path $evidenceRoot 'transaction-report'
$sensitiveRoot = Join-Path $fixtureRoot 'current-private-root'
$forbiddenRunnerPath =
    '([A-Za-z]:[\\/]a[\\/]|[A-Za-z]:[\\/]Users[\\/]runner|/home/runner/|/[cd]/a/)'

try {
    New-Item -ItemType Directory -Force `
        -Path $transactionRoot, $sensitiveRoot | Out-Null
    @'
[2026-06-11T00:00:00+0000] [ALPM-SCRIPTLET] /d/a/msys2-installer/msys2-installer/_build/newmsys/msys64/usr/bin/bash.exe
C:\a\MSYS2-packages\MSYS2-packages\artifacts\report.txt
D:\Users\runneradmin\AppData\Local\Temp\report.txt
/home/runner/work/MSYS2-packages/MSYS2-packages/report.txt
'@ | Set-Content -Encoding utf8NoBOM (
        Join-Path $transactionRoot 'isolated-pacman-transactions.log')
    "current=$sensitiveRoot" | Set-Content -Encoding utf8NoBOM (
        Join-Path $evidenceRoot 'current-root.txt')

    & (Join-Path $PSScriptRoot 'Sanitize-Evidence.ps1') `
        -EvidenceRoot $evidenceRoot `
        -SensitivePath $sensitiveRoot

    $combined = (
        Get-ChildItem -LiteralPath $evidenceRoot -Recurse -File |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
    ) -join "`n"
    if ([regex]::IsMatch(
            $combined,
            $forbiddenRunnerPath,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        throw 'sanitized complete evidence retains a forbidden runner path'
    }
    foreach ($token in @(
        '<runner-root>/msys2-installer/',
        '<runner-root>/MSYS2-packages\',
        '<runner-home>/AppData\',
        '<runner-home>/work/',
        '<private-root-1>'
    )) {
        if (-not $combined.Contains($token, [StringComparison]::Ordinal)) {
            throw "expected sanitization token missing: $token"
        }
    }
    Write-Output 'Complete-evidence path sanitization regression passed'
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

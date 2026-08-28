[CmdletBinding(DefaultParameterSetName = 'Pe')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Pe')]
    [string] $PePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Table')]
    [string] $TablePath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(ParameterSetName = 'Pe')]
    [string] $Objdump = 'aarch64-pc-msys-objdump.exe',

    [Parameter(ParameterSetName = 'Pe')]
    [string] $Nm = 'aarch64-pc-msys-nm.exe',

    [Parameter(ParameterSetName = 'Pe')]
    [switch] $RequireSymbolEvidence
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commit = '3356eec1411983cc252b04afac32bca5f3b8d824'
$expectedSha256 = '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
$scanner = Join-Path ([IO.Path]::GetTempPath()) "gnupg-$commit-check-aarch64-pseudo-relocs.ps1"
$repositoryEvidence = Join-Path $PSScriptRoot 'check-aarch64-pseudo-relocs.ps1'
$text = [IO.File]::ReadAllText($repositoryEvidence).Replace("`r`n", "`n")
[IO.File]::WriteAllText($scanner, $text, [Text.UTF8Encoding]::new($false))
$actualSha256 = (Get-FileHash -LiteralPath $scanner -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    Remove-Item -LiteralPath $scanner -Force -ErrorAction SilentlyContinue
    throw "Scanner SHA-256 mismatch: expected $expectedSha256, got $actualSha256"
}

$arguments = @('-NoProfile', '-File', $scanner, '-OutputPath', $OutputPath)
if ($PSCmdlet.ParameterSetName -eq 'Table') {
    $arguments += @('-TablePath', $TablePath)
}
else {
    $arguments += @('-PePath', $PePath, '-Objdump', $Objdump, '-Nm', $Nm)
}

& pwsh @arguments
$scannerExitCode = $LASTEXITCODE
if ($scannerExitCode -ne 0) {
    exit $scannerExitCode
}
if ($RequireSymbolEvidence) {
    $findings = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
    if ($findings.table_format -eq 'absent') {
        throw 'Pseudo-reloc symbols are absent; stripped or renamed table evidence is forbidden'
    }
}
exit 0

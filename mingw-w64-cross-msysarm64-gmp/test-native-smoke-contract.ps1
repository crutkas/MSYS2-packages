$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$path = Join-Path $PSScriptRoot 'native-smoke.ps1'
$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseFile(
    $path,
    [ref]$tokens,
    [ref]$errors) | Out-Null
if ($errors.Count -ne 0) {
    throw "native-smoke.ps1 has parser errors: $($errors.Message -join '; ')"
}
$content = Get-Content -LiteralPath $path -Raw
$required = @(
    "OSArchitecture -ne 'Arm64'",
    '$machine -eq 0x8664',
    'msys-gmp-10.dll',
    'gmp-dynamic-smoke.exe',
    'gmp-static-smoke.exe',
    'gmp-cxx-dynamic-smoke.exe',
    'gmp-cxx-static-smoke.exe',
    'canonical_runtime_admitted',
    'native execution requires a coordinator-admitted canonical runtime',
    'independently admitted GMP package records',
    'independent_redownload_verified',
    'coordinator_admission_reference',
    'Get-FileHash',
    "MSYS2_PATH_TYPE = 'strict'",
    'gmp-module-ready',
    'process.Modules',
    '0xa64e',
    '"x64-modules`t0"',
    'LP64 call=AAPCS64 unwind=SEH thread=ok process=ok'
)
foreach ($needle in $required) {
    if (-not $content.Contains($needle)) {
        throw "native smoke contract is missing: $needle"
    }
}

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$path = Join-Path $PSScriptRoot 'native-smoke.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $path, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {
    throw "native smoke parse errors: $($errors.Message -join '; ')"
}

$requiredFunctions = @(
    'Get-PeMachine',
    'Assert-Arm64Pe',
    'Assert-NativePe',
    'Invoke-Native',
    'Invoke-NativeWithInput',
    'Invoke-StdbufNegative',
    'Add-ProcessModuleAudit',
    'Add-ProcessTreeAudit'
)
$functions = @(
    $ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true)
)
foreach ($name in $requiredFunctions) {
    $matches = @($functions | Where-Object Name -eq $name)
    if ($matches.Count -ne 1) {
        throw "native helper count mismatch for $name`: $($matches.Count)"
    }
    if ($matches[0].Parent -isnot
        [Management.Automation.Language.NamedBlockAst]) {
        throw "native helper is not script scoped: $name"
    }
}

$text = Get-Content -LiteralPath $path -Raw
foreach ($marker in @(
    '[string] $BusyBoxRoot',
    '[string] $SemanticProofRoot',
    '[string] $SmokeRoot',
    'ProcessArchitecture',
    'busybox_audited_path_count = $busyboxFiles.Count',
    'semantic_proof_audited_path_count = $semanticFiles.Count',
    'x64_process_or_module_count = $foreignRecords.Count',
    'BusyBox contract path is missing',
    'semantic proof contract path is missing',
    'stdbuf-loader-closure',
    'stdbuf-missing-dll-negative',
    'stdbuf-corrupt-dll-negative',
    'libstdbuf.dll'
)) {
    if (-not $text.Contains($marker)) {
        throw "native evidence contract is missing: $marker"
    }
}

'native smoke static contract: PASS'

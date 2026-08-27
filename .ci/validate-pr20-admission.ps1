[CmdletBinding()]
param(
    [Parameter()]
    [string] $LockPath = (Join-Path $PSScriptRoot 'pr20-admission-lock.json'),

    [Parameter()]
    [string] $ScannerPath = (Join-Path $PSScriptRoot 'check-aarch64-pseudo-relocs.ps1'),

    [Parameter()]
    [switch] $RequireAdmission,

    [Parameter()]
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedScannerSha = '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
$forbiddenSharedRoot = 'C:\msys64'

function Read-Lock {
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Lock file not found: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
}

function Test-AbsolutePrivatePath {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    if ($Value -like '*{PRIVATE_ROOT}*') {
        return $true
    }
    if ($Value -match '^[A-Za-z]:\\') {
        return $true
    }
    if ($Value.StartsWith('/')) {
        return $true
    }
    return $false
}

function Assert-NoSharedRoot {
    param([string] $Value, [Parameter(Mandatory = $true)][string] $Description)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }
    if ($Value -like "*$forbiddenSharedRoot*") {
        throw "$Description must not reference shared root $forbiddenSharedRoot"
    }
}

function Assert-RequiredField {
    param(
        [Parameter(Mandatory = $true)][hashtable] $Item,
        [Parameter(Mandatory = $true)][string] $Name
    )
    if (-not $Item.ContainsKey($Name) -or $null -eq $Item[$Name]) {
        throw "Missing required field '$Name' in $($Item.package)"
    }
}

function Validate-Manifest {
    param(
        [Parameter(Mandatory = $true)][hashtable] $Lock,
        [Parameter(Mandatory = $true)][string] $ScannerPath,
        [switch] $Gate
    )

    if ($Lock.schema -ne 1) {
        throw "Unsupported lock schema: $($Lock.schema)"
    }

    foreach ($field in 'branch', 'base_ref', 'private_paths', 'toolchain', 'admitted_inputs', 'build_gate') {
        if (-not $Lock.ContainsKey($field)) {
            throw "Missing lock field: $field"
        }
    }

    foreach ($key in $Lock.private_paths.Keys) {
        Assert-NoSharedRoot -Value ([string]$Lock.private_paths[$key]) -Description "private_paths.$key"
        if (-not (Test-AbsolutePrivatePath -Value ([string]$Lock.private_paths[$key]))) {
            throw "private_paths.$key must be absolute or template-qualified"
        }
    }

    foreach ($toolName in 'cc', 'cxx') {
        $tool = $Lock.toolchain.compiler[$toolName]
        if (-not (Test-AbsolutePrivatePath -Value ([string]$tool))) {
            throw "compiler tool '$toolName' must be absolute"
        }
        Assert-NoSharedRoot -Value ([string]$tool) -Description "compiler.$toolName"
    }

    foreach ($toolName in 'ar', 'ranlib', 'nm', 'objdump', 'strip') {
        $tool = $Lock.toolchain.target_tools[$toolName]
        if (-not (Test-AbsolutePrivatePath -Value ([string]$tool))) {
            throw "target tool '$toolName' must be absolute"
        }
        Assert-NoSharedRoot -Value ([string]$tool) -Description "target_tools.$toolName"
        if ([string]$tool -notmatch 'aarch64-pc-cygwin-') {
            throw "target tool '$toolName' must be the candidate-owned aarch64-pc-cygwin personality"
        }
    }

    $scanner = $Lock.toolchain.scanner
    foreach ($scannerField in 'script', 'source', 'sha256', 'argv', 'coverage') {
        if (-not $scanner.ContainsKey($scannerField)) {
            throw "Scanner is missing field: $scannerField"
        }
    }
    if (-not (Test-Path -LiteralPath $ScannerPath -PathType Leaf)) {
        throw "Scanner script not found: $ScannerPath"
    }
    $scannerHash = (Get-FileHash -LiteralPath $ScannerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($scannerHash -ne $expectedScannerSha) {
        throw "Scanner file hash mismatch: $scannerHash"
    }
    if ($scanner.sha256 -ne $expectedScannerSha) {
        throw "Scanner SHA mismatch: $($scanner.sha256)"
    }
    if ($scanner.coverage -notcontains 'PePath' -or
        $scanner.coverage -notcontains 'OutputPath' -or
        $scanner.coverage -notcontains 'objdump' -or
        $scanner.coverage -notcontains 'nm') {
        throw 'Scanner coverage is incomplete'
    }
    if ($scanner.argv -notcontains '/opt/bin/aarch64-pc-cygwin-objdump.exe' -or
        $scanner.argv -notcontains '/opt/bin/aarch64-pc-cygwin-nm.exe') {
        throw 'Scanner must use candidate-owned objdump/nm'
    }

    foreach ($asset in $Lock.admitted_inputs) {
        foreach ($required in 'stage', 'role', 'package', 'admitted', 'provides') {
            Assert-RequiredField -Item $asset -Name $required
        }

        if ($asset.admitted) {
            foreach ($required in 'version', 'archive', 'bytes', 'sha256', 'release_tag', 'release_asset_id', 'url') {
                Assert-RequiredField -Item $asset -Name $required
            }
            if ($asset.bytes -le 0 -or -not $asset.sha256) {
                throw "Admitted input missing byte or hash metadata: $($asset.package)"
            }
            Assert-NoSharedRoot -Value ([string]$asset.url) -Description $asset.package
        }
        else {
            foreach ($required in 'provisional', 'reason') {
                Assert-RequiredField -Item $asset -Name $required
            }
            if (-not $asset.provisional) {
                throw "Unadmitted input must be marked provisional: $($asset.package)"
            }
            if ($asset.version -or $asset.archive -or $asset.bytes -or $asset.sha256 -or $asset.release_tag -or $asset.release_asset_id -or $asset.url) {
                throw "Provisional input must not carry admitted byte/hash metadata: $($asset.package)"
            }
        }
    }

    foreach ($asset in $Lock.admitted_inputs) {
        if ($asset.role -in @('apr-output', 'apr-candidate') -and -not $asset.armap_required) {
            throw "Candidate output $($asset.package) requires armap coverage"
        }
    }

    foreach ($asset in $Lock.admitted_inputs) {
        if ($asset.role -eq 'binutils' -and ($asset.sha256 -ne '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b')) {
            throw 'Canonical binutils SHA mismatch'
        }
    }

    foreach ($asset in $Lock.admitted_inputs) {
        if ($asset.role -eq 'gcc' -and ($asset.sha256 -ne 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22')) {
            throw 'Canonical GCC SHA mismatch'
        }
    }

    foreach ($asset in $Lock.admitted_inputs) {
        if ($asset.role -eq 'gcc-libs' -and ($asset.sha256 -ne '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438')) {
            throw 'Canonical GCC libs SHA mismatch'
        }
    }

    foreach ($asset in $Lock.admitted_inputs) {
        if (($asset.PSObject.Properties.Name -contains 'provisional') -and $asset.provisional -and $asset.admitted) {
            throw "Provisional input must not be admitted: $($asset.package)"
        }
    }

    if ($Gate) {
        $unadmitted = @($Lock.admitted_inputs | Where-Object { -not $_.admitted })
        if ($unadmitted.Count -gt 0) {
            $names = $unadmitted.package -join ', '
            throw "Build gate closed until admitted inputs land: $names"
        }
    }

    return $true
}

function Invoke-SelfTest {
    $lock = Read-Lock -Path $LockPath
    Validate-Manifest -Lock $lock -ScannerPath $ScannerPath | Out-Null

    $tmp = Join-Path ([IO.Path]::GetTempPath()) "apr-lock-test-$([Guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        $cases = @()

        $cases += @{
            Name = 'reject unresolved provisional input'
            Mutate = {
                param($m)
                $m.admitted_inputs += @{
                    stage = 'apr-stack'
                    role = 'leaf'
                    package = 'fake-unresolved'
                    admitted = $false
                    provisional = $true
                    reason = 'synthetic unresolved input'
                    provides = @('fake-unresolved')
                    version = $null
                    archive = $null
                    bytes = $null
                    sha256 = $null
                    release_tag = $null
                    release_asset_id = $null
                    url = $null
                }
            }
            ExpectFailure = $true
        }
        $cases += @{
            Name = 'reject shared msys64 path'
            Mutate = {
                param($m)
                $m.private_paths.root = 'C:\msys64'
            }
            ExpectFailure = $true
        }
        $cases += @{
            Name = 'reject missing armap coverage'
            Mutate = {
                param($m)
                $m.admitted_inputs += @{
                    stage = 'apr-candidate'
                    role = 'apr-output'
                    package = 'candidate-apr.dll'
                    version = '1.0'
                    archive = 'candidate-apr.dll'
                    bytes = 1
                    sha256 = 'deadbeef'
                    release_tag = 'candidate'
                    release_asset_id = 1
                    url = 'https://example.invalid/candidate-apr.dll'
                    provides = @('candidate-apr=1.0')
                    admitted = $true
                    armap_required = $false
                }
            }
            ExpectFailure = $true
        }
        $cases += @{
            Name = 'reject wrong target tool personality'
            Mutate = {
                param($m)
                $m.toolchain.target_tools.ar = '/opt/bin/aarch64-pc-msys-ar.exe'
            }
            ExpectFailure = $true
        }
        $cases += @{
            Name = 'reject incomplete scanner coverage'
            Mutate = {
                param($m)
                $m.toolchain.scanner.coverage = @('PePath', 'OutputPath')
            }
            ExpectFailure = $true
        }

        foreach ($case in $cases) {
            $copy = $lock | ConvertTo-Json -Depth 32 | ConvertFrom-Json -AsHashtable
            & $case.Mutate $copy
            $fixture = Join-Path $tmp "$($case.Name -replace '\s+', '-').json"
            $copy | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $fixture -Encoding utf8
            $threw = $false
            try {
                Validate-Manifest -Lock (Read-Lock -Path $fixture) -ScannerPath $ScannerPath -Gate | Out-Null
            }
            catch {
                $threw = $true
            }
            if (-not $threw) {
                throw "Self-test failed: $($case.Name)"
            }
        }

        return $true
    }
    finally {
        Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}

$lock = Read-Lock -Path $LockPath
if ($SelfTest) {
    Invoke-SelfTest | Out-Null
    exit 0
}

if ($RequireAdmission) {
    Validate-Manifest -Lock $lock -ScannerPath $ScannerPath -Gate | Out-Null
}
else {
    Validate-Manifest -Lock $lock -ScannerPath $ScannerPath | Out-Null
}
exit 0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StageRoot,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeArchive,

    [Parameter(Mandatory = $true)]
    [string]$GmpRuntimeArchive,

    [Parameter(Mandatory = $true)]
    [string]$SmokeDirectory,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [string]$DependencyLock
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$lock = Get-Content -LiteralPath $DependencyLock -Raw | ConvertFrom-Json
if ($lock.canonical_runtime_admitted -ne $true -or
    $lock.build_classification.admissible -ne $true -or
    $lock.build_classification.publishable -ne $true -or
    $lock.build_classification.consumable -ne $true) {
    throw 'native execution requires a coordinator-admitted canonical runtime'
}
$runtimeIdentity = $lock.canonical_runtime
if ($runtimeIdentity.admitted -ne $true -or
    $runtimeIdentity.independent_redownload_verified -ne $true -or
    [string]::IsNullOrWhiteSpace(
        $runtimeIdentity.coordinator_admission_reference) -or
    [string]::IsNullOrWhiteSpace($runtimeIdentity.version) -or
    [string]::IsNullOrWhiteSpace($runtimeIdentity.release_tag)) {
    throw 'canonical runtime identity is incomplete'
}
$packageRecords = @($lock.package_candidates.records)
if ($packageRecords.Count -ne 2 -or
    @($packageRecords | Where-Object {
        $_.admitted -ne $true -or
        $_.eligible_for_admission -ne $true -or
        $_.independent_redownload_verified -ne $true -or
        [string]::IsNullOrWhiteSpace(
            $_.coordinator_admission_reference) -or
        [string]::IsNullOrWhiteSpace($_.asset_name) -or
        $_.size -le 0 -or
        $_.sha256 -notmatch '^[0-9a-f]{64}$'
    }).Count -ne 0) {
    throw 'native execution requires independently admitted GMP package records'
}
$packageNames = @($packageRecords.package | Sort-Object -Unique)
if ($packageNames.Count -ne 2 -or
    @(
        Compare-Object `
            -ReferenceObject @(
                'mingw-w64-cross-msysarm64-gmp',
                'mingw-w64-cross-msysarm64-gmp-devel') `
            -DifferenceObject $packageNames
    ).Count -ne 0) {
    throw 'native admission package set is not exact'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64') {
    throw 'native GMP smoke requires Windows ARM64'
}
foreach ($file in @($RuntimeArchive, $GmpRuntimeArchive)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "native input is missing: $file"
    }
    $gmpRuntimeRecord = @($packageRecords | Where-Object {
        $_.package -ceq 'mingw-w64-cross-msysarm64-gmp' -and
        $_.required_version -ceq '6.3.0-2'
    })
    if ($gmpRuntimeRecord.Count -ne 1) {
        throw 'admitted GMP runtime package record is missing or ambiguous'
    }
    foreach ($binding in @(
            @{
                Path = $RuntimeArchive
                Name = $runtimeIdentity.asset_name
                Size = $runtimeIdentity.size
                Sha256 = $runtimeIdentity.sha256
            },
            @{
                Path = $GmpRuntimeArchive
                Name = $gmpRuntimeRecord[0].asset_name
                Size = $gmpRuntimeRecord[0].size
                Sha256 = $gmpRuntimeRecord[0].sha256
            })) {
        $item = Get-Item -LiteralPath $binding.Path
        if ($item.Name -cne $binding.Name -or
            $item.Length -ne $binding.Size -or
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $binding.Sha256) {
            throw "native archive does not match its admitted record: $($item.FullName)"
        }
    }
}
if (Test-Path -LiteralPath $StageRoot) {
    throw "native stage already exists: $StageRoot"
}
New-Item -ItemType Directory -Path $StageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null

foreach ($archive in @($RuntimeArchive, $GmpRuntimeArchive)) {
    & tar.exe -xf $archive -C $StageRoot
    if ($LASTEXITCODE -ne 0) {
        throw "native input extraction failed: $archive"
    }
}

$targetBin = Join-Path $StageRoot 'opt\aarch64-pc-msys\usr\bin'
$runtimeDll = Join-Path $StageRoot 'opt\aarch64-pc-msys\bin\msys-2.0.dll'
$gmpDll = Join-Path $targetBin 'msys-gmp-10.dll'
if (-not (Test-Path -LiteralPath $runtimeDll -PathType Leaf)) {
    throw "runtime DLL is missing: $runtimeDll"
}
if (-not (Test-Path -LiteralPath $gmpDll -PathType Leaf)) {
    throw "GMP DLL is missing: $gmpDll"
}
Copy-Item -LiteralPath $runtimeDll -Destination $targetBin
foreach ($name in @(
        'gmp-dynamic-smoke.exe',
        'gmp-static-smoke.exe',
        'gmp-cxx-dynamic-smoke.exe',
        'gmp-cxx-static-smoke.exe')) {
    $source = Join-Path $SmokeDirectory $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "consumer is missing: $source"
    }
    Copy-Item -LiteralPath $source -Destination $targetBin
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x40) {
        throw "truncated PE file: $Path"
    }
    $offset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($offset -lt 0 -or $offset + 6 -gt $bytes.Length) {
        throw "invalid PE header offset: $Path"
    }
    if ($bytes[$offset] -ne 0x50 -or $bytes[$offset + 1] -ne 0x45 -or
        $bytes[$offset + 2] -ne 0 -or $bytes[$offset + 3] -ne 0) {
        throw "invalid PE signature: $Path"
    }
    return [BitConverter]::ToUInt16($bytes, $offset + 4)
}

foreach ($path in @(
        (Join-Path $targetBin 'msys-2.0.dll'),
        $gmpDll,
        (Join-Path $targetBin 'gmp-dynamic-smoke.exe'),
        (Join-Path $targetBin 'gmp-static-smoke.exe'),
        (Join-Path $targetBin 'gmp-cxx-dynamic-smoke.exe'),
        (Join-Path $targetBin 'gmp-cxx-static-smoke.exe'))) {
    $machine = Get-PeMachine -Path $path
    if ($machine -ne 0xaa64) {
        throw "$path is not AA64: 0x$($machine.ToString('x4'))"
    }
}

$env:MSYSTEM = 'MSYS'
$env:MSYS2_PATH_TYPE = 'strict'
$env:PATH = "$targetBin;$env:SystemRoot\System32;$env:SystemRoot"
$env:GMP_MODULE_HOLD = '1'

function Invoke-ModuleSmoke {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$ExpectGmp
    )

    $executable = Join-Path $targetBin $Name
    $stdout = Join-Path $EvidenceDirectory "$Name.stdout.txt"
    $stderr = Join-Path $EvidenceDirectory "$Name.stderr.txt"
    $process = Start-Process `
        -FilePath $executable `
        -WorkingDirectory $targetBin `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($process.HasExited) {
            break
        }
        if ((Test-Path -LiteralPath $stdout) -and
            (Get-Content -LiteralPath $stdout -Raw) -match
                '(?m)^gmp-module-ready$') {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 100
        $process.Refresh()
    }
    if (-not $ready) {
        if (-not $process.HasExited) {
            $process.Kill()
        }
        throw "consumer did not reach module-ready hold for $Name"
    }

    $modules = @()
    $previousSignature = $null
    $stableCount = 0
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        if ($process.HasExited) {
            throw "$Name exited before module enumeration stabilized"
        }
        $modules = @(
            $process.Modules |
                ForEach-Object FileName |
                Sort-Object -Unique
        )
        $signature = $modules -join "`n"
        if ($signature -ceq $previousSignature) {
            $stableCount++
            if ($stableCount -ge 3) {
                break
            }
        }
        else {
            $stableCount = 0
            $previousSignature = $signature
        }
        Start-Sleep -Milliseconds 100
        $process.Refresh()
    }
    if ($stableCount -lt 3) {
        if (-not $process.HasExited) {
            $process.Kill()
        }
        throw "module enumeration did not stabilize for $Name"
    }

    $moduleRows = @()
    $stagePrefix = [IO.Path]::GetFullPath($StageRoot).TrimEnd('\') + '\'
    $systemPrefix = [IO.Path]::GetFullPath(
        (Join-Path $env:SystemRoot 'System32')).TrimEnd('\') + '\'
    foreach ($module in $modules) {
        $modulePath = [IO.Path]::GetFullPath($module)
        $machine = Get-PeMachine -Path $module
        if ($machine -eq 0x8664) {
            if (-not $process.HasExited) {
                $process.Kill()
            }
            throw "x64 module loaded in native ARM64 process: $module"
        }
        if ($modulePath.StartsWith(
                $stagePrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            if ($machine -ne 0xaa64) {
                if (-not $process.HasExited) {
                    $process.Kill()
                }
                throw "staged module is not AA64: $module"
            }
        }
        elseif ($modulePath.StartsWith(
                $systemPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            if ($machine -notin @(0xaa64, 0xa641, 0xa64e)) {
                if (-not $process.HasExited) {
                    $process.Kill()
                }
                throw "unexpected Windows module machine 0x$(
                    $machine.ToString('x4')): $module"
            }
        }
        else {
            if (-not $process.HasExited) {
                $process.Kill()
            }
            throw "module escaped staged and Windows system roots: $module"
        }
        $moduleRows += "{0}`t0x{1}`t{2}" -f `
            $Name, $machine.ToString('x4'), $module
    }
    $gmpLoaded = @($modules | Where-Object {
        [IO.Path]::GetFileName($_) -ieq 'msys-gmp-10.dll'
    }).Count -eq 1
    if ($gmpLoaded -ne $ExpectGmp) {
        if (-not $process.HasExited) {
            $process.Kill()
        }
        throw "unexpected GMP module state for $Name`: $gmpLoaded"
    }

    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "$Name failed with exit code $($process.ExitCode): $(
            Get-Content -LiteralPath $stderr -Raw)"
    }
    $output = Get-Content -LiteralPath $stdout -Raw
    if ($output -notmatch
        'gmp-smoke-ok abi=LP64 call=AAPCS64 unwind=SEH thread=ok process=ok') {
        throw "$Name omitted the complete native smoke result: $output"
    }
    return $moduleRows
}

$moduleEvidence = @()
$moduleEvidence += Invoke-ModuleSmoke `
    -Name 'gmp-dynamic-smoke.exe' -ExpectGmp $true
$moduleEvidence += Invoke-ModuleSmoke `
    -Name 'gmp-static-smoke.exe' -ExpectGmp $false
$moduleEvidence += Invoke-ModuleSmoke `
    -Name 'gmp-cxx-dynamic-smoke.exe' -ExpectGmp $true
$moduleEvidence += Invoke-ModuleSmoke `
    -Name 'gmp-cxx-static-smoke.exe' -ExpectGmp $false
$moduleEvidence |
    Sort-Object |
    Set-Content `
        -LiteralPath (Join-Path $EvidenceDirectory 'modules.tsv') `
        -Encoding utf8NoBOM
@(
    "processor`t$env:PROCESSOR_IDENTIFIER"
    "os-architecture`tArm64"
    "payload-machine`t0xaa64"
    "runtime`t$($runtimeIdentity.version)"
    "gmp`t6.3.0-2"
    "abi`tLP64/AAPCS64/SEH"
    "dynamic-gmp-module`tloaded"
    "static-gmp-module`tabsent"
    "cxx-dynamic-gmp-module`tloaded"
    "cxx-static-gmp-module`tabsent"
    "thread`tpass"
    "fork-process`tpass"
    "x64-modules`t0"
) | Set-Content `
    -LiteralPath (Join-Path $EvidenceDirectory 'native-smoke.tsv') `
    -Encoding utf8NoBOM

param(
    [Parameter(Mandatory = $true)]
    [string]$PackagesDirectory,
    [Parameter(Mandatory = $true)]
    [string]$InputsDirectory,
    [Parameter(Mandatory = $true)]
    [string]$ScannerPath,
    [Parameter(Mandatory = $true)]
    [string]$HostMsysRoot,
    [Parameter(Mandatory = $true)]
    [string]$NativeHarnessPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [System.Runtime.InteropServices.Architecture]::Arm64) {
    throw 'The native OpenSSL smoke test requires an ARM64 Windows host.'
}

$work = Join-Path $env:RUNNER_TEMP 'msysarm64-openssl-native'
$payload = Join-Path $work 'payload'
$root = Join-Path $work 'root'
$evidence = Join-Path $work 'evidence'
New-Item -ItemType Directory -Force -Path $payload, $root, $evidence | Out-Null

$archives = @(
    Get-ChildItem -File -Recurse $PackagesDirectory -Filter '*.pkg.tar.zst'
    Get-ChildItem -File -Recurse $InputsDirectory -Filter '*.pkg.tar.zst'
)
if ($archives.Count -lt 6) {
    throw "Expected OpenSSL, runtime, and GCC runtime archives; found $($archives.Count)."
}
foreach ($archive in $archives) {
    & tar.exe -xf $archive.FullName -C $payload
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract $($archive.Name)."
    }
}

$target = Join-Path $payload 'opt\aarch64-pc-msys'
$targetUsr = Join-Path $target 'usr'
$usr = Join-Path $root 'usr'
$bin = Join-Path $usr 'bin'
New-Item -ItemType Directory -Force -Path $usr, $bin | Out-Null
Copy-Item -Recurse -Force (Join-Path $targetUsr '*') $usr
Copy-Item -Force (Join-Path $target 'bin\msys-2.0.dll') $bin

$libgcc = Get-ChildItem -File -Recurse (Join-Path $payload 'opt\lib\gcc\aarch64-pc-msys') `
    -Filter 'msys-gcc_s-seh-1.dll' | Select-Object -First 1
if ($null -ne $libgcc) {
    Copy-Item -Force $libgcc.FullName $bin
}

$openssl = Join-Path $bin 'openssl.exe'
if (-not (Test-Path $openssl)) {
    throw 'The OpenSSL CLI was not staged into the native root.'
}

$objdump = Join-Path $payload 'opt\bin\aarch64-pc-cygwin-objdump.exe'
$nm = Join-Path $payload 'opt\bin\aarch64-pc-cygwin-nm.exe'
if (-not (Test-Path $objdump) -or -not (Test-Path $nm)) {
    throw 'The fixed-binutils scanner tools were not staged.'
}
$env:PATH = "$(Join-Path $HostMsysRoot 'usr\bin');$env:PATH"
$scannerHash = (Get-FileHash -Algorithm SHA256 $ScannerPath).Hash.ToLowerInvariant()
if ($scannerHash -ne '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') {
    throw "Unexpected pseudo-reloc scanner hash: $scannerHash"
}
$pseudoRelocReports = Join-Path $evidence 'pseudo-relocs'
New-Item -ItemType Directory -Force -Path $pseudoRelocReports | Out-Null
$smokePayload = Join-Path $target 'share\msys-sysroot\openssl\smoke'
$peFiles = @(
    Get-ChildItem -File -Recurse $targetUsr |
        Where-Object { $_.Extension -in '.exe', '.dll' }
    Get-ChildItem -File $smokePayload -Filter '*.exe'
)
if ($peFiles.Count -lt 9) {
    throw "Expected at least nine OpenSSL PE files; found $($peFiles.Count)."
}
foreach ($pe in $peFiles) {
    $relative = $pe.FullName.Substring($target.Length + 1)
    $outputName = ($relative -replace '[\\/:]', '_') + '.json'
    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    & $pwsh -NoProfile -File $ScannerPath -PePath $pe.FullName `
        -OutputPath (Join-Path $pseudoRelocReports $outputName) `
        -Objdump $objdump -Nm $nm
    if ($LASTEXITCODE -ne 0) {
        throw "Pseudo-reloc scan failed: $relative"
    }
}
$scanReports = @(Get-ChildItem -File $pseudoRelocReports -Filter '*.json' |
    ForEach-Object { Get-Content -Raw $_.FullName | ConvertFrom-Json })
if ($scanReports.Count -ne $peFiles.Count -or
    @($scanReports | Where-Object {
        $_.result -ne 'pass' -or
        $_.policy_violations.Count -ne 0 -or
        @($_.flags | Where-Object { $_ -in 12, 21 }).Count -ne 0
    }).Count -ne 0) {
    throw 'Native OpenSSL pseudo-reloc policy failed.'
}

$dynamicSmoke = Join-Path $bin 'openssl-dynamic-smoke.exe'
$staticSmoke = Join-Path $bin 'openssl-static-smoke.exe'
Copy-Item -Force (Join-Path $smokePayload 'openssl-smoke.exe') $dynamicSmoke
Copy-Item -Force (Join-Path $smokePayload 'openssl-static-smoke.exe') $staticSmoke
$bash = Join-Path $HostMsysRoot 'usr\bin\bash.exe'
$cygpath = Join-Path $HostMsysRoot 'usr\bin\cygpath.exe'
$rootMsys = (& $cygpath -u $root | Select-Object -Last 1).Trim()
$evidenceMsys = (& $cygpath -u $evidence | Select-Object -Last 1).Trim()
$harnessMsys = (& $cygpath -u $NativeHarnessPath | Select-Object -Last 1).Trim()
$nativeOutput = & $bash --noprofile --norc $harnessMsys $rootMsys $evidenceMsys 2>&1 |
    Out-String
if ($LASTEXITCODE -ne 0 -or $nativeOutput -notmatch 'native-arm64-openssl=pass') {
    throw "Native OpenSSL harness failed: $nativeOutput"
}

@{
    schema = 1
    host_architecture = 'ARM64'
    openssl_version = '3.5.1'
    pe_scans = $scanReports.Count
    rejected_pseudo_reloc_flags = @(12, 21)
    result = 'pass'
} | ConvertTo-Json -Depth 4 |
    Set-Content -Encoding utf8 (Join-Path $evidence 'native-summary.json')

Write-Output $nativeOutput
Write-Output "Native pseudo-reloc scans passed: $($scanReports.Count)"
Write-Output 'Native ARM64 crypto, provider, and TLS smoke tests passed.'

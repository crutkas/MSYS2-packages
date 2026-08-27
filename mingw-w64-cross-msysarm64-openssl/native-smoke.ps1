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
$structureReports = Join-Path $evidence 'pe-structure'
New-Item -ItemType Directory -Force -Path $pseudoRelocReports, $structureReports |
    Out-Null
$smokePayload = Join-Path $target 'share\msys-sysroot\openssl\smoke'
$peFiles = @(
    Get-ChildItem -File -Recurse $targetUsr |
        Where-Object { $_.Extension -in '.exe', '.dll' }
    Get-ChildItem -File $smokePayload |
        Where-Object { $_.Extension -in '.exe', '.dll' }
)
if ($peFiles.Count -lt 13) {
    throw "Expected at least thirteen OpenSSL PE files; found $($peFiles.Count)."
}
foreach ($pe in $peFiles) {
    $relative = $pe.FullName.Substring($target.Length + 1)
    $outputName = ($relative -replace '[\\/:]', '_') + '.json'
    $structure = @(& $objdump -f -p -h -x $pe.FullName 2>&1)
    $structureText = $structure -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0 -or
        $structureText -notmatch 'file format pei-aarch64-little' -or
        $structureText -notmatch 'architecture: aarch64') {
        throw "Invalid native PE structure: $relative"
    }
    $structure | Set-Content -Encoding utf8 `
        (Join-Path $structureReports ($outputName + '.txt'))
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

$legacy = Join-Path $targetUsr 'lib\ossl-modules\legacy.dll'
$crypto = Join-Path $targetUsr 'bin\msys-crypto-3.dll'
foreach ($dll in @($legacy, $crypto)) {
    $details = @(& $objdump -f -p -h -x $dll 2>&1)
    $detailsText = $details -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0 -or
        $detailsText -notmatch 'AddressOfEntryPoint\s+[0-9a-fA-F]*[1-9a-fA-F]' -or
        $detailsText -notmatch 'Exception Directory' -or
        $detailsText -notmatch '\.pdata' -or
        $detailsText -notmatch '\.xdata' -or
        $detailsText -notmatch 'Base Relocation Directory' -or
        $detailsText -notmatch '\.reloc') {
        throw "Incomplete PE metadata: $dll"
    }
}
$legacySymbols = @(& $nm -an $legacy 2>&1)
$legacySymbols | Set-Content -Encoding utf8 `
    (Join-Path $structureReports 'legacy.dll.symbols.txt')
if ($LASTEXITCODE -ne 0 -or
    @($legacySymbols | Where-Object {
        $_ -match '\sOSSL_provider_init\s*$'
    }).Count -ne 1) {
    throw 'legacy.dll does not export OSSL_provider_init.'
}

$closurePaths = @(
    $openssl,
    (Join-Path $bin 'msys-crypto-3.dll'),
    (Join-Path $bin 'msys-ssl-3.dll'),
    (Join-Path $bin 'msys-2.0.dll'),
    $legacy
)
if ($null -ne $libgcc) {
    $closurePaths += Join-Path $bin 'msys-gcc_s-seh-1.dll'
}
$closurePaths | ForEach-Object {
    $file = Get-Item $_
    [pscustomobject]@{
        path = $file.FullName
        bytes = $file.Length
        machine = 'AA64'
        sha256 = (Get-FileHash -Algorithm SHA256 $file.FullName).Hash.ToLowerInvariant()
    }
} | ConvertTo-Json -Depth 4 |
    Set-Content -Encoding utf8 (Join-Path $evidence 'loaded-closure.json')

$dynamicSmoke = Join-Path $bin 'openssl-dynamic-smoke.exe'
$staticSmoke = Join-Path $bin 'openssl-static-smoke.exe'
Copy-Item -Force (Join-Path $smokePayload 'openssl-smoke.exe') $dynamicSmoke
Copy-Item -Force (Join-Path $smokePayload 'openssl-static-smoke.exe') $staticSmoke
Copy-Item -Force (Join-Path $smokePayload 'dlopen-smoke.exe') $bin
Copy-Item -Force (Join-Path $smokePayload 'dlopen-generic.dll') $bin
Copy-Item -Force (Join-Path $smokePayload 'dlopen-nodllmain.dll') $bin
Copy-Item -Force (Join-Path $smokePayload 'dlopen-data-only.dll') $bin
Copy-Item -Force (Join-Path $smokePayload 'dlopen-crypto.dll') $bin
Copy-Item -Force (Join-Path $smokePayload 'loadlibrary-smoke.exe') $bin
Copy-Item -Force (Join-Path $smokePayload 'provider-minimal.dll') $bin

$bash = Join-Path $HostMsysRoot 'usr\bin\bash.exe'
$cygpath = Join-Path $HostMsysRoot 'usr\bin\cygpath.exe'
$rootMsys = (& $cygpath -u $root | Select-Object -Last 1).Trim()
$evidenceMsys = (& $cygpath -u $evidence | Select-Object -Last 1).Trim()
$harnessMsys = (& $cygpath -u $NativeHarnessPath | Select-Object -Last 1).Trim()
$dumpDirectory = Join-Path $evidence 'dumps'
New-Item -ItemType Directory -Force -Path $dumpDirectory | Out-Null
$cdbCandidates = @(
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe',
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
)
$cdb = $cdbCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
$procdumpCandidates = @('C:\Sysinternals\procdump.exe')
$procdumpCommand = Get-Command procdump.exe -CommandType Application `
    -ErrorAction SilentlyContinue
if ($null -ne $procdumpCommand) {
    $procdumpCandidates += $procdumpCommand.Source
}
$procdump = $procdumpCandidates |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
@{
    cdb = $cdb
    procdump = $procdump
} | ConvertTo-Json | Set-Content -Encoding utf8 `
    (Join-Path $evidence 'debugger-tools.json')
foreach ($imageName in @('openssl.exe', 'dlopen-smoke.exe', 'loadlibrary-smoke.exe')) {
    $werKey = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$imageName"
    New-Item -Path $werKey -Force | Out-Null
    New-ItemProperty -Path $werKey -Name DumpFolder -Value $dumpDirectory `
        -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path $werKey -Name DumpType -Value 2 `
        -PropertyType DWord -Force | Out-Null
}
$nativeOutput = & $bash --noprofile --norc $harnessMsys $rootMsys $evidenceMsys 2>&1 |
    Out-String
if ($LASTEXITCODE -ne 0 -or $nativeOutput -notmatch 'native-arm64-openssl=pass') {
    Start-Sleep -Seconds 3
    $dump = Get-ChildItem -File $dumpDirectory -Filter '*.dmp' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $dump -and $null -ne $procdump) {
        $loader = Join-Path $bin 'dlopen-smoke.exe'
        $module = Join-Path $bin 'dlopen-generic.dll'
        & $procdump -accepteula -ma -e -x $dumpDirectory `
            $loader $module *>&1 |
            Set-Content -Encoding utf8 (Join-Path $evidence 'procdump.txt')
        Start-Sleep -Seconds 3
        $dump = Get-ChildItem -File $dumpDirectory -Filter '*.dmp' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if ($null -ne $dump -and $null -ne $cdb) {
        & $cdb -z $dump.FullName `
            -c '!analyze -v; .exr -1; .ecxr; r; ln @pc; ub @pc; u @pc; kb; dps @sp L20; lmv m msys*; lmv m loadlibrary*; q' *>&1 |
            Set-Content -Encoding utf8 (Join-Path $evidence 'crash-analysis.txt')
    }
    elseif ($null -eq $dump -and $null -ne $cdb) {
        $loader = Join-Path $bin 'loadlibrary-smoke.exe'
        $module = Join-Path $bin 'loadlibrary-normal.dll'
        & $cdb -o `
            -c 'sxe av; bu KERNELBASE!FreeLibrary; g; .echo FREE_LIBRARY_ENTRY; r; kb; g; .echo FAULT; .exr -1; .ecxr; r; ln @pc; ub @pc; u @pc; kb; dps @sp L20; lmv m msys*; lmv m loadlibrary*; q' `
            $loader $module normal *>&1 |
            Set-Content -Encoding utf8 (Join-Path $evidence 'crash-analysis-live.txt')
    }
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

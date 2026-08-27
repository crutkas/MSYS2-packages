param(
    [Parameter(Mandatory = $true)]
    [string]$PackagesDirectory,
    [Parameter(Mandatory = $true)]
    [string]$InputsDirectory,
    [Parameter(Mandatory = $true)]
    [string]$ScannerPath,
    [Parameter(Mandatory = $true)]
    [string]$HostMsysRoot
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
New-Item -ItemType Directory -Force -Path $payload, $root | Out-Null

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
$pseudoRelocReports = Join-Path $work 'pseudo-relocs'
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

$env:PATH = "$bin;$env:PATH"
$env:MSYSTEM = 'MSYS'
$env:MSYS = 'winsymlinks:sys'
$env:OPENSSL_CONF = '/usr/ssl/openssl.cnf'
$env:OPENSSL_MODULES = '/usr/lib/ossl-modules'

$dynamicSmoke = Join-Path $bin 'openssl-dynamic-smoke.exe'
$staticSmoke = Join-Path $bin 'openssl-static-smoke.exe'
Copy-Item -Force (Join-Path $smokePayload 'openssl-smoke.exe') $dynamicSmoke
Copy-Item -Force (Join-Path $smokePayload 'openssl-static-smoke.exe') $staticSmoke
& $dynamicSmoke
if ($LASTEXITCODE -ne 0) {
    throw 'Native dynamic OpenSSL API smoke failed.'
}
& $staticSmoke
if ($LASTEXITCODE -ne 0) {
    throw 'Native static OpenSSL API smoke failed.'
}

$version = & $openssl version -a 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $version -notmatch 'OpenSSL 3\.5\.1') {
    throw "Unexpected OpenSSL version output: $version"
}
if ($version -notmatch 'OPENSSLDIR: "/usr/ssl"') {
    throw "Unexpected OpenSSL configuration directory: $version"
}
1..3 | ForEach-Object {
    & $openssl version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL lifecycle invocation $_ failed."
    }
}

$providers = & $openssl list -providers -provider default -provider legacy 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or
    $providers -notmatch '(?m)^\s+default\s*$' -or
    $providers -notmatch '(?m)^\s+legacy\s*$') {
    throw "Provider loading failed: $providers"
}

$data = Join-Path $work 'digest-input.txt'
[System.IO.File]::WriteAllText($data, "native aarch64-pc-msys OpenSSL`n")
$expected = (Get-FileHash -Algorithm SHA256 $data).Hash.ToLowerInvariant()
$digest = & $openssl dgst -sha256 $data 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $digest.ToLowerInvariant() -notmatch [regex]::Escape($expected)) {
    throw "SHA-256 smoke failed: $digest"
}

$speed = & $openssl speed -seconds 1 -bytes 1024 sha256 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $speed -notmatch 'sha256') {
    throw "Native SHA-256 speed smoke failed: $speed"
}

$tls = Join-Path $work 'tls'
New-Item -ItemType Directory -Force -Path $tls | Out-Null
Push-Location $tls
try {
    & $openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem `
        -sha256 -days 1 -nodes -subj '/CN=localhost' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to create the TLS smoke certificate.'
    }

    $serverOut = Join-Path $tls 'server.out'
    $serverErr = Join-Path $tls 'server.err'
    $server = Start-Process -FilePath $openssl -ArgumentList @(
        's_server', '-accept', '127.0.0.1:44330',
        '-cert', 'cert.pem', '-key', 'key.pem', '-www'
    ) -WorkingDirectory $tls -RedirectStandardOutput $serverOut `
      -RedirectStandardError $serverErr -PassThru
    try {
        Start-Sleep -Seconds 2
        $client = "GET / HTTP/1.0`r`n`r`n" |
            & $openssl s_client -connect '127.0.0.1:44330' `
                -CAfile cert.pem -verify_return_error 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or
            $client -notmatch 'Verification: OK' -or
            $client -notmatch 'Protocol\s*: TLSv1\.[23]') {
            throw "Native TLS handshake failed: $client"
        }
    }
    finally {
        if (-not $server.HasExited) {
            Stop-Process -Id $server.Id
            $server.WaitForExit()
        }
    }
}
finally {
    Pop-Location
}

Write-Output $version
Write-Output $providers
Write-Output $speed
Write-Output "Native pseudo-reloc scans passed: $($scanReports.Count)"
Write-Output 'Native ARM64 crypto, provider, and TLS smoke tests passed.'

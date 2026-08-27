param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory,

    [Parameter(Mandatory = $true)]
    [string]$MsysRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = $env:GITHUB_REPOSITORY
$branchCandidates = @($env:GITHUB_REF_NAME, $env:GITHUB_HEAD_REF) |
    Where-Object { $_ }
if ($repository -ne 'crutkas/MSYS2-packages') {
    throw "Refusing fork-only native smoke in $repository"
}
if ($branchCandidates -notcontains 'crutkas-arm64-msys-libuuid') {
    throw "Refusing libuuid native smoke for refs: $($branchCandidates -join ', ')"
}
$arm64Processors = @(Get-CimInstance Win32_Processor |
    Where-Object { $_.Architecture -eq 12 })
if ($arm64Processors.Count -eq 0) {
    throw 'Native smoke requires an ARM64 Windows host'
}
$archiveTool = Join-Path $MsysRoot 'usr\bin\bsdtar.exe'
if (-not (Test-Path -LiteralPath $archiveTool -PathType Leaf)) {
    throw "Missing setup-msys2 bsdtar: $archiveTool"
}
$msysBin = Split-Path -Parent $archiveTool
$originalPath = $env:PATH
$env:PATH = "$msysBin;$originalPath"

function Get-OnlyFile {
    param(
        [string]$Directory,
        [string]$Filter
    )

    $files = @(Get-ChildItem -LiteralPath $Directory -Filter $Filter -File)
    if ($files.Count -ne 1) {
        throw "Expected one $Filter in $Directory, found $($files.Count)"
    }
    return $files[0].FullName
}

function Get-PeMachine {
    param([string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64) {
        throw "Not a PE file: $Path"
    }
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3c)
    if ($peOffset + 6 -gt $bytes.Length) {
        throw "Invalid PE header offset: $Path"
    }
    if ($bytes[$peOffset] -ne 0x50 -or
        $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or
        $bytes[$peOffset + 3] -ne 0) {
        throw "Missing PE signature: $Path"
    }
    return [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

function Expand-Package {
    param(
        [string]$Package,
        [string]$Destination
    )

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    & $script:archiveTool -xf $Package -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract $Package"
    }
}

$work = Join-Path $env:RUNNER_TEMP 'msysarm64-libuuid-native-smoke'
$downloads = Join-Path $work 'downloads'
New-Item -ItemType Directory -Force -Path $downloads | Out-Null
$evidence = [System.Collections.Generic.List[string]]::new()
$evidence.Add("repository`t$repository")
$evidence.Add("runner`t$($env:RUNNER_NAME)")
$evidence.Add("processor`t$($arm64Processors[0].Name)")

$publishedAssets = @(
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-runtime-pr10-a527-20260824/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/msysarm64-gcc-pr13-20260826/mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
    },
    [pscustomobject]@{
        Name = 'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        Uri = 'https://github.com/crutkas/MSYS2-packages/releases/download/cygwinarm64-binutils-pr21-3356eec-20260827/mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        Sha256 = '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b'
    }
)
foreach ($asset in $publishedAssets) {
    $path = Join-Path $downloads $asset.Name
    & curl.exe --fail --location --retry 5 --silent --show-error `
        --output $path $asset.Uri
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed: $($asset.Uri)"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
    if ($actual -ne $asset.Sha256) {
        throw "SHA-256 mismatch for $($asset.Name): $actual"
    }
    $evidence.Add("published-input`t$($asset.Name)`t$actual")
}

$runtimePackage = Get-OnlyFile `
    -Directory $ArtifactDirectory `
    -Filter 'mingw-w64-cross-msysarm64-libuuid-2.40.2-1-x86_64.pkg.tar.*'
$develPackage = Get-OnlyFile `
    -Directory $ArtifactDirectory `
    -Filter 'mingw-w64-cross-msysarm64-libuuid-devel-2.40.2-1-x86_64.pkg.tar.*'
$evidence.Add("package-input`t$([IO.Path]::GetFileName($runtimePackage))`t$((Get-FileHash -Algorithm SHA256 $runtimePackage).Hash.ToLowerInvariant())")
$evidence.Add("package-input`t$([IO.Path]::GetFileName($develPackage))`t$((Get-FileHash -Algorithm SHA256 $develPackage).Hash.ToLowerInvariant())")

$runtimeRoot = Join-Path $work 'runtime'
$gccRoot = Join-Path $work 'gcc-libs'
$binutilsRoot = Join-Path $work 'binutils'
$libuuidRoot = Join-Path $work 'libuuid'
$develRoot = Join-Path $work 'libuuid-devel'
Expand-Package `
    -Package (Join-Path $downloads $publishedAssets[0].Name) `
    -Destination $runtimeRoot
Expand-Package `
    -Package (Join-Path $downloads $publishedAssets[1].Name) `
    -Destination $gccRoot
Expand-Package `
    -Package (Join-Path $downloads $publishedAssets[2].Name) `
    -Destination $binutilsRoot
Expand-Package -Package $runtimePackage -Destination $libuuidRoot
Expand-Package -Package $develPackage -Destination $develRoot

$pseudoRelocReport = Join-Path $develRoot 'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\validation\pseudo-relocs.tsv'
if (-not (Test-Path -LiteralPath $pseudoRelocReport -PathType Leaf)) {
    throw "Missing pseudo-reloc audit: $pseudoRelocReport"
}
$pseudoRelocs = Get-Content -LiteralPath $pseudoRelocReport
if ($pseudoRelocs -match "`t(12|21)$") {
    throw "Ambiguous pseudo-reloc record in package audit: $($pseudoRelocs -join '; ')"
}
$evidence.Add("pseudo-reloc-audit`t$((Get-FileHash -Algorithm SHA256 $pseudoRelocReport).Hash.ToLowerInvariant())")
$scanner = Join-Path $develRoot 'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\check-aarch64-pseudo-relocs-3356eec.ps1'
$objdump = Join-Path $binutilsRoot 'opt\bin\aarch64-pc-cygwin-objdump.exe'
$nm = Join-Path $binutilsRoot 'opt\bin\aarch64-pc-cygwin-nm.exe'
$linker = Join-Path $binutilsRoot 'opt\bin\aarch64-pc-cygwin-ld.exe'
if ((Get-FileHash -Algorithm SHA256 $scanner).Hash.ToLowerInvariant() -ne
    '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') {
    throw 'Canonical pseudo-reloc scanner hash mismatch'
}
if ((Get-FileHash -Algorithm SHA256 $linker).Hash.ToLowerInvariant() -ne
    '075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f') {
    throw 'Canonical linker hash mismatch'
}

$bin = Join-Path $work 'root\usr\bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$nativeFiles = @(
    (Join-Path $runtimeRoot 'opt\aarch64-pc-msys\bin\msys-2.0.dll'),
    (Join-Path $gccRoot 'opt\lib\gcc\aarch64-pc-msys\msys-gcc_s-seh-1.dll'),
    (Join-Path $libuuidRoot 'opt\aarch64-pc-msys\bin\msys-uuid-1.dll'),
    (Join-Path $develRoot 'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\validation\libuuid-smoke.exe'),
    (Join-Path $develRoot 'opt\aarch64-pc-msys\share\msys-sysroot\libuuid\validation\libuuid-static-smoke.exe')
)
foreach ($path in $nativeFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing native smoke input: $path"
    }
    if ((Get-PeMachine -Path $path) -ne 0xaa64) {
        throw "Non-ARM64 PE input: $path"
    }
    $evidence.Add("native-pe`t$([IO.Path]::GetFileName($path))`taa64`t$((Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant())")
    $scanOutput = Join-Path $work "$([IO.Path]::GetFileName($path)).pseudo-relocs.json"
    & (Get-Process -Id $PID).Path `
        -NoLogo `
        -NoProfile `
        -File $scanner `
        -PePath $path `
        -OutputPath $scanOutput `
        -Objdump $objdump `
        -Nm $nm
    if ($LASTEXITCODE -ne 0) {
        throw "Canonical pseudo-reloc scan failed: $path"
    }
    $scan = Get-Content -LiteralPath $scanOutput -Raw | ConvertFrom-Json
    if ($scan.result -ne 'pass' -or
        @($scan.flags | Where-Object { $_ -notin @(8, 16, 32, 64) }).Count -ne 0) {
        throw "Rejected pseudo-reloc scan result: $path"
    }
    $evidence.Add("native-pseudo-relocs`t$([IO.Path]::GetFileName($path))`t$($scan.table_format)`t$($scan.flags -join ',')")
    Copy-Item -LiteralPath $path -Destination $bin
}

$oldMsystem = $env:MSYSTEM
try {
    $env:MSYSTEM = 'MSYS'
    Push-Location $bin
    try {
        $outputs = [System.Collections.Generic.List[string]]::new()
        foreach ($smokeName in @(
            'libuuid-smoke.exe',
            'libuuid-static-smoke.exe'
        )) {
            $smoke = Join-Path $bin $smokeName
            $output = @(& $smoke 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "$smokeName failed with exit code $LASTEXITCODE"
            }
            $text = $output -join "`n"
            if ($text -notmatch 'libuuid-smoke:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}') {
                throw "Unexpected $smokeName output: $text"
            }
            $outputs.Add("$smokeName`t$text")
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:MSYSTEM = $oldMsystem
    $env:PATH = $originalPath
}

foreach ($outputLine in $outputs) {
    $evidence.Add("native-output`t$outputLine")
}
$evidenceDirectory = Join-Path $ArtifactDirectory 'native-smoke-evidence'
New-Item -ItemType Directory -Force -Path $evidenceDirectory | Out-Null
$evidencePath = Join-Path $evidenceDirectory 'native-smoke.tsv'
$evidence | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM
$evidenceHash = (Get-FileHash -Algorithm SHA256 $evidencePath).Hash.ToLowerInvariant()
"$evidenceHash  native-smoke.tsv" |
    Set-Content -LiteralPath (Join-Path $evidenceDirectory 'native-smoke.sha256') `
        -Encoding ascii
$outputs | Write-Output

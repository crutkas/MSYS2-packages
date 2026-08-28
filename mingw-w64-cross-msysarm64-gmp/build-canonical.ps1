[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Workspace,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [string]$SharedRoot = 'C:\msys64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$recipe = Join-Path $Workspace 'mingw-w64-cross-msysarm64-gmp'
$lockPath = Join-Path $recipe 'dependency-lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($lock.canonical_runtime_admitted -ne $true -or
    $lock.canonical_runtime.admitted -ne $true -or
    $lock.canonical_runtime.independent_redownload_verified -ne $true -or
    $lock.build_classification.status -cne
        'canonical-runtime-admitted-build-enabled') {
    throw 'canonical A/B build requires an independently admitted runtime'
}
foreach ($path in @($OutputDirectory, $EvidenceDirectory)) {
    if (Test-Path -LiteralPath $path) {
        throw "canonical build output already exists: $path"
    }
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null

$sentinel = Join-Path $recipe 'shared-sentinel.ps1'
$baseline = Join-Path $EvidenceDirectory 'shared-before.sentinel'
& $sentinel -Action Capture -ManifestPath $baseline -SharedRoot $SharedRoot

$pwshPath = (Get-Command pwsh -ErrorAction Stop).Source
$pythonPath = (Get-Command python -ErrorAction Stop).Source
try {
foreach ($label in @('A', 'B')) {
    $destination = Join-Path $OutputDirectory "private-$label"
    & (Join-Path $recipe 'bootstrap-private-root.ps1') `
        -Destination $destination `
        -Workspace $Workspace `
        -SharedRoot $SharedRoot

    $root = Join-Path $destination 'root'
    $neutralRecipe = Join-Path $root 'gmp-build'
    New-Item -ItemType Directory -Path $neutralRecipe | Out-Null
    foreach ($name in @(
            'PKGBUILD',
            'README.md',
            'dependency-lock.json',
            'gmp-consumer.c',
            'gmp-consumer.cpp',
            'scan-forbidden-paths.py',
            'validate-gmp.sh')) {
        Copy-Item `
            -LiteralPath (Join-Path $recipe $name) `
            -Destination $neutralRecipe
    }
    Copy-Item `
        -LiteralPath (Join-Path $destination 'sources\primary\gmp-6.3.0.tar.xz') `
        -Destination $neutralRecipe
    Copy-Item `
        -LiteralPath (Join-Path $destination 'sources\primary\gmp-6.3.0.tar.xz.sig') `
        -Destination $neutralRecipe
    Copy-Item `
        -LiteralPath (
            Join-Path $destination `
                'sources\primary\check-aarch64-pseudo-relocs.ps1') `
        -Destination $neutralRecipe

    $cygpath = Join-Path $root 'usr\bin\cygpath.exe'
    $bash = Join-Path $root 'usr\bin\bash.exe'
    $env:MSYS = 'winsymlinks:sys'
    $env:MSYSTEM = 'MSYS'
    $env:MSYS2_PATH_TYPE = 'strict'
    $env:MSYSARM64_CANONICAL_RUNTIME_ADMITTED = 'true'
    $env:MSYSARM64_CANONICAL_RUNTIME_VERSION =
        [string]$lock.canonical_runtime.version
    $env:MSYSARM64_CANONICAL_RUNTIME_PKGREL =
        [string]$lock.canonical_runtime.pkgrel
    $env:PWSH = (& $cygpath -u $pwshPath).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($env:PWSH)) {
        throw "cannot map PowerShell into private build $label"
    }
    $env:PYTHON = (& $cygpath -u $pythonPath).Trim()
    if ($LASTEXITCODE -ne 0 -or
        [string]::IsNullOrWhiteSpace($env:PYTHON)) {
        throw "cannot map Python into private build $label"
    }
    & $bash --noprofile --norc -c @'
set -euo pipefail
export PATH=/opt/bin:/usr/bin:/bin
export HOME=/home/gmp-builder
export GNUPGHOME=/var/lib/gmp-build-gnupg
mkdir -p "$HOME"
cd /gmp-build
makepkg --noconfirm --cleanbuild --clean --force
'@
    if ($LASTEXITCODE -ne 0) {
        throw "canonical private build $label failed"
    }

    $packages = @(
        Get-ChildItem -LiteralPath $neutralRecipe -File |
            Where-Object Name -Like '*.pkg.tar.zst'
    )
    if ($packages.Count -ne 2) {
        throw "canonical private build $label produced $($packages.Count) packages"
    }
    $buildOutput = Join-Path $OutputDirectory "build-$label"
    New-Item -ItemType Directory -Path $buildOutput | Out-Null
    Copy-Item -LiteralPath $packages.FullName -Destination $buildOutput
}

& (Join-Path $recipe 'compare-reproducibility.ps1') `
    -BuildA (Join-Path $OutputDirectory 'build-A') `
    -BuildB (Join-Path $OutputDirectory 'build-B') `
    -EvidenceDirectory (Join-Path $EvidenceDirectory 'reproducibility') `
    -DependencyLock $lockPath
}
finally {
    & $sentinel `
        -Action Compare `
        -ManifestPath $baseline `
        -SharedRoot $SharedRoot
}

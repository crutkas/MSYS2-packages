[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [string]$SourceInputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ToolchainDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHeadSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_REPOSITORY -ne 'crutkas/MSYS2-packages') {
    throw "Refusing fork-only build in $($env:GITHUB_REPOSITORY)"
}
$branchCandidates = @($env:GITHUB_REF_NAME, $env:GITHUB_HEAD_REF) |
    Where-Object { $_ }
if ($branchCandidates -notcontains 'crutkas-arm64-msys-libuuid') {
    throw "Refusing libuuid build for refs: $($branchCandidates -join ', ')"
}
$actualHeadSha = (git -C $SourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHeadSha -ne $ExpectedHeadSha) {
    throw "Checked-out commit mismatch: expected=$ExpectedHeadSha actual=$actualHeadSha"
}

$sourcePackageDirectory = Join-Path `
    $SourceRoot 'mingw-w64-cross-msysarm64-libuuid'
$packageDirectory = Join-Path `
    $RootPath 'build\mingw-w64-cross-msysarm64-libuuid'
$bash = Join-Path $RootPath 'usr\bin\bash.exe'
$cygpath = Join-Path $RootPath 'usr\bin\cygpath.exe'
$systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
foreach ($path in @(
    $sourcePackageDirectory,
    $bash,
    $cygpath,
    $systemTar,
    $SourceInputDirectory,
    $ToolchainDirectory
)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required private-build input is absent: $path"
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    [IO.File]::WriteAllLines(
        $Path,
        $Lines,
        [Text.UTF8Encoding]::new($false))
}

function Convert-ToPrivatePosix {
    param([Parameter(Mandatory = $true)][string]$Path)

    $converted = & $script:cygpath -u $Path
    if ($LASTEXITCODE -ne 0 -or -not $converted) {
        throw "Cannot convert private-root path: $Path"
    }
    return $converted.Trim()
}

function Quote-Bash {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value.Contains("'")) {
        throw "Cannot safely quote shell value: $Value"
    }
    return "'$Value'"
}

function Assert-SafeArchive {
    param([Parameter(Mandatory = $true)][string]$Archive)

    $entries = @(& $script:systemTar -tf $Archive)
    if ($LASTEXITCODE -ne 0 -or $entries.Count -eq 0) {
        throw "Cannot list output archive safely: $Archive"
    }
    foreach ($entry in $entries) {
        $normalized = $entry.Replace('\', '/')
        if (-not $normalized -or
            $normalized.StartsWith('/') -or
            $normalized -match '^[A-Za-z]:' -or
            $normalized.Split('/') -contains '..') {
            throw "Unsafe output archive entry: $entry"
        }
    }
    $links = @(& $script:systemTar -tvf $Archive |
        Where-Object { $_ -match '^[lh]' })
    if ($links.Count -ne 0) {
        throw "Unexpected output package links: $($links -join '; ')"
    }
}

foreach ($path in @($OutputDirectory, $EvidenceDirectory)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
New-Item -ItemType Directory -Force -Path `
    $OutputDirectory,
    $EvidenceDirectory,
    (Join-Path $EvidenceDirectory 'lifecycle'),
    (Join-Path $EvidenceDirectory 'package-extract'),
    (Join-Path $EvidenceDirectory 'package-mtree') |
    Out-Null

if (Test-Path -LiteralPath $packageDirectory) {
    Remove-Item -LiteralPath $packageDirectory -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $packageDirectory | Out-Null
foreach ($name in @(
    '2.40.2-uuid_time.patch',
    'PKGBUILD',
    'README.md',
    'libuuid-smoke.c',
    'validate-libuuid.sh'
)) {
    Copy-Item -LiteralPath (Join-Path $sourcePackageDirectory $name) `
        -Destination (Join-Path $packageDirectory $name)
}

$sourceInputs = @(
    [pscustomobject]@{
        Name = 'util-linux-2.40.2.tar.xz'
        Sha256 = 'd78b37a66f5922d70edf3bdfb01a6b33d34ed3c3cafd6628203b2a2b67c8e8b3'
    },
    [pscustomobject]@{
        Name = 'check-aarch64-pseudo-relocs-3356eec.ps1'
        Sha256 = '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
    }
)
foreach ($input in $sourceInputs) {
    $source = Join-Path $SourceInputDirectory $input.Name
    $destination = Join-Path $packageDirectory $input.Name
    if ((Get-FileHash -Algorithm SHA256 $source).Hash.ToLowerInvariant() -ne
        $input.Sha256) {
        throw "Source input changed: $($input.Name)"
    }
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

$packagePosix = Convert-ToPrivatePosix -Path $packageDirectory
$outputPosix = Convert-ToPrivatePosix -Path $OutputDirectory
$lifecyclePosix = Convert-ToPrivatePosix `
    -Path (Join-Path $EvidenceDirectory 'lifecycle')
$mtreePosix = Convert-ToPrivatePosix `
    -Path (Join-Path $EvidenceDirectory 'package-mtree')
$canonicalizerPosix = Convert-ToPrivatePosix `
    -Path (Join-Path $SourceRoot '.ci\canonicalize-packages.sh')
$lifecycleScriptPosix = Convert-ToPrivatePosix `
    -Path (Join-Path $SourceRoot '.ci\validate-msysarm64-libuuid-packages.sh')

$buildScript = @"
set -euo pipefail
export PATH=/opt/bin:/usr/bin:`$PATH
export SOURCE_DATE_EPOCH=1720080203
package=$(Quote-Bash $packagePosix)
output=$(Quote-Bash $outputPosix)
lifecycle=$(Quote-Bash $lifecyclePosix)
mtree=$(Quote-Bash $mtreePosix)
canonicalizer=$(Quote-Bash $canonicalizerPosix)
lifecycle_script=$(Quote-Bash $lifecycleScriptPosix)
cd "`$package"
rm -rf src pkg
rm -f ./*.pkg.tar.*
makepkg --cleanbuild --noconfirm
archives=(./*.pkg.tar.zst)
test "`${#archives[@]}" -eq 2
for archive in "`${archives[@]}"; do
  bash "`$canonicalizer" "`$archive"
done
LIBUUID_TRANSACTION_EVIDENCE_DIR="`$lifecycle" \
  bash "`$lifecycle_script"
mkdir -p "`$output"
cp ./*.pkg.tar.zst "`$output/"
for archive in "`$output/"*.pkg.tar.zst; do
  name=`$(basename "`$archive")
  bsdtar -xOf "`$archive" .MTREE > "`$mtree/`$name.MTREE"
  test -s "`$mtree/`$name.MTREE"
done
(
  cd "`$mtree"
  sha256sum ./*.MTREE > package-mtree.sha256
)
sha256sum "`$output/"*.pkg.tar.zst
"@

$oldMsystem = $env:MSYSTEM
$oldChere = $env:CHERE_INVOKING
$oldPathType = $env:MSYS2_PATH_TYPE
$oldMsys = $env:MSYS
$oldToolchain = $env:MSYSARM64_TOOLCHAIN_DIR
try {
    $env:MSYSTEM = 'MSYS'
    $env:CHERE_INVOKING = '1'
    $env:MSYS2_PATH_TYPE = 'inherit'
    $env:MSYS = 'winsymlinks:sys'
    $env:MSYSARM64_TOOLCHAIN_DIR = $ToolchainDirectory
    $output = @(& $bash --noprofile --norc -c $buildScript 2>&1)
    $exitCode = $LASTEXITCODE
}
finally {
    $env:MSYSTEM = $oldMsystem
    $env:CHERE_INVOKING = $oldChere
    $env:MSYS2_PATH_TYPE = $oldPathType
    $env:MSYS = $oldMsys
    $env:MSYSARM64_TOOLCHAIN_DIR = $oldToolchain
}
foreach ($input in $sourceInputs) {
    $copiedInput = Join-Path $packageDirectory $input.Name
    if (Test-Path -LiteralPath $copiedInput) {
        Remove-Item -LiteralPath $copiedInput -Force
    }
}
if ($exitCode -ne 0) {
    $output | ForEach-Object { Write-Host $_ }
    throw "Private libuuid build failed with exit code $exitCode"
}

$packages = @(Get-ChildItem -LiteralPath $OutputDirectory `
    -Filter '*.pkg.tar.zst' -File | Sort-Object Name)
if ($packages.Count -ne 2) {
    throw "Expected two private-root package outputs, found $($packages.Count)"
}
$expectedNames = @(
    'mingw-w64-cross-msysarm64-libuuid-2.40.2-2-x86_64.pkg.tar.zst',
    'mingw-w64-cross-msysarm64-libuuid-devel-2.40.2-2-x86_64.pkg.tar.zst'
)
if ((@($packages.Name) -join "`n") -ne ($expectedNames -join "`n")) {
    throw "Unexpected package outputs: $($packages.Name -join ', ')"
}

$extractRoot = Join-Path $EvidenceDirectory 'package-extract'
foreach ($package in $packages) {
    Assert-SafeArchive -Archive $package.FullName
    $destination = Join-Path $extractRoot $package.BaseName
    New-Item -ItemType Directory -Path $destination | Out-Null
    & $systemTar -xf $package.FullName -C $destination
    if ($LASTEXITCODE -ne 0) {
        throw "Output evidence extraction failed: $($package.Name)"
    }
}

$buildReport = Join-Path $packageDirectory 'src\libuuid-report'
$evidenceBuildReport = Join-Path $EvidenceDirectory 'build-report'
Copy-Item -LiteralPath $buildReport `
    -Destination $evidenceBuildReport -Recurse

$pathScanner = Join-Path `
    $SourceRoot '.ci\scan-msysarm64-libuuid-private-paths.ps1'
$binaryRoots = @(
    (Join-Path $packageDirectory 'src\build-aarch64-pc-msys'),
    (Join-Path $packageDirectory 'src\stage-aarch64-pc-msys'),
    (Join-Path $packageDirectory 'src\libuuid-report'),
    (Join-Path $packageDirectory 'src\libuuid-check-report')
)
foreach ($root in $binaryRoots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "Expected emitted-output root is absent: $root"
    }
}
$binaryArtifacts = @($binaryRoots | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -Recurse -File |
        Where-Object {
            $_.Extension -in @('.a', '.dll', '.exe', '.o', '.obj')
        }
} | Sort-Object FullName -Unique)
if ($binaryArtifacts.Count -lt 31) {
    throw "Emitted binary coverage is unexpectedly small: $(
        $binaryArtifacts.Count)"
}
$coverageLines = @($binaryArtifacts | ForEach-Object {
    $relative = $_.FullName.Substring($packageDirectory.Length + 1).
        Replace('\', '/')
    $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).
        Hash.ToLowerInvariant()
    "$hash  $relative"
})
Write-Utf8NoBom `
    -Path (Join-Path $EvidenceDirectory 'binary-coverage.sha256') `
    -Lines $coverageLines
$scanPaths = @($EvidenceDirectory, $OutputDirectory) +
    @($binaryArtifacts.FullName)
$forbiddenPaths = @(
    @(
        $RootPath,
        $SourceRoot,
        $sourcePackageDirectory,
        $packageDirectory,
        $OutputDirectory,
        $EvidenceDirectory,
        $env:GITHUB_WORKSPACE,
        $env:RUNNER_TEMP
    ) | Where-Object { $_ }
)
& $pathScanner -SelfTest
& $pathScanner `
    -Paths $scanPaths `
    -ForbiddenPaths $forbiddenPaths `
    -OutputPath (Join-Path $EvidenceDirectory 'path-scan.json')

$summary = [ordered]@{
    schema = 1
    commit = $actualHeadSha
    package_count = $packages.Count
    packages = @($packages | ForEach-Object {
        [ordered]@{
            name = $_.Name
            size = $_.Length
            sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).
                Hash.ToLowerInvariant()
            mtree_sha256 = (
                Get-FileHash -Algorithm SHA256 (
                    Join-Path `
                        $EvidenceDirectory "package-mtree\$($_.Name).MTREE")
            ).Hash.ToLowerInvariant()
        }
    })
}
[IO.File]::WriteAllText(
    (Join-Path $EvidenceDirectory 'build-summary.json'),
    ($summary | ConvertTo-Json -Depth 5),
    [Text.UTF8Encoding]::new($false))

$manifestPath = Join-Path $EvidenceDirectory 'evidence-manifest.sha256'
$sealPath = Join-Path $EvidenceDirectory 'evidence.seal'
$manifest = Get-ChildItem -LiteralPath $EvidenceDirectory -Recurse -File |
    Where-Object { $_.FullName -notin @($manifestPath, $sealPath) } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($EvidenceDirectory.Length + 1).
            Replace('\', '/')
        $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).
            Hash.ToLowerInvariant()
        "$hash  $relative"
    }
Write-Utf8NoBom -Path $manifestPath -Lines @($manifest)
$seal = (Get-FileHash -Algorithm SHA256 $manifestPath).
    Hash.ToLowerInvariant()
Write-Utf8NoBom -Path $sealPath `
    -Lines @("$seal  evidence-manifest.sha256")

if (Test-Path -LiteralPath $packageDirectory) {
    Remove-Item -LiteralPath $packageDirectory -Recurse -Force
}

$summary

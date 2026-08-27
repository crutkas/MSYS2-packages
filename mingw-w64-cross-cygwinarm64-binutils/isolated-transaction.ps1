[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CandidatePackage,
    [Parameter(Mandatory = $true)]
    [string] $WorkRoot,
    [Parameter(Mandatory = $true)]
    [string] $ReportRoot,
    [string] $SharedMsysRoot = 'C:\msys64',
    [string] $AllowedWorkParent = $(
        if ($env:RUNNER_TEMP) {
            $env:RUNNER_TEMP
        }
        else {
            [System.IO.Path]::GetTempPath()
        }),
    [string] $InputsPath = (Join-Path $PSScriptRoot 'candidate-inputs.json'),
    [string] $PseudoRelocChecker = (
        Join-Path (Split-Path $PSScriptRoot -Parent) '.ci\check-aarch64-pseudo-relocs.ps1'),
    [string] $SourcePseudoRelocChecker = (
        Join-Path (Split-Path $PSScriptRoot -Parent) '.ci\source-scanner-v2\check-aarch64-pseudo-relocs.ps1'),
    [string] $PseudoRelocTest = (
        Join-Path (Split-Path $PSScriptRoot -Parent) '.ci\test-check-aarch64-pseudo-relocs.ps1'),
    [string] $PseudoRelocFixtures = (
        Join-Path (Split-Path $PSScriptRoot -Parent) '.ci\fixtures\aarch64-pseudo-relocs')
)

$ErrorActionPreference = 'Stop'
$PackageName = 'mingw-w64-cross-cygwinarm64-binutils'
$AliasTools = @(
    'addr2line', 'ar', 'as', 'c++filt', 'dlltool', 'dllwrap', 'elfedit',
    'gprof', 'ld', 'ld.bfd', 'nm', 'objcopy', 'objdump', 'ranlib',
    'readelf', 'size', 'strings', 'strip', 'windmc', 'windres'
)

function Get-DirectoryFingerprint {
    param([Parameter(Mandatory = $true)][string] $Path)

    $root = (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\')
    $lines = Get-ChildItem -LiteralPath $root -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($root.Length + 1)
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).
                Hash.ToLowerInvariant()
            "$hash  $relative"
        }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    $sha = [System.Security.Cryptography.SHA256]::HashData($bytes)
    [pscustomobject]@{
        sha256 = [Convert]::ToHexString($sha).ToLowerInvariant()
        file_count = @($lines).Count
    }
}

function Test-PathOverlap {
    param(
        [Parameter(Mandatory = $true)][string] $Left,
        [Parameter(Mandatory = $true)][string] $Right
    )

    $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd('\')
    $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd('\')
    return (
        $leftPath.Equals(
            $rightPath,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $leftPath.StartsWith(
            "$rightPath\",
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $rightPath.StartsWith(
            "$leftPath\",
            [System.StringComparison]::OrdinalIgnoreCase)
    )
}

function Invoke-RootPacman {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,
        [switch] $AllowFailure
    )

    $output = & $script:Pacman @script:PacmanRootArgs @Arguments
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "isolated pacman failed with exit code $exitCode"
    }
    return $exitCode
}

function Get-IsolatedIdentity {
    $output = & $script:Pacman @script:PacmanRootArgs -Q $PackageName
    if ($LASTEXITCODE -ne 0) {
        throw "cannot query $PackageName in isolated root"
    }
    return ($output | Out-String).Trim()
}

$CandidatePackage = (Resolve-Path -LiteralPath $CandidatePackage).Path
$PseudoRelocChecker = (Resolve-Path -LiteralPath $PseudoRelocChecker).Path
$SourcePseudoRelocChecker = (
    Resolve-Path -LiteralPath $SourcePseudoRelocChecker).Path
$PseudoRelocTest = (Resolve-Path -LiteralPath $PseudoRelocTest).Path
$PseudoRelocFixtures = (Resolve-Path -LiteralPath $PseudoRelocFixtures).Path
$InputsPath = (Resolve-Path -LiteralPath $InputsPath).Path
$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
$ReportRoot = [System.IO.Path]::GetFullPath($ReportRoot)
$AllowedWorkParent = [System.IO.Path]::GetFullPath($AllowedWorkParent)
$SharedMsysRoot = (Resolve-Path -LiteralPath $SharedMsysRoot).Path
$SharedDb = Join-Path $SharedMsysRoot 'var\lib\pacman\local'
if ([System.IO.Path]::GetPathRoot($WorkRoot) -eq $WorkRoot) {
    throw 'WorkRoot must not be a filesystem root.'
}
if (-not $WorkRoot.StartsWith(
    "$($AllowedWorkParent.TrimEnd('\'))\",
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "WorkRoot must be beneath AllowedWorkParent: $AllowedWorkParent"
}
if (Test-Path -LiteralPath $WorkRoot) {
    $workItem = Get-Item -LiteralPath $WorkRoot -Force
    if ($workItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'WorkRoot must not be a reparse point.'
    }
}
$protectedPaths = @($SharedMsysRoot, $SharedDb)
foreach ($protectedPath in $protectedPaths) {
    if (Test-PathOverlap -Left $WorkRoot -Right $protectedPath) {
        throw "WorkRoot overlaps protected path: $protectedPath"
    }
    if (Test-PathOverlap -Left $ReportRoot -Right $protectedPath) {
        throw "ReportRoot overlaps protected path: $protectedPath"
    }
}
if (Test-PathOverlap -Left $WorkRoot -Right $ReportRoot) {
    throw 'WorkRoot and ReportRoot must not overlap.'
}

$Pacman = Join-Path $SharedMsysRoot 'usr\bin\pacman.exe'
$env:MSYS = 'winsymlinks:sys'
$sharedBefore = Get-DirectoryFingerprint -Path $SharedDb

if (Test-Path -LiteralPath $WorkRoot) {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $WorkRoot, $ReportRoot |
    Out-Null
$Root = Join-Path $WorkRoot 'root'
$Cache = Join-Path $WorkRoot 'cache'
$Packages = Join-Path $Root 'tmp\candidate-packages'
$RootReport = Join-Path $Root 'tmp\fixed-binutils-report'
New-Item -ItemType Directory -Force -Path (
    Join-Path $Root 'var\lib\pacman'
), (Join-Path $Root 'etc'), $Cache, $Packages, $RootReport | Out-Null
Copy-Item -LiteralPath (Join-Path $SharedMsysRoot 'etc\pacman.conf') `
    -Destination (Join-Path $Root 'etc\pacman.conf') -Force
Copy-Item -LiteralPath (Join-Path $SharedMsysRoot 'etc\pacman.d') `
    -Destination (Join-Path $Root 'etc\pacman.d') -Recurse -Force

$PacmanRootArgs = @(
    '--root', $Root,
    '--dbpath', (Join-Path $Root 'var\lib\pacman'),
    '--cachedir', $Cache,
    '--config', (Join-Path $Root 'etc\pacman.conf'),
    '--noconfirm'
)

$inputs = Get-Content -LiteralPath $InputsPath -Raw | ConvertFrom-Json
$allInputs = @($inputs.baseline_binutils) + @($inputs.immutable_packages)
foreach ($input in $allInputs) {
    $destination = Join-Path $Packages $input.filename
    Invoke-WebRequest -Uri $input.url -OutFile $destination
    $item = Get-Item -LiteralPath $destination
    if ($item.Length -ne $input.size) {
        throw "size mismatch for $($input.filename): $($item.Length)"
    }
    $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).
        Hash.ToLowerInvariant()
    if ($sha256 -ne $input.sha256) {
        throw "SHA-256 mismatch for $($input.filename): $sha256"
    }
}

$candidateDestination = Join-Path $Packages (
    Split-Path -Leaf $CandidatePackage)
Copy-Item -LiteralPath $CandidatePackage -Destination $candidateDestination -Force
$candidateIdentityOutput = & $Pacman -Qp $candidateDestination
if ($LASTEXITCODE -ne 0) {
    throw 'cannot read candidate package identity'
}
$candidateIdentity = ($candidateIdentityOutput | Out-String).Trim()
if ($candidateIdentity -notmatch "^$([regex]::Escape($PackageName)) ") {
    throw "unexpected candidate identity: $candidateIdentity"
}

$baselinePath = Join-Path $Packages $inputs.baseline_binutils.filename
$immutablePaths = @(
    $inputs.immutable_packages |
        ForEach-Object { Join-Path $Packages $_.filename }
)
$transaction = [ordered]@{
    schema_version = 1
    baseline_identity = $null
    candidate_identity = $candidateIdentity
    safe_remove_rejected = $false
    forced_remove_missing_dependency = $false
    aliases_absent_after_remove = $false
    rollback_identity = $null
    reinstall_identity = $null
    shared_database_before = $sharedBefore.sha256
    shared_database_after = $null
    shared_database_unchanged = $false
}

try {
    Invoke-RootPacman -Arguments @('-Sy') | Out-Null
    Invoke-RootPacman -Arguments @(
        '-S', '--needed', 'base', 'python', 'libiconv', 'libintl', 'zlib', 'libzstd'
    ) | Out-Null
    Invoke-RootPacman -Arguments (
        @('-U', $baselinePath) + $immutablePaths
    ) | Out-Null
    foreach ($immutablePath in $immutablePaths) {
        $expected = (& $Pacman -Qp $immutablePath | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^(\S+) ') {
            throw "cannot read immutable package identity: $immutablePath"
        }
        $actual = (& $Pacman @PacmanRootArgs -Q $Matches[1] | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) {
            throw "immutable package was skipped or changed: $expected"
        }
    }
    $transaction.baseline_identity = Get-IsolatedIdentity
    if ($transaction.baseline_identity -ne
        "$PackageName $($inputs.baseline_binutils.version)") {
        throw "baseline identity mismatch: $($transaction.baseline_identity)"
    }
    Invoke-RootPacman -Arguments @(
        '-T', "$PackageName>=2.44.50"
    ) | Out-Null

    Invoke-RootPacman -Arguments @('-U', $candidateDestination) | Out-Null
    if ((Get-IsolatedIdentity) -ne $candidateIdentity) {
        throw 'candidate upgrade identity mismatch'
    }
    Invoke-RootPacman -Arguments @('-T', "$PackageName>=2.44.50") |
        Out-Null

    $savedPath = $env:PATH
    try {
        $env:PATH = (
            (Join-Path $Root 'usr\bin'),
            (Join-Path $Root 'opt\bin'),
            $savedPath
        ) -join [System.IO.Path]::PathSeparator
        & (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -File $PseudoRelocTest `
            -RealFixtureDirectory $PseudoRelocFixtures `
            -Objdump (Join-Path $Root 'opt\bin\aarch64-pc-cygwin-objdump.exe') `
            -Nm (Join-Path $Root 'opt\bin\aarch64-pc-cygwin-nm.exe') `
            -RequireRealFixtures
        if ($LASTEXITCODE -ne 0) {
            throw 'sealed real pseudo-reloc fixture matrix failed'
        }
    }
    finally {
        $env:PATH = $savedPath
    }

    $validationRoot = Join-Path $Root 'tmp\fixed-binutils-validation'
    New-Item -ItemType Directory -Force -Path $validationRoot | Out-Null
    Copy-Item -LiteralPath (
        Join-Path $PSScriptRoot 'validate-binutils-package.sh'
    ), (
        Join-Path $PSScriptRoot 'validate-consumers.sh'
    ), $PseudoRelocChecker -Destination $validationRoot -Force
    Copy-Item -LiteralPath $SourcePseudoRelocChecker `
        -Destination (Join-Path $validationRoot 'source-check-aarch64-pseudo-relocs.ps1') `
        -Force
    $bash = Join-Path $Root 'usr\bin\bash.exe'
    $env:CHERE_INVOKING = '1'
    $script = @'
export PATH=/usr/bin:/opt/bin
set -euo pipefail
bash /tmp/fixed-binutils-validation/validate-binutils-package.sh \
  "/tmp/candidate-packages/CANDIDATE_FILENAME" \
  /tmp/fixed-binutils-report/package
bash /tmp/fixed-binutils-validation/validate-consumers.sh \
  /tmp/fixed-binutils-report/consumers \
  /tmp/fixed-binutils-validation/check-aarch64-pseudo-relocs.ps1 \
  /tmp/fixed-binutils-validation/source-check-aarch64-pseudo-relocs.ps1
'@.Replace('CANDIDATE_FILENAME', (Split-Path -Leaf $candidateDestination))
    & $bash --login -lc $script
    if ($LASTEXITCODE -ne 0) {
        throw 'candidate package or consumer validation failed'
    }

    $safeRemoveExit = Invoke-RootPacman -Arguments @(
        '-R', $PackageName
    ) -AllowFailure
    if ($safeRemoveExit -eq 0) {
        throw 'dependency-aware candidate removal unexpectedly succeeded'
    }
    if ((Get-IsolatedIdentity) -ne $candidateIdentity) {
        throw 'failed safe removal changed candidate installation'
    }
    $transaction.safe_remove_rejected = $true

    Invoke-RootPacman -Arguments @('-Rdd', $PackageName) | Out-Null
    $missingOutput = & $Pacman @PacmanRootArgs -T "$PackageName>=2.44.50"
    $missingExit = $LASTEXITCODE
    if ($missingExit -ne 127 -or
        ($missingOutput | Out-String).Trim() -ne "$PackageName>=2.44.50") {
        throw 'forced removal did not expose the final GCC dependency'
    }
    $transaction.forced_remove_missing_dependency = $true
    foreach ($tool in $AliasTools) {
        $alias = Join-Path $Root "opt\bin\aarch64-pc-msys-$tool.exe"
        if (Test-Path -LiteralPath $alias) {
            throw "candidate alias survived package removal: $tool"
        }
    }
    $transaction.aliases_absent_after_remove = $true

    Invoke-RootPacman -Arguments @('-U', $baselinePath) | Out-Null
    $transaction.rollback_identity = Get-IsolatedIdentity
    if ($transaction.rollback_identity -ne
        "$PackageName $($inputs.baseline_binutils.version)") {
        throw 'baseline rollback identity mismatch'
    }
    Invoke-RootPacman -Arguments @('-T', "$PackageName>=2.44.50") |
        Out-Null

    Invoke-RootPacman -Arguments @('-U', $candidateDestination) | Out-Null
    $transaction.reinstall_identity = Get-IsolatedIdentity
    if ($transaction.reinstall_identity -ne $candidateIdentity) {
        throw 'candidate reinstall identity mismatch'
    }
    $ownedPaths = @(& $Pacman @PacmanRootArgs -Ql $PackageName)
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot query candidate package file ownership'
    }
    foreach ($tool in $AliasTools) {
        $alias = Join-Path $Root "opt\bin\aarch64-pc-msys-$tool.exe"
        if (-not (Test-Path -LiteralPath $alias)) {
            throw "candidate alias missing after reinstall: $tool"
        }
        $isolatedPath = $alias.Substring($Root.Length).Replace('\', '/')
        $owned = @($ownedPaths | Where-Object {
            $_.StartsWith(
                "$PackageName ",
                [System.StringComparison]::Ordinal) -and
            $_.EndsWith(
                $isolatedPath,
                [System.StringComparison]::Ordinal)
        })
        if ($owned.Count -ne 1) {
            throw "alias absent from package ownership list: $isolatedPath"
        }
    }
}
finally {
    $sharedAfter = Get-DirectoryFingerprint -Path $SharedDb
    $transaction.shared_database_after = $sharedAfter.sha256
    $transaction.shared_database_unchanged = (
        $sharedBefore.sha256 -eq $sharedAfter.sha256 -and
        $sharedBefore.file_count -eq $sharedAfter.file_count
    )
    $transaction | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (
            Join-Path $ReportRoot 'transaction-report.json'
        ) -Encoding utf8
    if (Test-Path -LiteralPath $RootReport) {
        Copy-Item -Path (Join-Path $RootReport '*') `
            -Destination $ReportRoot -Recurse -Force
    }
    if (-not $transaction.shared_database_unchanged) {
        throw 'shared C:\msys64 pacman database changed'
    }
}

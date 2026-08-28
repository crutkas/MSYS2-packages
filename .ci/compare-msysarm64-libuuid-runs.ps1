[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [long]$PushRunId,

    [Parameter(Mandatory = $true)]
    [long]$PullRequestRunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHeadSha,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

$repository = 'crutkas/MSYS2-packages'
$apiRoot = "https://api.github.com/repos/$repository"
$systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $systemTar -PathType Leaf)) {
    throw "Missing archive tool: $systemTar"
}
$sourceRoot = Split-Path -Parent $PSScriptRoot
$currentHead = (git -C $sourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $currentHead -ne $ExpectedHeadSha) {
    throw "Cross-run verifier head mismatch: $currentHead"
}
git -C $sourceRoot diff --quiet $ExpectedHeadSha -- `
    '.ci/compare-msysarm64-libuuid-runs.ps1' `
    '.ci/scan-msysarm64-libuuid-private-paths.ps1'
if ($LASTEXITCODE -ne 0) {
    throw 'Cross-run verifier or binary-safe scanner differs from expected head'
}
$scannerPath = Join-Path `
    $PSScriptRoot 'scan-msysarm64-libuuid-private-paths.ps1'
$expectedScannerSha256 = (
    Get-FileHash -Algorithm SHA256 $scannerPath
).Hash.ToLowerInvariant()
$token = (& gh auth token).Trim()
if ($LASTEXITCODE -ne 0 -or -not $token) {
    throw 'GitHub authentication is required to preserve Actions artifacts'
}
$headers = @{
    Accept = 'application/vnd.github+json'
    Authorization = "Bearer $token"
    'User-Agent' = 'msysarm64-libuuid-evidence'
    'X-GitHub-Api-Version' = '2022-11-28'
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

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    return $Path.Substring($Root.Length + 1).Replace('\', '/')
}

function Expand-SafeZip {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($entry in $archive.Entries) {
            $normalized = $entry.FullName.Replace('\', '/')
            if (-not $normalized -or
                $normalized.StartsWith('/') -or
                $normalized -match '^[A-Za-z]:' -or
                $normalized.Split('/') -contains '..' -or
                -not $seen.Add($normalized)) {
                throw "Unsafe or duplicate ZIP entry: $normalized"
            }
            $unixMode = ($entry.ExternalAttributes -shr 16) -band 0xf000
            if ($unixMode -eq 0xa000) {
                throw "ZIP symlink entries are forbidden: $normalized"
            }
            $destinationPath = [IO.Path]::GetFullPath(
                (Join-Path $Destination $normalized.Replace('/', '\')))
            if (-not $destinationPath.StartsWith(
                $root,
                [StringComparison]::OrdinalIgnoreCase)) {
                throw "ZIP entry escapes extraction root: $normalized"
            }
            if ($normalized.EndsWith('/')) {
                New-Item -ItemType Directory -Force -Path $destinationPath |
                    Out-Null
                continue
            }
            $parent = Split-Path -Parent $destinationPath
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
            $input = $entry.Open()
            $output = [IO.File]::Open(
                $destinationPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try {
                $input.CopyTo($output)
            }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-PackageMtree {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $entries = @(& $script:systemTar -tf $PackagePath)
    if ($LASTEXITCODE -ne 0 -or
        @($entries | Where-Object { $_ -eq '.MTREE' }).Count -ne 1) {
        throw "Package does not contain exactly one .MTREE: $PackagePath"
    }
    foreach ($entry in $entries) {
        $normalized = $entry.Replace('\', '/')
        if (-not $normalized -or
            $normalized.StartsWith('/') -or
            $normalized -match '^[A-Za-z]:' -or
            $normalized.Split('/') -contains '..') {
            throw "Unsafe package archive entry: $entry"
        }
    }
    $links = @(& $script:systemTar -tvf $PackagePath |
        Where-Object { $_ -match '^[lh]' })
    if ($LASTEXITCODE -ne 0 -or $links.Count -ne 0) {
        throw "Package links are forbidden: $PackagePath"
    }
    New-Item -ItemType Directory -Path $Destination | Out-Null
    & $systemTar -xf $PackagePath -C $Destination .MTREE
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot extract package .MTREE: $PackagePath"
    }
    $mtree = Join-Path $Destination '.MTREE'
    if (-not (Test-Path -LiteralPath $mtree -PathType Leaf)) {
        throw "Package .MTREE extraction is incomplete: $PackagePath"
    }
    return $mtree
}

function Test-EvidenceSeal {
    param([Parameter(Mandatory = $true)][string]$SealPath)

    $componentRoot = Split-Path -Parent $SealPath
    $sealValue = (Get-Content -LiteralPath $SealPath -Raw).Trim()
    if ($sealValue -notmatch
        '^([0-9a-f]{64})(?:  | \*)evidence-manifest\.sha256$') {
        throw "Invalid evidence seal format: $SealPath"
    }
    $manifestHash = $Matches[1]
    $manifestPath = Join-Path $componentRoot 'evidence-manifest.sha256'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-FileHash -Algorithm SHA256 $manifestPath).
            Hash.ToLowerInvariant() -ne $manifestHash) {
        throw "Evidence manifest seal mismatch: $SealPath"
    }
    $listedPaths = [Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        if ($line -notmatch '^([0-9a-f]{64})(?:  | \*)(.+)$') {
            throw "Invalid evidence manifest line in $manifestPath`: $line"
        }
        $expectedHash = $Matches[1]
        $relative = $Matches[2].Replace('/', '\')
        if ([IO.Path]::IsPathRooted($relative) -or
            $relative.Split('\') -contains '..') {
            throw "Unsafe evidence manifest path: $relative"
        }
        $path = [IO.Path]::GetFullPath((Join-Path $componentRoot $relative))
        $rootPrefix = [IO.Path]::GetFullPath($componentRoot).
            TrimEnd('\') + '\'
        if (-not $path.StartsWith(
            $rootPrefix,
            [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileHash -Algorithm SHA256 $path).
                Hash.ToLowerInvariant() -ne $expectedHash) {
            throw "Evidence manifest entry mismatch: $relative"
        }
        $canonicalRelative = $relative.Replace('\', '/')
        if ($listedPaths.Contains($canonicalRelative)) {
            throw "Duplicate evidence manifest entry: $canonicalRelative"
        }
        $listedPaths.Add($canonicalRelative)
    }
    $actualPaths = @(Get-ChildItem -LiteralPath $componentRoot -Recurse -File |
        Where-Object {
            $_.FullName -notin @($manifestPath, $SealPath)
        } |
        ForEach-Object {
            Get-RelativePath -Root $componentRoot -Path $_.FullName
        } |
        Sort-Object)
    if ((@($listedPaths | Sort-Object) -join "`n") -ne
        ($actualPaths -join "`n")) {
        throw "Evidence manifest coverage is incomplete: $SealPath"
    }
    return [ordered]@{
        seal_sha256 = (
            Get-FileHash -Algorithm SHA256 $SealPath
        ).Hash.ToLowerInvariant()
        manifest_sha256 = $manifestHash
        value = $sealValue
    }
}

function Get-RunBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][long]$RunId,
        [Parameter(Mandatory = $true)][string]$ExpectedEvent,
        [Parameter(Mandatory = $true)][string]$ScratchRoot
    )

    $run = Invoke-RestMethod -Headers $script:headers `
        -Uri "$script:apiRoot/actions/runs/$RunId"
    if ($run.status -ne 'completed' -or
        $run.conclusion -ne 'success' -or
        $run.event -ne $ExpectedEvent -or
        $run.head_sha -ne $script:ExpectedHeadSha) {
        throw "$Role run identity or result changed"
    }

    $jobsResponse = Invoke-RestMethod -Headers $script:headers `
        -Uri "$script:apiRoot/actions/runs/$RunId/jobs?per_page=100"
    $requiredJobs = @(
        'Immutable private MSYS build',
        'package-grokker',
        'native'
    )
    foreach ($name in $requiredJobs) {
        $jobs = @($jobsResponse.jobs | Where-Object {
            $_.name -eq $name -and $_.conclusion -eq 'success'
        })
        if ($jobs.Count -ne 1) {
            throw "$Role run does not have one successful $name job"
        }
    }

    $artifactsResponse = Invoke-RestMethod -Headers $script:headers `
        -Uri "$script:apiRoot/actions/runs/$RunId/artifacts?per_page=100"
    $expectedArtifacts = @(
        'MSYS-libuuid-packages',
        'MSYS-libuuid-private-evidence',
        'MSYS-libuuid-native-attestation'
    )
    $artifactRecords = [Collections.Generic.List[object]]::new()
    $extractPaths = @{}
    foreach ($name in $expectedArtifacts) {
        $matches = @($artifactsResponse.artifacts | Where-Object {
            $_.name -eq $name
        })
        if ($matches.Count -ne 1 -or $matches[0].expired) {
            throw "$Role run does not have one live $name artifact"
        }
        $artifact = $matches[0]
        if ($artifact.digest -notmatch '^sha256:[0-9a-f]{64}$') {
            throw "$Role $name artifact does not expose a SHA-256 digest"
        }
        $zipName = "$Role-run$RunId-$name.zip"
        $zipPath = Join-Path $script:OutputDirectory $zipName
        Invoke-WebRequest -Headers $script:headers `
            -Uri $artifact.archive_download_url `
            -OutFile $zipPath
        $zipHash = (Get-FileHash -Algorithm SHA256 $zipPath).
            Hash.ToLowerInvariant()
        if ((Get-Item -LiteralPath $zipPath).Length -ne
                $artifact.size_in_bytes -or
            "sha256:$zipHash" -ne $artifact.digest) {
            throw "$Role $name raw ZIP identity changed"
        }

        $extractPath = Join-Path $ScratchRoot "$Role-$name"
        New-Item -ItemType Directory -Path $extractPath | Out-Null
        Expand-SafeZip -Path $zipPath -Destination $extractPath
        $extractPaths[$name] = $extractPath
        $artifactRecords.Add([ordered]@{
            name = $name
            id = $artifact.id
            size = $artifact.size_in_bytes
            sha256 = $zipHash
            release_file = $zipName
        })
    }

    $packageRoot = $extractPaths['MSYS-libuuid-packages']
    $packages = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File `
        -Filter '*.pkg.tar.zst' | Sort-Object Name)
    if ($packages.Count -ne 2) {
        throw "$Role run contains $($packages.Count) package files"
    }
    $evidenceRoot = $extractPaths['MSYS-libuuid-private-evidence']
    $packageRecords = @($packages | ForEach-Object {
        $mtreeEvidence = Join-Path `
            $evidenceRoot "build\package-mtree\$($_.Name).MTREE"
        if (-not (Test-Path -LiteralPath $mtreeEvidence -PathType Leaf)) {
            throw "$Role build evidence is missing $($_.Name).MTREE"
        }
        $mtreeExtract = Join-Path `
            $ScratchRoot "$Role-mtree-$($_.BaseName)"
        $actualMtree = Get-PackageMtree `
            -PackagePath $_.FullName `
            -Destination $mtreeExtract
        $mtreeSha256 = (
            Get-FileHash -Algorithm SHA256 $actualMtree
        ).Hash.ToLowerInvariant()
        if ((Get-FileHash -Algorithm SHA256 $mtreeEvidence).
            Hash.ToLowerInvariant() -ne $mtreeSha256) {
            throw "$Role package .MTREE evidence differs from package bytes"
        }
        [ordered]@{
            name = $_.Name
            size = $_.Length
            sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).
                Hash.ToLowerInvariant()
            mtree_sha256 = $mtreeSha256
        }
    })

    $jsonPathScans = @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse `
        -File -Filter 'path-scan.json')
    $expectedPathScans = @(
        'path-scan.json',
        'root/path-scan.json',
        'build/path-scan.json',
        'build/lifecycle/path-scan.json'
    )
    $actualPathScans = @($jsonPathScans | ForEach-Object {
        Get-RelativePath -Root $evidenceRoot -Path $_.FullName
    } | Sort-Object)
    if (($actualPathScans -join "`n") -ne
        (@($expectedPathScans | Sort-Object) -join "`n")) {
        throw "$Role private evidence is missing zero-leak reports"
    }
    foreach ($scan in $jsonPathScans) {
        $result = Get-Content -LiteralPath $scan.FullName -Raw |
            ConvertFrom-Json
        if ($result.scanner_sha256 -ne $script:expectedScannerSha256 -or
            $result.result -ne 'pass' -or $result.leak_count -ne 0 -or
            $result.files_scanned -lt 1 -or
            $result.files_enumerated -ne $result.files_scanned) {
            throw "$Role private binary-safe path scan failed"
        }
    }
    $heldRegressionPath = Join-Path `
        $evidenceRoot 'root\held-release-path-regression.json'
    $heldRegression = Get-Content -LiteralPath $heldRegressionPath -Raw |
        ConvertFrom-Json
    $expectedHeldHashes = @(
        '425444b6744ee3897e44e1a7f2de1b1903506ff208fd40cd0a80c12589a885de',
        '9b4e044699ff8779373efc8a070b6b5ac029f09b3621ecf9cd7bf47a9955c0eb'
    )
    if ($heldRegression.result -ne 'expected-rejection' -or
        $heldRegression.scanner_sha256 -ne $script:expectedScannerSha256 -or
        $heldRegression.files_enumerated -ne 45 -or
        $heldRegression.files_scanned -ne 45 -or
        $heldRegression.leak_count -ne 188 -or
        $heldRegression.unique_leak_values -ne 20 -or
        @($heldRegression.value_sha256).Count -ne 20 -or
        (@($heldRegression.assets.sha256 | Sort-Object) -join "`n") -ne
            (@($expectedHeldHashes | Sort-Object) -join "`n")) {
        throw "$Role held-release path regression is not canonical"
    }
    foreach ($valueHash in $heldRegression.value_sha256) {
        if ($valueHash -notmatch '^[0-9a-f]{64}$') {
            throw "$Role held-release finding hash is malformed"
        }
    }

    $buildSummary = Get-Content -LiteralPath (
        Join-Path $evidenceRoot 'build\build-summary.json') -Raw |
        ConvertFrom-Json
    if ($buildSummary.commit -ne $script:ExpectedHeadSha -or
        $buildSummary.package_count -ne 2 -or
        @($buildSummary.packages).Count -ne 2) {
        throw "$Role build summary identity is wrong"
    }
    foreach ($package in $packageRecords) {
        $summaryRecord = @($buildSummary.packages | Where-Object {
            $_.name -eq $package.name
        })
        if ($summaryRecord.Count -ne 1 -or
            $summaryRecord[0].size -ne $package.size -or
            $summaryRecord[0].sha256 -ne $package.sha256 -or
            $summaryRecord[0].mtree_sha256 -ne $package.mtree_sha256) {
            throw "$Role build summary differs for $($package.name)"
        }
    }
    $comparisons = @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -File `
        -Filter 'comparison.json')
    if ($comparisons.Count -ne 1) {
        throw "$Role shared-root comparison count is $($comparisons.Count)"
    }
    $comparison = $comparisons[0]
    if (
        -not (Get-Content -LiteralPath $comparison.FullName -Raw |
            ConvertFrom-Json).stable) {
        throw "$Role shared-root comparison is missing or unstable"
    }
    $sealFiles = @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -File `
        -Filter 'evidence.seal' | Sort-Object FullName)
    $expectedSealPaths = @(
        'evidence.seal',
        'commit/evidence.seal',
        'root/evidence.seal',
        'build/evidence.seal',
        'build/lifecycle/evidence.seal',
        'shared/evidence.seal'
    )
    $actualSealPaths = @($sealFiles | ForEach-Object {
        Get-RelativePath -Root $evidenceRoot -Path $_.FullName
    } | Sort-Object)
    if (($actualSealPaths -join "`n") -ne
        (@($expectedSealPaths | Sort-Object) -join "`n")) {
        throw "$Role private evidence component set is incomplete"
    }
    $privateSeals = @($sealFiles | ForEach-Object {
            $verified = Test-EvidenceSeal -SealPath $_.FullName
            [ordered]@{
                path = Get-RelativePath `
                    -Root $evidenceRoot `
                    -Path $_.FullName
                sha256 = $verified.seal_sha256
                manifest_sha256 = $verified.manifest_sha256
                value = $verified.value
            }
        })
    $deterministicSuffixes = @(
        'commit/commit-trailers.json',
        'root/base-input.sha256',
        'root/host-packages.sha256',
        'root/target-packages.sha256',
        'root/source-inputs.sha256',
        'root/package-state.txt',
        'root/root-summary.json',
        'root/path-scan.json',
        'root/held-release-path-regression.json',
        'build/build-summary.json',
        'build/path-scan.json',
        'build/package-mtree/package-mtree.sha256',
        'build/lifecycle/corruption-qk.txt',
        'build/lifecycle/corruption-recovery-file.sha256',
        'build/lifecycle/corruption-recovery-summary.tsv',
        'build/lifecycle/corruption-recovery-imports.tsv',
        'build/lifecycle/corruption-recovery-pseudo-relocs.tsv',
        'build/lifecycle/input-snapshot.sha256',
        'build/lifecycle/input-snapshot.seal',
        'build/lifecycle/path-scan.json'
    )
    $privateDeterministic = [ordered]@{}
    foreach ($suffix in $deterministicSuffixes) {
        $matches = @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -File |
            Where-Object {
                (Get-RelativePath -Root $evidenceRoot -Path $_.FullName).
                    EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)
            })
        if ($matches.Count -ne 1) {
            throw "$Role deterministic evidence count for $suffix is $(
                $matches.Count)"
        }
        $privateDeterministic[$suffix] = (
            Get-FileHash -Algorithm SHA256 $matches[0].FullName
        ).Hash.ToLowerInvariant()
    }

    $nativeRoot = $extractPaths['MSYS-libuuid-native-attestation']
    $nativeSeals = @(Get-ChildItem -LiteralPath $nativeRoot -Recurse -File `
        -Filter 'evidence.seal')
    if ($nativeSeals.Count -ne 1) {
        throw "$Role native attestation is incomplete"
    }
    $nativeSeal = $nativeSeals[0]
    $sealedNativeRoot = Split-Path -Parent $nativeSeal.FullName
    if ([IO.Path]::GetFullPath($sealedNativeRoot) -ne
        [IO.Path]::GetFullPath($nativeRoot)) {
        throw "$Role native artifact root is not the sealed root"
    }
    $verifiedNativeSeal = Test-EvidenceSeal `
        -SealPath $nativeSeal.FullName
    $attestationPath = Get-Item -LiteralPath (
        Join-Path $sealedNativeRoot 'process-attestation.json')
    $modulePath = Get-Item -LiteralPath (
        Join-Path $sealedNativeRoot 'loaded-modules.tsv')
    $nativePathScanPath = Get-Item -LiteralPath (
        Join-Path $sealedNativeRoot 'path-scan.json')
    $nativePathScan = Get-Content `
        -LiteralPath $nativePathScanPath.FullName -Raw |
        ConvertFrom-Json
    if ($nativePathScan.scanner_sha256 -ne $script:expectedScannerSha256 -or
        $nativePathScan.result -ne 'pass' -or
        $nativePathScan.leak_count -ne 0 -or
        $nativePathScan.files_scanned -lt 1 -or
        $nativePathScan.files_enumerated -ne
            $nativePathScan.files_scanned) {
        throw "$Role native binary-safe path scan failed"
    }
    $attestation = Get-Content -LiteralPath $attestationPath.FullName -Raw |
        ConvertFrom-Json
    if ($attestation.admission -ne 'diagnostic-a527-runtime' -or
        @($attestation.processes).Count -ne 2) {
        throw "$Role native attestation status or process set is invalid"
    }
    foreach ($process in $attestation.processes) {
        if ($process.exit_code -ne 0 -or
            $process.is_wow64_process2.effective_machine -ne '0xaa64' -or
            $process.module_count -lt 3) {
            throw "$Role native process attestation failed"
        }
    }
    $moduleRows = @(Import-Csv -LiteralPath $modulePath.FullName `
        -Delimiter "`t")
    $nativeInputNames = @($attestation.native_inputs.PSObject.Properties.Name)
    $customModuleRecords = [Collections.Generic.List[object]]::new()
    $processSemantics = [Collections.Generic.List[object]]::new()
    foreach ($process in $attestation.processes) {
        $expectedModules = if ($process.name -eq 'libuuid-smoke.exe') {
            @(
                'libuuid-smoke.exe',
                'msys-2.0.dll',
                'msys-gcc_s-seh-1.dll',
                'msys-uuid-1.dll'
            )
        }
        elseif ($process.name -eq 'libuuid-static-smoke.exe') {
            @(
                'libuuid-static-smoke.exe',
                'msys-2.0.dll',
                'msys-gcc_s-seh-1.dll'
            )
        }
        else {
            throw "$Role attests an unexpected process: $($process.name)"
        }
        $customRows = @($moduleRows | Where-Object {
            $_.process -eq $process.name -and
            $_.module -in $nativeInputNames
        })
        if ((@($customRows.module | Sort-Object) -join "`n") -ne
            (@($expectedModules | Sort-Object) -join "`n")) {
            throw "$Role custom module set is wrong for $($process.name)"
        }
        foreach ($moduleName in $expectedModules) {
            $rows = @($customRows | Where-Object {
                $_.module -eq $moduleName
            })
            $hashProperty =
                $attestation.native_inputs.PSObject.Properties[$moduleName]
            if (-not $hashProperty) {
                throw "$Role native input hash is missing: $moduleName"
            }
            $expectedHash = $hashProperty.Value
            if ($rows.Count -ne 1 -or
                $rows[0].machine -ne '0xaa64' -or
                $rows[0].sha256 -ne $expectedHash) {
                throw "$Role module identity is wrong: $(
                    $process.name)/$moduleName"
            }
            $customModuleRecords.Add([ordered]@{
                process = $process.name
                module = $moduleName
                machine = $rows[0].machine
                sha256 = $rows[0].sha256
            })
        }
        $processSemantics.Add([ordered]@{
            name = $process.name
            exit_code = $process.exit_code
            is_wow64_process2 = $process.is_wow64_process2
        })
    }

    return [ordered]@{
        role = $Role
        run_id = $RunId
        event = $run.event
        head_sha = $run.head_sha
        html_url = $run.html_url
        artifacts = @($artifactRecords)
        packages = $packageRecords
        private_evidence_seals = $privateSeals
        private_deterministic = $privateDeterministic
        native_evidence_seal = [ordered]@{
            sha256 = $verifiedNativeSeal.seal_sha256
            manifest_sha256 = $verifiedNativeSeal.manifest_sha256
            value = $verifiedNativeSeal.value
        }
        process_attestation_sha256 = (
            Get-FileHash -Algorithm SHA256 $attestationPath.FullName
        ).Hash.ToLowerInvariant()
        loaded_modules_sha256 = (
            Get-FileHash -Algorithm SHA256 $modulePath.FullName
        ).Hash.ToLowerInvariant()
        native_semantics = [ordered]@{
            controller = $attestation.controller
            processes = @($processSemantics)
            native_inputs = $attestation.native_inputs
            scanner_tools = $attestation.scanner_tools
            custom_modules = @($customModuleRecords | Sort-Object process, module)
            path_scan = [ordered]@{
                scanner_sha256 = $nativePathScan.scanner_sha256
                files_enumerated = $nativePathScan.files_enumerated
                files_scanned = $nativePathScan.files_scanned
                leak_count = $nativePathScan.leak_count
                result = $nativePathScan.result
                encodings = $nativePathScan.encodings
            }
        }
    }
}

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$scratch = Join-Path $OutputDirectory '.scratch'
New-Item -ItemType Directory -Path $scratch | Out-Null

$push = Get-RunBundle `
    -Role 'push' `
    -RunId $PushRunId `
    -ExpectedEvent 'push' `
    -ScratchRoot $scratch
$pullRequest = Get-RunBundle `
    -Role 'pull-request' `
    -RunId $PullRequestRunId `
    -ExpectedEvent 'pull_request' `
    -ScratchRoot $scratch

if (($push.packages | ConvertTo-Json -Compress -Depth 5) -ne
    ($pullRequest.packages | ConvertTo-Json -Compress -Depth 5)) {
    throw 'Push and pull-request package files are not byte-identical'
}
if (($push.private_deterministic | ConvertTo-Json -Compress -Depth 5) -ne
    ($pullRequest.private_deterministic |
        ConvertTo-Json -Compress -Depth 5)) {
    throw 'Push and pull-request deterministic private evidence differs'
}
if (($push.native_semantics | ConvertTo-Json -Compress -Depth 10) -ne
    ($pullRequest.native_semantics | ConvertTo-Json -Compress -Depth 10)) {
    throw 'Push and pull-request native process/module semantics differ'
}

$equality = [ordered]@{
    schema = 1
    repository = $repository
    expected_head_sha = $ExpectedHeadSha
    packages_byte_identical = $true
    package_mtree_byte_identical = $true
    deterministic_private_evidence_equal = $true
    native_process_module_semantics_equal = $true
    packages = $push.packages
    runs = @($push, $pullRequest)
}
$equalityPath = Join-Path $OutputDirectory 'cross-run-equality.json'
[IO.File]::WriteAllText(
    $equalityPath,
    ($equality | ConvertTo-Json -Depth 10),
    [Text.UTF8Encoding]::new($false))

Remove-Item -LiteralPath $scratch -Recurse -Force
& $scannerPath -SelfTest
& $scannerPath `
    -Paths @($OutputDirectory) `
    -ForbiddenPaths @() `
    -OutputPath (Join-Path $OutputDirectory 'release-path-scan.json')
$manifestPath = Join-Path $OutputDirectory 'evidence-manifest.sha256'
$sealPath = Join-Path $OutputDirectory 'evidence.seal'
$manifest = Get-ChildItem -LiteralPath $OutputDirectory -File |
    Where-Object { $_.FullName -notin @($manifestPath, $sealPath) } |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).
            Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
Write-Utf8NoBom -Path $manifestPath -Lines @($manifest)
$seal = (Get-FileHash -Algorithm SHA256 $manifestPath).
    Hash.ToLowerInvariant()
Write-Utf8NoBom -Path $sealPath `
    -Lines @("$seal  evidence-manifest.sha256")

$equality

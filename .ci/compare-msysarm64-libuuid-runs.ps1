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
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
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
    $packageRecords = @($packages | ForEach-Object {
        [ordered]@{
            name = $_.Name
            size = $_.Length
            sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).
                Hash.ToLowerInvariant()
        }
    })

    $evidenceRoot = $extractPaths['MSYS-libuuid-private-evidence']
    $pathScans = @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -File `
        -Filter 'path-scan.tsv')
    if ($pathScans.Count -lt 3) {
        throw "$Role private evidence is missing zero-leak reports"
    }
    foreach ($scan in $pathScans) {
        if ((Get-Content -LiteralPath $scan.FullName -Raw).Trim() -ne
            "private-path-leaks`t0") {
            throw "$Role private evidence contains a failed path scan"
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
    $privateSeals = @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -File `
        -Filter 'evidence.seal' | Sort-Object FullName | ForEach-Object {
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
    if ($privateSeals.Count -lt 3) {
        throw "$Role private evidence is missing component seals"
    }
    $deterministicSuffixes = @(
        'root/base-input.sha256',
        'root/host-packages.sha256',
        'root/target-packages.sha256',
        'root/source-inputs.sha256',
        'root/package-state.txt',
        'root/root-summary.json',
        'build/build-summary.json',
        'build/lifecycle/input-snapshot.sha256'
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
    $attestationPaths = @(Get-ChildItem -LiteralPath $nativeRoot -Recurse `
        -File -Filter 'process-attestation.json')
    $modulePaths = @(Get-ChildItem -LiteralPath $nativeRoot -Recurse -File `
        -Filter 'loaded-modules.tsv')
    if ($nativeSeals.Count -ne 1 -or
        $attestationPaths.Count -ne 1 -or
        $modulePaths.Count -ne 1) {
        throw "$Role native attestation is incomplete"
    }
    $nativeSeal = $nativeSeals[0]
    $verifiedNativeSeal = Test-EvidenceSeal `
        -SealPath $nativeSeal.FullName
    $attestationPath = $attestationPaths[0]
    $modulePath = $modulePaths[0]
    $attestation = Get-Content -LiteralPath $attestationPath.FullName -Raw |
        ConvertFrom-Json
    if (@($attestation.processes).Count -ne 2) {
        throw "$Role native attestation does not contain two processes"
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

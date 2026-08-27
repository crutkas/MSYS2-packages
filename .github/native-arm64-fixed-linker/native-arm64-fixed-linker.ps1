[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsysRoot,
    [Parameter(Mandatory = $true)][string] $CandidateDirectory,
    [Parameter(Mandatory = $true)][string] $ReportRoot,
    [Parameter(Mandatory = $true)][string] $AdmissionPath,
    [Parameter(Mandatory = $true)][string] $BaselinePath,
    [Parameter(Mandatory = $true)][string] $ExpectedHeadSha,
    [Parameter(Mandatory = $true)][long] $GitHubRunId,
    [string] $GitHubToken = $env:GITHUB_TOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-Sha256([string] $Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-File([string] $Path, [long] $Bytes, [string] $Sha256) {
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Bytes) { throw "Size mismatch for $($item.Name): $($item.Length) != $Bytes" }
    $actual = Get-Sha256 $Path
    if ($actual -ne $Sha256) { throw "SHA-256 mismatch for $($item.Name): $actual != $Sha256" }
}

function Invoke-External([string] $FilePath, [string[]] $Arguments, [string] $Group) {
    Write-Host "::group::$Group"
    try { & $FilePath @Arguments; $code = $LASTEXITCODE }
    finally { Write-Host '::endgroup::' }
    if ($code -ne 0) { throw "$Group failed with exit code $code" }
}

function Read-PackageInfo([string] $Bsdtar, [string] $Package) {
    $lines = @(& $Bsdtar -xOf $Package .PKGINFO)
    if ($LASTEXITCODE -ne 0) { throw "Could not read .PKGINFO from $Package" }
    $values = @{}
    foreach ($line in $lines) {
        if ($line -match '^([^ ]+) = (.*)$' -and -not $values.ContainsKey($Matches[1])) {
            $values[$Matches[1]] = $Matches[2]
        }
    }
    foreach ($key in @('pkgname', 'pkgver', 'arch')) {
        if (-not $values.ContainsKey($key)) { throw "Missing $key in $Package .PKGINFO" }
    }
    $values
}

function Get-PeMachine([string] $Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Not an MZ image: $Path" }
        [void]$stream.Seek(0x3c, [IO.SeekOrigin]::Begin)
        [void]$stream.Seek($reader.ReadInt32(), [IO.SeekOrigin]::Begin)
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Not a PE image: $Path" }
        $reader.ReadUInt16()
    }
    finally { $reader.Dispose(); $stream.Dispose() }
}

function Get-MsysPath([string] $Cygpath, [string] $Path) {
    $value = & $Cygpath -u $Path
    if ($LASTEXITCODE -ne 0) { throw "cygpath failed for $Path" }
    ($value | Select-Object -Last 1).Trim()
}

if (-not $GitHubToken) { throw 'GITHUB_TOKEN is required' }
if ($ExpectedHeadSha -notmatch '^[0-9a-f]{40}$') { throw "Invalid expected head SHA: $ExpectedHeadSha" }
$MsysRoot = [IO.Path]::GetFullPath($MsysRoot)
$CandidateDirectory = [IO.Path]::GetFullPath($CandidateDirectory)
$ReportRoot = [IO.Path]::GetFullPath($ReportRoot)
$AdmissionPath = [IO.Path]::GetFullPath($AdmissionPath)
$BaselinePath = [IO.Path]::GetFullPath($BaselinePath)
if (-not (Test-Path $MsysRoot -PathType Container)) { throw "Missing MSYS2 root: $MsysRoot" }
if (-not (Test-Path $CandidateDirectory -PathType Container)) { throw "Missing candidate artifact: $CandidateDirectory" }
if (-not (Test-Path $AdmissionPath -PathType Leaf)) { throw "Execution closed: missing exact admission file $AdmissionPath" }
if (-not (Test-Path $BaselinePath -PathType Leaf)) { throw "Missing baseline profile: $BaselinePath" }
if (Test-Path $ReportRoot) { throw "Report root must be fresh: $ReportRoot" }
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
Start-Transcript -Path (Join-Path $ReportRoot 'powershell-transcript.txt') | Out-Null

$primaryError = $null
$rollbackError = $null
$rollbackPending = $false
$pacman = Join-Path $MsysRoot 'usr\bin\pacman.exe'
$bsdtar = Join-Path $MsysRoot 'usr\bin\bsdtar.exe'
$baselineBinutilsPath = $null
$baselineLdHash = $null

try {
  try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeArch {
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
}
"@
    [uint16]$processMachine = 0; [uint16]$nativeMachine = 0
    if (-not [NativeArch]::IsWow64Process2([Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$processMachine, [ref]$nativeMachine)) {
        throw "IsWow64Process2 failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($nativeMachine -ne 0xaa64 -or $osArch -ne 'Arm64') {
        throw "Native ARM64 required: native=$('0x{0:x4}' -f $nativeMachine), OS=$osArch"
    }
    [ordered]@{ PROCESSOR_ARCHITECTURE=$env:PROCESSOR_ARCHITECTURE; process_machine=('0x{0:x4}' -f $processMachine); native_machine=('0x{0:x4}' -f $nativeMachine); os_architecture=$osArch } |
      ConvertTo-Json | Set-Content (Join-Path $ReportRoot 'host-architecture.json')

    $baselineHash = Get-Sha256 $BaselinePath
    $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    if ($baseline.schema -ne 1 -or $baseline.profile -ne 'pr18-immutable-a527-gcc13-support-v1') { throw 'Invalid baseline profile identity' }
    $admissionHash = Get-Sha256 $AdmissionPath
    if ($admissionHash -ne '4c44f7570689403ab46e25791c090fd82d340fd15e3d9f0a2329a24a1cd15fd4') { throw "Admission file hash mismatch: $admissionHash" }
    $admission = Get-Content $AdmissionPath -Raw | ConvertFrom-Json
    if ($baselineHash -ne 'ee285341b4920407e96965e82ab95f173d4b0027bf3ad6976aaadad4a95cd922') { throw 'Baseline profile hash mismatch' }
    if ($admission.schema -ne 1 -or $admission.decision -ne 'ADMIT_EXACT_FIXED_BINUTILS_NATIVE_EXECUTION') { throw 'Invalid admission decision' }
    if ($admission.scope.repository -ne 'crutkas/MSYS2-packages' -or $admission.scope.package_pr -ne 21 -or $admission.scope.package_head -ne $ExpectedHeadSha -or $admission.scope.package_run_id -ne $GitHubRunId -or $admission.scope.package_run_id -ne 33044771291 -or $admission.scope.package_job_id -ne 98426220391 -or $admission.scope.package_run_conclusion -ne 'success' -or $admission.scope.artifact_id -ne 9635492584 -or $admission.scope.artifact_name -ne 'fixed-aarch64-binutils-candidate' -or $admission.scope.artifact_bytes -ne 6713122 -or $admission.scope.artifact_sha256 -ne '2ae2aa00528a7e4db2954b2fda85d800216292a1b6a1c4423a10ff3c9c57ca76') { throw 'Package run/artifact admission mismatch' }
    if ($admission.candidate.package -ne 'mingw-w64-cross-cygwinarm64-binutils' -or $admission.candidate.version -ne '2.44.50-2' -or $admission.candidate.filename -ne 'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst' -or $admission.candidate.bytes -ne 6545114 -or $admission.candidate.sha256 -ne '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b' -or $admission.candidate.linker_path -ne '/opt/bin/aarch64-pc-cygwin-ld.exe' -or $admission.candidate.linker_bytes -ne 1887140 -or $admission.candidate.linker_sha256 -ne '075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f') { throw 'Candidate admission mismatch' }
    if ($admission.source.repository -ne 'crutkas/binutils-woarm64' -or $admission.source.commit -ne '3f05fc4d3e0eeab265f2157e3257a7067b6e7223' -or $admission.source.tree -ne 'ecca625d45883e13128283a8c1750dac7997f729' -or $admission.source.archive_bytes -ne 66204943 -or $admission.source.archive_sha256 -ne 'd11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e' -or $admission.source.handoff_sha256 -ne '2e49f41fe87318294a48369958880abd9457571ebbcb9393eef0f1261f8f0a3f' -or $admission.source.design_review_sha256 -ne '43ef9b9a1331d96304c1b232e6adf3b89fc3ccb1a6e71ea56390cd4368c50a58') { throw 'Source admission mismatch' }
    if ($admission.evidence.independent_audit_zip_sha256 -ne '38747a44178b4f973fd97e87474ca1f55dc0d4e19f19c0242d254fc2e85c815e' -or $admission.evidence.independent_audit_json_sha256 -ne 'e17fc2515c8add5284265b8338e5a50c4449836ef02d8e3f6737477edbccdd2b' -or -not $admission.verified.flags_12_21_absent -or $admission.execution_contract.runner -ne 'windows-11-arm' -or $admission.execution_contract.replace_only -ne 'mingw-w64-cross-cygwinarm64-binutils' -or -not $admission.execution_contract.relink_all -or -not $admission.execution_contract.scan_before_execution -or -not $admission.execution_contract.rollback_in_finally -or -not $admission.execution_contract.preserve_pr18) { throw 'Execution contract mismatch' }

    $headers = @{ Accept='application/vnd.github+json'; Authorization="Bearer $GitHubToken"; 'User-Agent'='native-arm64-fixed-linker'; 'X-GitHub-Api-Version'='2022-11-28' }
    $packageRun = Invoke-RestMethod -Headers $headers -Uri 'https://api.github.com/repos/crutkas/MSYS2-packages/actions/runs/33044771291'
    if ($packageRun.status -ne 'completed' -or $packageRun.conclusion -ne 'success' -or $packageRun.head_sha -ne $ExpectedHeadSha -or $packageRun.html_url -ne 'https://github.com/crutkas/MSYS2-packages/actions/runs/33044771291') { throw 'Live package run admission failed' }
    $packageArtifact = Invoke-RestMethod -Headers $headers -Uri 'https://api.github.com/repos/crutkas/MSYS2-packages/actions/artifacts/9635492584'
    if ($packageArtifact.id -ne 9635492584 -or $packageArtifact.name -ne 'fixed-aarch64-binutils-candidate' -or $packageArtifact.expired -or $packageArtifact.size_in_bytes -ne 6713122 -or $packageArtifact.digest -ne 'sha256:2ae2aa00528a7e4db2954b2fda85d800216292a1b6a1c4423a10ff3c9c57ca76' -or $packageArtifact.workflow_run.id -ne 33044771291 -or $packageArtifact.workflow_run.head_sha -ne $ExpectedHeadSha) { throw 'Live package artifact admission failed' }
    $sourceCommit = Invoke-RestMethod -Headers $headers -Uri 'https://api.github.com/repos/crutkas/binutils-woarm64/commits/3f05fc4d3e0eeab265f2157e3257a7067b6e7223'
    if ($sourceCommit.sha -ne $admission.source.commit -or $sourceCommit.commit.tree.sha -ne $admission.source.tree) { throw 'Live source commit admission failed' }

    $matchingCandidates = @(
        foreach ($file in Get-ChildItem $CandidateDirectory -Recurse -File -Filter '*.pkg.tar.zst') {
            $info = Read-PackageInfo $bsdtar $file.FullName
            if ($info.pkgname -eq $admission.candidate.package) {
                [pscustomobject]@{ File = $file; Info = $info }
            }
        }
    )
    if ($matchingCandidates.Count -ne 1) { throw "Expected exactly one admitted binutils package, got $($matchingCandidates.Count)" }
    $candidate = $matchingCandidates[0].File
    $candidateInfo = $matchingCandidates[0].Info
    if ($candidateInfo.pkgname -ne $admission.candidate.package -or $candidateInfo.pkgver -ne $admission.candidate.version -or $candidateInfo.arch -ne 'x86_64') { throw 'Candidate .PKGINFO does not match admission' }
    $expectedName = $admission.candidate.filename
    if ($candidate.Name -ne $expectedName) { throw "Candidate filename mismatch: $($candidate.Name) != $expectedName" }
    Assert-File $candidate.FullName ([long]$admission.candidate.bytes) $admission.candidate.sha256
    $candidateIdentity = [ordered]@{ schema=1; admitted=$true; package_run_id=$GitHubRunId; package_head=$ExpectedHeadSha; artifact_id=$admission.scope.artifact_id; artifact_sha256=$admission.scope.artifact_sha256; package=$candidateInfo.pkgname; version=$candidateInfo.pkgver; filename=$candidate.Name; bytes=$candidate.Length; sha256=(Get-Sha256 $candidate.FullName); source_repository=$admission.source.repository; source_commit=$admission.source.commit; source_tree=$admission.source.tree; source_archive_sha256=$admission.source.archive_sha256; admission_sha256=$admissionHash }
    $candidateIdentity | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ReportRoot 'candidate-manifest.json')
    Copy-Item $AdmissionPath (Join-Path $ReportRoot 'admission.json')
    Copy-Item $BaselinePath (Join-Path $ReportRoot 'baseline.json')
    Copy-Item $candidate.FullName (Join-Path $ReportRoot $candidate.Name)

    $downloadRoot = Join-Path $env:RUNNER_TEMP "fixed-linker-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $downloadRoot | Out-Null
    $assetPaths = @{}
    $downloadEvidence = [Collections.Generic.List[object]]::new()
    foreach ($asset in $baseline.assets) {
        $destination = Join-Path $downloadRoot $asset.filename
        Invoke-WebRequest -Uri $asset.url -OutFile $destination
        Assert-File $destination ([long]$asset.bytes) $asset.sha256
        $info = Read-PackageInfo $bsdtar $destination
        if ($info.pkgname -ne $asset.package -or $info.pkgver -ne $asset.version -or $info.arch -ne 'x86_64') { throw "Baseline .PKGINFO mismatch: $($asset.filename)" }
        $assetPaths[$asset.package] = $destination
        $downloadEvidence.Add([ordered]@{ package=$asset.package; version=$asset.version; filename=$asset.filename; bytes=[long]$asset.bytes; sha256=$asset.sha256; url=$asset.url; role=$asset.role })
    }
    $downloadEvidence | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ReportRoot 'baseline-downloads.json')

    $baselineBinutilsPath = $assetPaths['mingw-w64-cross-cygwinarm64-binutils']
    $baselineExtract = Join-Path $downloadRoot 'baseline-extract'
    $candidateExtract = Join-Path $downloadRoot 'candidate-extract'
    New-Item -ItemType Directory -Path $baselineExtract,$candidateExtract | Out-Null
    $linkerMembers = @('opt/aarch64-pc-cygwin/bin/ld.bfd.exe','opt/bin/aarch64-pc-cygwin-ld.exe')
    Invoke-External $bsdtar (@('-xf',$baselineBinutilsPath,'-C',$baselineExtract) + $linkerMembers) 'Extract baseline linker'
    Invoke-External $bsdtar (@('-xf',$candidate.FullName,'-C',$candidateExtract) + $linkerMembers) 'Extract candidate linker'
    $baselineLdTarget = Join-Path $baselineExtract 'opt\aarch64-pc-cygwin\bin\ld.bfd.exe'
    $baselineLdPublic = Join-Path $baselineExtract 'opt\bin\aarch64-pc-cygwin-ld.exe'
    $candidateLdTarget = Join-Path $candidateExtract 'opt\aarch64-pc-cygwin\bin\ld.bfd.exe'
    $candidateLdPublic = Join-Path $candidateExtract 'opt\bin\aarch64-pc-cygwin-ld.exe'
    $baselineLdHash = Get-Sha256 $baselineLdTarget
    $candidateLdHash = Get-Sha256 $candidateLdTarget
    if ((Get-Sha256 $baselineLdPublic) -ne $baselineLdHash -or (Get-Sha256 $candidateLdPublic) -ne $candidateLdHash) { throw 'Linker public/target hardlink bytes differ' }
    if ((Get-Item $candidateLdTarget).Length -ne $admission.candidate.linker_bytes -or $candidateLdHash -ne $admission.candidate.linker_sha256) { throw 'Extracted candidate linker identity mismatch' }
    if ($baselineLdHash -eq $candidateLdHash) { throw 'Candidate linker is byte-identical to immutable baseline' }

    if ((Test-Path (Join-Path $MsysRoot 'opt\aarch64-pc-cygwin')) -or (Test-Path (Join-Path $MsysRoot 'opt\aarch64-pc-msys'))) { throw 'MSYS2 target prefixes are not fresh' }
    $env:MSYS='winsymlinks:sys'; $env:MSYSTEM='MSYS'
    function Install-Paths([string]$Name,[string[]]$Paths) { Invoke-External $pacman (@('--noconfirm','--noprogressbar','-U') + $Paths) $Name }
    $bootstrapOrder = @('mingw-w64-cross-cygwinarm64-headers','mingw-w64-cross-cygwinarm64-windows-default-manifest','mingw-w64-cross-cygwinarm64-sysroot','mingw-w64-cross-cygwinarm64-w32api-runtime','mingw-w64-cross-cygwinarm64-gcc-stage1','mingw-w64-cross-cygwinarm64-gcc-libs-stage1','mingw-w64-cross-cygwinarm64-libstdc++-headers')
    Install-Paths 'Install candidate binutils/bootstrap atomically' (@($candidate.FullName) + @($bootstrapOrder | ForEach-Object { $assetPaths[$_] }))
    $rollbackPending = $true
    $installedCandidateLd = Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-ld.exe'
    if ((Get-Sha256 $installedCandidateLd) -ne $candidateLdHash) { throw 'Installed candidate linker hash mismatch' }
    [ordered]@{ baseline_ld_sha256=$baselineLdHash; candidate_ld_sha256=$candidateLdHash; installed_candidate_ld_sha256=(Get-Sha256 $installedCandidateLd) } | ConvertTo-Json | Set-Content (Join-Path $ReportRoot 'linker-identities.json')

    $runtimeOrder = @('mingw-w64-cross-msysarm64-headers','mingw-w64-cross-msysarm64-windows-default-manifest','mingw-w64-cross-msysarm64-sysroot','mingw-w64-cross-msysarm64-w32api-runtime','mingw-w64-cross-msysarm64-runtime','mingw-w64-cross-msysarm64-runtime-devel','mingw-w64-cross-msysarm64-libstdc++-headers')
    Install-Paths 'Install immutable a527 runtime/support atomically' @($runtimeOrder | ForEach-Object { $assetPaths[$_] })
    Install-Paths 'Install immutable GCC atomically' @($assetPaths['mingw-w64-cross-msysarm64-gcc-libs'],$assetPaths['mingw-w64-cross-msysarm64-gcc'])

    $bash = Join-Path $MsysRoot 'usr\bin\bash.exe'; $cygpath = Join-Path $MsysRoot 'usr\bin\cygpath.exe'
    $env:CANDIDATE_BINUTILS_VERSION = $candidateInfo.pkgver
    $env:CANDIDATE_LD_SHA256 = $candidateLdHash
    $harness = Get-MsysPath $cygpath (Join-Path $PSScriptRoot 'native-arm64-fixed-linker.sh')
    $reportUnix = Get-MsysPath $cygpath $ReportRoot
        Invoke-External $bash @('--noprofile','--norc',$harness,$reportUnix) 'Relink and audit with candidate binutils'

    $scannerBundle = Join-Path $PSScriptRoot 'pseudo-reloc-decoder-v2.zip'
    if ((Get-Sha256 $scannerBundle) -ne '774dc88b490589fdf8a551834b1fb772e6465926b5c0aa7cf4bf31dcefa08c9f') { throw 'Hardened scanner V2 bundle hash mismatch' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $scanner = Join-Path $ReportRoot 'check-aarch64-pseudo-relocs.ps1'
    $scannerArchive = [IO.Compression.ZipFile]::OpenRead($scannerBundle)
    try {
        $entries = @($scannerArchive.Entries | Where-Object { $_.FullName -eq 'pseudo-reloc-decoder-v2/check-aarch64-pseudo-relocs.ps1' })
        if ($entries.Count -ne 1) { throw "Expected one hardened scanner entry, got $($entries.Count)" }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $scanner, $false)
    }
    finally { $scannerArchive.Dispose() }
    if ((Get-Sha256 $scanner) -ne '9d086e655a8636e733c96a8c514942bc249dd60218fa496507c390110867d201') { throw 'Hardened scanner V2 checker hash mismatch' }
    [ordered]@{ bundle_sha256=(Get-Sha256 $scannerBundle); checker_sha256=(Get-Sha256 $scanner); independent_review_sha256=$admission.source.design_review_sha256 } | ConvertTo-Json | Set-Content (Join-Path $ReportRoot 'scanner-v2-identities.json')
    $env:PATH = "$(Join-Path $MsysRoot 'usr\bin');$(Join-Path $MsysRoot 'opt\bin');$env:PATH"
    $scannerRoot = Join-Path $ReportRoot 'scanner-v2'
    New-Item -ItemType Directory -Path $scannerRoot | Out-Null
    $scannerSummary = @()
    foreach ($file in Get-ChildItem (Join-Path $ReportRoot 'binaries') -File | Where-Object { $_.Extension -in @('.exe','.dll') }) {
        $output = Join-Path $scannerRoot "$($file.Name).json"
        & (Get-Process -Id $PID).Path -NoProfile -File $scanner -PePath $file.FullName -OutputPath $output -Objdump (Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-objdump.exe') -Nm (Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-nm.exe')
        $scannerExit = $LASTEXITCODE
        $finding = Get-Content $output -Raw | ConvertFrom-Json
        if ($scannerExit -ne 0 -or $finding.result -ne 'pass' -or @($finding.policy_violations).Count -ne 0 -or @($finding.flags | Where-Object { [int]$_ -ne 64 }).Count -ne 0) {
            throw "Hardened scanner rejected $($file.Name): exit=$scannerExit result=$($finding.result) flags=$(@($finding.flags) -join ',')"
        }
        $scannerSummary += [ordered]@{ name=$file.Name; sha256=(Get-Sha256 $file.FullName); table_present=$finding.table_present; record_count=$finding.record_count; flags=@($finding.flags); result=$finding.result }
    }
    $scannerSummary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ReportRoot 'scanner-v2-summary.json')

    $nativeRun = Join-Path $ReportRoot 'native-run'; New-Item -ItemType Directory -Path $nativeRun | Out-Null
    $expectations = [ordered]@{}
    foreach ($line in Get-Content (Join-Path $ReportRoot 'native-binaries.tsv')) {
        $parts = $line -split "`t",2; if ($parts.Count -ne 2) { throw "Invalid native expectation: $line" }; $expectations[$parts[0]]=$parts[1]
    }
    foreach ($name in $expectations.Keys) { Copy-Item (Join-Path $ReportRoot "binaries\$name") $nativeRun }
    foreach ($name in @('aarch64-near-import.dll','aarch64-far-import.dll')) { Copy-Item (Join-Path $ReportRoot "binaries\$name") $nativeRun }
    foreach ($dll in @((Join-Path $MsysRoot 'opt\aarch64-pc-msys\bin\msys-2.0.dll'),(Join-Path $MsysRoot 'opt\lib\gcc\aarch64-pc-msys\msys-gcc_s-seh-1.dll'),(Join-Path $MsysRoot 'opt\lib\gcc\aarch64-pc-msys\15.0.1\msys-stdc++-6.dll'))) { Copy-Item $dll $nativeRun }
    $peEvidence = foreach ($file in Get-ChildItem $nativeRun -File | Where-Object {$_.Extension -in @('.exe','.dll')}) {
        $machine=Get-PeMachine $file.FullName; if($machine-ne0xaa64){throw "Non-AA64 payload: $($file.Name)"}; [ordered]@{name=$file.Name;machine='0xaa64';sha256=(Get-Sha256 $file.FullName)}
    }
    $peEvidence | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ReportRoot 'native-pe-evidence.json')
    Push-Location $nativeRun
    try {
        foreach ($entry in $expectations.GetEnumerator()) {
            $output=@(& (Join-Path $nativeRun $entry.Key) 2>&1); $code=$LASTEXITCODE
            $output | ForEach-Object {$_.ToString()} | Set-Content (Join-Path $ReportRoot "$($entry.Key).stdout.txt")
            $output | ForEach-Object {Write-Host $_}
            if($code-ne0){throw "$($entry.Key) failed natively with exit code $code"}
            if(@($output|ForEach-Object{$_.ToString()}) -notcontains $entry.Value){throw "$($entry.Key) missing marker $($entry.Value)"}
        }
    }
    finally { Pop-Location }
    @('candidate-linker-installed-and-traced','zero-pseudo-flags-12-or-21','immutable-a527-runtime','immutable-gcc','dynamic-cxx-thread-constinit','far-map','process','lto','native-result=success') | Set-Content (Join-Path $ReportRoot 'candidate-result.txt')
  }
  catch { $primaryError = $_ }
}
finally {
  if ($rollbackPending) {
    try {
      $env:MSYS='winsymlinks:sys'; $env:MSYSTEM='MSYS'
      Invoke-External $pacman @('--noconfirm','--noprogressbar','-U',$baselineBinutilsPath) 'Rollback immutable binutils'
      $actual = @(& $pacman -Q mingw-w64-cross-cygwinarm64-binutils)
      if ($LASTEXITCODE -ne 0 -or $actual -ne 'mingw-w64-cross-cygwinarm64-binutils 2.44.50-1') { throw "Rollback package identity failed: $actual" }
      $installedLd = Join-Path $MsysRoot 'opt\bin\aarch64-pc-cygwin-ld.exe'
      if ((Get-Sha256 $installedLd) -ne $baselineLdHash) { throw 'Rollback linker hash mismatch' }
      foreach ($tool in @('addr2line','ar','as','c++filt','dlltool','dllwrap','elfedit','gprof','ld','ld.bfd','nm','objcopy','objdump','ranlib','readelf','size','strings','strip','windmc','windres')) {
          $alias = Join-Path $MsysRoot "opt\bin\aarch64-pc-msys-$tool.exe"
          if (Test-Path $alias) { throw "Candidate public alias survived rollback: $alias" }
      }
      & $pacman -T -- 'mingw-w64-cross-cygwinarm64-binutils>=2.44.50' 'mingw-w64-cross-cygwinarm64-gcc-stage1=15.0.1dev-2' 'mingw-w64-cross-msysarm64-gcc=15.0.1dev-1' > (Join-Path $ReportRoot 'rollback-missing-dependencies.txt')
      if ($LASTEXITCODE -ne 0 -or (Get-Item (Join-Path $ReportRoot 'rollback-missing-dependencies.txt')).Length -ne 0) { throw 'Rollback reverse dependency proof failed' }
      'rollback=success' | Set-Content (Join-Path $ReportRoot 'rollback-result.txt')
    }
    catch { $rollbackError = $_; "rollback=failure`n$($_ | Out-String)" | Set-Content (Join-Path $ReportRoot 'rollback-result.txt') }
  }
  Stop-Transcript | Out-Null
}
if ($rollbackError -and $primaryError) { throw "Validation failed: $($primaryError.Exception.Message); rollback also failed: $($rollbackError.Exception.Message)" }
if ($rollbackError) { throw $rollbackError }
if ($primaryError) { throw $primaryError }

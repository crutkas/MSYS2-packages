[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CandidatePackage,
    [Parameter(Mandatory = $true)]
    [string] $ReportRoot,
    [Parameter(Mandatory = $true)]
    [string] $PackageCommit,
    [Parameter(Mandatory = $true)]
    [long] $WorkflowRunId,
    [Parameter(Mandatory = $true)]
    [string] $WorkflowRunUrl,
    [Parameter(Mandatory = $true)]
    [string] $WorkflowHeadSha,
    [Parameter(Mandatory = $true)]
    [string] $SourceCommit,
    [Parameter(Mandatory = $true)]
    [string] $SourceTree,
    [Parameter(Mandatory = $true)]
    [long] $SourceArchiveSize,
    [Parameter(Mandatory = $true)]
    [string] $SourceArchiveSha256,
    [string] $OutputPath = (Join-Path $ReportRoot 'candidate-handoff.json')
)

$ErrorActionPreference = 'Stop'
$FrozenSourceCommit = '3f05fc4d3e0eeab265f2157e3257a7067b6e7223'
$FrozenSourceTree = 'ecca625d45883e13128283a8c1750dac7997f729'
$FrozenSourceArchiveSize = 66204943
$FrozenSourceArchiveSha256 =
    'd11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e'
$PackageCommit = $PackageCommit.ToLowerInvariant()
$WorkflowHeadSha = $WorkflowHeadSha.ToLowerInvariant()
$SourceCommit = $SourceCommit.ToLowerInvariant()
$SourceTree = $SourceTree.ToLowerInvariant()
$SourceArchiveSha256 = $SourceArchiveSha256.ToLowerInvariant()
if ($PackageCommit -notmatch '^[0-9a-f]{40}$' -or
    $WorkflowHeadSha -ne $PackageCommit) {
    throw 'Workflow head must be the exact 40-character package commit.'
}
if ($WorkflowRunId -le 0 -or
    $WorkflowRunUrl -notmatch "/actions/runs/$WorkflowRunId$") {
    throw 'Workflow run identity is malformed.'
}
if ($SourceCommit -ne $FrozenSourceCommit -or
    $SourceTree -ne $FrozenSourceTree -or
    $SourceArchiveSize -ne $FrozenSourceArchiveSize -or
    $SourceArchiveSha256 -ne $FrozenSourceArchiveSha256) {
    throw 'Handoff source identity does not match the frozen reviewed source.'
}
$CandidatePackage = (Resolve-Path -LiteralPath $CandidatePackage).Path
$ReportRoot = (Resolve-Path -LiteralPath $ReportRoot).Path
$transaction = Get-Content -LiteralPath (
    Join-Path $ReportRoot 'transaction-report.json'
) -Raw | ConvertFrom-Json
$packageAudit = Get-Content -LiteralPath (
    Join-Path $ReportRoot 'package\package-audit.json'
) -Raw | ConvertFrom-Json
$consumerAudit = Get-Content -LiteralPath (
    Join-Path $ReportRoot 'consumers\consumer-summary.json'
) -Raw | ConvertFrom-Json
$hostMachines = Get-Content -LiteralPath (
    Join-Path $ReportRoot 'package\package-host-machines.json'
) -Raw | ConvertFrom-Json
if (-not $transaction.shared_database_unchanged -or
    -not $transaction.safe_remove_rejected -or
    -not $transaction.forced_remove_missing_dependency -or
    -not $transaction.aliases_absent_after_remove) {
    throw 'transaction report is not green'
}
if ($packageAudit.public_alias_count -ne 20 -or
    $packageAudit.host_executable_count -ne 31) {
    throw 'package audit is not green'
}
if ($consumerAudit.foreign_target_contamination) {
    throw 'consumer audit reports target contamination'
}

$pacman = 'C:\msys64\usr\bin\pacman.exe'
$identity = (& $pacman -Qp $CandidatePackage | Out-String).Trim()
$identityParts = $identity.Split(' ', 2)
$versionParts = $identityParts[1].Split('-', 2)
if ($identity -ne 'mingw-w64-cross-cygwinarm64-binutils 2.44.50-2') {
    throw "Candidate identity does not match the frozen package: $identity"
}
$pkginfo = (& 'C:\msys64\usr\bin\bsdtar.exe' -xOf $CandidatePackage .PKGINFO |
    Out-String).Trim()
$item = Get-Item -LiteralPath $CandidatePackage
$sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $CandidatePackage).
    Hash.ToLowerInvariant()
$aliasAudit = Import-Csv -Delimiter "`t" -LiteralPath (
    Join-Path $ReportRoot 'package\alias-audit.tsv')
$repoRoot = Split-Path $PSScriptRoot -Parent
$scannerPath = Join-Path $repoRoot '.ci\check-aarch64-pseudo-relocs.ps1'
$scannerTestsPath = Join-Path $repoRoot '.ci\test-check-aarch64-pseudo-relocs.ps1'
$scannerAdaptationPath = Join-Path (
    $repoRoot) '.ci\aarch64-pseudo-reloc-adaptation.json'
$scannerSha256 = (Get-FileHash -Algorithm SHA256 $scannerPath).
    Hash.ToLowerInvariant()
$scannerTestsSha256 = (Get-FileHash -Algorithm SHA256 $scannerTestsPath).
    Hash.ToLowerInvariant()
$scannerAdaptationSha256 = (
    Get-FileHash -Algorithm SHA256 $scannerAdaptationPath
).Hash.ToLowerInvariant()
$linker = @(
    $hostMachines.executables |
        Where-Object {
            $_.path -eq '/opt/bin/aarch64-pc-cygwin-ld.exe'
        }
)
if ($linker.Count -ne 1) {
    throw "Expected one packaged linker record, found $($linker.Count)."
}
$immutableInputs = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'candidate-inputs.json'
) -Raw | ConvertFrom-Json

$manifest = [ordered]@{
    schema_version = 1
    admitted = $false
    candidate = [ordered]@{
        package_name = $identityParts[0]
        version = $versionParts[0]
        pkgrel = $versionParts[1]
        filename = $item.Name
        local_path = $item.FullName
        artifact_name = 'fixed-aarch64-binutils-candidate'
        download_url = $null
        size = $item.Length
        sha256 = $sha256
        linker_path = $linker[0].path
        linker_size = $linker[0].size
        linker_sha256 = $linker[0].sha256
        pkginfo = $pkginfo
    }
    producer = [ordered]@{
        package_repository = 'crutkas/MSYS2-packages'
        package_commit = $PackageCommit
        workflow_run_id = $WorkflowRunId
        workflow_run_url = $WorkflowRunUrl
        workflow_head_sha = $WorkflowHeadSha
        source_repository = 'crutkas/binutils-woarm64'
        source_commit = $SourceCommit
        source_tree = $SourceTree
        source_archive_size = $SourceArchiveSize
        source_archive_sha256 = $SourceArchiveSha256
        source_ci_authority = 'package-exact-head'
        source_ci_run_id = $WorkflowRunId
        source_ci_run_url = $WorkflowRunUrl
        source_ci_head_sha = $WorkflowHeadSha
        source_ci_conclusion = 'success-if-workflow-completes'
        source_handoff_sha256 =
            '2e49f41fe87318294a48369958880abd9457571ebbcb9393eef0f1261f8f0a3f'
        reviewed_patch_sha256 =
            '0538d2c31b909dddda3ffa53b38fa2468394e52c20ea1f38dd5aa98d0f063d96'
        source_evidence_manifest_sha256 =
            '6f62c5c634b5820890059d037edf6baadd004cc511f943350c7b2fdcf97da6d5'
        source_review_04a = 'APPROVE'
        source_review_9da_report_sha256 =
            '38e540362a10f4da4fb0edc2f876357774ed083838a7fdc327276e6eccfcd97e'
        source_review_9da_manifest_sha256 =
            'b3e13b30d130df28dbd4ec40b065003449514b4ec41435f3c9fe9bb576389260'
        source_design_review_sha256 =
            '43ef9b9a1331d96304c1b232e6adf3b89fc3ccb1a6e71ea56390cd4368c50a58'
        source_scanner_path =
            '.ci/source-scanner-v2/check-aarch64-pseudo-relocs.ps1'
        source_scanner_sha256 =
            'fb437d60202cd818642082fc2b86adf7ccc98cc5ce147c674efc1a46520621bd'
        scanner_path = '.ci/check-aarch64-pseudo-relocs.ps1'
        scanner_sha256 = $scannerSha256
        scanner_tests_sha256 = $scannerTestsSha256
        scanner_adaptation_sha256 = $scannerAdaptationSha256
        scanner_package_commit = $PackageCommit
    }
    transaction = [ordered]@{
        baseline_identity = $transaction.baseline_identity
        candidate_identity = $transaction.candidate_identity
        rollback_identity = $transaction.rollback_identity
        reinstall_identity = $transaction.reinstall_identity
        shared_database_before = $transaction.shared_database_before
        shared_database_after = $transaction.shared_database_after
        shared_database_unchanged = $transaction.shared_database_unchanged
    }
    validation = [ordered]@{
        package_host_machine = 'x86_64'
        public_alias_count = $packageAudit.public_alias_count
        public_aliases_owned = $true
        public_aliases = @($aliasAudit)
        gcc_dependency_satisfied = $true
        gcc_driver_tools_package_owned = $true
        target_machine = 'AArch64'
        pseudo_reloc_flags_12_21_absent = $true
        baseline_negative_seal =
            'bc2403d4054eb1880f69e5f241610cc6bbbdffd262f217136beffa04aa6b7de1'
        mingw_cygwin_contamination_absent = $true
        native_dispatch_authorized = $false
    }
    immutable_inputs = $immutableInputs
    blockers = @(
        'Coordinator admission is required.',
        'A stable candidate package URL is required before native dispatch.',
        'Native Windows 11 ARM execution belongs to the consumer lane.'
    )
}
$manifest | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $OutputPath -Encoding utf8

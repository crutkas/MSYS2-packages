[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CandidateRoot,

    [Parameter(Mandatory = $true)]
    [string] $InventoryPath,

    [string] $Objdump = 'aarch64-pc-msys-objdump.exe',
    [string] $Nm = 'aarch64-pc-msys-nm.exe',
    [string] $Ar = 'aarch64-pc-msys-ar.exe',
    [string] $ScannerWrapper = (Join-Path $PSScriptRoot 'Invoke-Aarch64PseudoRelocScanner.ps1'),
    [string] $EvidencePath = (Join-Path $CandidateRoot 'gnupg-package-evidence.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CheckedTool {
    param([string] $Tool, [string[]] $Arguments)
    $output = @(& $Tool @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Tool failed: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object ToString)
}

function Export-ArchiveMember {
    param([string] $Tool, [string] $Archive, [string] $Member, [string] $Destination)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Tool
    foreach ($argument in @('p', $Archive, $Member)) {
        $start.ArgumentList.Add($argument)
    }
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    $stream = [IO.File]::Create($Destination)
    try {
        $process.StandardOutput.BaseStream.CopyTo($stream)
    }
    finally {
        $stream.Dispose()
    }
    $errorText = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "$Tool could not extract $Member from $Archive`: $errorText"
    }
}

$root = (Resolve-Path -LiteralPath $CandidateRoot).Path
$inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
$expected = @($inventory.expected_pe | ForEach-Object { $_.Replace('/', '\').ToLowerInvariant() } | Sort-Object)
$actual = @(
    Get-ChildItem -LiteralPath $root -Recurse -File |
        Where-Object Extension -in @('.exe', '.dll') |
        ForEach-Object { $_.FullName.Substring($root.Length + 1).ToLowerInvariant() } |
        Sort-Object
)
if (Compare-Object $expected $actual) {
    throw "PE inventory mismatch. Expected: $($expected -join ', '); actual: $($actual -join ', ')"
}

$peEvidence = @()
foreach ($relative in $expected) {
    $path = Join-Path $root $relative
    $fileOutput = Invoke-CheckedTool $Objdump @('-f', $path)
    $fileText = $fileOutput -join "`n"
    if ($fileText -notmatch 'file format pei-aarch64-little' -or
        $fileText -notmatch 'architecture: aarch64') {
        throw "Wrong architecture or PE personality: $relative"
    }
    $importsOutput = Invoke-CheckedTool $Objdump @('-p', $path)
    $imports = @(
        $importsOutput |
            ForEach-Object {
                if ($_ -match 'DLL Name:\s*(?<name>\S+)') {
                    $Matches.name.ToLowerInvariant()
                }
            }
    )
    if ('msys-2.0.dll' -notin $imports) {
        throw "Missing msys-2.0.dll import: $relative"
    }
    foreach ($import in $imports) {
        if (@($inventory.forbidden_import_patterns | Where-Object { $import -match $_ }).Count -ne 0) {
            throw "Forbidden import $import in $relative"
        }
        if (@($inventory.allowed_target_dll_patterns | Where-Object { $import -match $_ }).Count -eq 0) {
            throw "Unapproved import $import in $relative"
        }
    }
    $scanOutput = Join-Path ([IO.Path]::GetTempPath()) "$([IO.Path]::GetRandomFileName()).json"
    & pwsh -NoProfile -File $ScannerWrapper -PePath $path -OutputPath $scanOutput -Objdump $Objdump -Nm $Nm -RequireSymbolEvidence
    if ($LASTEXITCODE -ne 0) {
        throw "Pseudo-reloc scan failed for $relative"
    }
    $scan = Get-Content -LiteralPath $scanOutput -Raw | ConvertFrom-Json
    Remove-Item -LiteralPath $scanOutput -Force
    if ($scan.result -ne 'pass') {
        throw "Pseudo-reloc evidence did not pass for $relative"
    }
    $peEvidence += [pscustomobject]@{
        path = $relative.Replace('\', '/')
        imports = $imports
        pseudo_reloc = $scan
    }
}

$archiveEvidence = @()
$archives = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object Extension -eq '.a')
foreach ($archive in $archives) {
    $members = @(Invoke-CheckedTool $Ar @('t', $archive.FullName) | Where-Object { $_ -and $_ -notmatch '^/' -and $_ -notmatch '^__.SYMDEF' })
    if ($members.Count -eq 0) {
        throw "Archive has no members: $($archive.FullName)"
    }
    $index = Invoke-CheckedTool $Nm @('-s', $archive.FullName)
    if (($index -join "`n") -notmatch 'Archive index:') {
        throw "Archive has no armap: $($archive.FullName)"
    }
    foreach ($member in $members) {
        $memberPath = Join-Path ([IO.Path]::GetTempPath()) "$([IO.Path]::GetRandomFileName()).o"
        Export-ArchiveMember $Ar $archive.FullName $member $memberPath
        $memberFile = Invoke-CheckedTool $Objdump @('-f', $memberPath)
        Remove-Item -LiteralPath $memberPath -Force
        if (($memberFile -join "`n") -notmatch 'architecture: aarch64' -or
            ($memberFile -join "`n") -notmatch 'pei-aarch64-little') {
            throw "Archive member is not AArch64 PE/COFF: $($archive.FullName)($member)"
        }
    }
    $archiveEvidence += [pscustomobject]@{
        path = $archive.FullName.Substring($root.Length + 1).Replace('\', '/')
        members = $members.Count
        armap = $true
    }
}
if (-not $inventory.archive_policy.expected -and $archives.Count -ne 0) {
    throw 'GnuPG unexpectedly shipped development archives'
}

$evidence = [ordered]@{
    schema_version = 1
    result = 'pass'
    target = 'aarch64-pc-msys'
    pe_count = $peEvidence.Count
    pe = $peEvidence
    archives = $archiveEvidence
}
$parent = Split-Path -Parent $EvidencePath
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
$evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

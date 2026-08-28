[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LockPath,

    [Parameter(Mandatory = $true)]
    [string] $RootPath,

    [string[]] $CandidatePackages = @(),
    [string] $EvidencePath = (Join-Path $RootPath 'transaction-evidence.json'),
    [string] $Pacman = 'C:\msys64\usr\bin\pacman.exe',
    [string] $Bsdtar = 'C:\msys64\usr\bin\bsdtar.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:MSYS = 'winsymlinks:sys'

function Get-CanonicalSnapshot {
    param([string] $SharedRoot)
    $database = Join-Path $SharedRoot 'var\lib\pacman\local'
    $log = Join-Path $SharedRoot 'var\log\pacman.log'
    $rows = @(
        Get-ChildItem -LiteralPath $database -Recurse -File |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($database.Length + 1).Replace('\', '/')
                "$relative`t$($_.Length)`t$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
            }
    )
    $manifestBytes = [Text.Encoding]::UTF8.GetBytes(($rows -join "`n") + "`n")
    return [ordered]@{
        database_file_count = $rows.Count
        database_canonical_manifest_sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($manifestBytes)).ToLowerInvariant()
        pacman_log_bytes = (Get-Item -LiteralPath $log).Length
        pacman_log_sha256 = (Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Convert-ToMsysPath {
    param([string] $Path)
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -notmatch '^(?<drive>[A-Za-z]):\\(?<tail>.*)$') {
        throw "Cannot convert path to MSYS form: $resolved"
    }
    return "/$($Matches.drive.ToLowerInvariant())/$($Matches.tail.Replace('\', '/'))"
}

function Invoke-Pacman {
    param(
        [string] $OperationRoot,
        [string[]] $Arguments,
        [switch] $ExpectFailure
    )
    $root = Convert-ToMsysPath $OperationRoot
    $base = @(
        '--root', $root,
        '--dbpath', "$root/var/lib/pacman",
        '--cachedir', "$root/var/cache/pacman/pkg",
        '--logfile', "$root/var/log/pacman.log",
        '--config', "$root/etc/pacman.conf",
        '--hookdir', "$root/etc/pacman.d/hooks",
        '--noconfirm'
    )
    if ($Arguments[0] -in @('-U', '-Rdd')) {
        $base += '--noscriptlet'
    }
    $output = @(& $Pacman @base @Arguments 2>&1)
    if ($ExpectFailure) {
        if ($LASTEXITCODE -eq 0) {
            throw "pacman unexpectedly succeeded: $($Arguments -join ' ')"
        }
        return
    }
    if ($LASTEXITCODE -ne 0) {
        throw "pacman failed: $($output -join [Environment]::NewLine)"
    }
    return $output
}

function Initialize-RootLayout {
    param([string] $Path)
    foreach ($relative in @(
        'etc',
        'etc\pacman.d\hooks',
        'var\cache\pacman\pkg',
        'var\lib\pacman',
        'var\log'
    )) {
        New-Item -ItemType Directory -Force -Path (Join-Path $Path $relative) | Out-Null
    }
    @'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
CheckSpace
'@ | Set-Content -LiteralPath (Join-Path $Path 'etc\pacman.conf') -Encoding ascii
}

function Get-PackageInfo {
    param([string] $Archive)
    $lines = @(& $Bsdtar -xOf $Archive .PKGINFO)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read .PKGINFO from $Archive"
    }
    $values = @{}
    foreach ($line in $lines) {
        if ($line -match '^(?<key>[^ ]+) = (?<value>.*)$') {
            if (-not $values.ContainsKey($Matches.key)) {
                $values[$Matches.key] = @()
            }
            $values[$Matches.key] += $Matches.value
        }
    }
    return $values
}

function Export-ArchiveEntry {
    param([string] $Archive, [string] $Entry, [string] $Destination)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Bsdtar
    foreach ($argument in @('-xOf', $Archive, $Entry)) {
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
        throw "Unable to extract $Entry from $Archive`: $errorText"
    }
}

function Get-InstalledManifest {
    param([string] $OperationRoot, [string[]] $OwnedEntries)
    $records = @(
        foreach ($entry in $OwnedEntries) {
            $relative = $entry.TrimEnd('/')
            $installed = Join-Path $OperationRoot $relative
            if (-not (Test-Path -LiteralPath $installed)) {
                throw "Installed package entry is missing: $entry"
            }
            $item = Get-Item -LiteralPath $installed -Force
            if ($entry.EndsWith('/')) {
                if (-not $item.PSIsContainer) {
                    throw "Installed package directory changed type: $entry"
                }
                [ordered]@{ path = $entry; type = 'directory' }
            }
            elseif ($item.LinkType -and $item.LinkType -ne 'HardLink') {
                [ordered]@{ path = $entry; type = 'link'; target = [string] $item.Target }
            }
            else {
                [ordered]@{
                    path = $entry
                    type = 'file'
                    bytes = $item.Length
                    sha256 = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        }
    )
    return $records
}

function Get-ArchiveManifest {
    param([string] $Archive, [string[]] $OwnedEntries, [string] $TemporaryRoot)
    $listing = @(& $Bsdtar -tf $Archive)
    $verbose = @(& $Bsdtar -tvf $Archive)
    if ($LASTEXITCODE -ne 0 -or $listing.Count -ne $verbose.Count) {
        throw "Unable to align package entries with archive metadata: $Archive"
    }
    if (@($listing | Sort-Object -Unique).Count -ne $listing.Count) {
        throw "Package archive contains duplicate paths: $Archive"
    }
    $records = @(
        foreach ($entry in $OwnedEntries) {
            $index = [Array]::IndexOf([object[]] $listing, $entry)
            if ($index -lt 0) {
                throw "Owned entry disappeared from package archive: $entry"
            }
            if ($entry.EndsWith('/')) {
                [ordered]@{ path = $entry; type = 'directory' }
                continue
            }
            if ($verbose[$index] -match ' -> (?<target>.+)$') {
                [ordered]@{ path = $entry; type = 'link'; target = $Matches.target }
                continue
            }
            $entryPath = Join-Path $TemporaryRoot "$([guid]::NewGuid().ToString('N')).entry"
            Export-ArchiveEntry $Archive $entry $entryPath
            $item = Get-Item -LiteralPath $entryPath
            [ordered]@{
                path = $entry
                type = 'file'
                bytes = $item.Length
                sha256 = (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            Remove-Item -LiteralPath $entryPath -Force
        }
    )
    return $records
}

function Get-MtreePaths {
    param([string] $MtreePath)
    $bytes = [IO.File]::ReadAllBytes($MtreePath)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x1f -and $bytes[1] -eq 0x8b) {
        $input = [IO.MemoryStream]::new($bytes)
        $gzip = [IO.Compression.GZipStream]::new($input, [IO.Compression.CompressionMode]::Decompress)
        $output = [IO.MemoryStream]::new()
        try {
            $gzip.CopyTo($output)
            $text = [Text.Encoding]::UTF8.GetString($output.ToArray())
        }
        finally {
            $output.Dispose()
            $gzip.Dispose()
            $input.Dispose()
        }
    }
    else {
        $text = [Text.Encoding]::UTF8.GetString($bytes)
    }
    return @(
        foreach ($line in $text -split "`r?`n") {
            if (-not $line -or $line.StartsWith('#') -or $line.StartsWith('/')) {
                continue
            }
            $encoded = ($line -split '\s+', 2)[0]
            $decoded = [regex]::Replace($encoded, '\\(?<octal>[0-7]{3})', {
                param($match)
                [char] [Convert]::ToInt32($match.Groups['octal'].Value, 8)
            })
            $normalized = $decoded.TrimStart('.').TrimStart('/').TrimEnd('/')
            if ($normalized) {
                $normalized
            }
        }
    )
}

& (Join-Path $PSScriptRoot 'Test-Aarch64GnuPGDependencyLock.ps1') -LockPath $LockPath | Out-Null
$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$sharedBefore = Get-CanonicalSnapshot 'C:\msys64'
$root = [IO.Path]::GetFullPath($RootPath)
if ($root.TrimEnd('\') -eq 'C:\msys64') {
    throw 'The shared root can never be a candidate root'
}
if (Test-Path -LiteralPath $root) {
    throw "Private root already exists: $root"
}
Initialize-RootLayout $root

$downloadDirectory = Join-Path $root 'downloads'
New-Item -ItemType Directory -Force -Path $downloadDirectory | Out-Null
$dependencyArchives = @()
$packageRecords = @()
$pathScanner = Join-Path $PSScriptRoot 'Test-Aarch64GnuPGForbiddenPaths.ps1'
foreach ($dependency in @($lock.dependencies | Where-Object status -eq 'admitted')) {
    $archive = Join-Path $downloadDirectory $dependency.asset_name
    Invoke-WebRequest -Uri $dependency.asset_url -OutFile $archive
    $item = Get-Item -LiteralPath $archive
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($item.Length -ne $dependency.asset_bytes -or $hash -ne $dependency.asset_sha256) {
        throw "Asset byte/hash mismatch for $($dependency.id)"
    }
    $info = Get-PackageInfo $archive
    if (@($info.pkgname).Count -ne 1 -or $info.pkgname[0] -ne $dependency.package.name -or
        @($info.pkgver).Count -ne 1 -or $info.pkgver[0] -ne $dependency.package.version) {
        throw "Package metadata mismatch for $($dependency.id)"
    }
    foreach ($provide in @($dependency.package.provides)) {
        if ($provide -notin @($info.provides)) {
            throw "Missing package provide '$provide' for $($dependency.id)"
        }
    }
    $owned = @(& $Bsdtar -tf $archive)
    if (@($owned | Where-Object {
        $_ -eq '.INSTALL' -or $_ -like '*/.INSTALL' -or
        $_ -like 'usr/share/libalpm/hooks*' -or $_ -like 'etc/pacman.d/hooks*'
    }).Count -ne 0) {
        throw "Executable package metadata is forbidden: $($dependency.id)"
    }
    & $pathScanner `
        -InputPath $archive `
        -ForbiddenPath @($root, 'C:\msys64', $PSScriptRoot) `
        -Bsdtar $Bsdtar
    foreach ($path in @($dependency.package.owned_files)) {
        if ($path -notin $owned) {
            throw "Missing package-owned path '$path' for $($dependency.id)"
        }
    }
    $dependencyArchives += Convert-ToMsysPath $archive
    $packageRecords += [ordered]@{
        id = $dependency.id
        release_tag = $dependency.release_tag
        asset_url = $dependency.asset_url
        producer_commit = $dependency.producer_commit
        archive = $dependency.asset_name
        bytes = $item.Length
        sha256 = $hash
        package = $info.pkgname[0]
        version = $info.pkgver[0]
    }
}

Invoke-Pacman $root (@('-U') + $dependencyArchives)

$candidateArchivePaths = @($CandidatePackages | ForEach-Object { [IO.Path]::GetFullPath($_) })
$candidateIntegrity = @()
if ($candidateArchivePaths.Count -ne 0) {
    foreach ($archive in $candidateArchivePaths) {
        $info = Get-PackageInfo $archive
        if ($info.pkgname[0] -notmatch '^mingw-w64-cross-msysarm64-gnupg($|-docs$)' -or
            $info.arch[0] -ne 'x86_64') {
            throw "Unexpected candidate package metadata in $archive"
        }
        $entries = @(& $Bsdtar -tf $archive)
        if ($LASTEXITCODE -ne 0 -or @($entries | Where-Object {
            $_ -eq '.INSTALL' -or $_ -like '*/.INSTALL' -or
            $_ -like 'usr/share/libalpm/hooks*' -or $_ -like 'etc/pacman.d/hooks*'
        }).Count -ne 0) {
            throw "Candidate archive contains invalid or executable package metadata: $archive"
        }
        & $pathScanner `
            -InputPath $archive `
            -ForbiddenPath @($root, 'C:\msys64', $PSScriptRoot) `
            -Bsdtar $Bsdtar
    }
    $candidateMsysPaths = @($candidateArchivePaths | ForEach-Object { Convert-ToMsysPath $_ })
    Invoke-Pacman $root (@('-U') + $candidateMsysPaths)
    $candidateNames = @()
    foreach ($archive in $candidateArchivePaths) {
        $info = Get-PackageInfo $archive
        $name = $info.pkgname[0]
        if ($name -notmatch '^mingw-w64-cross-msysarm64-gnupg($|-docs$)' -or
            $info.arch[0] -ne 'x86_64') {
            throw "Unexpected candidate package metadata in $archive"
        }
        $candidateNames += $name
        Invoke-Pacman $root @('-Q', $name)
        $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $allEntries = @(& $Bsdtar -tf $archive)
        if (@($allEntries | Where-Object {
            $_ -eq '.INSTALL' -or $_ -like '*/.INSTALL' -or
            $_ -like 'usr/share/libalpm/hooks*' -or $_ -like 'etc/pacman.d/hooks*'
        }).Count -ne 0) {
            throw "Executable package metadata is forbidden: $name"
        }
        $owned = @($allEntries | Where-Object { $_ -and -not $_.StartsWith('.') })
        if ($LASTEXITCODE -ne 0 -or $owned.Count -eq 0) {
            throw "Candidate package is empty: $name"
        }
        $registered = @(
            Invoke-Pacman $root @('-Qlq', $name) |
                ForEach-Object { $_.Trim().TrimStart('/').Replace('\', '/') } |
                Where-Object { $_ }
        )
        if (Compare-Object ($owned | Sort-Object) ($registered | Sort-Object)) {
            throw "Registered ownership differs from the complete package archive for $name"
        }
        foreach ($entry in $owned) {
            Invoke-Pacman $root @('-Qo', "/$($entry.TrimEnd('/'))") | Out-Null
        }
        Invoke-Pacman $root @('-Qkk', $name) | Out-Null

        $mtreePath = Join-Path $root "var\cache\pacman\pkg\$name.MTREE"
        Export-ArchiveEntry $archive '.MTREE' $mtreePath
        $ownershipText = (($owned | Sort-Object) -join "`n") + "`n"
        $ownershipHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($ownershipText))
        ).ToLowerInvariant()
        $mtreeEntries = @(Get-MtreePaths $mtreePath | Sort-Object)
        $normalizedOwned = @($owned | ForEach-Object { $_.TrimEnd('/') } | Sort-Object)
        if (Compare-Object $normalizedOwned $mtreeEntries) {
            throw "Package MTREE does not cover the complete ownership set for $name"
        }
        $archiveManifest = @(Get-ArchiveManifest $archive $owned (Join-Path $root 'var\cache\pacman\pkg'))
        $installedManifest = @(Get-InstalledManifest $root $owned)
        if (($archiveManifest | ConvertTo-Json -Depth 6 -Compress) -ne
            ($installedManifest | ConvertTo-Json -Depth 6 -Compress)) {
            throw "Installed content differs from the complete package archive for $name"
        }

        $regularEntry = @(
            $owned |
                Where-Object { -not $_.EndsWith('/') } |
                Where-Object {
                    $item = Get-Item -LiteralPath (Join-Path $root $_) -Force
                    -not $item.LinkType -and -not $item.PSIsContainer
                } |
                Select-Object -First 1
        )
        if ($regularEntry.Count -ne 1) {
            throw "Candidate package has no corruption-testable regular file: $name"
        }
        $corruptPath = Join-Path $root $regularEntry[0]
        $originalInstalledHash = (Get-FileHash -LiteralPath $corruptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $stream = [IO.File]::Open($corruptPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.WriteByte(0xa5)
        }
        finally {
            $stream.Dispose()
        }
        Invoke-Pacman $root @('-Qkk', $name) -ExpectFailure
        Invoke-Pacman $root @('-U', (Convert-ToMsysPath $archive)) | Out-Null
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) {
            throw "Candidate archive changed during recovery: $name"
        }
        Invoke-Pacman $root @('-Qkk', $name) | Out-Null
        $recoveredHash = (Get-FileHash -LiteralPath $corruptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($recoveredHash -ne $originalInstalledHash) {
            throw "Exact reinstall did not recover the original file: $($regularEntry[0])"
        }
        $recoveredManifest = @(Get-InstalledManifest $root $owned)
        if (($archiveManifest | ConvertTo-Json -Depth 6 -Compress) -ne
            ($recoveredManifest | ConvertTo-Json -Depth 6 -Compress)) {
            throw "Exact reinstall did not recover the complete package manifest for $name"
        }
        $candidateIntegrity += [ordered]@{
            package = $name
            archive = (Split-Path -Leaf $archive)
            archive_bytes = (Get-Item -LiteralPath $archive).Length
            archive_sha256 = $archiveHash
            ownership_manifest_sha256 = $ownershipHash
            owned_entries = $owned.Count
            mtree_sha256 = (Get-FileHash -LiteralPath $mtreePath -Algorithm SHA256).Hash.ToLowerInvariant()
            qkk_before = 'pass'
            corrupted_path = $regularEntry[0]
            qkk_detected_corruption = $true
            exact_reinstall_recovered_sha256 = $recoveredHash
            final_installed_manifest = $recoveredManifest
        }

        $symlinks = @(
            & $Bsdtar -tvf $archive |
                Where-Object { $_ -match '^l' -and $_ -match '\s(?<path>\S+)\s+->\s+' } |
                ForEach-Object { $Matches.path }
        )
        foreach ($symlink in $symlinks) {
            $installedLink = Get-Item -LiteralPath (Join-Path $root $symlink) -Force
            if (-not $installedLink.LinkType) {
                throw "Package symlink was not preserved: $symlink"
            }
        }
    }
    Invoke-Pacman $root (@('-Rdd') + $candidateNames)
    foreach ($name in $candidateNames) {
        Invoke-Pacman $root @('-Q', $name) -ExpectFailure
    }
    Invoke-Pacman $root (@('-U') + $candidateMsysPaths)

    $collisionRoot = "$root-collision"
    Initialize-RootLayout $collisionRoot
    Invoke-Pacman $collisionRoot (@('-U') + $dependencyArchives)
    $collisionFiles = @(
        & $Bsdtar -tf $candidateArchivePaths[0] |
            Where-Object { $_ -and $_ -notmatch '^\.|/$|^usr/share/licenses/' }
    )
    if ($collisionFiles.Count -eq 0) {
        throw 'Candidate package has no collision-testable owned file'
    }
    $blocker = Join-Path $collisionRoot $collisionFiles[0]
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $blocker) | Out-Null
    Set-Content -LiteralPath $blocker -Value 'unmanaged-collision' -Encoding ascii
    Invoke-Pacman $collisionRoot (@('-U') + $candidateMsysPaths) -ExpectFailure
}

$sharedAfter = Get-CanonicalSnapshot 'C:\msys64'
if (($sharedBefore | ConvertTo-Json -Compress) -ne ($sharedAfter | ConvertTo-Json -Compress)) {
    throw 'Shared pacman database or log changed during the isolated transaction'
}

$evidence = [ordered]@{
    schema_version = 1
    result = 'pass'
    root = $root
    msys = $env:MSYS
    pacman_arguments = @('--root', '--dbpath', '--cachedir', '--logfile', '--config', '--hookdir')
    tools = [ordered]@{
        pacman_path = (Resolve-Path -LiteralPath $Pacman).Path
        pacman_sha256 = (Get-FileHash -LiteralPath $Pacman -Algorithm SHA256).Hash.ToLowerInvariant()
        pacman_file_version = (Get-Item -LiteralPath $Pacman).VersionInfo.FileVersion
        bsdtar_path = (Resolve-Path -LiteralPath $Bsdtar).Path
        bsdtar_sha256 = (Get-FileHash -LiteralPath $Bsdtar -Algorithm SHA256).Hash.ToLowerInvariant()
        bsdtar_version = (@(& $Bsdtar --version)[0]).Trim()
    }
    dependencies = $packageRecords
    candidate_packages = $candidateArchivePaths
    candidate_integrity = $candidateIntegrity
    shared_before = $sharedBefore
    shared_after = $sharedAfter
}
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

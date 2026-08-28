param(
    [Parameter(Mandatory = $true)]
    [string]$Pacman,

    [Parameter(Mandatory = $true)]
    [string]$Bsdtar,

    [Parameter(Mandatory = $true)]
    [string]$TransactionRoot,

    [Parameter(Mandatory = $true)]
    [string[]]$DependencyArchives,

    [Parameter(Mandatory = $true)]
    [string[]]$CandidateArchives,

    [Parameter(Mandatory = $true)]
    [string]$ReportDirectory,

    [string]$SharedDatabase = 'C:\msys64\var\lib\pacman\local',

    [string]$SharedLog = 'C:\msys64\var\log\pacman.log'
)

$ErrorActionPreference = 'Stop'
$env:MSYS = 'winsymlinks:sys'
$buildInfoValidator = Join-Path $PSScriptRoot 'validate-buildinfo-path.ps1'
$gzip = Join-Path (Split-Path -Parent $Bsdtar) 'gzip.exe'
if (-not (Test-Path -LiteralPath $gzip)) {
    throw "Private package tools are missing gzip: $gzip"
}
$expectedNames = @(
    'mingw-w64-cross-msysarm64-libassuan',
    'mingw-w64-cross-msysarm64-libassuan-devel',
    'mingw-w64-cross-msysarm64-libassuan-tools'
)
$expectedFiles = @{
    'mingw-w64-cross-msysarm64-libassuan' = @(
        'opt/aarch64-pc-msys/usr/bin/msys-assuan-9.dll',
        'usr/share/licenses/mingw-w64-cross-msysarm64-libassuan/COPYING.LIB'
    )
    'mingw-w64-cross-msysarm64-libassuan-devel' = @(
        'opt/aarch64-pc-msys/usr/include/assuan.h',
        'opt/aarch64-pc-msys/usr/lib/libassuan.a',
        'opt/aarch64-pc-msys/usr/lib/libassuan.dll.a',
        'opt/aarch64-pc-msys/usr/lib/libassuan.la',
        'opt/aarch64-pc-msys/usr/lib/pkgconfig/libassuan.pc',
        'opt/aarch64-pc-msys/usr/share/aclocal/libassuan.m4',
        'opt/aarch64-pc-msys/usr/share/info/assuan.info',
        'opt/aarch64-pc-msys/usr/share/info/dir',
        'usr/share/licenses/mingw-w64-cross-msysarm64-libassuan-devel/COPYING.LIB'
    )
    'mingw-w64-cross-msysarm64-libassuan-tools' = @(
        'opt/aarch64-pc-msys/usr/bin/libassuan-config',
        'usr/share/licenses/mingw-w64-cross-msysarm64-libassuan-tools/COPYING.LIB'
    )
}
$transactionFullPath = [IO.Path]::GetFullPath($TransactionRoot)
if ([IO.Path]::GetPathRoot($transactionFullPath) -eq $transactionFullPath -or
    [IO.Path]::GetFileName($transactionFullPath) -notmatch 'libassuan') {
    throw "Refusing unsafe transaction root: $transactionFullPath"
}
$TransactionRoot = $transactionFullPath

function Get-DirectorySeal {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Database path does not exist: $Path"
    }

    $lines = Get-ChildItem -LiteralPath $Path -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($Path.Length).Replace('\', '/')
            '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant(), $relative
        }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Write-DirectoryManifest {
    param(
        [string]$Path,
        [string]$Destination
    )

    $lines = Get-ChildItem -LiteralPath $Path -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($Path.Length).Replace('\', '/')
            '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant(), $relative
        }
    $lines | Set-Content -Encoding ascii $Destination
    return (Get-FileHash -Algorithm SHA256 $Destination).Hash.ToLowerInvariant()
}

function Write-CanonicalDatabaseManifest {
    param(
        [string]$Path,
        [string]$Destination
    )

    Get-ChildItem -LiteralPath $Path -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                path = $_.FullName.Substring($Path.Length + 1)
                length = $_.Length
                lastWriteUtc = $_.LastWriteTimeUtc.ToString('o')
                sha256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
            }
        } |
        Export-Csv $Destination -NoTypeInformation -Encoding utf8
    return (Get-FileHash -Algorithm SHA256 $Destination).Hash.ToLowerInvariant()
}

function Get-FileSeal {
    param([string]$Path)

    $item = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        path = $item.FullName
        size = $item.Length
        lastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
        sha256 = (Get-FileHash -Algorithm SHA256 $item.FullName).Hash.ToLowerInvariant()
    }
}

function Get-PackageInfo {
    param([string]$Archive)

    $lines = & $Bsdtar -xOf $Archive .PKGINFO
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read .PKGINFO from $Archive"
    }

    $result = @{}
    foreach ($line in $lines) {
        if ($line -match '^([^#][^=]+?) = (.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2]
            if (-not $result.ContainsKey($key)) {
                $result[$key] = [Collections.Generic.List[string]]::new()
            }
            $result[$key].Add($value)
        }
    }
    return $result
}

function Get-PackageFiles {
    param([string]$Archive)

    $files = & $Bsdtar -tf $Archive
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list $Archive"
    }
    return @($files | Where-Object {
        $_ -and
        -not $_.EndsWith('/') -and
        $_ -notin @('.BUILDINFO', '.MTREE', '.PKGINFO')
    })
}

function Export-ArchiveMember {
    param(
        [string]$Archive,
        [string]$Member,
        [string]$Destination
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Bsdtar
    $startInfo.ArgumentList.Add('-xOf')
    $startInfo.ArgumentList.Add($Archive)
    $startInfo.ArgumentList.Add($Member)
    $startInfo.RedirectStandardOutput = $true
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($startInfo)
    $stream = [IO.File]::Create($Destination)
    try {
        $process.StandardOutput.BaseStream.CopyTo($stream)
    }
    finally {
        $stream.Dispose()
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Unable to extract $Member from $Archive"
    }
}

function Export-MtreeText {
    param(
        [string]$Archive,
        [string]$RawDestination,
        [string]$TextDestination
    )

    Export-ArchiveMember -Archive $Archive -Member '.MTREE' -Destination $RawDestination
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $gzip
    $startInfo.ArgumentList.Add('-dc')
    $startInfo.ArgumentList.Add($RawDestination)
    $startInfo.RedirectStandardOutput = $true
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($startInfo)
    $stream = [IO.File]::Create($TextDestination)
    try {
        $process.StandardOutput.BaseStream.CopyTo($stream)
    }
    finally {
        $stream.Dispose()
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Unable to decompress .MTREE from $Archive"
    }
}

function Invoke-Pacman {
    param([string[]]$Arguments)

    & $Pacman @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "pacman failed with exit code $LASTEXITCODE`: $($Arguments -join ' ')"
    }
}

New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null
$sharedBefore = Get-DirectorySeal -Path $SharedDatabase
$sharedBefore | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-before.sha256')
$sharedManifestBefore = Write-DirectoryManifest `
    -Path $SharedDatabase `
    -Destination (Join-Path $ReportDirectory 'shared-db-before.manifest')
$sharedManifestBefore |
    Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-before.manifest.sha256')
$sharedCanonicalBefore = Write-CanonicalDatabaseManifest `
    -Path $SharedDatabase `
    -Destination (Join-Path $ReportDirectory 'shared-db-before.csv')
$sharedCanonicalBefore |
    Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-before.csv.sha256')
$sharedLogBefore = Get-FileSeal -Path $SharedLog
$sharedLogBefore | ConvertTo-Json |
    Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'shared-log-before.json')

if ($CandidateArchives.Count -ne 3) {
    throw "Expected three candidate archives, found $($CandidateArchives.Count)"
}

$owners = @{}
$packageRecords = @()
foreach ($archive in $CandidateArchives) {
    if (-not (Test-Path -LiteralPath $archive)) {
        throw "Candidate archive does not exist: $archive"
    }

    $info = Get-PackageInfo -Archive $archive
    $name = $info.pkgname | Select-Object -First 1
    $version = $info.pkgver | Select-Object -First 1
    if ($name -notin $expectedNames) {
        throw "Unexpected package identity $name in $archive"
    }
    if ($version -ne '3.0.2-1') {
        throw "Unexpected package version $version for $name"
    }

    $required = switch ($name) {
        'mingw-w64-cross-msysarm64-libassuan' {
            @(
                'aarch64-pc-msys-runtime=3.6.10.r0.ga527ace21',
                'aarch64-pc-msys-libgpg-error=1.56'
            )
        }
        'mingw-w64-cross-msysarm64-libassuan-devel' {
            @(
                'aarch64-pc-msys-libassuan=3.0.2',
                'aarch64-pc-msys-libgpg-error-devel=1.56'
            )
        }
        'mingw-w64-cross-msysarm64-libassuan-tools' {
            @('sh', 'aarch64-pc-msys-libassuan-devel=3.0.2')
        }
    }
    foreach ($dependency in $required) {
        if ($dependency -notin $info.depend) {
            throw "$name is missing exact dependency $dependency"
        }
    }
    if ((($info.depend | Sort-Object) -join "`n") -ne
        (($required | Sort-Object) -join "`n")) {
        throw "$name has unexpected dependency metadata: $($info.depend -join ', ')"
    }
    $expectedProvide = $name.Replace('mingw-w64-cross-msysarm64-', 'aarch64-pc-msys-') + '=3.0.2'
    if (($info.provides.Count -ne 1) -or ($info.provides[0] -ne $expectedProvide)) {
        throw "$name has unexpected provides metadata: $($info.provides -join ', ')"
    }
    $expectedConflict = $expectedProvide.Split('=')[0]
    if (($info.conflict.Count -ne 1) -or ($info.conflict[0] -ne $expectedConflict)) {
        throw "$name has unexpected conflicts metadata: $($info.conflict -join ', ')"
    }

    $files = Get-PackageFiles -Archive $archive
    if ($files.Count -eq 0) {
        throw "$name has an empty payload"
    }
    if ((($files | Sort-Object) -join "`n") -cne
        (($expectedFiles[$name] | Sort-Object) -join "`n")) {
        throw "$name does not own its exact required split payload"
    }
    foreach ($file in $files) {
        if ($file -notmatch '^(opt/aarch64-pc-msys/usr/|usr/share/licenses/)') {
            throw "$name owns path outside the approved prefixes: $file"
        }
        if ($owners.ContainsKey($file)) {
            throw "Ownership collision: $file belongs to $($owners[$file]) and $name"
        }
        $owners[$file] = $name
    }

    $entries = @(& $Bsdtar -tf $archive)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enumerate package archive $archive"
    }
    foreach ($metadata in @('.PKGINFO', '.BUILDINFO', '.MTREE')) {
        if (@($entries | Where-Object { $_ -ceq $metadata }).Count -ne 1) {
            throw "$name does not contain exactly one $metadata entry"
        }
    }
    $duplicates = @($entries | Group-Object -CaseSensitive | Where-Object Count -gt 1)
    if ($duplicates.Count -ne 0) {
        throw "$name contains duplicate archive entries: $($duplicates.Name -join ', ')"
    }

    $pkgInfoPath = Join-Path $ReportDirectory "$name.PKGINFO"
    Export-ArchiveMember -Archive $archive -Member '.PKGINFO' -Destination $pkgInfoPath
    $buildInfoPath = Join-Path $ReportDirectory "$name.BUILDINFO"
    Export-ArchiveMember -Archive $archive -Member '.BUILDINFO' -Destination $buildInfoPath
    & $buildInfoValidator -Path $buildInfoPath
    $mtreeRawPath = Join-Path $ReportDirectory "$name.MTREE.gz"
    $mtreeTextPath = Join-Path $ReportDirectory "$name.MTREE"
    Export-MtreeText `
        -Archive $archive `
        -RawDestination $mtreeRawPath `
        -TextDestination $mtreeTextPath
    $mtreeLines = @(Get-Content -LiteralPath $mtreeTextPath)
    if ($mtreeLines.Count -eq 0 -or $mtreeLines[0] -cne '#mtree') {
        throw "$name has an invalid decompressed .MTREE header"
    }
    $unexpectedTimes = @($mtreeLines | Where-Object {
        $_ -match ' time=' -and $_ -notmatch ' time=1786817435\.0(?: |$)'
    })
    if ($unexpectedTimes.Count -ne 0) {
        throw "$name .MTREE contains nondeterministic timestamps"
    }
    $mtreeFiles = @($mtreeLines | ForEach-Object {
        if ($_ -match '^\./(\S+)(?: |$)' -and $_ -notmatch ' type=dir(?: |$)') {
            $Matches[1]
        }
    } | Where-Object { $_ -notin @('.BUILDINFO', '.PKGINFO') } | Sort-Object)
    if (($mtreeFiles -join "`n") -cne (($files | Sort-Object) -join "`n")) {
        throw "$name .MTREE file ownership differs from its archive payload"
    }
    $hash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    $packageRecords += [pscustomobject]@{
        name = $name
        version = $version
        archive = (Resolve-Path -LiteralPath $archive).Path
        size = (Get-Item -LiteralPath $archive).Length
        sha256 = $hash
        pkginfoSize = (Get-Item -LiteralPath $pkgInfoPath).Length
        pkginfoSha256 = (Get-FileHash -Algorithm SHA256 $pkgInfoPath).Hash.ToLowerInvariant()
        buildinfoSize = (Get-Item -LiteralPath $buildInfoPath).Length
        buildinfoSha256 = (Get-FileHash -Algorithm SHA256 $buildInfoPath).Hash.ToLowerInvariant()
        mtreeSize = (Get-Item -LiteralPath $mtreeRawPath).Length
        mtreeSha256 = (Get-FileHash -Algorithm SHA256 $mtreeRawPath).Hash.ToLowerInvariant()
        mtreeTextSha256 = (Get-FileHash -Algorithm SHA256 $mtreeTextPath).Hash.ToLowerInvariant()
        files = $files.Count
        depends = @($info.depend)
        provides = @($info.provides)
    }
    $files | Sort-Object | Set-Content -Encoding utf8 (Join-Path $ReportDirectory "$name.files")
}

if ((($packageRecords.name | Sort-Object) -join "`n") -ne
    (($expectedNames | Sort-Object) -join "`n")) {
    throw 'The candidate package set is incomplete'
}
$packageRecords | ConvertTo-Json -Depth 5 |
    Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'candidate-seal.json')

if (Test-Path -LiteralPath $TransactionRoot) {
    Remove-Item -LiteralPath $TransactionRoot -Recurse -Force
}
$db = Join-Path $TransactionRoot 'var\lib\pacman'
$cache = Join-Path $TransactionRoot 'var\cache\pacman\pkg'
$log = Join-Path $TransactionRoot 'var\log\pacman.log'
$config = Join-Path $TransactionRoot 'etc\pacman-local.conf'
$hooks = Join-Path $TransactionRoot 'etc\pacman.d\hooks'
$gpg = Join-Path $TransactionRoot 'etc\pacman.d\gnupg'
New-Item -ItemType Directory -Force -Path `
    $db, $cache, (Split-Path $log), $hooks, $gpg | Out-Null
@'
[options]
Architecture = auto
CheckSpace
SigLevel = Never
LocalFileSigLevel = Never
'@ | Set-Content -Encoding ascii $config

$common = @(
    '--root', $TransactionRoot,
    '--dbpath', $db,
    '--cachedir', $cache,
    '--logfile', $log,
    '--config', $config,
    '--hookdir', $hooks,
    '--gpgdir', $gpg,
    '--noconfirm'
)
Invoke-Pacman -Arguments ($common + @(
    '--assume-installed', 'sh',
    '-U'
) + $DependencyArchives)
Invoke-Pacman -Arguments ($common + @(
    '--assume-installed', 'sh',
    '-U'
) + $CandidateArchives)

$query = & $Pacman @common -Q
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to query isolated package database'
}
$query | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'installed-first.txt')
$queryText = $query -join "`n"
foreach ($name in $expectedNames) {
    if ($queryText -notmatch "(?m)^$([regex]::Escape($name)) 3\.0\.2-1$") {
        throw "$name was not installed with the expected version"
    }
}

$baselineCheck = & $Pacman @common -Qkk @expectedNames 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'Freshly installed candidate packages failed pacman -Qkk'
}
$baselineCheck | Set-Content -Encoding utf8 `
    (Join-Path $ReportDirectory 'qkk-installed.txt')

$runtimeDll = Join-Path $TransactionRoot `
    'opt\aarch64-pc-msys\usr\bin\msys-assuan-9.dll'
$header = Join-Path $TransactionRoot 'opt\aarch64-pc-msys\usr\include\assuan.h'
$runtimeHash = (Get-FileHash -LiteralPath $runtimeDll -Algorithm SHA256).Hash.ToLowerInvariant()
$stream = [IO.File]::Open($runtimeDll, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
try {
    $null = $stream.Seek(-1, [IO.SeekOrigin]::End)
    $value = $stream.ReadByte()
    $null = $stream.Seek(-1, [IO.SeekOrigin]::End)
    $stream.WriteByte($value -bxor 1)
}
finally {
    $stream.Dispose()
}
$corruptCheck = & $Pacman @common -Qkk `
    'mingw-w64-cross-msysarm64-libassuan' 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'pacman -Qkk did not reject the corrupted runtime DLL'
}
$corruptCheck | Set-Content -Encoding utf8 `
    (Join-Path $ReportDirectory 'qkk-corrupt-runtime.txt')

Remove-Item -LiteralPath $header -Force
$missingCheck = & $Pacman @common -Qk `
    'mingw-w64-cross-msysarm64-libassuan-devel' 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'pacman -Qk did not reject the missing public header'
}
$missingCheck | Set-Content -Encoding utf8 `
    (Join-Path $ReportDirectory 'qk-missing-header.txt')

Invoke-Pacman -Arguments ($common + @(
    '--assume-installed', 'sh',
    '-U'
) + $CandidateArchives)
if ((Get-FileHash -LiteralPath $runtimeDll -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $runtimeHash) {
    throw 'Candidate reinstall did not restore the exact runtime DLL'
}
$recoveredCheck = & $Pacman @common -Qkk @expectedNames 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'Candidate packages failed pacman -Qkk after corruption recovery'
}
$recoveredCheck | Set-Content -Encoding utf8 `
    (Join-Path $ReportDirectory 'qkk-recovered.txt')

Invoke-Pacman -Arguments ($common + @('-Rdd') + $expectedNames)
foreach ($file in $owners.Keys) {
    if (Test-Path -LiteralPath (Join-Path $TransactionRoot $file.Replace('/', '\'))) {
        throw "Package-owned path remained after removal: $file"
    }
}

Invoke-Pacman -Arguments ($common + @(
    '--assume-installed', 'sh',
    '-U'
) + $CandidateArchives)
$query = & $Pacman @common -Q
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to query isolated package database after reinstall'
}
$query | Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'installed-reinstall.txt')
$queryText = $query -join "`n"
foreach ($name in $expectedNames) {
    if ($queryText -notmatch "(?m)^$([regex]::Escape($name)) 3\.0\.2-1$") {
        throw "$name was not reinstalled with the expected version"
    }
}
$finalCheck = & $Pacman @common -Qkk @expectedNames 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'Reinstalled candidate packages failed final pacman -Qkk'
}
$finalCheck | Set-Content -Encoding utf8 `
    (Join-Path $ReportDirectory 'qkk-reinstalled.txt')

Copy-Item -LiteralPath $log -Destination (Join-Path $ReportDirectory 'transaction-pacman.log')
$sharedAfter = Get-DirectorySeal -Path $SharedDatabase
$sharedAfter | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-after.sha256')
$sharedManifestAfter = Write-DirectoryManifest `
    -Path $SharedDatabase `
    -Destination (Join-Path $ReportDirectory 'shared-db-after.manifest')
$sharedManifestAfter |
    Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-after.manifest.sha256')
$sharedCanonicalAfter = Write-CanonicalDatabaseManifest `
    -Path $SharedDatabase `
    -Destination (Join-Path $ReportDirectory 'shared-db-after.csv')
$sharedCanonicalAfter |
    Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-after.csv.sha256')
$sharedLogAfter = Get-FileSeal -Path $SharedLog
$sharedLogAfter | ConvertTo-Json |
    Set-Content -Encoding utf8 (Join-Path $ReportDirectory 'shared-log-after.json')
if ($sharedAfter -ne $sharedBefore) {
    throw 'Shared C:\msys64 package database changed during isolated transactions'
}
if ($sharedManifestAfter -ne $sharedManifestBefore) {
    throw 'Shared C:\msys64 package database manifest changed during isolated transactions'
}
if ($sharedCanonicalAfter -ne $sharedCanonicalBefore) {
    throw 'Shared C:\msys64 canonical package database manifest changed during isolated transactions'
}
if ($sharedLogAfter.sha256 -ne $sharedLogBefore.sha256 -or
    $sharedLogAfter.size -ne $sharedLogBefore.size) {
    throw 'Shared C:\msys64 pacman log changed during isolated transactions'
}

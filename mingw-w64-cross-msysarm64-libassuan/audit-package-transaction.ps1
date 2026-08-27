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

    [string]$SharedDatabase = 'C:\msys64\var\lib\pacman\local'
)

$ErrorActionPreference = 'Stop'
$expectedNames = @(
    'mingw-w64-cross-msysarm64-libassuan',
    'mingw-w64-cross-msysarm64-libassuan-devel',
    'mingw-w64-cross-msysarm64-libassuan-tools'
)
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
                'aarch64-pc-msys-libgpg-error=1.55'
            )
        }
        'mingw-w64-cross-msysarm64-libassuan-devel' {
            @(
                'aarch64-pc-msys-libassuan=3.0.2',
                'aarch64-pc-msys-libgpg-error-devel=1.55'
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
    foreach ($file in $files) {
        if ($file -notmatch '^(opt/aarch64-pc-msys/usr/|usr/share/licenses/)') {
            throw "$name owns path outside the approved prefixes: $file"
        }
        if ($owners.ContainsKey($file)) {
            throw "Ownership collision: $file belongs to $($owners[$file]) and $name"
        }
        $owners[$file] = $name
    }

    $hash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    $packageRecords += [pscustomobject]@{
        name = $name
        version = $version
        archive = (Resolve-Path -LiteralPath $archive).Path
        size = (Get-Item -LiteralPath $archive).Length
        sha256 = $hash
        files = $files.Count
        depends = @($info.depend)
        provides = @($info.provides)
    }
    $infoText = & $Bsdtar -xOf $archive .PKGINFO
    $infoText | Set-Content -Encoding utf8 (Join-Path $ReportDirectory "$name.PKGINFO")
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
$config = Join-Path $TransactionRoot 'pacman-local.conf'
New-Item -ItemType Directory -Force -Path $db, $cache, (Split-Path $log) | Out-Null
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

Copy-Item -LiteralPath $log -Destination (Join-Path $ReportDirectory 'transaction-pacman.log')
$sharedAfter = Get-DirectorySeal -Path $SharedDatabase
$sharedAfter | Set-Content -Encoding ascii (Join-Path $ReportDirectory 'shared-db-after.sha256')
if ($sharedAfter -ne $sharedBefore) {
    throw 'Shared C:\msys64 package database changed during isolated transactions'
}

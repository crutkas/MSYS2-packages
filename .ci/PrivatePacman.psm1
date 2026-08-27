Set-StrictMode -Version Latest

if (-not ('PrivatePacman.NativePath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PrivatePacman
{
    public static class NativePath
    {
        private const uint FileShareAll = 0x00000001 | 0x00000002 | 0x00000004;
        private const uint OpenExisting = 3;
        private const uint BackupSemantics = 0x02000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        public static string GetFinalPath(string path)
        {
            using (SafeFileHandle handle = CreateFile(
                path,
                0,
                FileShareAll,
                IntPtr.Zero,
                OpenExisting,
                BackupSemantics,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), path);
                }

                StringBuilder buffer = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0 || length >= buffer.Capacity)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), path);
                }

                string finalPath = buffer.ToString();
                if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return @"\\" + finalPath.Substring(8);
                }
                if (finalPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                {
                    return finalPath.Substring(4);
                }
                return finalPath;
            }
        }
    }
}
'@
}

enum PacmanOperationKind {
    ReadOnly
    Mutating
}

class PrivatePacmanContext {
    [string] $Root
    [string] $DbPath
    [string] $CacheDir
    [string] $LogFile
    [string] $ConfigFile
    [string] $HookDir
    [string] $GpgDir
    [string] $EvidenceDir
    [string] $PacmanPath
    [string] $RepositoryRoot
    [string] $SharedRoot
    [string] $SessionId
    [string[]] $SharedToolTreePaths
}

class PrivatePacmanResult {
    [PacmanOperationKind] $OperationKind
    [int] $ExitCode
    [string[]] $Arguments
    [string] $LogFile
    [string] $EvidenceFile
}

function Resolve-CanonicalPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $AllowDevicePath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Paths cannot be empty.'
    }
    if (-not $AllowDevicePath -and $Path -match '^(\\\\\?\\|\\\\\.\\|\\\?\?\\)') {
        throw "Windows device namespace paths are not allowed: '$Path'."
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $existingPath = $fullPath
    $suffix = [System.Collections.Generic.List[string]]::new()
    while (-not (Test-Path -LiteralPath $existingPath)) {
        $leaf = Split-Path -Path $existingPath -Leaf
        if ([string]::IsNullOrWhiteSpace($leaf)) {
            throw "Unable to find an existing ancestor while resolving '$Path'."
        }
        $suffix.Insert(0, $leaf)
        $parent = Split-Path -Path $existingPath -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $existingPath) {
            throw "Unable to find an existing ancestor while resolving '$Path'."
        }
        $existingPath = $parent
    }

    $canonical = [PrivatePacman.NativePath]::GetFinalPath($existingPath)
    foreach ($segment in $suffix) {
        $canonical = Join-Path -Path $canonical -ChildPath $segment
    }
    return [System.IO.Path]::GetFullPath($canonical)
}

function Test-SamePath {
    param(
        [Parameter(Mandatory)]
        [string] $Left,

        [Parameter(Mandatory)]
        [string] $Right
    )

    return [string]::Equals(
        $Left.TrimEnd('\', '/'),
        $Right.TrimEnd('\', '/'),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Parent
    )

    if (Test-SamePath -Left $Path -Right $Parent) {
        return $false
    }

    $parentPrefix = $Parent.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    return $Path.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-SafePrivateRoot {
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [string] $RepositoryRoot,

        [Parameter(Mandatory)]
        [string] $SharedRoot
    )

    $filesystemRoot = [System.IO.Path]::GetPathRoot($Root)
    if (Test-SamePath -Left $Root -Right $filesystemRoot) {
        throw "Private pacman root cannot be a filesystem root: '$Root'."
    }

    $home = Resolve-CanonicalPath -Path ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::UserProfile
        ))
    foreach ($forbidden in @($home, $RepositoryRoot)) {
        if (Test-SamePath -Left $Root -Right $forbidden) {
            throw "Private pacman root collides with protected path '$forbidden'."
        }
    }

    if ((Test-SamePath -Left $Root -Right $SharedRoot) -or
        (Test-PathWithin -Path $Root -Parent $SharedRoot)) {
        throw "Private pacman root resolves inside the shared MSYS2 root '$SharedRoot'."
    }
}

function Assert-IsolationLayout {
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [hashtable] $Paths
    )

    foreach ($entry in $Paths.GetEnumerator()) {
        if (-not (Test-PathWithin -Path $entry.Value -Parent $Root)) {
            throw "$($entry.Key) must resolve inside private root '$Root'; got '$($entry.Value)'."
        }
    }

    $entries = @($Paths.GetEnumerator())
    for ($left = 0; $left -lt $entries.Count; $left++) {
        for ($right = $left + 1; $right -lt $entries.Count; $right++) {
            if (Test-SamePath -Left $entries[$left].Value -Right $entries[$right].Value) {
                throw "$($entries[$left].Key) and $($entries[$right].Key) collide at '$($entries[$left].Value)'."
            }
        }
    }

    $directoryNames = @('DbPath', 'CacheDir', 'HookDir', 'GpgDir', 'EvidenceDir')
    for ($left = 0; $left -lt $directoryNames.Count; $left++) {
        for ($right = $left + 1; $right -lt $directoryNames.Count; $right++) {
            $leftPath = $Paths[$directoryNames[$left]]
            $rightPath = $Paths[$directoryNames[$right]]
            if ((Test-PathWithin -Path $leftPath -Parent $rightPath) -or
                (Test-PathWithin -Path $rightPath -Parent $leftPath)) {
                throw "$($directoryNames[$left]) and $($directoryNames[$right]) cannot contain one another."
            }
        }
    }

    foreach ($fileName in @('LogFile', 'ConfigFile')) {
        foreach ($directoryName in $directoryNames) {
            if (Test-PathWithin -Path $Paths[$fileName] -Parent $Paths[$directoryName]) {
                throw "$fileName cannot be stored inside $directoryName."
            }
        }
    }
}

function ConvertTo-PacmanConfigPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    return $Path.Replace('\', '/')
}

function New-PrivatePacmanContext {
    [CmdletBinding()]
    [OutputType([PrivatePacmanContext])]
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [string] $DbPath,

        [Parameter(Mandatory)]
        [string] $CacheDir,

        [Parameter(Mandatory)]
        [string] $LogFile,

        [Parameter(Mandatory)]
        [string] $ConfigFile,

        [Parameter(Mandatory)]
        [string] $HookDir,

        [Parameter(Mandatory)]
        [string] $GpgDir,

        [Parameter(Mandatory)]
        [string] $EvidenceDir,

        [Parameter(Mandatory)]
        [string] $PacmanPath,

        [Parameter(Mandatory)]
        [string] $RepositoryRoot,

        [Parameter(Mandatory)]
        [string] $SessionId,

        [string] $SharedRoot = 'C:\msys64',

        [string[]] $SharedToolTreePaths = @()
    )

    if ([string]::IsNullOrWhiteSpace($SessionId)) {
        throw 'SessionId must be an explicit non-empty value owned by the current package lane.'
    }

    $canonicalRoot = Resolve-CanonicalPath -Path $Root
    $canonicalRepositoryRoot = Resolve-CanonicalPath -Path $RepositoryRoot
    $canonicalSharedRoot = Resolve-CanonicalPath -Path $SharedRoot
    Assert-SafePrivateRoot `
        -Root $canonicalRoot `
        -RepositoryRoot $canonicalRepositoryRoot `
        -SharedRoot $canonicalSharedRoot

    if (Test-Path -LiteralPath $Root) {
        throw "Private pacman root must be fresh; '$Root' already exists."
    }

    $layout = @{
        DbPath = Resolve-CanonicalPath -Path $DbPath
        CacheDir = Resolve-CanonicalPath -Path $CacheDir
        LogFile = Resolve-CanonicalPath -Path $LogFile
        ConfigFile = Resolve-CanonicalPath -Path $ConfigFile
        HookDir = Resolve-CanonicalPath -Path $HookDir
        GpgDir = Resolve-CanonicalPath -Path $GpgDir
        EvidenceDir = Resolve-CanonicalPath -Path $EvidenceDir
    }
    Assert-IsolationLayout -Root $canonicalRoot -Paths $layout

    $canonicalPacmanPath = Resolve-CanonicalPath -Path $PacmanPath
    if (-not (Test-Path -LiteralPath $canonicalPacmanPath -PathType Leaf)) {
        throw "Pacman executable does not exist: '$canonicalPacmanPath'."
    }

    $canonicalToolTrees = foreach ($toolTree in $SharedToolTreePaths) {
        $canonicalToolTree = Resolve-CanonicalPath -Path $toolTree
        if (-not (Test-SamePath -Left $canonicalToolTree -Right $canonicalSharedRoot) -and
            -not (Test-PathWithin -Path $canonicalToolTree -Parent $canonicalSharedRoot)) {
            throw "Shared tool-tree observation '$canonicalToolTree' is outside '$canonicalSharedRoot'."
        }
        $canonicalToolTree
    }

    New-Item -ItemType Directory -Path $canonicalRoot -ErrorAction Stop | Out-Null
    foreach ($directory in @(
            $layout.DbPath,
            $layout.CacheDir,
            (Split-Path -Parent $layout.LogFile),
            (Split-Path -Parent $layout.ConfigFile),
            $layout.HookDir,
            $layout.GpgDir,
            $layout.EvidenceDir
        )) {
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    }

    $config = @(
        '[options]'
        "RootDir = $(ConvertTo-PacmanConfigPath -Path $canonicalRoot)"
        "DBPath = $(ConvertTo-PacmanConfigPath -Path $layout.DbPath)"
        "CacheDir = $(ConvertTo-PacmanConfigPath -Path $layout.CacheDir)"
        "LogFile = $(ConvertTo-PacmanConfigPath -Path $layout.LogFile)"
        "HookDir = $(ConvertTo-PacmanConfigPath -Path $layout.HookDir)"
        "GPGDir = $(ConvertTo-PacmanConfigPath -Path $layout.GpgDir)"
        'Architecture = auto'
        'SigLevel = Required DatabaseOptional'
        'LocalFileSigLevel = Optional'
    )
    Set-Content -LiteralPath $layout.ConfigFile -Value $config -Encoding utf8 -ErrorAction Stop

    $sentinel = [ordered]@{
        format = 1
        sessionId = $SessionId
        root = $canonicalRoot
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    $sentinelPath = Join-Path -Path $canonicalRoot -ChildPath '.private-pacman-root.json'
    $sentinel | ConvertTo-Json | Set-Content -LiteralPath $sentinelPath -Encoding utf8 -ErrorAction Stop

    $context = [PrivatePacmanContext]::new()
    $context.Root = $canonicalRoot
    $context.DbPath = $layout.DbPath
    $context.CacheDir = $layout.CacheDir
    $context.LogFile = $layout.LogFile
    $context.ConfigFile = $layout.ConfigFile
    $context.HookDir = $layout.HookDir
    $context.GpgDir = $layout.GpgDir
    $context.EvidenceDir = $layout.EvidenceDir
    $context.PacmanPath = $canonicalPacmanPath
    $context.RepositoryRoot = $canonicalRepositoryRoot
    $context.SharedRoot = $canonicalSharedRoot
    $context.SessionId = $SessionId
    $context.SharedToolTreePaths = @($canonicalToolTrees)
    return $context
}

function Get-PacmanOperationKind {
    [CmdletBinding()]
    [OutputType([PacmanOperationKind])]
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList
    )

    if ($ArgumentList.Count -eq 0) {
        return [PacmanOperationKind]::Mutating
    }

    $selector = $ArgumentList[0]
    if ($selector -in @('--query', '--deptest', '--version', '--help')) {
        return [PacmanOperationKind]::ReadOnly
    }
    if ($selector -match '^-[^-]+$' -and
        $selector -notmatch '[SRUDF]' -and
        $selector -match '[QTVh]') {
        return [PacmanOperationKind]::ReadOnly
    }

    return [PacmanOperationKind]::Mutating
}

function Get-TreeManifest {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{
            exists = $false
            entryCount = 0
            manifest = ''
            manifestHash = ''
        }
    }

    $canonicalPath = Resolve-CanonicalPath -Path $Path
    $lines = foreach ($item in @(Get-ChildItem -LiteralPath $canonicalPath -Force -Recurse -ErrorAction Stop |
            Sort-Object -Property FullName)) {
        $relative = $item.FullName.Substring($canonicalPath.Length).TrimStart(
            [char[]]@('\', '/')
        )
        if ($item.PSIsContainer) {
            "D`t$relative"
        }
        else {
            $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            "F`t$relative`t$($item.Length)`t$($item.LastWriteTimeUtc.Ticks)`t$hash"
        }
    }
    $manifest = @($lines) -join "`n"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($manifest)
        $manifestHash = [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }

    return [ordered]@{
        exists = $true
        entryCount = @($lines).Count
        manifest = $manifest
        manifestHash = $manifestHash
    }
}

function Get-SharedPacmanState {
    [CmdletBinding()]
    param(
        [string] $SharedRoot = 'C:\msys64',

        [string[]] $ToolTreePaths = @()
    )

    $canonicalSharedRoot = Resolve-CanonicalPath -Path $SharedRoot
    $logPath = Join-Path -Path $canonicalSharedRoot -ChildPath 'var\log\pacman.log'
    $localDbPath = Join-Path -Path $canonicalSharedRoot -ChildPath 'var\lib\pacman\local'

    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $log = Get-Item -LiteralPath $logPath -Force -ErrorAction Stop
        $logState = [ordered]@{
            exists = $true
            length = $log.Length
            lastWriteTimeUtcTicks = $log.LastWriteTimeUtc.Ticks
            sha256 = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    }
    else {
        $logState = [ordered]@{
            exists = $false
            length = 0
            lastWriteTimeUtcTicks = 0
            sha256 = ''
        }
    }

    $toolTrees = [ordered]@{}
    foreach ($toolTreePath in @($ToolTreePaths | Sort-Object -Unique)) {
        $canonicalToolTree = Resolve-CanonicalPath -Path $toolTreePath
        if (-not (Test-SamePath -Left $canonicalToolTree -Right $canonicalSharedRoot) -and
            -not (Test-PathWithin -Path $canonicalToolTree -Parent $canonicalSharedRoot)) {
            throw "Shared tool-tree observation '$canonicalToolTree' is outside '$canonicalSharedRoot'."
        }
        $toolTrees[$canonicalToolTree] = Get-TreeManifest -Path $canonicalToolTree
    }

    return [ordered]@{
        sharedRoot = $canonicalSharedRoot
        observedAtUtc = [DateTime]::UtcNow.ToString('o')
        pacmanLog = $logState
        localDatabase = Get-TreeManifest -Path $localDbPath
        toolTrees = $toolTrees
    }
}

function Assert-RootSentinel {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $sentinelPath = Join-Path -Path $Context.Root -ChildPath '.private-pacman-root.json'
    if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) {
        throw "Mutating operation requires root sentinel '$sentinelPath'."
    }

    $sentinel = Get-Content -LiteralPath $sentinelPath -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($sentinel.format -ne 1 -or
        $sentinel.sessionId -cne $Context.SessionId -or
        -not (Test-SamePath -Left ([string]$sentinel.root) -Right $Context.Root)) {
        throw "Root sentinel '$sentinelPath' is not owned by session '$($Context.SessionId)'."
    }
}

function Assert-ContextIsolation {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $root = Resolve-CanonicalPath -Path $Context.Root
    $repositoryRoot = Resolve-CanonicalPath -Path $Context.RepositoryRoot
    $sharedRoot = Resolve-CanonicalPath -Path $Context.SharedRoot
    Assert-SafePrivateRoot -Root $root -RepositoryRoot $repositoryRoot -SharedRoot $sharedRoot

    $layout = @{
        DbPath = Resolve-CanonicalPath -Path $Context.DbPath
        CacheDir = Resolve-CanonicalPath -Path $Context.CacheDir
        LogFile = Resolve-CanonicalPath -Path $Context.LogFile
        ConfigFile = Resolve-CanonicalPath -Path $Context.ConfigFile
        HookDir = Resolve-CanonicalPath -Path $Context.HookDir
        GpgDir = Resolve-CanonicalPath -Path $Context.GpgDir
        EvidenceDir = Resolve-CanonicalPath -Path $Context.EvidenceDir
    }
    Assert-IsolationLayout -Root $root -Paths $layout

    foreach ($propertyName in $layout.Keys) {
        if (-not (Test-SamePath -Left $Context.$propertyName -Right $layout[$propertyName])) {
            throw "$propertyName changed or now resolves outside its validated location."
        }

        $pacmanPath = Resolve-CanonicalPath -Path $Context.PacmanPath
        if (-not (Test-SamePath -Left $Context.PacmanPath -Right $pacmanPath) -or
            -not (Test-Path -LiteralPath $pacmanPath -PathType Leaf)) {
            throw 'Pacman executable changed or no longer resolves to its validated location.'
        }
    }
}

function Assert-NoEscapingReparsePoint {
    param(
        [Parameter(Mandatory)]
        [string] $Root
    )

    $canonicalRoot = Resolve-CanonicalPath -Path $Root
    $reparsePoints = @(Get-ChildItem `
            -LiteralPath $canonicalRoot `
            -Force `
            -Recurse `
            -Attributes ReparsePoint `
            -ErrorAction Stop)
    foreach ($reparsePoint in $reparsePoints) {
        $target = Resolve-CanonicalPath -Path $reparsePoint.FullName
        if (-not (Test-PathWithin -Path $target -Parent $canonicalRoot)) {
            throw "Filesystem link '$($reparsePoint.FullName)' escapes private root '$canonicalRoot'."
        }
    }
}

function Resolve-PackagePaths {
    param(
        [Parameter(Mandatory)]
        [string[]] $PackagePath,

        [Parameter(Mandatory)]
        [string] $PackageRoot
    )

    $canonicalPackageRoot = Resolve-CanonicalPath -Path $PackageRoot
    if (-not (Test-Path -LiteralPath $canonicalPackageRoot -PathType Container)) {
        throw "PackageRoot does not exist: '$canonicalPackageRoot'."
    }

    $resolved = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $PackagePath) {
        $canonicalPackagePath = Resolve-CanonicalPath -Path $path
        if (-not (Test-PathWithin -Path $canonicalPackagePath -Parent $canonicalPackageRoot)) {
            throw "Package path '$path' escapes PackageRoot '$canonicalPackageRoot'."
        }
        if (-not (Test-Path -LiteralPath $canonicalPackagePath -PathType Leaf)) {
            throw "Package path does not exist: '$canonicalPackagePath'."
        }
        $resolved.Add($canonicalPackagePath)
    }
    return $resolved.ToArray()
}

function Test-IsUpgradeOperation {
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList
    )

    foreach ($argument in $ArgumentList) {
        if ($argument -eq '--upgrade' -or $argument -match '^-[^-]*U') {
            return $true
        }
    }
    return $false
}

function Assert-NoIsolationOverrides {
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList
    )

    $longOptions = @(
        '--root',
        '--dbpath',
        '--cachedir',
        '--logfile',
        '--config',
        '--hookdir',
        '--gpgdir',
        '--sysroot'
    )
    foreach ($argument in $ArgumentList) {
        if ($argument -eq '--') {
            throw "Caller cannot supply '--'; the helper owns option termination."
        }
        $optionName = @($argument.Split('=', 2))[0]
        foreach ($option in $longOptions) {
            if ($optionName.StartsWith('--') -and
                $option.StartsWith($optionName, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Caller cannot override pacman isolation option '$option'."
            }
        }
        if ($argument -match '^-[^-]*[rb]') {
            throw "Caller cannot override pacman isolation through short option '$argument'."
        }
    }
}

function Compare-SharedPacmanState {
    param(
        [Parameter(Mandatory)]
        $Before,

        [Parameter(Mandatory)]
        $After
    )

    $beforeComparable = [ordered]@{
        sharedRoot = $Before.sharedRoot
        pacmanLog = $Before.pacmanLog
        localDatabase = $Before.localDatabase
        toolTrees = $Before.toolTrees
    } | ConvertTo-Json -Depth 8 -Compress
    $afterComparable = [ordered]@{
        sharedRoot = $After.sharedRoot
        pacmanLog = $After.pacmanLog
        localDatabase = $After.localDatabase
        toolTrees = $After.toolTrees
    } | ConvertTo-Json -Depth 8 -Compress
    return $beforeComparable -ceq $afterComparable
}

function Invoke-PrivatePacman {
    [CmdletBinding()]
    [OutputType([PrivatePacmanResult])]
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context,

        [Parameter(Mandatory)]
        [string[]] $ArgumentList,

        [string] $PackageRoot,

        [string[]] $PackagePath = @()
    )

    Assert-ContextIsolation -Context $Context
    Assert-NoIsolationOverrides -ArgumentList $ArgumentList
    $operationKind = Get-PacmanOperationKind -ArgumentList $ArgumentList
    if ($operationKind -eq [PacmanOperationKind]::Mutating) {
        Assert-RootSentinel -Context $Context
        Assert-NoEscapingReparsePoint -Root $Context.Root
    }

    $resolvedPackagePaths = @()
    if (Test-IsUpgradeOperation -ArgumentList $ArgumentList) {
        if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
            throw 'Local package upgrades require an explicit PackageRoot.'
        }
        if ($PackagePath.Count -eq 0) {
            throw 'Local package upgrades require at least one explicit PackagePath.'
        }
        if (@($ArgumentList | Where-Object { -not $_.StartsWith('-') }).Count -ne 0) {
            throw 'Pass local package files only through PackagePath, not ArgumentList.'
        }
        $resolvedPackagePaths = @(
            Resolve-PackagePaths `
                -PackagePath $PackagePath `
                -PackageRoot $PackageRoot
        )
        $operationArguments = $ArgumentList
    }
    else {
        if ($PackagePath.Count -ne 0 -or -not [string]::IsNullOrWhiteSpace($PackageRoot)) {
            throw 'PackagePath and PackageRoot are valid only for local upgrade operations.'
        }
        $operationArguments = $ArgumentList
    }

    $isolationArguments = @(
        '--root', $Context.Root,
        '--dbpath', $Context.DbPath,
        '--cachedir', $Context.CacheDir,
        '--logfile', $Context.LogFile,
        '--config', $Context.ConfigFile,
        '--hookdir', $Context.HookDir,
        '--gpgdir', $Context.GpgDir
    )
    $pacmanArguments = $operationArguments + $isolationArguments
    if ($resolvedPackagePaths.Count -ne 0) {
        $pacmanArguments += @('--') + $resolvedPackagePaths
    }

    $before = $null
    if ($operationKind -eq [PacmanOperationKind]::Mutating) {
        $before = Get-SharedPacmanState `
            -SharedRoot $Context.SharedRoot `
            -ToolTreePaths $Context.SharedToolTreePaths
    }

    $transactionId = [guid]::NewGuid().ToString('N')
    $evidenceFile = Join-Path -Path $Context.EvidenceDir -ChildPath "$transactionId.json"
    $exitCode = -1
    $invocationError = $null
    $priorMsys = [Environment]::GetEnvironmentVariable('MSYS', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('MSYS', 'winsymlinks:sys', 'Process')
        & $Context.PacmanPath @pacmanArguments
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
    }
    catch {
        $invocationError = $_
    }
    finally {
        [Environment]::SetEnvironmentVariable('MSYS', $priorMsys, 'Process')
    }

    $after = $null
    if ($operationKind -eq [PacmanOperationKind]::Mutating) {
        $after = Get-SharedPacmanState `
            -SharedRoot $Context.SharedRoot `
            -ToolTreePaths $Context.SharedToolTreePaths
    }

    $evidence = [ordered]@{
        format = 1
        transactionId = $transactionId
        sessionId = $Context.SessionId
        operationKind = $operationKind.ToString()
        pacmanPath = $Context.PacmanPath
        arguments = $pacmanArguments
        logFile = $Context.LogFile
        exitCode = $exitCode
        invocationError = if ($null -eq $invocationError) { $null } else { $invocationError.ToString() }
        sharedStateBefore = $before
        sharedStateAfter = $after
    }
    $evidence | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $evidenceFile -Encoding utf8 -ErrorAction Stop

    if ($null -ne $before -and -not (Compare-SharedPacmanState -Before $before -After $after)) {
        throw "Shared MSYS2 state changed during private pacman transaction. Evidence: '$evidenceFile'. No rollback was attempted."
    }
    if ($null -ne $invocationError) {
        throw $invocationError
    }
    if ($exitCode -ne 0) {
        throw "Pacman exited with code $exitCode. Evidence: '$evidenceFile'."
    }

    $result = [PrivatePacmanResult]::new()
    $result.OperationKind = $operationKind
    $result.ExitCode = $exitCode
    $result.Arguments = $pacmanArguments
    $result.LogFile = $Context.LogFile
    $result.EvidenceFile = $evidenceFile
    return $result
}

Export-ModuleMember -Function @(
    'Get-PacmanOperationKind',
    'Get-SharedPacmanState',
    'Invoke-PrivatePacman',
    'New-PrivatePacmanContext'
)

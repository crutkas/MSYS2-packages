Set-StrictMode -Version Latest

if (-not ('PrivatePacman.NativePath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace PrivatePacman
{
    public sealed class TreeChangeMonitor : IDisposable
    {
        private readonly FileSystemWatcher watcher;
        private readonly ConcurrentQueue<string> changes = new ConcurrentQueue<string>();
        private readonly object callbackLock = new object();
        private int activeCallbacks;
        private DateTime lastCallbackUtc = DateTime.MinValue;

        public bool Overflowed { get; private set; }

        public TreeChangeMonitor(string root)
        {
            watcher = new FileSystemWatcher(root);
            watcher.IncludeSubdirectories = true;
            watcher.NotifyFilter =
                NotifyFilters.FileName |
                NotifyFilters.DirectoryName |
                NotifyFilters.LastWrite |
                NotifyFilters.Size |
                NotifyFilters.Attributes |
                NotifyFilters.Security;
            watcher.InternalBufferSize = 65536;
            watcher.Changed += OnChanged;
            watcher.Created += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Renamed += OnRenamed;
            watcher.Error += OnError;
            watcher.EnableRaisingEvents = true;
        }

        public string[] Stop()
        {
            watcher.EnableRaisingEvents = false;
            DateTime deadline = DateTime.UtcNow.AddSeconds(5);
            lock (callbackLock)
            {
                lastCallbackUtc = DateTime.UtcNow;
                while (activeCallbacks != 0 ||
                    DateTime.UtcNow - lastCallbackUtc < TimeSpan.FromMilliseconds(250))
                {
                    TimeSpan remaining = deadline - DateTime.UtcNow;
                    if (remaining <= TimeSpan.Zero)
                    {
                        Overflowed = true;
                        changes.Enqueue("WatcherDrainTimeout");
                        break;
                    }
                    Monitor.Wait(
                        callbackLock,
                        remaining < TimeSpan.FromMilliseconds(50)
                            ? remaining
                            : TimeSpan.FromMilliseconds(50));
                }
            }
            return changes.ToArray();
        }

        private void OnChanged(object sender, FileSystemEventArgs args)
        {
            EnterCallback();
            try
            {
                changes.Enqueue(args.ChangeType + "\t" + args.FullPath);
            }
            finally
            {
                ExitCallback();
            }
        }

        private void OnRenamed(object sender, RenamedEventArgs args)
        {
            EnterCallback();
            try
            {
                changes.Enqueue("Renamed\t" + args.OldFullPath + "\t" + args.FullPath);
            }
            finally
            {
                ExitCallback();
            }
        }

        private void OnError(object sender, ErrorEventArgs args)
        {
            EnterCallback();
            try
            {
                Overflowed = true;
                changes.Enqueue("WatcherError\t" + args.GetException().GetType().FullName);
            }
            finally
            {
                ExitCallback();
            }
        }

        private void EnterCallback()
        {
            lock (callbackLock)
            {
                activeCallbacks++;
            }
        }

        private void ExitCallback()
        {
            lock (callbackLock)
            {
                lastCallbackUtc = DateTime.UtcNow;
                activeCallbacks--;
                Monitor.PulseAll(callbackLock);
            }
        }

        public void Dispose()
        {
            watcher.Dispose();
        }
    }

    public static class NativePath
    {
        private const uint FileShareAll = 0x00000001 | 0x00000002 | 0x00000004;
        private const uint FileShareRead = 0x00000001;
        private const uint GenericRead = 0x80000000;
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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectory(string path, IntPtr securityAttributes);

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out BY_HANDLE_FILE_INFORMATION information);

        public static void CreateDirectoryExclusive(string path)
        {
            if (!CreateDirectory(path, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), path);
            }
        }

        public static SafeFileHandle OpenDirectoryNoDelete(string path)
        {
            SafeFileHandle handle = CreateFile(
                path,
                GenericRead,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                BackupSemantics,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), path);
            }
            return handle;
        }

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

                return NormalizeFinalPath(buffer.ToString());
            }
        }

        public static string GetFinalPath(SafeFileHandle handle)
        {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return NormalizeFinalPath(buffer.ToString());
        }

        public static string GetFileIdentity(string path)
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

                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), path);
                }
                return String.Format(
                    "{0:X8}:{1:X8}{2:X8}",
                    information.VolumeSerialNumber,
                    information.FileIndexHigh,
                    information.FileIndexLow);
            }
        }

        private static string NormalizeFinalPath(string finalPath)
        {
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
    [string] $ConfigHash
    [string] $PrivatePacmanSeed
    [string] $SeedManifestHash
    [string] $PacmanHash
    [string] $PacmanIdentity
    [string[]] $ProtectedPacmanIdentities
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

function Assert-LocalFixedPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($Path -match '^(\\\\|\\\?\?\\)') {
        throw "$Name must use a local drive path, not UNC or a device namespace: '$Path'."
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $drive = [System.IO.DriveInfo]::new($pathRoot)
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw "$Name must use a fixed local drive; '$pathRoot' is '$($drive.DriveType)'."
    }
}

function Assert-NoReparseAncestor {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "Trusted parent directory does not exist: '$fullPath'."
    }

    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $relative = $fullPath.Substring($root.Length)
    $current = $root
    foreach ($segment in $relative.Split(
            [char[]]@('\', '/'),
            [System.StringSplitOptions]::RemoveEmptyEntries
        )) {
        $current = Join-Path -Path $current -ChildPath $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Trusted private-root parent cannot contain filesystem link '$current'."
        }
    }
}

function Get-DirectoryChain {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $chain = [System.Collections.Generic.List[string]]::new()
    $chain.Add($root)
    $relative = $fullPath.Substring($root.Length)
    $current = $root
    foreach ($segment in $relative.Split(
            [char[]]@('\', '/'),
            [System.StringSplitOptions]::RemoveEmptyEntries
        )) {
        $current = Join-Path -Path $current -ChildPath $segment
        $chain.Add($current)
    }
    return $chain.ToArray()
}

function Open-LockedDirectories {
    param(
        [Parameter(Mandatory)]
        [string[]] $DirectoryPath
    )

    $paths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($directory in $DirectoryPath) {
        foreach ($ancestor in Get-DirectoryChain -Path $directory) {
            [void]$paths.Add($ancestor)
        }
    }

    $locks = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($path in @($paths | Sort-Object { $_.Length })) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) {
                throw "Expected directory while locking private path: '$path'."
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Directory lock chain contains filesystem link '$path'."
            }

            $handle = [PrivatePacman.NativePath]::OpenDirectoryNoDelete($path)
            $lockedPath = [PrivatePacman.NativePath]::GetFinalPath($handle)
            if (-not (Test-SamePath -Left $lockedPath -Right $path)) {
                $handle.Dispose()
                throw "Directory changed filesystem identity while locking '$path'; got '$lockedPath'."
            }
            $locks.Add([pscustomobject]@{
                    Path = [System.IO.Path]::GetFullPath($path)
                    Handle = $handle
                })
        }
        return $locks.ToArray()
    }
    catch {
        foreach ($lock in $locks) {
            $lock.Handle.Dispose()
        }
        throw
    }
}

function Assert-LockedDirectoryIdentity {
    param(
        [Parameter(Mandatory)]
        [object[]] $DirectoryLock
    )

    foreach ($lock in $DirectoryLock) {
        $lockedPath = [PrivatePacman.NativePath]::GetFinalPath($lock.Handle)
        if (-not (Test-SamePath -Left $lockedPath -Right $lock.Path)) {
            throw "Locked directory identity changed for '$($lock.Path)'; got '$lockedPath'."
        }
    }
}

function New-LockedPrivateDirectories {
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [string[]] $DirectoryPath,

        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]] $DirectoryLock
    )

    $lockedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($lock in $DirectoryLock) {
        [void]$lockedPaths.Add($lock.Path)
    }

    foreach ($directory in @($DirectoryPath | Sort-Object { $_.Length })) {
        if (-not (Test-SamePath -Left $directory -Right $Root) -and
            -not (Test-PathWithin -Path $directory -Parent $Root)) {
            throw "Cannot create or lock directory outside private root: '$directory'."
        }

        foreach ($path in Get-DirectoryChain -Path $directory) {
            if (-not (Test-SamePath -Left $path -Right $Root) -and
                -not (Test-PathWithin -Path $path -Parent $Root)) {
                continue
            }
            if ($lockedPaths.Contains($path)) {
                continue
            }

            if (-not (Test-Path -LiteralPath $path)) {
                [PrivatePacman.NativePath]::CreateDirectoryExclusive($path)
            }
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Private directory is not a plain local directory: '$path'."
            }

            $handle = [PrivatePacman.NativePath]::OpenDirectoryNoDelete($path)
            $lockedPath = [PrivatePacman.NativePath]::GetFinalPath($handle)
            if (-not (Test-SamePath -Left $lockedPath -Right $path)) {
                $handle.Dispose()
                throw "Private directory changed identity while creating '$path'; got '$lockedPath'."
            }
            $DirectoryLock.Add([pscustomobject]@{
                    Path = [System.IO.Path]::GetFullPath($path)
                    Handle = $handle
                })
            [void]$lockedPaths.Add($path)
        }
    }
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

function Get-Sha256 {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Get-ProtectedPacmanIdentities {
    param(
        [Parameter(Mandatory)]
        [string] $ConfiguredSharedRoot
    )

    $identities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($protectedRoot in @('C:\msys64', $ConfiguredSharedRoot)) {
        $canonicalProtectedRoot = Resolve-CanonicalPath -Path $protectedRoot
        $protectedPacman = Join-Path $canonicalProtectedRoot 'usr\bin\pacman.exe'
        if (Test-Path -LiteralPath $protectedPacman -PathType Leaf) {
            [void]$identities.Add(
                [PrivatePacman.NativePath]::GetFileIdentity($protectedPacman)
            )
        }
    }
    return @($identities | Sort-Object)
}

function Assert-PacmanConfigIntegrity {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $actualHash = Get-Sha256 -Path $Context.ConfigFile
    if ($actualHash -cne $Context.ConfigHash) {
        throw "Private pacman config changed after creation: '$($Context.ConfigFile)'."
    }

    $unsafeDirective = '^\s*(Include|RootDir|DBPath|CacheDir|LogFile|HookDir|GPGDir)\s*='
    foreach ($line in Get-Content -LiteralPath $Context.ConfigFile -ErrorAction Stop) {
        if ($line -match $unsafeDirective) {
            throw "Private pacman config contains helper-owned or recursive directive '$($Matches[1])'."
        }
    }
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

        [string[]] $SharedToolTreePaths = @(),

        [hashtable] $Repositories = @{},

        [string] $PrivatePacmanSeed
    )

    if ([string]::IsNullOrWhiteSpace($SessionId)) {
        throw 'SessionId must be an explicit non-empty value owned by the current package lane.'
    }

    Assert-LocalFixedPath -Path $Root -Name 'Private pacman root'
    $rootParent = Split-Path -Path ([System.IO.Path]::GetFullPath($Root)) -Parent
    Assert-NoReparseAncestor -Path $rootParent

    $canonicalRoot = Resolve-CanonicalPath -Path $Root
    $canonicalRepositoryRoot = Resolve-CanonicalPath -Path $RepositoryRoot
    Assert-LocalFixedPath -Path $SharedRoot -Name 'Shared MSYS2 root'
    $canonicalSharedRoot = Resolve-CanonicalPath -Path $SharedRoot
    Assert-SafePrivateRoot `
        -Root $canonicalRoot `
        -RepositoryRoot $canonicalRepositoryRoot `
        -SharedRoot $canonicalSharedRoot
    $canonicalSystemSharedRoot = Resolve-CanonicalPath -Path 'C:\msys64'
    if (-not (Test-SamePath -Left $canonicalSharedRoot -Right $canonicalSystemSharedRoot)) {
        Assert-SafePrivateRoot `
            -Root $canonicalRoot `
            -RepositoryRoot $canonicalRepositoryRoot `
            -SharedRoot $canonicalSystemSharedRoot
    }

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
    $pacmanIsPrivate = Test-PathWithin -Path $canonicalPacmanPath -Parent $canonicalRoot
    if (-not $pacmanIsPrivate -and
        -not (Test-Path -LiteralPath $canonicalPacmanPath -PathType Leaf)) {
        throw "Pacman executable does not exist: '$canonicalPacmanPath'."
    }

    $canonicalPacmanSeed = $null
    $seedManifestHash = ''
    if (-not [string]::IsNullOrWhiteSpace($PrivatePacmanSeed)) {
        Assert-LocalFixedPath -Path $PrivatePacmanSeed -Name 'Private pacman seed'
        $canonicalPacmanSeed = Resolve-CanonicalPath -Path $PrivatePacmanSeed
        Assert-LocalFixedPath -Path $canonicalPacmanSeed -Name 'Canonical private pacman seed'
        if (-not (Test-Path -LiteralPath $canonicalPacmanSeed -PathType Container)) {
            throw "Private pacman seed does not exist: '$canonicalPacmanSeed'."
        }
        foreach ($forbiddenSeedRoot in @($canonicalSharedRoot, $canonicalSystemSharedRoot)) {
            if ((Test-SamePath -Left $canonicalPacmanSeed -Right $forbiddenSeedRoot) -or
                (Test-PathWithin -Path $canonicalPacmanSeed -Parent $forbiddenSeedRoot)) {
                throw "Private pacman seed cannot come from shared MSYS2 root '$forbiddenSeedRoot'."
            }
        }
        Assert-NoEscapingReparsePoint -Root $canonicalPacmanSeed
        $seedManifestHash = (Get-TreeManifest -Path $canonicalPacmanSeed -OmitManifest).manifestHash
    }
    elseif ($pacmanIsPrivate) {
        throw 'A private PacmanPath requires constructor-established PrivatePacmanSeed provenance.'
    }

    $canonicalToolTrees = foreach ($toolTree in $SharedToolTreePaths) {
        $canonicalToolTree = Resolve-CanonicalPath -Path $toolTree
        if (-not (Test-SamePath -Left $canonicalToolTree -Right $canonicalSharedRoot) -and
            -not (Test-PathWithin -Path $canonicalToolTree -Parent $canonicalSharedRoot)) {
            throw "Shared tool-tree observation '$canonicalToolTree' is outside '$canonicalSharedRoot'."
        }
        $canonicalToolTree
    }

    $creationLocks = [System.Collections.Generic.List[object]]::new()
    foreach ($creationLock in @(Open-LockedDirectories -DirectoryPath @($rootParent))) {
        $creationLocks.Add($creationLock)
    }
    try {
        $canonicalRoot = Resolve-CanonicalPath -Path $Root
        Assert-SafePrivateRoot `
            -Root $canonicalRoot `
            -RepositoryRoot $canonicalRepositoryRoot `
            -SharedRoot $canonicalSharedRoot
        if (-not (Test-SamePath -Left $canonicalSharedRoot -Right $canonicalSystemSharedRoot)) {
            Assert-SafePrivateRoot `
                -Root $canonicalRoot `
                -RepositoryRoot $canonicalRepositoryRoot `
                -SharedRoot $canonicalSystemSharedRoot
        }
        Assert-LockedDirectoryIdentity -DirectoryLock $creationLocks
        [PrivatePacman.NativePath]::CreateDirectoryExclusive($canonicalRoot)
        if ($null -ne $canonicalPacmanSeed) {
            Get-ChildItem -LiteralPath $canonicalPacmanSeed -Force -ErrorAction Stop |
                Copy-Item -Destination $canonicalRoot -Recurse -Force -ErrorAction Stop
            $postCopySeedHash = (
                Get-TreeManifest -Path $canonicalPacmanSeed -OmitManifest
            ).manifestHash
            $copiedSeedHash = (
                Get-TreeManifest -Path $canonicalRoot -OmitManifest
            ).manifestHash
            if ($postCopySeedHash -cne $seedManifestHash -or
                $copiedSeedHash -cne $seedManifestHash) {
                throw 'Private pacman seed changed during construction or did not copy exactly.'
            }
        }
        $managedDirectories = @(
            $canonicalRoot
            $layout.DbPath
            $layout.CacheDir
            (Split-Path -Parent $layout.LogFile)
            (Split-Path -Parent $layout.ConfigFile)
            $layout.HookDir
            $layout.GpgDir
            $layout.EvidenceDir
        )
        if ($pacmanIsPrivate) {
            $managedDirectories += Split-Path -Parent $canonicalPacmanPath
        }
        New-LockedPrivateDirectories `
            -Root $canonicalRoot `
            -DirectoryPath $managedDirectories `
            -DirectoryLock $creationLocks

        $config = [System.Collections.Generic.List[string]]::new()
        foreach ($line in @(
            '[options]'
            'Architecture = auto'
            'SigLevel = Required DatabaseOptional'
            'LocalFileSigLevel = Optional'
        )) {
            $config.Add($line)
        }
        foreach ($repositoryName in @($Repositories.Keys | Sort-Object)) {
            if ($repositoryName -notmatch '^[A-Za-z0-9_.-]+$') {
                throw "Unsafe pacman repository name '$repositoryName'."
            }
            $servers = @($Repositories[$repositoryName])
            if ($servers.Count -eq 0) {
                throw "Pacman repository '$repositoryName' requires at least one HTTPS server."
            }
            $config.Add('')
            $config.Add("[$repositoryName]")
            foreach ($server in $servers) {
                if ($server -notmatch '^https://\S+$') {
                    throw "Pacman repository '$repositoryName' has unsafe server '$server'; only whitespace-free HTTPS URLs are allowed."
                }
                $config.Add("Server = $server")
            }
        }
        Set-Content -LiteralPath $layout.ConfigFile -Value $config -Encoding utf8 -ErrorAction Stop
        $configHash = Get-Sha256 -Path $layout.ConfigFile

        $pacmanHash = Get-Sha256 -Path $canonicalPacmanPath
        $pacmanIdentity = [PrivatePacman.NativePath]::GetFileIdentity($canonicalPacmanPath)
        $protectedPacmanIdentities = @(
            Get-ProtectedPacmanIdentities -ConfiguredSharedRoot $canonicalSharedRoot
        )
        if ($pacmanIdentity -cin $protectedPacmanIdentities) {
            throw 'Private PacmanPath is a hardlink to a protected shared pacman executable.'
        }

        $sentinel = [ordered]@{
            format = 1
            sessionId = $SessionId
            root = $canonicalRoot
            configHash = $configHash
            privatePacmanSeed = $canonicalPacmanSeed
            seedManifestHash = $seedManifestHash
            pacmanHash = $pacmanHash
            pacmanIdentity = $pacmanIdentity
            protectedPacmanIdentities = $protectedPacmanIdentities
            sharedRoot = $canonicalSharedRoot
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
        $context.ConfigHash = $configHash
        $context.PrivatePacmanSeed = $canonicalPacmanSeed
        $context.SeedManifestHash = $seedManifestHash
        $context.PacmanHash = $pacmanHash
        $context.PacmanIdentity = $pacmanIdentity
        $context.ProtectedPacmanIdentities = $protectedPacmanIdentities
        $context.SharedToolTreePaths = @($canonicalToolTrees)
        if (-not (Test-Path -LiteralPath $context.PacmanPath -PathType Leaf) -and
            $null -ne $canonicalPacmanSeed) {
            throw "Private pacman seed did not provide PacmanPath '$($context.PacmanPath)'."
        }
        Assert-PacmanConfigIntegrity -Context $context
        return $context
    }
    finally {
        foreach ($creationLock in $creationLocks) {
            $creationLock.Handle.Dispose()
        }
    }
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
    if ($selector -cin @('--query', '--deptest', '--version', '--help')) {
        return [PacmanOperationKind]::ReadOnly
    }
    if ($selector -cmatch '^-[^-]+$' -and
        $selector -cnotmatch '[SRUDF]' -and
        $selector -cmatch '[QTVh]') {
        return [PacmanOperationKind]::ReadOnly
    }

    return [PacmanOperationKind]::Mutating
}

function Get-TreeManifest {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $OmitManifest,

        [switch] $MetadataOnly
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
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $targets = @($item.Target) -join '|'
                $finalTarget = Resolve-CanonicalPath -Path $item.FullName
                "L`t$relative`t$($item.LinkType)`t$targets`t$finalTarget"
            }
            else {
                "D`t$relative"
            }
        }
        else {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $targets = @($item.Target) -join '|'
                $finalTarget = Resolve-CanonicalPath -Path $item.FullName
                "L`t$relative`t$($item.LinkType)`t$targets`t$finalTarget"
            }
            else {
                if ($MetadataOnly) {
                    "F`t$relative`t$($item.Length)`t$($item.LastWriteTimeUtc.Ticks)`t$([int]$item.Attributes)"
                }
                else {
                    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    "F`t$relative`t$($item.Length)`t$($item.LastWriteTimeUtc.Ticks)`t$hash"
                }
            }
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
        manifest = if ($OmitManifest) { '' } else { $manifest }
        manifestHash = $manifestHash
    }
}

function Get-SharedPacmanState {
    [CmdletBinding()]
    param(
        [string] $SharedRoot = 'C:\msys64',

        [string[]] $ToolTreePaths = @(),

        [switch] $SkipProtectedRootScan
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

    if ($SkipProtectedRootScan) {
        $protectedRoot = [ordered]@{
            exists = $true
            entryCount = 0
            manifest = ''
            manifestHash = [PrivatePacman.NativePath]::GetFileIdentity($canonicalSharedRoot)
        }
    }
    else {
        $protectedRoot = Get-TreeManifest `
            -Path $canonicalSharedRoot `
            -OmitManifest `
            -MetadataOnly
    }

    return [ordered]@{
        sharedRoot = $canonicalSharedRoot
        observedAtUtc = [DateTime]::UtcNow.ToString('o')
        pacmanLog = $logState
        localDatabase = Get-TreeManifest -Path $localDbPath
        protectedRoot = $protectedRoot
        toolTrees = $toolTrees
    }
}

function Get-ProtectedPacmanState {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $systemRoot = Resolve-CanonicalPath -Path 'C:\msys64'
    $systemState = Get-SharedPacmanState -SharedRoot $systemRoot -SkipProtectedRootScan
    $configuredRoot = Resolve-CanonicalPath -Path $Context.SharedRoot
    $configuredState = $null
    if (Test-SamePath -Left $configuredRoot -Right $systemRoot) {
        if ($Context.SharedToolTreePaths.Count -ne 0) {
            $systemState = Get-SharedPacmanState `
                -SharedRoot $systemRoot `
                -ToolTreePaths $Context.SharedToolTreePaths `
                -SkipProtectedRootScan
        }
    }
    else {
        $configuredState = Get-SharedPacmanState `
            -SharedRoot $configuredRoot `
            -ToolTreePaths $Context.SharedToolTreePaths `
            -SkipProtectedRootScan
    }

    return [ordered]@{
        systemRoot = $systemState
        configuredRoot = $configuredState
    }
}

function Start-ProtectedRootMonitors {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $roots = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    [void]$roots.Add((Resolve-CanonicalPath -Path 'C:\msys64'))
    [void]$roots.Add((Resolve-CanonicalPath -Path $Context.SharedRoot))

    $monitors = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($root in @($roots | Sort-Object)) {
            $monitors.Add([pscustomobject]@{
                    Root = $root
                    Monitor = [PrivatePacman.TreeChangeMonitor]::new($root)
                })
        }
        return $monitors.ToArray()
    }
    catch {
        foreach ($entry in $monitors) {
            $entry.Monitor.Dispose()
        }
        throw
    }
}

function Stop-ProtectedRootMonitors {
    param(
        [Parameter(Mandatory)]
        [object[]] $Monitor
    )

    $result = [ordered]@{}
    foreach ($entry in $Monitor) {
        $events = @()
        $captureError = $null
        try {
            $events = @($entry.Monitor.Stop() | Sort-Object)
        }
        catch {
            $captureError = $_.Exception.ToString()
        }
        finally {
            try {
                $entry.Monitor.Dispose()
            }
            catch {
                if ($null -eq $captureError) {
                    $captureError = $_.Exception.ToString()
                }
                else {
                    $captureError += "`nDispose failure: $($_.Exception)"
                }
            }
        }

        try {
            $eventText = $events -join "`n"
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $hash = [BitConverter]::ToString(
                    $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($eventText))
                ).Replace('-', '')
            }
            finally {
                $sha256.Dispose()
            }
            $result[$entry.Root] = [ordered]@{
                overflowed = $entry.Monitor.Overflowed
                changeCount = $events.Count
                changeHash = $hash
                changes = $events
                captureError = $captureError
            }
        }
        catch {
            $result[$entry.Root] = [ordered]@{
                overflowed = $true
                changeCount = $events.Count
                changeHash = $null
                changes = $events
                captureError = $_.Exception.ToString()
            }
        }
    }
    return $result
}

function Get-ProtectedRootChangeSummary {
    param(
        [Parameter(Mandatory)]
        [object] $RootChanges
    )

    $firstChange = @($RootChanges.changes | Select-Object -First 1)
    if ($firstChange.Count -ne 0) {
        return $firstChange[0]
    }
    if (-not [string]::IsNullOrWhiteSpace($RootChanges.captureError)) {
        return "WatcherCaptureError: $($RootChanges.captureError)"
    }
    return 'WatcherOverflow'
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
        $sentinel.configHash -cne $Context.ConfigHash -or
        $sentinel.privatePacmanSeed -cne $Context.PrivatePacmanSeed -or
        $sentinel.seedManifestHash -cne $Context.SeedManifestHash -or
        $sentinel.pacmanHash -cne $Context.PacmanHash -or
        $sentinel.pacmanIdentity -cne $Context.PacmanIdentity -or
        (@($sentinel.protectedPacmanIdentities) -join '|') -cne
            (@($Context.ProtectedPacmanIdentities) -join '|') -or
        -not (Test-SamePath -Left ([string]$sentinel.sharedRoot) -Right $Context.SharedRoot) -or
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
    Assert-LocalFixedPath -Path $root -Name 'Private pacman root'
    $repositoryRoot = Resolve-CanonicalPath -Path $Context.RepositoryRoot
    $sharedRoot = Resolve-CanonicalPath -Path $Context.SharedRoot
    Assert-SafePrivateRoot -Root $root -RepositoryRoot $repositoryRoot -SharedRoot $sharedRoot
    $systemSharedRoot = Resolve-CanonicalPath -Path 'C:\msys64'
    if (-not (Test-SamePath -Left $sharedRoot -Right $systemSharedRoot)) {
        Assert-SafePrivateRoot `
            -Root $root `
            -RepositoryRoot $repositoryRoot `
            -SharedRoot $systemSharedRoot
    }

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
    }

    $pacmanPath = Resolve-CanonicalPath -Path $Context.PacmanPath
    if (-not (Test-SamePath -Left $Context.PacmanPath -Right $pacmanPath) -or
        -not (Test-Path -LiteralPath $pacmanPath -PathType Leaf)) {
        throw 'Pacman executable changed or no longer resolves to its validated location.'
    }
    $pacmanHash = Get-Sha256 -Path $pacmanPath
    $pacmanIdentity = [PrivatePacman.NativePath]::GetFileIdentity($pacmanPath)
    if ($pacmanHash -cne $Context.PacmanHash -or
        $pacmanIdentity -cne $Context.PacmanIdentity) {
        throw 'Pacman executable no longer matches its constructor-established hash and file identity.'
    }
    $protectedPacmanIdentities = @(
        Get-ProtectedPacmanIdentities -ConfiguredSharedRoot $Context.SharedRoot
    )
    if ((@($protectedPacmanIdentities) -join '|') -cne
        (@($Context.ProtectedPacmanIdentities) -join '|')) {
        throw 'Protected shared pacman identity set changed after context construction.'
    }
    if ($pacmanIdentity -cin $protectedPacmanIdentities) {
        throw 'Pacman executable is a hardlink to a protected shared pacman executable.'
    }
    Assert-PacmanConfigIntegrity -Context $Context
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

    foreach ($file in @(Get-ChildItem `
            -LiteralPath $canonicalRoot `
            -File `
            -Force `
            -Recurse `
            -ErrorAction Stop)) {
        if ($file.Extension -ieq '.lnk') {
            throw "Windows shortcut links are not allowed in private pacman root: '$($file.FullName)'."
        }
        if ($file.Length -lt 10) {
            continue
        }

        $stream = [System.IO.File]::Open(
            $file.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        )
        try {
            $header = [byte[]]::new(10)
            if ($stream.Read($header, 0, $header.Length) -eq $header.Length -and
                [System.Text.Encoding]::ASCII.GetString($header) -ceq '!<symlink>') {
                throw "Cygwin magic-file symlinks are not allowed in private pacman root: '$($file.FullName)'."
            }
        }
        finally {
            $stream.Dispose()
        }
    }
}

function Assert-EmptyPacmanHooks {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $hookPaths = @(
        $Context.HookDir
        (Join-Path -Path $Context.Root -ChildPath 'usr\share\libalpm\hooks')
    )
    foreach ($hookPath in $hookPaths) {
        if (-not (Test-Path -LiteralPath $hookPath)) {
            continue
        }
        $canonicalHookPath = Resolve-CanonicalPath -Path $hookPath
        if (-not (Test-PathWithin -Path $canonicalHookPath -Parent $Context.Root)) {
            throw "Pacman hook directory escapes private root: '$hookPath'."
        }
        if (-not (Test-Path -LiteralPath $canonicalHookPath -PathType Container)) {
            throw "Pacman hook location is not a directory: '$canonicalHookPath'."
        }
        if ($null -ne (Get-ChildItem -LiteralPath $canonicalHookPath -Force -ErrorAction Stop |
                Select-Object -First 1)) {
            throw "Pacman hook directory must be empty for mutating operations: '$canonicalHookPath'."
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
        if ($path -ceq '-') {
            throw "PackagePath cannot be '-' because pacman treats it as standard input."
        }
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
        if ($argument -ceq '--upgrade' -or $argument -cmatch '^-[^-]*U') {
            return $true
        }
    }
    return $false
}

function Test-SupportsNoScriptlet {
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList
    )

    if ($ArgumentList.Count -eq 0) {
        return $false
    }
    foreach ($argument in $ArgumentList) {
        if ($argument -ceq '--print' -or $argument -cmatch '^-[^-]*p') {
            return $false
        }
    }

    $selector = $ArgumentList[0]
    if ($selector -cin @('--sync', '--remove', '--upgrade')) {
        return $true
    }
    return $selector -cmatch '^-[^-]*[SRU]'
}

function Assert-PacmanCommandShape {
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList
    )

    if ($ArgumentList.Count -eq 0) {
        throw 'ArgumentList requires an exact pacman operation selector as its first argument.'
    }

    $longOperations = @(
        '--query',
        '--deptest',
        '--version',
        '--help',
        '--sync',
        '--remove',
        '--upgrade',
        '--database',
        '--files'
    )
    $selector = $ArgumentList[0]
    $validLongSelector = $selector -cin $longOperations
    $validShortSelector = $false
    if ($selector -cmatch '^-[^-]+$') {
        $operationCount = 0
        foreach ($character in $selector.Substring(1).ToCharArray()) {
            if ('QTVhSRUDF'.IndexOf($character) -ge 0) {
                $operationCount++
            }
        }
        $validShortSelector = $operationCount -eq 1
    }
    if (-not $validLongSelector -and -not $validShortSelector) {
        throw "First argument must be one exact pacman operation selector; got '$selector'."
    }

    foreach ($argument in @($ArgumentList | Select-Object -Skip 1)) {
        $optionName = @($argument.Split('=', 2))[0]
        foreach ($operation in $longOperations) {
            if ($optionName.StartsWith('--') -and
                $operation.StartsWith($optionName, [System.StringComparison]::Ordinal)) {
                throw "Pacman operation selector '$argument' must be the first argument."
            }
        }
        if ($argument -cmatch '^-[^-]*[QTVhSRUDF]') {
            throw "Pacman operation selector '$argument' must be the first argument."
        }
    }
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
        if ($argument -ceq '-') {
            throw "Pacman target '-' is not allowed because it reads from standard input."
        }
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
        if ($argument -cmatch '^-[^-]*[rb]') {
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
        systemRoot = [ordered]@{
            sharedRoot = $Before.systemRoot.sharedRoot
            pacmanLog = $Before.systemRoot.pacmanLog
            localDatabase = $Before.systemRoot.localDatabase
            protectedRoot = $Before.systemRoot.protectedRoot
            toolTrees = $Before.systemRoot.toolTrees
        }
        configuredRoot = if ($null -eq $Before.configuredRoot) {
            $null
        }
        else {
            [ordered]@{
                sharedRoot = $Before.configuredRoot.sharedRoot
                pacmanLog = $Before.configuredRoot.pacmanLog
                localDatabase = $Before.configuredRoot.localDatabase
                protectedRoot = $Before.configuredRoot.protectedRoot
                toolTrees = $Before.configuredRoot.toolTrees
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress
    $afterComparable = [ordered]@{
        systemRoot = [ordered]@{
            sharedRoot = $After.systemRoot.sharedRoot
            pacmanLog = $After.systemRoot.pacmanLog
            localDatabase = $After.systemRoot.localDatabase
            protectedRoot = $After.systemRoot.protectedRoot
            toolTrees = $After.systemRoot.toolTrees
        }
        configuredRoot = if ($null -eq $After.configuredRoot) {
            $null
        }
        else {
            [ordered]@{
                sharedRoot = $After.configuredRoot.sharedRoot
                pacmanLog = $After.configuredRoot.pacmanLog
                localDatabase = $After.configuredRoot.localDatabase
                protectedRoot = $After.configuredRoot.protectedRoot
                toolTrees = $After.configuredRoot.toolTrees
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress
    return $beforeComparable -ceq $afterComparable
}

function Open-LockedReadFile {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $lockedPath = [PrivatePacman.NativePath]::GetFinalPath($stream.SafeFileHandle)
        if (-not (Test-SamePath -Left $lockedPath -Right $Path)) {
            throw "$Name changed filesystem identity before launch: '$Path' resolved to '$lockedPath'."
        }
        return $stream
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Get-PrivatePacmanState {
    param(
        [Parameter(Mandatory)]
        [PrivatePacmanContext] $Context
    )

    $owners = [ordered]@{}
    foreach ($path in @(
            $Context.Root
            $Context.DbPath
            $Context.CacheDir
            (Split-Path -Parent $Context.LogFile)
            (Split-Path -Parent $Context.ConfigFile)
            $Context.HookDir
            $Context.GpgDir
            $Context.EvidenceDir
            (Split-Path -Parent $Context.PacmanPath)
        ) | Sort-Object -Unique) {
        $owners[$path] = (Get-Acl -LiteralPath $path -ErrorAction Stop).Owner
    }

    return [ordered]@{
        root = Get-TreeManifest -Path $Context.Root -OmitManifest -MetadataOnly
        localDatabase = Get-TreeManifest -Path $Context.DbPath -OmitManifest -MetadataOnly
        cache = Get-TreeManifest -Path $Context.CacheDir -OmitManifest -MetadataOnly
        owners = $owners
    }
}

function Get-FileLength {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [long]0
    }
    return (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length
}

function Assert-NoPacmanLogFailure {
    param(
        [Parameter(Mandatory)]
        [string] $LogFile,

        [Parameter(Mandatory)]
        [long] $StartLength
    )

    if (-not (Test-Path -LiteralPath $LogFile -PathType Leaf)) {
        return
    }
    $stream = [System.IO.File]::Open(
        $LogFile,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    )
    try {
        if ($stream.Length -le $StartLength) {
            return
        }
        [void]$stream.Seek($StartLength, [System.IO.SeekOrigin]::Begin)
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $true, 4096, $true)
        try {
            $newLogContent = $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    $failurePattern = @'
(?im)^(?!.*\[PACMAN\]\s+Running\s).*\[(?:ALPM|PACMAN|ALPM-SCRIPTLET)\]\s+(?:error:|(?:transaction|file operation)\s+(?:failed|failure)\b|failed to (?:commit|install|upgrade|remove|unlink|rename|write|open)\b|could not (?:commit|install|upgrade|remove|unlink|rename|write|open)\b|cannot (?:commit|install|upgrade|remove|unlink|rename|write|open)\b)
'@.Trim()
    if ($newLogContent -match $failurePattern) {
        throw "Pacman logged a file or transaction failure despite its process exit code: '$LogFile'."
    }
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
    Assert-PacmanCommandShape -ArgumentList $ArgumentList
    Assert-NoIsolationOverrides -ArgumentList $ArgumentList
    $operationKind = Get-PacmanOperationKind -ArgumentList $ArgumentList
    if ($operationKind -eq [PacmanOperationKind]::Mutating) {
        if ([string]::IsNullOrWhiteSpace($Context.PrivatePacmanSeed) -or
            [string]::IsNullOrWhiteSpace($Context.SeedManifestHash) -or
            [string]::IsNullOrWhiteSpace($Context.PacmanHash) -or
            [string]::IsNullOrWhiteSpace($Context.PacmanIdentity)) {
            throw 'Mutating operations require constructor-established private pacman seed provenance.'
        }
        if (-not (Test-PathWithin -Path $Context.PacmanPath -Parent $Context.Root)) {
            throw 'Mutating operations require PacmanPath itself to be inside the private root.'
        }
        Assert-RootSentinel -Context $Context
        Assert-EmptyPacmanHooks -Context $Context
    }

    $resolvedPackagePaths = @()
    if (Test-IsUpgradeOperation -ArgumentList $ArgumentList) {
        if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
            throw 'Local package upgrades require an explicit PackageRoot.'
        }
        if ($PackagePath.Count -eq 0) {
            throw 'Local package upgrades require at least one explicit PackagePath.'
        }
        if ('-' -in $ArgumentList) {
            throw "Local package upgrades cannot use '-' as a standard-input package target."
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
    if (Test-SupportsNoScriptlet -ArgumentList $operationArguments) {
        $isolationArguments += '--noscriptlet'
    }
    $pacmanArguments = $isolationArguments + $operationArguments
    if ($resolvedPackagePaths.Count -ne 0) {
        $pacmanArguments += @('--') + $resolvedPackagePaths
    }

    $before = $null
    $privateBefore = $null
    $privateLogStart = Get-FileLength -Path $Context.LogFile
    $protectedMonitors = @()
    $protectedRootChanges = $null
    if ($operationKind -eq [PacmanOperationKind]::Mutating) {
        try {
            $before = Get-ProtectedPacmanState -Context $Context
            $privateBefore = Get-PrivatePacmanState -Context $Context
            $protectedMonitors = @(Start-ProtectedRootMonitors -Context $Context)
        }
        catch {
            if ($protectedMonitors.Count -ne 0) {
                [void](Stop-ProtectedRootMonitors -Monitor $protectedMonitors)
            }
            throw
        }
    }

    $transactionId = [guid]::NewGuid().ToString('N')
    $evidenceFile = Join-Path -Path $Context.EvidenceDir -ChildPath "$transactionId.json"
    $exitCode = -1
    $invocationError = $null
    $lockedFiles = [System.Collections.Generic.List[System.IDisposable]]::new()
    $lockedDirectories = @()
    $process = $null
    try {
        if ($operationKind -eq [PacmanOperationKind]::Mutating) {
            Assert-NoEscapingReparsePoint -Root $Context.Root
        }
        $directoryPaths = @(
            $Context.Root
            $Context.DbPath
            $Context.CacheDir
            (Split-Path -Parent $Context.LogFile)
            (Split-Path -Parent $Context.ConfigFile)
            $Context.HookDir
            $Context.GpgDir
            $Context.EvidenceDir
            (Split-Path -Parent $Context.PacmanPath)
        )
        $lockedDirectories = @(Open-LockedDirectories -DirectoryPath $directoryPaths)
        $configLock = Open-LockedReadFile -Path $Context.ConfigFile -Name 'Pacman config'
        $lockedFiles.Add($configLock)
        $pacmanLock = Open-LockedReadFile -Path $Context.PacmanPath -Name 'Pacman executable'
        $lockedFiles.Add($pacmanLock)
        Assert-PacmanConfigIntegrity -Context $Context
        foreach ($package in $resolvedPackagePaths) {
            $lockedFiles.Add((Open-LockedReadFile -Path $package -Name 'Package file'))
        }

        Assert-ContextIsolation -Context $Context
        Assert-LockedDirectoryIdentity -DirectoryLock $lockedDirectories
        if ($operationKind -eq [PacmanOperationKind]::Mutating) {
            Assert-EmptyPacmanHooks -Context $Context
        }

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $Context.PacmanPath
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.CreateNoWindow = $true
        if ($null -eq $startInfo.ArgumentList) {
            throw 'ProcessStartInfo.ArgumentList is required; run the helper with PowerShell 7 or newer.'
        }
        foreach ($argument in $pacmanArguments) {
            $startInfo.ArgumentList.Add($argument)
        }
        [void]$startInfo.Environment.Remove('POSIXLY_CORRECT')
        $startInfo.Environment['MSYS'] = 'winsymlinks:nativestrict'

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "Failed to start pacman executable '$($Context.PacmanPath)'."
        }
        $process.StandardInput.Close()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        Assert-NoPacmanLogFailure -LogFile $Context.LogFile -StartLength $privateLogStart

        Assert-ContextIsolation -Context $Context
        Assert-LockedDirectoryIdentity -DirectoryLock $lockedDirectories
        if ($operationKind -eq [PacmanOperationKind]::Mutating) {
            Assert-NoEscapingReparsePoint -Root $Context.Root
            Assert-EmptyPacmanHooks -Context $Context
        }
    }
    catch {
        $invocationError = $_
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
        foreach ($lockedFile in $lockedFiles) {
            $lockedFile.Dispose()
        }
        foreach ($lockedDirectory in $lockedDirectories) {
            $lockedDirectory.Handle.Dispose()
        }
    }

    $after = $null
    $privateAfter = $null
    $postCaptureErrors = [System.Collections.Generic.List[string]]::new()
    if ($operationKind -eq [PacmanOperationKind]::Mutating) {
        try {
            $protectedRootChanges = Stop-ProtectedRootMonitors -Monitor $protectedMonitors
            foreach ($rootChanges in @($protectedRootChanges.Values)) {
                if ($null -ne $rootChanges.captureError) {
                    $postCaptureErrors.Add(
                        "Protected-root monitor capture failed: $($rootChanges.captureError)"
                    )
                }
            }
        }
        catch {
            $postCaptureErrors.Add("Protected-root monitor shutdown failed: $($_.Exception)")
        }
        finally {
            $protectedMonitors = @()
        }
        try {
            $after = Get-ProtectedPacmanState -Context $Context
        }
        catch {
            $postCaptureErrors.Add("Protected pacman state capture failed: $($_.Exception)")
        }
        try {
            $privateAfter = Get-PrivatePacmanState -Context $Context
        }
        catch {
            $postCaptureErrors.Add("Private pacman state capture failed: $($_.Exception)")
        }
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
        privateStateBefore = $privateBefore
        privateStateAfter = $privateAfter
        protectedRootChanges = $protectedRootChanges
        postCaptureErrors = @($postCaptureErrors)
    }
    $evidence | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $evidenceFile -Encoding utf8 -ErrorAction Stop

    if ($null -ne $before -and $null -ne $after -and
        -not (Compare-SharedPacmanState -Before $before -After $after)) {
        throw "Shared MSYS2 state changed during private pacman transaction. Evidence: '$evidenceFile'. No rollback was attempted."
    }
    if ($null -ne $protectedRootChanges) {
        foreach ($rootChanges in @($protectedRootChanges.Values)) {
            if ($rootChanges.overflowed -or $rootChanges.changeCount -ne 0) {
                $firstChange = Get-ProtectedRootChangeSummary -RootChanges $rootChanges
                throw "Protected MSYS2 root changed during private pacman transaction ('$firstChange'). Evidence: '$evidenceFile'. No rollback was attempted."
            }
        }
    }
    if ($postCaptureErrors.Count -ne 0) {
        throw "Post-transaction evidence capture failed. Evidence: '$evidenceFile'."
    }
    if ($null -ne $invocationError) {
        throw $invocationError
    }
    if ($exitCode -ne 0) {
        throw "Pacman exited with code $exitCode. Evidence: '$evidenceFile'."
    }
    if ($null -ne $privateBefore -and
        (($privateBefore.owners | ConvertTo-Json -Compress) -cne
            ($privateAfter.owners | ConvertTo-Json -Compress))) {
        throw "Private pacman invariant ownership changed during transaction. Evidence: '$evidenceFile'."
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

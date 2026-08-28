Set-StrictMode -Version Latest

$script:PrivatePacmanSchema = 'private-pacman-session/v2'
$script:OwnershipManifestSchema = 'private-pacman-package-ownership/v2'
$script:OwnershipSignatureAlgorithm = 'ecdsa-p256-sha256'
$script:CanonicalSharedRoot = 'C:\msys64'
$script:OwnerFileName = '.private-pacman-owner.json'
$script:TestSnapshotBarrier = $null
$script:RequiredIsolationSwitches = @(
    '--root',
    '--dbpath',
    '--cachedir',
    '--logfile',
    '--config',
    '--hookdir',
    '--gpgdir'
)

$nativeType = [System.Management.Automation.PSTypeName]'PrivatePacmanV2.NativePath'
if ($null -eq $nativeType.Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PrivatePacmanV2
{
    public sealed class FileIdentity
    {
        public string FinalPath { get; set; }
        public string Identity { get; set; }
        public uint LinkCount { get; set; }
    }

    public sealed class SecurityState
    {
        public string OwnerSid { get; set; }
        public string SecurityDescriptorSddl { get; set; }
        public long ChangeTimeFileTime { get; set; }
        public uint FileAttributes { get; set; }
        public string Identity { get; set; }
    }

    public static class NativePath
    {
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;
        private const uint FileReadAttributes = 0x00000080;
        private const uint ReadControl = 0x00020000;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint GroupSecurityInformation = 0x00000002;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint SecurityInformation =
            OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation;
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
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

        [StructLayout(LayoutKind.Sequential)]
        private struct FileBasicInformation
        {
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public long ChangeTime;
            public uint FileAttributes;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Win32FindStreamData
        {
            public long StreamSize;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string StreamName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder filePath,
            uint filePathSize,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int fileInformationClass,
            out FileBasicInformation information,
            uint bufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string deviceName,
            StringBuilder targetPath,
            int maximumLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInformation,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr securityDescriptor,
            uint requestedStringSdRevision,
            uint securityInformation,
            out IntPtr stringSecurityDescriptor,
            out uint stringSecurityDescriptorLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstStreamW(
            string fileName,
            int infoLevel,
            out Win32FindStreamData findStreamData,
            uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextStreamW(
            IntPtr findStream,
            out Win32FindStreamData findStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr findFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        private static string StripExtendedPrefix(string path)
        {
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + path.Substring(8);
            }

            if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                return path.Substring(4);
            }

            return path;
        }

        public static string GetFinalPath(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                0,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open path: " + path);
                }

                return GetFinalPath(handle);
            }
        }

        public static string GetFinalPath(SafeFileHandle handle)
        {
            int capacity = 512;
            while (true)
            {
                StringBuilder buffer = new StringBuilder(capacity);
                uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resolve an open file handle.");
                }

                if (length < buffer.Capacity)
                {
                    return StripExtendedPrefix(buffer.ToString());
                }

                capacity = checked((int)length + 1);
            }
        }

        public static FileIdentity GetIdentity(SafeFileHandle handle)
        {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify an open file handle.");
            }

            ulong fileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
            return new FileIdentity
            {
                FinalPath = GetFinalPath(handle),
                Identity = information.VolumeSerialNumber.ToString("x8") + ":" + fileIndex.ToString("x16"),
                LinkCount = information.NumberOfLinks
            };
        }

        public static string QueryDriveTarget(string drive)
        {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = QueryDosDeviceW(drive.TrimEnd('\\'), buffer, buffer.Capacity);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resolve drive: " + drive);
            }

            return buffer.ToString();
        }

        public static SecurityState GetSecurityState(string path, bool openReparsePoint)
        {
            uint flags = FileFlagBackupSemantics;
            if (openReparsePoint)
            {
                flags |= FileFlagOpenReparsePoint;
            }

            using (SafeFileHandle handle = CreateFileW(
                path,
                ReadControl | FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                flags,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read security state: " + path);
                }

                FileBasicInformation basicInformation;
                if (!GetFileInformationByHandleEx(
                    handle,
                    0,
                    out basicInformation,
                    (uint)Marshal.SizeOf(typeof(FileBasicInformation))))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to read change-time state: " + path);
                }

                ByHandleFileInformation identityInformation;
                if (!GetFileInformationByHandle(handle, out identityInformation))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to read snapshot identity: " + path);
                }
                ulong fileIndex =
                    ((ulong)identityInformation.FileIndexHigh << 32) |
                    identityInformation.FileIndexLow;

                IntPtr owner;
                IntPtr group;
                IntPtr dacl;
                IntPtr sacl;
                IntPtr securityDescriptor;
                uint result = GetSecurityInfo(
                    handle.DangerousGetHandle(),
                    1,
                    SecurityInformation,
                    out owner,
                    out group,
                    out dacl,
                    out sacl,
                    out securityDescriptor);
                if (result != 0)
                {
                    throw new Win32Exception((int)result, "Unable to read security descriptor: " + path);
                }

                try
                {
                    IntPtr stringDescriptor;
                    uint stringLength;
                    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        securityDescriptor,
                        1,
                        SecurityInformation,
                        out stringDescriptor,
                        out stringLength))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Unable to serialize security descriptor: " + path);
                    }

                    try
                    {
                        return new SecurityState
                        {
                            OwnerSid = owner == IntPtr.Zero ? null : new SecurityIdentifier(owner).Value,
                            SecurityDescriptorSddl = Marshal.PtrToStringUni(stringDescriptor),
                            ChangeTimeFileTime = basicInformation.ChangeTime,
                            FileAttributes = basicInformation.FileAttributes,
                            Identity =
                                identityInformation.VolumeSerialNumber.ToString("x8") +
                                ":" +
                                fileIndex.ToString("x16")
                        };
                    }
                    finally
                    {
                        LocalFree(stringDescriptor);
                    }
                }
                finally
                {
                    LocalFree(securityDescriptor);
                }
            }
        }

        public static string[] GetAlternateStreams(string path)
        {
            Win32FindStreamData data;
            IntPtr handle = FindFirstStreamW(path, 0, out data, 0);
            if (handle == InvalidHandleValue)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 38)
                {
                    return new string[0];
                }
                throw new Win32Exception(error, "Unable to enumerate named streams: " + path);
            }

            List<string> streams = new List<string>();
            try
            {
                do
                {
                    if (!String.Equals(data.StreamName, "::$DATA", StringComparison.Ordinal))
                    {
                        streams.Add(data.StreamName);
                    }
                }
                while (FindNextStreamW(handle, out data));

                int error = Marshal.GetLastWin32Error();
                if (error != 38)
                {
                    throw new Win32Exception(error, "Unable to complete named-stream enumeration: " + path);
                }
            }
            finally
            {
                FindClose(handle);
            }

            streams.Sort(StringComparer.Ordinal);
            return streams.ToArray();
        }
    }

    public sealed class ChangeRecord
    {
        public string TimestampUtc { get; set; }
        public string ChangeType { get; set; }
        public string Path { get; set; }
        public string OldPath { get; set; }
    }

    public sealed class TreeWatcher : IDisposable
    {
        private readonly FileSystemWatcher watcher;
        private readonly ConcurrentQueue<ChangeRecord> changes = new ConcurrentQueue<ChangeRecord>();
        private readonly ConcurrentQueue<string> errors = new ConcurrentQueue<string>();

        public TreeWatcher(string path, string filter, bool includeSubdirectories)
        {
            watcher = new FileSystemWatcher(path, filter);
            watcher.IncludeSubdirectories = includeSubdirectories;
            watcher.InternalBufferSize = 65536;
            watcher.NotifyFilter =
                NotifyFilters.Attributes |
                NotifyFilters.DirectoryName |
                NotifyFilters.FileName |
                NotifyFilters.LastWrite |
                NotifyFilters.Security |
                NotifyFilters.Size;
            watcher.Changed += OnChanged;
            watcher.Created += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Renamed += OnRenamed;
            watcher.Error += OnError;
        }

        private void OnChanged(object sender, FileSystemEventArgs args)
        {
            changes.Enqueue(new ChangeRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("O"),
                ChangeType = args.ChangeType.ToString(),
                Path = args.FullPath,
                OldPath = null
            });
        }

        private void OnRenamed(object sender, RenamedEventArgs args)
        {
            changes.Enqueue(new ChangeRecord
            {
                TimestampUtc = DateTime.UtcNow.ToString("O"),
                ChangeType = args.ChangeType.ToString(),
                Path = args.FullPath,
                OldPath = args.OldFullPath
            });
        }

        private void OnError(object sender, ErrorEventArgs args)
        {
            Exception error = args.GetException();
            errors.Enqueue(error == null ? "Unknown FileSystemWatcher failure." : error.ToString());
        }

        public void Start()
        {
            watcher.EnableRaisingEvents = true;
        }

        public void Stop()
        {
            watcher.EnableRaisingEvents = false;
        }

        public ChangeRecord[] GetChanges()
        {
            return changes.ToArray();
        }

        public string[] GetErrors()
        {
            return errors.ToArray();
        }

        public void Dispose()
        {
            watcher.Dispose();
        }
    }
}
'@
}

function Get-PrivatePacmanSha256 {
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream
    )

    $position = $Stream.Position
    try {
        $Stream.Position = 0
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return [Convert]::ToHexString($sha.ComputeHash($Stream)).ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $Stream.Position = $position
    }
}

function Get-PrivatePacmanStringSha256 {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Test-PrivatePacmanReservedName {
    param(
        [Parameter(Mandatory)]
        [string] $Segment
    )

    $baseName = $Segment.Split('.')[0].ToUpperInvariant()
    return $baseName -match '^(CON|PRN|AUX|NUL|CLOCK\$|COM[1-9]|LPT[1-9])$'
}

function ConvertTo-PrivatePacmanAbsolutePath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cne $Path.Trim()) {
        throw "$Name must be a nonempty path without leading or trailing whitespace."
    }

    if ($Path.Contains('/') -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith('\\.\', [StringComparison]::OrdinalIgnoreCase) -or
        $Path -notmatch '^[A-Za-z]:\\') {
        throw "$Name must be a DOS drive path, not a UNC, device, provider, or share path: $Path"
    }

    if ($Path.IndexOf(':', 2) -ge 0) {
        throw "$Name must not contain an alternate data stream: $Path"
    }

    if ($Path.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) {
        throw "$Name contains an invalid path character: $Path"
    }

    $tail = if ($Path.Length -gt 3) { $Path.Substring(3) } else { '' }
    if ($tail.Length -gt 0) {
        $segments = $tail.Split('\', [StringSplitOptions]::None)
        foreach ($segment in $segments) {
            if ([string]::IsNullOrEmpty($segment) -or
                $segment -eq '.' -or
                $segment -eq '..' -or
                $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
                $segment.EndsWith('.', [StringComparison]::Ordinal) -or
                $segment.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
                (Test-PrivatePacmanReservedName -Segment $segment)) {
                throw "$Name contains a noncanonical path segment: $segment"
            }
        }
    }

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.Length -gt 3) {
        $fullPath = $fullPath.TrimEnd('\')
    }

    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($Path.TrimEnd('\'), $fullPath.TrimEnd('\'))) {
        throw "$Name must not contain path traversal or a lexical alias: $Path"
    }

    return $fullPath
}

function ConvertTo-PrivatePacmanRelativePath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -cne $Path.Trim() -or
        [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.Contains('/') -or
        $Path.Contains(':')) {
        throw "$Name must be a nonempty canonical relative path: $Path"
    }

    $segments = $Path.Split('\', [StringSplitOptions]::None)
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or
            $segment -eq '.' -or
            $segment -eq '..' -or
            $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.EndsWith('.', [StringComparison]::Ordinal) -or
            $segment.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
            (Test-PrivatePacmanReservedName -Segment $segment)) {
            throw "$Name contains a noncanonical path segment: $segment"
        }
    }

    return [string]::Join('\', $segments)
}

function Assert-PrivatePacmanFixedDrive {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $root = [IO.Path]::GetPathRoot($Path)
    $drive = [IO.DriveInfo]::new($root)
    if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw "$Name must be on a ready local fixed drive: $Path"
    }

    $target = [PrivatePacmanV2.NativePath]::QueryDriveTarget($root)
    if ($target.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase) -or
        $target.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw "$Name must not use a substituted, redirected, or network drive alias: $Path"
    }
}

function Assert-PrivatePacmanNoReparseChain {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $current = [IO.Path]::GetPathRoot($Path)
    $tail = $Path.Substring($current.Length)
    if ($tail.Length -eq 0) {
        return
    }

    foreach ($segment in $tail.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [IO.Path]::Combine($current, $segment)
        if (-not [IO.File]::Exists($current) -and -not [IO.Directory]::Exists($current)) {
            break
        }

        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Name must not contain a junction, symbolic link, or other reparse point: $current"
        }
    }
}

function Resolve-PrivatePacmanExistingPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [ValidateSet('Directory', 'File')]
        [string] $Kind,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $normalized = ConvertTo-PrivatePacmanAbsolutePath -Path $Path -Name $Name
    Assert-PrivatePacmanFixedDrive -Path $normalized -Name $Name

    $exists = if ($Kind -eq 'Directory') {
        [IO.Directory]::Exists($normalized)
    }
    else {
        [IO.File]::Exists($normalized)
    }

    if (-not $exists) {
        throw "$Name does not exist as a $($Kind.ToLowerInvariant()): $normalized"
    }

    Assert-PrivatePacmanNoReparseChain -Path $normalized -Name $Name
    $finalPath = ConvertTo-PrivatePacmanAbsolutePath `
        -Path ([PrivatePacmanV2.NativePath]::GetFinalPath($normalized)) `
        -Name "$Name final path"

    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($normalized, $finalPath)) {
        throw "$Name uses a filesystem alias instead of its canonical path: $normalized -> $finalPath"
    }

    if (-not [StringComparer]::Ordinal.Equals(
        [IO.Path]::GetPathRoot($normalized).ToUpperInvariant(),
        [IO.Path]::GetPathRoot($finalPath).ToUpperInvariant())) {
        throw "$Name resolves to a different drive: $normalized -> $finalPath"
    }

    return $finalPath
}

function Resolve-PrivatePacmanMissingPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $normalized = ConvertTo-PrivatePacmanAbsolutePath -Path $Path -Name $Name
    Assert-PrivatePacmanFixedDrive -Path $normalized -Name $Name
    if ([IO.File]::Exists($normalized) -or [IO.Directory]::Exists($normalized)) {
        throw "$Name must not already exist: $normalized"
    }

    $ancestor = [IO.Path]::GetDirectoryName($normalized)
    while (-not [IO.Directory]::Exists($ancestor)) {
        $next = [IO.Path]::GetDirectoryName($ancestor)
        if ([string]::IsNullOrEmpty($next) -or $next -eq $ancestor) {
            throw "$Name has no existing canonical parent: $normalized"
        }
        $ancestor = $next
    }

    [void](Resolve-PrivatePacmanExistingPath -Path $ancestor -Kind Directory -Name "$Name parent")
    Assert-PrivatePacmanNoReparseChain -Path $normalized -Name $Name
    return $normalized
}

function Test-PrivatePacmanPathWithin {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Root,

        [switch] $AllowEqual
    )

    if ([StringComparer]::OrdinalIgnoreCase.Equals($Path, $Root)) {
        return $AllowEqual.IsPresent
    }

    $prefix = $Root.TrimEnd('\') + '\'
    return $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-PrivatePacmanSameDrive {
    param(
        [Parameter(Mandatory)]
        [string] $First,

        [Parameter(Mandatory)]
        [string] $Second,

        [Parameter(Mandatory)]
        [string] $Description
    )

    $firstRoot = [IO.Path]::GetPathRoot($First)
    $secondRoot = [IO.Path]::GetPathRoot($Second)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($firstRoot, $secondRoot)) {
        throw "$Description must be on the same fixed drive: $firstRoot versus $secondRoot"
    }
}

function New-PrivatePacmanLayout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $WorkspaceRoot,

        [Parameter(Mandatory)]
        [string] $SessionId,

        [string] $PacmanRelativePath = 'usr\bin\pacman.exe'
    )

    if ($SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or
        $SessionId -eq '.' -or
        $SessionId -eq '..') {
        throw 'SessionId must contain 1-64 ASCII letters, digits, dots, underscores, or hyphens and must not be dot traversal.'
    }

    $workspace = Resolve-PrivatePacmanExistingPath `
        -Path $WorkspaceRoot `
        -Kind Directory `
        -Name 'WorkspaceRoot'

    if ($workspace -eq [IO.Path]::GetPathRoot($workspace)) {
        throw 'WorkspaceRoot must not be a drive root.'
    }

    $pacmanRelative = ConvertTo-PrivatePacmanRelativePath `
        -Path $PacmanRelativePath `
        -Name 'PacmanRelativePath'
    $root = [IO.Path]::Combine($workspace, $SessionId)
    $stateBase = [IO.Path]::Combine($workspace, '.private-pacman-state')
    $stateDirectory = [IO.Path]::Combine($stateBase, $SessionId)

    [pscustomobject][ordered]@{
        Schema = $script:PrivatePacmanSchema
        SessionId = $SessionId
        WorkspaceRoot = $workspace
        Root = $root
        DatabasePath = [IO.Path]::Combine($root, 'var\lib\pacman')
        CachePath = [IO.Path]::Combine($root, 'var\cache\pacman\pkg')
        LogPath = [IO.Path]::Combine($root, 'var\log\pacman.log')
        ConfigPath = [IO.Path]::Combine($root, 'etc\pacman.conf')
        HookPath = [IO.Path]::Combine($root, 'etc\pacman.d\hooks')
        GpgPath = [IO.Path]::Combine($root, 'etc\pacman.d\gnupg')
        PacmanPath = [IO.Path]::Combine($root, $pacmanRelative)
        StateBase = $stateBase
        StateDirectory = $stateDirectory
        EvidenceDirectory = [IO.Path]::Combine($stateDirectory, 'evidence')
        OwnerPath = [IO.Path]::Combine($stateDirectory, 'owner.json')
        PacmanRelativePath = $pacmanRelative
    }
}

function Assert-PrivatePacmanLayout {
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout
    )

    foreach ($property in @(
        'Schema', 'SessionId', 'WorkspaceRoot', 'Root', 'DatabasePath',
        'CachePath', 'LogPath', 'ConfigPath', 'HookPath', 'GpgPath',
        'PacmanPath', 'StateBase', 'StateDirectory', 'EvidenceDirectory',
        'OwnerPath', 'PacmanRelativePath'
    )) {
        if ($null -eq $Layout.PSObject.Properties[$property]) {
            throw "Layout is missing required property: $property"
        }
    }

    $expected = New-PrivatePacmanLayout `
        -WorkspaceRoot ([string]$Layout.WorkspaceRoot) `
        -SessionId ([string]$Layout.SessionId) `
        -PacmanRelativePath ([string]$Layout.PacmanRelativePath)

    foreach ($property in $expected.PSObject.Properties.Name) {
        if (-not [StringComparer]::Ordinal.Equals(
            [string]$Layout.$property,
            [string]$expected.$property)) {
            throw "Layout property $property is not canonical or was modified."
        }
    }

    return $expected
}

function Get-PrivatePacmanFileHash {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete,
        131072,
        [IO.FileOptions]::SequentialScan
    )
    try {
        return Get-PrivatePacmanSha256 -Stream $stream
    }
    finally {
        $stream.Dispose()
    }
}

function Get-PrivatePacmanSnapshotMetadata {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [IO.FileAttributes] $Attributes
    )

    $alternateStreams = @([PrivatePacmanV2.NativePath]::GetAlternateStreams($Path))
    if ($alternateStreams.Count -ne 0) {
        throw "Alternate data streams are forbidden in private package state: $Path [$($alternateStreams -join ', ')]"
    }

    $isReparse = ($Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    $security = [PrivatePacmanV2.NativePath]::GetSecurityState($Path, $isReparse)
    if ([uint32]$security.FileAttributes -ne [uint32][int64]$Attributes) {
        throw "File attributes changed while snapshot metadata was captured: $Path"
    }
    return [pscustomobject][ordered]@{
        Attributes = [int64]$Attributes
        OwnerSid = [string]$security.OwnerSid
        SecurityDescriptorSddl = [string]$security.SecurityDescriptorSddl
        ChangeTimeFileTime = [int64]$security.ChangeTimeFileTime
        Identity = [string]$security.Identity
        AlternateStreams = @()
    }
}

function Get-PrivatePacmanTreeSnapshotCore {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $AllowMissing,

        [switch] $RejectReparsePoint,

        [string[]] $ExcludeRelativePath = @()
    )

    $normalized = ConvertTo-PrivatePacmanAbsolutePath -Path $Path -Name 'Snapshot path'
    Assert-PrivatePacmanFixedDrive -Path $normalized -Name 'Snapshot path'

    if (-not [IO.Directory]::Exists($normalized)) {
        if (-not $AllowMissing) {
            throw "Snapshot directory does not exist: $normalized"
        }

        $ancestor = [IO.Path]::GetDirectoryName($normalized)
        while (-not [IO.Directory]::Exists($ancestor)) {
            $ancestor = [IO.Path]::GetDirectoryName($ancestor)
        }
        [void](Resolve-PrivatePacmanExistingPath -Path $ancestor -Kind Directory -Name 'Snapshot parent')

        return [pscustomobject][ordered]@{
            Path = $normalized
            Exists = $false
            Digest = Get-PrivatePacmanStringSha256 -Value 'missing'
            ContentDigest = Get-PrivatePacmanStringSha256 -Value 'missing'
            EntryCount = 0
            RootAttributes = $null
            RootOwnerSid = $null
            RootSecurityDescriptorSddl = $null
            RootChangeTimeFileTime = $null
            RootIdentity = $null
            RootAlternateStreams = @()
            Entries = @()
        }
    }

    $root = Resolve-PrivatePacmanExistingPath -Path $normalized -Kind Directory -Name 'Snapshot path'
    $rootAttributes = [IO.File]::GetAttributes($root)
    $rootMetadata = Get-PrivatePacmanSnapshotMetadata `
        -Path $root `
        -Attributes $rootAttributes
    $testBarrier = $script:TestSnapshotBarrier
    if ($null -ne $testBarrier -and
        [StringComparer]::OrdinalIgnoreCase.Equals([string]$testBarrier.Root, $root)) {
        if ([int]$testBarrier.SkipMatches -gt 0) {
            $testBarrier.SkipMatches = [int]$testBarrier.SkipMatches - 1
        }
        else {
            $script:TestSnapshotBarrier = $null
            [IO.File]::WriteAllText(
                [string]$testBarrier.EnteredPath,
                'entered',
                [Text.UTF8Encoding]::new($false)
            )
            $deadline = [DateTime]::UtcNow.AddSeconds(120)
            while (-not [IO.File]::Exists([string]$testBarrier.ReleasePath)) {
                if ([DateTime]::UtcNow -ge $deadline) {
                    throw "Timed out at the private snapshot test barrier: $root"
                }
                [Threading.Thread]::Sleep(25)
            }
        }
    }
    $excluded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($relativePath in $ExcludeRelativePath) {
        [void]$excluded.Add($relativePath)
    }

    $entries = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)

    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $children = [IO.Directory]::GetFileSystemEntries($directory)
        [Array]::Sort($children, [StringComparer]::Ordinal)
        for ($index = $children.Length - 1; $index -ge 0; $index--) {
            $child = $children[$index]
            $relative = [IO.Path]::GetRelativePath($root, $child)
            if ($excluded.Contains($relative)) {
                continue
            }

            $attributes = [IO.File]::GetAttributes($child)
            $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
            $isReparse = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            if ($isReparse -and $RejectReparsePoint) {
                throw "Reparse points are forbidden in protected package state: $child"
            }
            if ($isReparse) {
                $security = [PrivatePacmanV2.NativePath]::GetSecurityState($child, $true)
                $metadata = [pscustomobject][ordered]@{
                    Attributes = [int64]$attributes
                    OwnerSid = [string]$security.OwnerSid
                    SecurityDescriptorSddl = [string]$security.SecurityDescriptorSddl
                    ChangeTimeFileTime = [int64]$security.ChangeTimeFileTime
                    Identity = [string]$security.Identity
                    AlternateStreams = @('<not-enumerated-for-reparse-entry>')
                }
            }
            else {
                $metadata = Get-PrivatePacmanSnapshotMetadata `
                    -Path $child `
                    -Attributes $attributes
            }
            $kind = if ($isReparse) {
                if ($isDirectory) { 'directory-link' } else { 'file-link' }
            }
            elseif ($isDirectory) {
                'directory'
            }
            else {
                'file'
            }

            $rawTarget = $null
            $resolvedTarget = $null
            $length = $null
            $sha256 = $null
            if ($isReparse) {
                $item = Get-Item -Force -LiteralPath $child
                $rawTarget = [string]$item.LinkTarget
                try {
                    $resolved = $item.ResolveLinkTarget($true)
                    if ($null -ne $resolved) {
                        $resolvedTarget = [string]$resolved.FullName
                    }
                }
                catch {
                    $resolvedTarget = '<unresolved>'
                }
            }
            elseif ($isDirectory) {
                $pending.Push($child)
            }
            else {
                $before = [IO.FileInfo]::new($child)
                $length = $before.Length
                $beforeWrite = $before.LastWriteTimeUtc
                $sha256 = Get-PrivatePacmanFileHash -Path $child
                $after = [IO.FileInfo]::new($child)
                if ($length -ne $after.Length -or $beforeWrite -ne $after.LastWriteTimeUtc) {
                    throw "File changed while its byte snapshot was captured: $child"
                }
            }

            $entries.Add([pscustomobject][ordered]@{
                RelativePath = $relative
                Kind = $kind
                Length = $length
                Sha256 = $sha256
                Attributes = $metadata.Attributes
                OwnerSid = $metadata.OwnerSid
                SecurityDescriptorSddl = $metadata.SecurityDescriptorSddl
                ChangeTimeFileTime = $metadata.ChangeTimeFileTime
                Identity = $metadata.Identity
                AlternateStreams = $metadata.AlternateStreams
                LinkType = if ($isReparse) { [string]$item.LinkType } else { $null }
                RawTarget = $rawTarget
                ResolvedTarget = $resolvedTarget
            })
        }
    }

    $sortedEntries = [Collections.Generic.SortedDictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($entry in $entries) {
        $sortedEntries.Add([string]$entry.RelativePath, $entry)
    }
    $orderedEntries = @($sortedEntries.Values)
    $contentLines = foreach ($entry in $orderedEntries) {
        [pscustomobject][ordered]@{
            RelativePath = $entry.RelativePath
            Kind = $entry.Kind
            Length = $entry.Length
            Sha256 = $entry.Sha256
            LinkType = $entry.LinkType
            RawTarget = $entry.RawTarget
            ResolvedTarget = $entry.ResolvedTarget
        } | ConvertTo-Json -Compress
    }
    $canonicalLines = @(
        [pscustomobject][ordered]@{
            RelativePath = '.'
            Kind = 'root'
            Attributes = $rootMetadata.Attributes
            OwnerSid = $rootMetadata.OwnerSid
            SecurityDescriptorSddl = $rootMetadata.SecurityDescriptorSddl
            ChangeTimeFileTime = $rootMetadata.ChangeTimeFileTime
            Identity = $rootMetadata.Identity
            AlternateStreams = $rootMetadata.AlternateStreams
        } | ConvertTo-Json -Compress
    )
    $canonicalLines += @(foreach ($entry in $orderedEntries) {
        [pscustomobject][ordered]@{
            RelativePath = $entry.RelativePath
            Kind = $entry.Kind
            Length = $entry.Length
            Sha256 = $entry.Sha256
            Attributes = $entry.Attributes
            OwnerSid = $entry.OwnerSid
            SecurityDescriptorSddl = $entry.SecurityDescriptorSddl
            ChangeTimeFileTime = $entry.ChangeTimeFileTime
            Identity = $entry.Identity
            AlternateStreams = $entry.AlternateStreams
            LinkType = $entry.LinkType
            RawTarget = $entry.RawTarget
            ResolvedTarget = $entry.ResolvedTarget
        } | ConvertTo-Json -Compress
    })

    [pscustomobject][ordered]@{
        Path = $root
        Exists = $true
        Digest = Get-PrivatePacmanStringSha256 -Value ($canonicalLines -join "`n")
        ContentDigest = Get-PrivatePacmanStringSha256 -Value ($contentLines -join "`n")
        EntryCount = $orderedEntries.Count
        RootAttributes = $rootMetadata.Attributes
        RootOwnerSid = $rootMetadata.OwnerSid
        RootSecurityDescriptorSddl = $rootMetadata.SecurityDescriptorSddl
        RootChangeTimeFileTime = $rootMetadata.ChangeTimeFileTime
        RootIdentity = $rootMetadata.Identity
        RootAlternateStreams = $rootMetadata.AlternateStreams
        Entries = $orderedEntries
    }
}

function Get-PrivatePacmanTreeSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $AllowMissing
    )

    Get-PrivatePacmanTreeSnapshotCore -Path $Path -AllowMissing:$AllowMissing
}

function Write-PrivatePacmanJson {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Value
    )

    $json = $Value | ConvertTo-Json -Depth 20
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $Path, $true)
    }
    finally {
        if ([IO.File]::Exists($temporaryPath)) {
            [IO.File]::Delete($temporaryPath)
        }
    }
}

function Set-PrivatePacmanLockedJson {
    param(
        [Parameter(Mandatory)]
        [IO.FileStream] $Stream,

        [Parameter(Mandatory)]
        [object] $Value
    )

    $json = $Value | ConvertTo-Json -Depth 20
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $Stream.Position = 0
    $Stream.SetLength(0)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush($true)
}

function Open-PrivatePacmanReadLock {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read,
        131072,
        [IO.FileOptions]::SequentialScan
    )
    try {
        $identity = [PrivatePacmanV2.NativePath]::GetIdentity($stream.SafeFileHandle)
        $finalPath = ConvertTo-PrivatePacmanAbsolutePath -Path $identity.FinalPath -Name "$Name locked path"
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($Path, $finalPath)) {
            throw "$Name changed identity while its lock was acquired: $Path -> $finalPath"
        }

        [pscustomobject][ordered]@{
            Path = $Path
            Stream = $stream
            Identity = $identity.Identity
            LinkCount = $identity.LinkCount
            Sha256 = Get-PrivatePacmanSha256 -Stream $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Close-PrivatePacmanLocks {
    param(
        [Parameter(Mandatory)]
        [Collections.IEnumerable] $Locks
    )

    foreach ($lock in $Locks) {
        if ($null -ne $lock -and $null -ne $lock.Stream) {
            $lock.Stream.Dispose()
        }
    }
}

function Copy-PrivatePacmanSeed {
    param(
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter(Mandatory)]
        [string] $Destination,

        [Parameter(Mandatory)]
        [string] $OwnerRelativePath
    )

    $watcher = [PrivatePacmanV2.TreeWatcher]::new($Source, '*', $true)
    $watcherStopped = $false
    try {
        $preflight = @(
            Get-PrivatePacmanQuiescentSnapshotSet `
                -ProtectedRoot @(
                    [pscustomobject][ordered]@{
                        Path = $Source
                        Exists = $true
                    }
                ) `
                -RejectReparsePoint
        )[0]
        $watcher.Start()
        $before = Get-PrivatePacmanTreeSnapshotCore -Path $Source -RejectReparsePoint
        if ($preflight.Digest -cne $before.Digest) {
            throw 'Private seed was not stable before its monitored copy.'
        }
        $reparseEntry = $before.Entries | Where-Object { $_.Kind -like '*-link' } | Select-Object -First 1
        if ($null -ne $reparseEntry) {
            throw "Private seed contains a forbidden reparse point: $($reparseEntry.RelativePath)"
        }
        if ($before.Entries.RelativePath -contains $OwnerRelativePath) {
            throw "Private seed contains the reserved owner marker: $OwnerRelativePath"
        }

        foreach ($entry in $before.Entries) {
            $sourcePath = [IO.Path]::Combine($Source, $entry.RelativePath)
            $destinationPath = [IO.Path]::Combine($Destination, $entry.RelativePath)
            if ($entry.Kind -eq 'directory') {
                [void][IO.Directory]::CreateDirectory($destinationPath)
                continue
            }

            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destinationPath))
            $input = [IO.FileStream]::new(
                $sourcePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read,
                131072,
                [IO.FileOptions]::SequentialScan
            )
            try {
                $output = [IO.FileStream]::new(
                    $destinationPath,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None,
                    131072,
                    [IO.FileOptions]::SequentialScan
                )
                try {
                    $input.CopyTo($output)
                    $output.Flush($true)
                }
                finally {
                    $output.Dispose()
                }
            }
            finally {
                $input.Dispose()
            }
        }

        $after = Get-PrivatePacmanTreeSnapshotCore -Path $Source -RejectReparsePoint
        $copied = Get-PrivatePacmanTreeSnapshotCore `
            -Path $Destination `
            -RejectReparsePoint `
            -ExcludeRelativePath @($OwnerRelativePath)
        [Threading.Thread]::Sleep(150)
        $watcher.Stop()
        $watcherStopped = $true

        if ($before.Digest -cne $after.Digest -or
            $before.ContentDigest -cne $copied.ContentDigest) {
            throw 'Private seed changed during its copy or the copied bytes do not match.'
        }
        if ($watcher.GetErrors().Count -ne 0 -or $watcher.GetChanges().Count -ne 0) {
            throw 'Private seed changed while its atomic copy was being prepared.'
        }

        return [pscustomobject][ordered]@{
            Path = $before.Path
            Digest = $before.Digest
            ContentDigest = $before.ContentDigest
            EntryCount = $before.EntryCount
        }
    }
    finally {
        if (-not $watcherStopped) {
            $watcher.Stop()
        }
        $watcher.Dispose()
    }
}

function Test-PrivatePacmanDirectoryEmpty {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ([IO.Directory]::Exists($Path) -and [IO.Directory]::GetFileSystemEntries($Path).Length -ne 0) {
        throw "$Name must be empty: $Path"
    }
}

function Get-PrivatePacmanStagingPath {
    param(
        [Parameter(Mandatory)]
        [string] $FinalPath,

        [Parameter(Mandatory)]
        [string] $FinalRoot,

        [Parameter(Mandatory)]
        [string] $StagingRoot
    )

    if (-not (Test-PrivatePacmanPathWithin -Path $FinalPath -Root $FinalRoot -AllowEqual)) {
        throw "Managed path escapes the private root: $FinalPath"
    }
    return $StagingRoot + $FinalPath.Substring($FinalRoot.Length)
}

function Initialize-PrivatePacmanRoot {
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [string] $SeedRoot,

        [Parameter(Mandatory)]
        [string] $StagingRoot,

        [Parameter(Mandatory)]
        [string] $Nonce
    )

    [void][IO.Directory]::CreateDirectory($StagingRoot)
    $ownerPath = [IO.Path]::Combine($StagingRoot, $script:OwnerFileName)
    $owner = [pscustomobject][ordered]@{
        Schema = $script:PrivatePacmanSchema
        SessionId = $Layout.SessionId
        Nonce = $Nonce
        Root = $Layout.Root
        StateDirectory = $Layout.StateDirectory
    }
    Write-PrivatePacmanJson -Path $ownerPath -Value $owner

    $seedEvidence = Copy-PrivatePacmanSeed `
        -Source $SeedRoot `
        -Destination $StagingRoot `
        -OwnerRelativePath $script:OwnerFileName

    $managedDirectories = @(
        $Layout.DatabasePath,
        $Layout.CachePath,
        ([IO.Path]::GetDirectoryName($Layout.LogPath)),
        ([IO.Path]::GetDirectoryName($Layout.ConfigPath)),
        $Layout.HookPath,
        $Layout.GpgPath,
        ([IO.Path]::Combine($Layout.Root, 'tmp')),
        ([IO.Path]::Combine($Layout.Root, 'home'))
    )
    foreach ($directory in $managedDirectories) {
        $stagingDirectory = Get-PrivatePacmanStagingPath `
            -FinalPath $directory `
            -FinalRoot $Layout.Root `
            -StagingRoot $StagingRoot
        [void][IO.Directory]::CreateDirectory($stagingDirectory)
    }

    $stagingHookPath = Get-PrivatePacmanStagingPath `
        -FinalPath $Layout.HookPath `
        -FinalRoot $Layout.Root `
        -StagingRoot $StagingRoot
    Test-PrivatePacmanDirectoryEmpty -Path $stagingHookPath -Name 'Configured hook directory'

    $defaultHookPath = [IO.Path]::Combine($StagingRoot, 'usr\share\libalpm\hooks')
    Test-PrivatePacmanDirectoryEmpty -Path $defaultHookPath -Name 'Root-local default hook directory'

    $configPath = Get-PrivatePacmanStagingPath `
        -FinalPath $Layout.ConfigPath `
        -FinalRoot $Layout.Root `
        -StagingRoot $StagingRoot
    $config = @(
        '# Generated by PrivatePacman.psm1. Repository sections are intentionally absent.'
        '[options]'
        'Architecture = auto'
        'SigLevel = Required DatabaseOptional'
        'LocalFileSigLevel = Optional'
        ''
    ) -join "`n"
    [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))

    $logPath = Get-PrivatePacmanStagingPath `
        -FinalPath $Layout.LogPath `
        -FinalRoot $Layout.Root `
        -StagingRoot $StagingRoot
    [IO.File]::WriteAllBytes($logPath, [byte[]]::new(0))

    $pacmanPath = Get-PrivatePacmanStagingPath `
        -FinalPath $Layout.PacmanPath `
        -FinalRoot $Layout.Root `
        -StagingRoot $StagingRoot
    [void](Resolve-PrivatePacmanExistingPath -Path $pacmanPath -Kind File -Name 'Private pacman executable')

    if ([IO.Directory]::Exists($Layout.Root) -or [IO.File]::Exists($Layout.Root)) {
        throw "Private root appeared before its atomic publication: $($Layout.Root)"
    }
    [IO.Directory]::Move($StagingRoot, $Layout.Root)

    [pscustomobject][ordered]@{
        Seed = $seedEvidence
        ConfigSha256 = Get-PrivatePacmanFileHash -Path $Layout.ConfigPath
    }
}

function Get-PrivatePacmanPackageInventory {
    param(
        [Parameter(Mandatory)]
        [string] $PackageRoot,

        [Parameter(Mandatory)]
        [string] $WorkspaceRoot
    )

    $root = Resolve-PrivatePacmanExistingPath -Path $PackageRoot -Kind Directory -Name 'PackageRoot'
    Assert-PrivatePacmanSameDrive -First $root -Second $WorkspaceRoot -Description 'PackageRoot'

    $snapshot = Get-PrivatePacmanTreeSnapshotCore -Path $root -RejectReparsePoint
    $packages = [Collections.Generic.List[object]]::new()
    foreach ($entry in $snapshot.Entries) {
        if ($entry.Kind -like '*-link') {
            throw "PackageRoot contains a forbidden reparse point: $($entry.RelativePath)"
        }
        if ($entry.Kind -eq 'directory') {
            continue
        }
        if ($entry.Kind -ne 'file' -or $entry.RelativePath -notmatch '\.pkg\.tar\.[A-Za-z0-9]+$') {
            throw "PackageRoot contains an unowned non-package file: $($entry.RelativePath)"
        }

        $relative = ConvertTo-PrivatePacmanRelativePath `
            -Path $entry.RelativePath `
            -Name 'Package manifest path'
        $packages.Add([pscustomobject][ordered]@{
            Path = $relative
            Length = [int64]$entry.Length
            Sha256 = [string]$entry.Sha256
        })
    }

    if ($packages.Count -eq 0) {
        throw 'PackageRoot must contain at least one local pacman package archive.'
    }

    $sorted = [Collections.Generic.SortedDictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($package in $packages) {
        $sorted.Add([string]$package.Path, $package)
    }
    $ordered = @($sorted.Values)
    [pscustomobject][ordered]@{
        Root = $root
        SnapshotDigest = $snapshot.Digest
        Packages = $ordered
    }
}

function Get-PrivatePacmanPackageSetSha256 {
    param(
        [Parameter(Mandatory)]
        [object[]] $Package
    )

    $lines = foreach ($entry in $Package) {
        $pathBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$entry.Path)
        '{0}`t{1}`t{2}' -f @(
            [Convert]::ToBase64String($pathBytes),
            [int64]$entry.Length,
            [string]$entry.Sha256
        )
    }
    return Get-PrivatePacmanStringSha256 -Value ($lines -join "`n")
}

function ConvertTo-PrivatePacmanCanonicalOwnershipJson {
    param(
        [Parameter(Mandatory)]
        [string] $Owner,

        [Parameter(Mandatory)]
        [string] $SessionId,

        [Parameter(Mandatory)]
        [object[]] $Package
    )

    $packageSetSha256 = Get-PrivatePacmanPackageSetSha256 -Package $Package
    $manifest = [pscustomobject][ordered]@{
        Schema = $script:OwnershipManifestSchema
        Owner = $Owner
        SessionId = $SessionId
        SignatureAlgorithm = $script:OwnershipSignatureAlgorithm
        PackageSetSha256 = $packageSetSha256
        Packages = @($Package | ForEach-Object {
            [pscustomobject][ordered]@{
                Path = [string]$_.Path
                Length = [int64]$_.Length
                Sha256 = [string]$_.Sha256
            }
        })
    }
    return ($manifest | ConvertTo-Json -Depth 8 -Compress) + "`n"
}

function Assert-PrivatePacmanOwnershipName {
    param(
        [Parameter(Mandatory)]
        [string] $Owner
    )

    if ($Owner -notmatch '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$') {
        throw 'Owner must contain 1-128 ASCII letters, digits, dots, underscores, colons, at signs, or hyphens.'
    }
}

function Assert-PrivatePacmanSha256Text {
    param(
        [Parameter(Mandatory)]
        [string] $Value,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Name must be one lowercase SHA-256 value."
    }
}

function Assert-PrivatePacmanSequence {
    param(
        [Parameter(Mandatory)]
        [object[]] $Expected,

        [Parameter(Mandatory)]
        [object[]] $Actual,

        [Parameter(Mandatory)]
        [string] $Message
    )

    if ($Expected.Count -ne $Actual.Count) {
        throw "$Message Expected $($Expected.Count) values; found $($Actual.Count)."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (-not [StringComparer]::Ordinal.Equals(
            [string]$Expected[$index],
            [string]$Actual[$index])) {
            throw "$Message Value $index does not match."
        }
    }
}

function Write-PrivatePacmanTextAtomic {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Value
    )

    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporaryPath, $Value, [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $Path, $false)
    }
    finally {
        if ([IO.File]::Exists($temporaryPath)) {
            [IO.File]::Delete($temporaryPath)
        }
    }
}

function New-PrivatePacmanOwnershipManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PackageRoot,

        [Parameter(Mandatory)]
        [string] $Owner,

        [Parameter(Mandatory)]
        [string] $SessionId,

        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    Assert-PrivatePacmanOwnershipName -Owner $Owner
    if ($SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or
        $SessionId -eq '.' -or
        $SessionId -eq '..') {
        throw 'SessionId is not canonical.'
    }

    $root = Resolve-PrivatePacmanExistingPath -Path $PackageRoot -Kind Directory -Name 'PackageRoot'
    $output = Resolve-PrivatePacmanMissingPath -Path $OutputPath -Name 'Ownership manifest output'
    Assert-PrivatePacmanSameDrive -First $root -Second $output -Description 'Ownership manifest output'
    if ((Test-PrivatePacmanPathWithin -Path $output -Root $root -AllowEqual) -or
        (Test-PrivatePacmanPathWithin -Path $root -Root $output -AllowEqual)) {
        throw 'Ownership manifest output must be outside PackageRoot.'
    }

    $inventory = Get-PrivatePacmanPackageInventory `
        -PackageRoot $root `
        -WorkspaceRoot ([IO.Path]::GetDirectoryName($output))
    $json = ConvertTo-PrivatePacmanCanonicalOwnershipJson `
        -Owner $Owner `
        -SessionId $SessionId `
        -Package $inventory.Packages
    Write-PrivatePacmanTextAtomic -Path $output -Value $json

    [pscustomobject][ordered]@{
        Schema = $script:OwnershipManifestSchema
        Path = $output
        Sha256 = Get-PrivatePacmanStringSha256 -Value $json
        PackageSetSha256 = Get-PrivatePacmanPackageSetSha256 -Package $inventory.Packages
        PackageCount = $inventory.Packages.Count
    }
}

function Read-PrivatePacmanLockedBytes {
    param(
        [Parameter(Mandatory)]
        [psobject] $Lock
    )

    $position = $Lock.Stream.Position
    try {
        $Lock.Stream.Position = 0
        $memory = [IO.MemoryStream]::new()
        try {
            $Lock.Stream.CopyTo($memory)
            return $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $Lock.Stream.Position = $position
    }
}

function Open-PrivatePacmanOwnership {
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [string] $PackageRoot,

        [Parameter(Mandatory)]
        [string] $ManifestPath,

        [Parameter(Mandatory)]
        [string] $SignaturePath,

        [Parameter(Mandatory)]
        [string] $PublicKeyPath,

        [Parameter(Mandatory)]
        [string] $ExpectedManifestSha256,

        [Parameter(Mandatory)]
        [string] $ExpectedPublicKeySha256,

        [Parameter(Mandatory)]
        [string] $ExpectedOwner
    )

    Assert-PrivatePacmanSha256Text -Value $ExpectedManifestSha256 -Name 'ExpectedManifestSha256'
    Assert-PrivatePacmanSha256Text -Value $ExpectedPublicKeySha256 -Name 'ExpectedPublicKeySha256'
    Assert-PrivatePacmanOwnershipName -Owner $ExpectedOwner

    $inventory = Get-PrivatePacmanPackageInventory `
        -PackageRoot $PackageRoot `
        -WorkspaceRoot $Layout.WorkspaceRoot
    $manifest = Resolve-PrivatePacmanExistingPath -Path $ManifestPath -Kind File -Name 'OwnershipManifestPath'
    $signature = Resolve-PrivatePacmanExistingPath -Path $SignaturePath -Kind File -Name 'OwnershipSignaturePath'
    $publicKey = Resolve-PrivatePacmanExistingPath -Path $PublicKeyPath -Kind File -Name 'OwnershipPublicKeyPath'
    foreach ($path in @($manifest, $signature, $publicKey)) {
        Assert-PrivatePacmanSameDrive `
            -First $path `
            -Second $Layout.WorkspaceRoot `
            -Description 'Ownership evidence'
        if (Test-PrivatePacmanPathWithin -Path $path -Root $inventory.Root -AllowEqual) {
            throw "Ownership evidence must be outside PackageRoot: $path"
        }
    }
    $ownershipPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @($manifest, $signature, $publicKey)) {
        if (-not $ownershipPaths.Add($path)) {
            throw 'Ownership manifest, signature, and public key must be distinct files.'
        }
    }

    $ownershipLocks = [Collections.Generic.List[object]]::new()
    $packageLocks = [Collections.Generic.List[object]]::new()
    try {
        $manifestLock = Open-PrivatePacmanReadLock -Path $manifest -Name 'Ownership manifest'
        $ownershipLocks.Add($manifestLock)
        $signatureLock = Open-PrivatePacmanReadLock -Path $signature -Name 'Ownership signature'
        $ownershipLocks.Add($signatureLock)
        $publicKeyLock = Open-PrivatePacmanReadLock -Path $publicKey -Name 'Ownership public key'
        $ownershipLocks.Add($publicKeyLock)

        if ($manifestLock.Sha256 -cne $ExpectedManifestSha256) {
            throw 'Ownership manifest does not match ExpectedManifestSha256.'
        }
        if ($publicKeyLock.Sha256 -cne $ExpectedPublicKeySha256) {
            throw 'Ownership public key does not match ExpectedPublicKeySha256.'
        }

        $manifestBytes = Read-PrivatePacmanLockedBytes -Lock $manifestLock
        $manifestText = [Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)
        $parsed = $manifestText | ConvertFrom-Json
        $propertyNames = @($parsed.PSObject.Properties.Name)
        Assert-PrivatePacmanSequence `
            -Expected @(
                'Schema', 'Owner', 'SessionId', 'SignatureAlgorithm',
                'PackageSetSha256', 'Packages'
            ) `
            -Actual $propertyNames `
            -Message 'Ownership manifest property set or order is not canonical.'
        if ($parsed.Schema -cne $script:OwnershipManifestSchema -or
            $parsed.SignatureAlgorithm -cne $script:OwnershipSignatureAlgorithm) {
            throw 'Ownership manifest schema or signature algorithm is unsupported.'
        }
        if ($parsed.Owner -cne $ExpectedOwner -or $parsed.SessionId -cne $Layout.SessionId) {
            throw 'Ownership manifest owner or session binding does not match this invocation.'
        }

        $manifestPackages = @($parsed.Packages)
        if ($manifestPackages.Count -ne $inventory.Packages.Count) {
            throw 'Ownership manifest is not a complete PackageRoot inventory.'
        }
        for ($index = 0; $index -lt $manifestPackages.Count; $index++) {
            $listed = $manifestPackages[$index]
            Assert-PrivatePacmanSequence `
                -Expected @('Path', 'Length', 'Sha256') `
                -Actual @($listed.PSObject.Properties.Name) `
                -Message "Ownership package entry $index is not canonical."
            $relative = ConvertTo-PrivatePacmanRelativePath `
                -Path ([string]$listed.Path) `
                -Name "Ownership package entry $index"
            Assert-PrivatePacmanSha256Text `
                -Value ([string]$listed.Sha256) `
                -Name "Ownership package entry $index hash"
            $actual = $inventory.Packages[$index]
            if ($relative -cne $actual.Path -or
                [int64]$listed.Length -ne $actual.Length -or
                [string]$listed.Sha256 -cne $actual.Sha256) {
                throw "Ownership package entry $index does not match PackageRoot bytes."
            }
        }

        $canonicalJson = ConvertTo-PrivatePacmanCanonicalOwnershipJson `
            -Owner ([string]$parsed.Owner) `
            -SessionId ([string]$parsed.SessionId) `
            -Package $manifestPackages
        if ($manifestText -cne $canonicalJson) {
            throw 'Ownership manifest JSON is not in canonical deterministic form.'
        }
        $packageSetSha256 = Get-PrivatePacmanPackageSetSha256 -Package $manifestPackages
        if ([string]$parsed.PackageSetSha256 -cne $packageSetSha256) {
            throw 'Ownership manifest PackageSetSha256 is invalid.'
        }

        $signatureText = [Text.UTF8Encoding]::new($false, $true).GetString(
            (Read-PrivatePacmanLockedBytes -Lock $signatureLock)
        )
        if ($signatureText -notmatch '^[A-Za-z0-9+/]+={0,2}\r?\n?$') {
            throw 'Ownership signature must contain one canonical base64 value.'
        }
        $signatureBytes = [Convert]::FromBase64String($signatureText.TrimEnd("`r", "`n"))
        $publicKeyText = [Text.UTF8Encoding]::new($false, $true).GetString(
            (Read-PrivatePacmanLockedBytes -Lock $publicKeyLock)
        )
        $ecdsa = [Security.Cryptography.ECDsa]::Create()
        try {
            $ecdsa.ImportFromPem($publicKeyText)
            if ($ecdsa.KeySize -ne 256 -or
                -not $ecdsa.VerifyData(
                    $manifestBytes,
                    $signatureBytes,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
                )) {
                throw 'Ownership manifest ECDSA P-256 signature is invalid.'
            }
        }
        finally {
            $ecdsa.Dispose()
        }

        foreach ($entry in $inventory.Packages) {
            $path = Resolve-PrivatePacmanExistingPath `
                -Path ([IO.Path]::Combine($inventory.Root, $entry.Path)) `
                -Kind File `
                -Name 'Owned package'
            $lock = Open-PrivatePacmanReadLock -Path $path -Name 'Owned package'
            if ($lock.Sha256 -cne $entry.Sha256) {
                $lock.Stream.Dispose()
                throw "Owned package changed before its lock was acquired: $($entry.Path)"
            }
            $packageLocks.Add($lock)
        }

        return [pscustomobject][ordered]@{
            Root = $inventory.Root
            Paths = @($packageLocks | ForEach-Object Path)
            OwnershipLocks = $ownershipLocks
            PackageLocks = $packageLocks
            Evidence = [pscustomobject][ordered]@{
                Schema = $script:OwnershipManifestSchema
                Owner = $ExpectedOwner
                SessionId = $Layout.SessionId
                SignatureAlgorithm = $script:OwnershipSignatureAlgorithm
                ManifestPath = $manifest
                ManifestSha256 = $manifestLock.Sha256
                SignaturePath = $signature
                SignatureSha256 = $signatureLock.Sha256
                PublicKeyPath = $publicKey
                PublicKeySha256 = $publicKeyLock.Sha256
                PackageSetSha256 = $packageSetSha256
                PackageCount = $inventory.Packages.Count
                PackageRootSnapshotSha256 = $inventory.SnapshotDigest
            }
        }
    }
    catch {
        Close-PrivatePacmanLocks -Locks $packageLocks
        Close-PrivatePacmanLocks -Locks $ownershipLocks
        throw
    }
}

function Get-PrivatePacmanProtectedRoots {
    param(
        [string[]] $ProtectedRoot = @()
    )

    $roots = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $candidates = @($script:CanonicalSharedRoot) + @($ProtectedRoot)
    foreach ($candidate in $candidates) {
        $normalized = ConvertTo-PrivatePacmanAbsolutePath -Path $candidate -Name 'ProtectedRoot'
        if ([IO.Directory]::Exists($normalized)) {
            $canonical = Resolve-PrivatePacmanExistingPath `
                -Path $normalized `
                -Kind Directory `
                -Name 'ProtectedRoot'
            $exists = $true
        }
        else {
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($normalized, $script:CanonicalSharedRoot)) {
                throw "Additional ProtectedRoot must exist: $normalized"
            }
            Assert-PrivatePacmanFixedDrive -Path $normalized -Name 'ProtectedRoot'
            $canonical = $normalized
            $exists = $false
        }

        if ($seen.Add($canonical)) {
            $roots.Add([pscustomobject][ordered]@{
                Path = $canonical
                Exists = $exists
                IsCanonicalSharedRoot = [StringComparer]::OrdinalIgnoreCase.Equals(
                    $canonical,
                    $script:CanonicalSharedRoot
                )
            })
        }
    }
    return @($roots)
}

function Assert-PrivatePacmanNoProtectedOverlap {
    param(
        [Parameter(Mandatory)]
        [string[]] $InputPath,

        [Parameter(Mandatory)]
        [object[]] $ProtectedRoot
    )

    foreach ($input in $InputPath) {
        foreach ($protected in $ProtectedRoot) {
            if ((Test-PrivatePacmanPathWithin -Path $input -Root $protected.Path -AllowEqual) -or
                (Test-PrivatePacmanPathWithin -Path $protected.Path -Root $input -AllowEqual)) {
                throw "Private input overlaps protected package state: $input and $($protected.Path)"
            }
        }
    }
}

function New-PrivatePacmanArgumentList {
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [string[]] $PackagePath
    )

    $arguments = @(
        '--root', $Layout.Root,
        '--dbpath', $Layout.DatabasePath,
        '--cachedir', $Layout.CachePath,
        '--logfile', $Layout.LogPath,
        '--config', $Layout.ConfigPath,
        '--hookdir', $Layout.HookPath,
        '--gpgdir', $Layout.GpgPath,
        '--noconfirm',
        '--noscriptlet',
        '-U',
        '--'
    ) + @($PackagePath)

    foreach ($requiredSwitch in $script:RequiredIsolationSwitches) {
        if (@($arguments | Where-Object { $_ -ceq $requiredSwitch }).Count -ne 1) {
            throw "Generated pacman arguments do not contain exactly one $requiredSwitch switch."
        }
        $index = [Array]::IndexOf($arguments, $requiredSwitch)
        if ($index -lt 0 -or $index + 1 -ge $arguments.Count -or
            [string]::IsNullOrWhiteSpace([string]$arguments[$index + 1])) {
            throw "Generated pacman argument $requiredSwitch has no explicit value."
        }
    }

    if (@($arguments | Where-Object { $_ -ceq '-U' }).Count -ne 1 -or
        @($arguments | Where-Object { $_ -ceq '--' }).Count -ne 1 -or
        $arguments -contains '-S' -or
        $arguments -contains '--sync') {
        throw 'Generated pacman arguments are not one repository-free local upgrade operation.'
    }

    return [string[]]$arguments
}

function Start-PrivatePacmanWatchers {
    param(
        [Parameter(Mandatory)]
        [object[]] $ProtectedRoot
    )

    $watchers = [Collections.Generic.List[object]]::new()
    try {
        foreach ($protected in $ProtectedRoot) {
            if ($protected.Exists) {
                $watcher = [PrivatePacmanV2.TreeWatcher]::new($protected.Path, '*', $true)
            }
            else {
                $parent = [IO.Path]::GetDirectoryName($protected.Path)
                $leaf = [IO.Path]::GetFileName($protected.Path)
                $watcher = [PrivatePacmanV2.TreeWatcher]::new($parent, $leaf, $false)
            }
            $watcher.Start()
            $watchers.Add([pscustomobject][ordered]@{
                Path = $protected.Path
                Watcher = $watcher
            })
        }
        return @($watchers)
    }
    catch {
        foreach ($entry in $watchers) {
            $entry.Watcher.Dispose()
        }
        throw
    }
}

function Stop-PrivatePacmanWatchers {
    param(
        [Parameter(Mandatory)]
        [object[]] $Watcher
    )

    [Threading.Thread]::Sleep(150)
    $results = foreach ($entry in $Watcher) {
        $entry.Watcher.Stop()
        [Threading.Thread]::Sleep(25)
        try {
            [pscustomobject][ordered]@{
                Path = $entry.Path
                Changes = @($entry.Watcher.GetChanges())
                Errors = @($entry.Watcher.GetErrors())
            }
        }
        finally {
            $entry.Watcher.Dispose()
        }
    }
    return @($results)
}

function Get-PrivatePacmanQuiescentSnapshotSet {
    param(
        [Parameter(Mandatory)]
        [object[]] $ProtectedRoot,

        [switch] $RejectReparsePoint,

        [ValidateRange(1, 10)]
        [int] $MaximumAttempts = 4
    )

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        $snapshots = @(foreach ($protected in $ProtectedRoot) {
            Get-PrivatePacmanTreeSnapshotCore `
                -Path $protected.Path `
                -AllowMissing `
                -RejectReparsePoint:$RejectReparsePoint
        })
        $probeWatchers = @(Start-PrivatePacmanWatchers -ProtectedRoot $ProtectedRoot)
        [Threading.Thread]::Sleep(1000)
        $probeEvidence = @(Stop-PrivatePacmanWatchers -Watcher $probeWatchers)
        $errors = @($probeEvidence | ForEach-Object Errors)
        if ($errors.Count -ne 0) {
            throw "Protected-state quiescence watcher failed: $($errors -join '; ')"
        }

        $changes = @($probeEvidence | ForEach-Object Changes)
        if ($changes.Count -eq 0) {
            return $snapshots
        }
    }

    throw "Protected package state did not become quiescent after $MaximumAttempts attempts."
}

function New-PrivatePacmanExternalState {
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [string] $Nonce,

        [Parameter(Mandatory)]
        [string] $StagingRoot
    )

    if ([IO.Directory]::Exists($Layout.StateBase)) {
        [void](Resolve-PrivatePacmanExistingPath `
            -Path $Layout.StateBase `
            -Kind Directory `
            -Name 'Private state base')
    }
    else {
        [void][IO.Directory]::CreateDirectory($Layout.StateBase)
        [void](Resolve-PrivatePacmanExistingPath `
            -Path $Layout.StateBase `
            -Kind Directory `
            -Name 'Private state base')
    }

    if ([IO.Directory]::Exists($Layout.StateDirectory) -or
        [IO.File]::Exists($Layout.StateDirectory)) {
        throw "External session sentinel already exists: $($Layout.StateDirectory)"
    }

    $temporaryState = [IO.Path]::Combine(
        $Layout.StateBase,
        ".$($Layout.SessionId).$Nonce.creating"
    )
    [void][IO.Directory]::CreateDirectory($temporaryState)
    try {
        $temporaryOwner = [IO.Path]::Combine($temporaryState, 'owner.json')
        $sentinel = [pscustomobject][ordered]@{
            Schema = $script:PrivatePacmanSchema
            SessionId = $Layout.SessionId
            Nonce = $Nonce
            Root = $Layout.Root
            StagingRoot = $StagingRoot
            StateDirectory = $Layout.StateDirectory
            EvidenceDirectory = $Layout.EvidenceDirectory
            OwnerProcessId = $PID
            OwnerProcessStartUtc = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('O')
            CreatedUtc = [DateTime]::UtcNow.ToString('O')
            Status = 'initializing'
            ProtectedRoots = @()
            ArgumentsSha256 = $null
            FinishedUtc = $null
            Success = $null
            ResultPath = $null
            ResultSha256 = $null
            RecoveryPath = $null
        }
        Write-PrivatePacmanJson -Path $temporaryOwner -Value $sentinel
        [IO.Directory]::Move($temporaryState, $Layout.StateDirectory)
    }
    catch {
        if ([IO.Directory]::Exists($temporaryState)) {
            foreach ($file in [IO.Directory]::GetFiles($temporaryState)) {
                [IO.File]::Delete($file)
            }
            [IO.Directory]::Delete($temporaryState)
        }
        throw
    }

    [void][IO.Directory]::CreateDirectory($Layout.EvidenceDirectory)
    $stream = [IO.FileStream]::new(
        $Layout.OwnerPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
    return [pscustomobject][ordered]@{
        Sentinel = $sentinel
        Stream = $stream
    }
}

function Remove-PrivatePacmanTreeEntry {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $attributes = [IO.File]::GetAttributes($Path)
    $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    $isReparse = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0

    if ($isDirectory -and -not $isReparse) {
        $children = [IO.Directory]::GetFileSystemEntries($Path)
        foreach ($child in $children) {
            Remove-PrivatePacmanTreeEntry -Path $child
        }
    }

    if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
        [IO.File]::SetAttributes($Path, $attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
    }

    if ($isDirectory) {
        [IO.Directory]::Delete($Path, $false)
    }
    else {
        [IO.File]::Delete($Path)
    }
}

function Remove-OwnedPrivatePacmanRoot {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [string] $Nonce,

        [Parameter(Mandatory)]
        [string[]] $AllowedPath
    )

    if (-not [IO.Directory]::Exists($Path)) {
        return $false
    }

    $allowed = $false
    foreach ($candidate in $AllowedPath) {
        if ([StringComparer]::Ordinal.Equals($Path, $candidate)) {
            $allowed = $true
            break
        }
    }
    if (-not $allowed) {
        throw "Refusing cleanup outside the exact owned root paths: $Path"
    }

    $canonical = Resolve-PrivatePacmanExistingPath -Path $Path -Kind Directory -Name 'Cleanup root'
    if (-not [StringComparer]::Ordinal.Equals($canonical, $Path)) {
        throw "Refusing cleanup through a root alias: $Path -> $canonical"
    }

    $ownerPath = [IO.Path]::Combine($Path, $script:OwnerFileName)
    $ownerCanonical = Resolve-PrivatePacmanExistingPath -Path $ownerPath -Kind File -Name 'Private root owner marker'
    $owner = Get-Content -Raw -LiteralPath $ownerCanonical | ConvertFrom-Json
    if ($owner.Schema -cne $script:PrivatePacmanSchema -or
        $owner.SessionId -cne $Layout.SessionId -or
        $owner.Nonce -cne $Nonce -or
        $owner.Root -cne $Layout.Root -or
        $owner.StateDirectory -cne $Layout.StateDirectory) {
        throw "Refusing cleanup because the private root owner marker does not match: $Path"
    }

    Remove-PrivatePacmanTreeEntry -Path $Path
    return $true
}

function Invoke-PrivatePacmanProcess {
    param(
        [Parameter(Mandatory)]
        [string] $Executable,

        [Parameter(Mandatory)]
        [string[]] $ArgumentList,

        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [TimeSpan] $Timeout
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $Layout.Root
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    [void]$startInfo.Environment.Remove('POSIXLY_CORRECT')
    $startInfo.Environment['MSYS'] = 'winsymlinks:nativestrict'
    $startInfo.Environment['HOME'] = [IO.Path]::Combine($Layout.Root, 'home')
    $startInfo.Environment['TMP'] = [IO.Path]::Combine($Layout.Root, 'tmp')
    $startInfo.Environment['TEMP'] = [IO.Path]::Combine($Layout.Root, 'tmp')
    $startInfo.Environment['TMPDIR'] = [IO.Path]::Combine($Layout.Root, 'tmp')
    $startInfo.Environment['GNUPGHOME'] = $Layout.GpgPath

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = [DateTime]::UtcNow
    if (-not $process.Start()) {
        throw "Unable to start private pacman executable: $Executable"
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Close()
    $timedOut = -not $process.WaitForExit([int][Math]::Ceiling($Timeout.TotalMilliseconds))
    if ($timedOut) {
        $process.Kill($true)
        $process.WaitForExit()
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $result = [pscustomobject][ordered]@{
        ProcessId = $process.Id
        StartedUtc = $started.ToString('O')
        FinishedUtc = [DateTime]::UtcNow.ToString('O')
        TimedOut = $timedOut
        ExitCode = $process.ExitCode
        Stdout = $stdout
        Stderr = $stderr
    }
    $process.Dispose()
    return $result
}

function Invoke-PrivatePacmanUpgrade {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout,

        [Parameter(Mandatory)]
        [string] $SeedRoot,

        [Parameter(Mandatory)]
        [string] $PackageRoot,

        [Parameter(Mandatory)]
        [string] $OwnershipManifestPath,

        [Parameter(Mandatory)]
        [string] $OwnershipSignaturePath,

        [Parameter(Mandatory)]
        [string] $OwnershipPublicKeyPath,

        [Parameter(Mandatory)]
        [string] $ExpectedManifestSha256,

        [Parameter(Mandatory)]
        [string] $ExpectedPublicKeySha256,

        [Parameter(Mandatory)]
        [string] $ExpectedOwner,

        [string[]] $ProtectedRoot = @(),

        [ValidateRange(1, 3600)]
        [int] $TimeoutSeconds = 900
    )

    $canonicalLayout = Assert-PrivatePacmanLayout -Layout $Layout
    if ([IO.Directory]::Exists($canonicalLayout.Root) -or
        [IO.File]::Exists($canonicalLayout.Root)) {
        throw "Private root already exists and will not be reused or deleted: $($canonicalLayout.Root)"
    }
    if ([IO.Directory]::Exists($canonicalLayout.StateDirectory) -or
        [IO.File]::Exists($canonicalLayout.StateDirectory)) {
        throw "External session sentinel already exists: $($canonicalLayout.StateDirectory)"
    }

    $seed = Resolve-PrivatePacmanExistingPath -Path $SeedRoot -Kind Directory -Name 'SeedRoot'
    Assert-PrivatePacmanSameDrive `
        -First $seed `
        -Second $canonicalLayout.WorkspaceRoot `
        -Description 'SeedRoot'
    $ownership = $null
    try {
        $ownership = Open-PrivatePacmanOwnership `
            -Layout $canonicalLayout `
            -PackageRoot $PackageRoot `
            -ManifestPath $OwnershipManifestPath `
            -SignaturePath $OwnershipSignaturePath `
            -PublicKeyPath $OwnershipPublicKeyPath `
            -ExpectedManifestSha256 $ExpectedManifestSha256 `
            -ExpectedPublicKeySha256 $ExpectedPublicKeySha256 `
            -ExpectedOwner $ExpectedOwner
        if ((Test-PrivatePacmanPathWithin -Path $seed -Root $ownership.Root -AllowEqual) -or
            (Test-PrivatePacmanPathWithin -Path $ownership.Root -Root $seed -AllowEqual)) {
            throw 'SeedRoot and PackageRoot must be disjoint.'
        }

        $protected = @(Get-PrivatePacmanProtectedRoots -ProtectedRoot $ProtectedRoot)
        Assert-PrivatePacmanNoProtectedOverlap `
            -InputPath @(
                $canonicalLayout.WorkspaceRoot,
                $seed,
                $ownership.Root,
                $ownership.Evidence.ManifestPath,
                $ownership.Evidence.SignaturePath,
                $ownership.Evidence.PublicKeyPath
            ) `
            -ProtectedRoot $protected
    }
    catch {
        if ($null -ne $ownership) {
            Close-PrivatePacmanLocks -Locks $ownership.PackageLocks
            Close-PrivatePacmanLocks -Locks $ownership.OwnershipLocks
        }
        throw
    }
    $packages = $ownership
    $packageLocks = $ownership.PackageLocks
    $ownershipLocks = $ownership.OwnershipLocks

    $nonce = [guid]::NewGuid().ToString('N')
    $stagingRoot = [IO.Path]::Combine(
        $canonicalLayout.WorkspaceRoot,
        ".$($canonicalLayout.SessionId).$nonce.creating"
    )
    $state = $null
    $watchers = @()
    $rootLocks = [Collections.Generic.List[object]]::new()
    $failures = [Collections.Generic.List[string]]::new()
    $protectedBefore = @()
    $protectedAfter = @()
    $watcherEvidence = @()
    $processEvidence = $null
    $rootEvidence = $null
    $arguments = @()
    $rootRemoved = $false
    $stagingRemoved = $false
    $resultPath = $null
    $startedUtc = [DateTime]::UtcNow.ToString('O')

    try {
        $state = New-PrivatePacmanExternalState `
            -Layout $canonicalLayout `
            -Nonce $nonce `
            -StagingRoot $stagingRoot
        $resultPath = [IO.Path]::Combine($canonicalLayout.EvidenceDirectory, 'result.json')

        $protectedPreflight = @(
            Get-PrivatePacmanQuiescentSnapshotSet `
                -ProtectedRoot $protected `
                -RejectReparsePoint
        )
        $watchers = @(Start-PrivatePacmanWatchers -ProtectedRoot $protected)
        $protectedBefore = @(for ($index = 0; $index -lt $protected.Count; $index++) {
            $protectedEntry = $protected[$index]
            $snapshot = Get-PrivatePacmanTreeSnapshotCore `
                -Path $protectedEntry.Path `
                -AllowMissing `
                -RejectReparsePoint
            $fileName = "protected-$index-before.json"
            Write-PrivatePacmanJson `
                -Path ([IO.Path]::Combine($canonicalLayout.EvidenceDirectory, $fileName)) `
                -Value $snapshot
            [pscustomobject][ordered]@{
                Path = $snapshot.Path
                Exists = $snapshot.Exists
                Digest = $snapshot.Digest
                ContentDigest = $snapshot.ContentDigest
                EntryCount = $snapshot.EntryCount
                RootAttributes = $snapshot.RootAttributes
                RootOwnerSid = $snapshot.RootOwnerSid
                RootSecurityDescriptorSddl = $snapshot.RootSecurityDescriptorSddl
                RootChangeTimeFileTime = $snapshot.RootChangeTimeFileTime
                RootIdentity = $snapshot.RootIdentity
                AlternateDataStreams = 'forbidden'
                Manifest = $fileName
                IsCanonicalSharedRoot = $protectedEntry.IsCanonicalSharedRoot
            }
        })
        for ($index = 0; $index -lt $protectedBefore.Count; $index++) {
            if ($protectedPreflight[$index].Exists -ne $protectedBefore[$index].Exists -or
                $protectedPreflight[$index].Digest -cne $protectedBefore[$index].Digest) {
                throw "Protected package state was not stable before monitoring: $($protectedBefore[$index].Path)"
            }
        }
        $state.Sentinel.ProtectedRoots = @($protectedBefore)
        Set-PrivatePacmanLockedJson -Stream $state.Stream -Value $state.Sentinel

        $rootEvidence = Initialize-PrivatePacmanRoot `
            -Layout $canonicalLayout `
            -SeedRoot $seed `
            -StagingRoot $stagingRoot `
            -Nonce $nonce

        foreach ($managedDirectory in @(
            $canonicalLayout.Root,
            $canonicalLayout.DatabasePath,
            $canonicalLayout.CachePath,
            $canonicalLayout.HookPath,
            $canonicalLayout.GpgPath
        )) {
            [void](Resolve-PrivatePacmanExistingPath `
                -Path $managedDirectory `
                -Kind Directory `
                -Name 'Managed private directory')
        }
        foreach ($managedFile in @(
            $canonicalLayout.LogPath,
            $canonicalLayout.ConfigPath,
            $canonicalLayout.PacmanPath,
            ([IO.Path]::Combine($canonicalLayout.Root, $script:OwnerFileName))
        )) {
            [void](Resolve-PrivatePacmanExistingPath `
                -Path $managedFile `
                -Kind File `
                -Name 'Managed private file')
        }

        Test-PrivatePacmanDirectoryEmpty `
            -Path $canonicalLayout.HookPath `
            -Name 'Configured hook directory'
        Test-PrivatePacmanDirectoryEmpty `
            -Path ([IO.Path]::Combine($canonicalLayout.Root, 'usr\share\libalpm\hooks')) `
            -Name 'Root-local default hook directory'

        $rootLocks.Add((Open-PrivatePacmanReadLock `
            -Path $canonicalLayout.ConfigPath `
            -Name 'Private config'))
        $rootLocks.Add((Open-PrivatePacmanReadLock `
            -Path $canonicalLayout.PacmanPath `
            -Name 'Private pacman executable'))
        $rootLocks.Add((Open-PrivatePacmanReadLock `
            -Path ([IO.Path]::Combine($canonicalLayout.Root, $script:OwnerFileName)) `
            -Name 'Private root owner marker'))

        $arguments = New-PrivatePacmanArgumentList `
            -Layout $canonicalLayout `
            -PackagePath $packages.Paths
        Write-PrivatePacmanJson `
            -Path ([IO.Path]::Combine($canonicalLayout.EvidenceDirectory, 'invocation.json')) `
            -Value ([pscustomobject][ordered]@{
                Executable = $canonicalLayout.PacmanPath
                Arguments = $arguments
                Ownership = $ownership.Evidence
                Packages = @($packageLocks | Select-Object Path, Identity, LinkCount, Sha256)
                Root = $rootEvidence
                Environment = [pscustomobject][ordered]@{
                    MSYS = 'winsymlinks:nativestrict'
                    POSIXLY_CORRECT = '<removed>'
                    HOME = [IO.Path]::Combine($canonicalLayout.Root, 'home')
                    TMP = [IO.Path]::Combine($canonicalLayout.Root, 'tmp')
                    GNUPGHOME = $canonicalLayout.GpgPath
                }
            })

        $state.Sentinel.Status = 'running'
        $state.Sentinel.ArgumentsSha256 = Get-PrivatePacmanStringSha256 `
            -Value ($arguments | ConvertTo-Json -Compress)
        Set-PrivatePacmanLockedJson -Stream $state.Stream -Value $state.Sentinel

        $processEvidence = Invoke-PrivatePacmanProcess `
            -Executable $canonicalLayout.PacmanPath `
            -ArgumentList $arguments `
            -Layout $canonicalLayout `
            -Timeout ([TimeSpan]::FromSeconds($TimeoutSeconds))
        if ($processEvidence.TimedOut) {
            $failures.Add("Private pacman timed out after $TimeoutSeconds seconds.")
        }
        elseif ($processEvidence.ExitCode -ne 0) {
            $failures.Add("Private pacman exited with code $($processEvidence.ExitCode).")
        }

        foreach ($lock in @($ownershipLocks) + @($packageLocks) + @($rootLocks)) {
            if ($lock.Sha256 -cne (Get-PrivatePacmanFileHash -Path $lock.Path)) {
                $failures.Add("Locked input bytes changed: $($lock.Path)")
            }
        }
        if ($rootEvidence.ConfigSha256 -cne (Get-PrivatePacmanFileHash -Path $canonicalLayout.ConfigPath)) {
            $failures.Add('Private pacman configuration changed during execution.')
        }
    }
    catch {
        $failures.Add($_.Exception.Message)
    }
    finally {
        try {
            Close-PrivatePacmanLocks -Locks $rootLocks
        }
        catch {
            $failures.Add("Unable to release private-root locks: $($_.Exception.Message)")
        }

        try {
            if ([IO.Directory]::Exists($canonicalLayout.Root)) {
                $rootRemoved = Remove-OwnedPrivatePacmanRoot `
                    -Path $canonicalLayout.Root `
                    -Layout $canonicalLayout `
                    -Nonce $nonce `
                    -AllowedPath @($canonicalLayout.Root, $stagingRoot)
            }
        }
        catch {
            $failures.Add("Private-root cleanup failed: $($_.Exception.Message)")
        }

        try {
            if ([IO.Directory]::Exists($stagingRoot)) {
                $stagingRemoved = Remove-OwnedPrivatePacmanRoot `
                    -Path $stagingRoot `
                    -Layout $canonicalLayout `
                    -Nonce $nonce `
                    -AllowedPath @($canonicalLayout.Root, $stagingRoot)
            }
        }
        catch {
            $failures.Add("Staging-root cleanup failed: $($_.Exception.Message)")
        }

        try {
            Close-PrivatePacmanLocks -Locks $packageLocks
        }
        catch {
            $failures.Add("Unable to release package locks: $($_.Exception.Message)")
        }

        try {
            Close-PrivatePacmanLocks -Locks $ownershipLocks
        }
        catch {
            $failures.Add("Unable to release ownership-evidence locks: $($_.Exception.Message)")
        }

        if ($watchers.Count -ne 0) {
            try {
                $protectedAfter = @(foreach ($protectedEntry in $protected) {
                    $snapshot = Get-PrivatePacmanTreeSnapshotCore `
                        -Path $protectedEntry.Path `
                        -AllowMissing `
                        -RejectReparsePoint
                    $fileName = "protected-$([Array]::IndexOf($protected, $protectedEntry))-after.json"
                    Write-PrivatePacmanJson `
                        -Path ([IO.Path]::Combine($canonicalLayout.EvidenceDirectory, $fileName)) `
                        -Value $snapshot
                    [pscustomobject][ordered]@{
                        Path = $snapshot.Path
                        Exists = $snapshot.Exists
                        Digest = $snapshot.Digest
                        ContentDigest = $snapshot.ContentDigest
                        EntryCount = $snapshot.EntryCount
                        RootAttributes = $snapshot.RootAttributes
                        RootOwnerSid = $snapshot.RootOwnerSid
                        RootSecurityDescriptorSddl = $snapshot.RootSecurityDescriptorSddl
                        RootChangeTimeFileTime = $snapshot.RootChangeTimeFileTime
                        RootIdentity = $snapshot.RootIdentity
                        AlternateDataStreams = 'forbidden'
                        Manifest = $fileName
                        IsCanonicalSharedRoot = $protectedEntry.IsCanonicalSharedRoot
                    }
                })
            }
            catch {
                $failures.Add("Protected-state after-snapshot failed: $($_.Exception.Message)")
            }

            try {
                $watcherEvidence = @(Stop-PrivatePacmanWatchers -Watcher $watchers)
            }
            catch {
                $failures.Add("Protected-state watcher shutdown failed: $($_.Exception.Message)")
            }
        }

        if ($protectedBefore.Count -ne $protectedAfter.Count) {
            $failures.Add('Protected-state evidence is incomplete.')
        }
        else {
            for ($index = 0; $index -lt $protectedBefore.Count; $index++) {
                $before = $protectedBefore[$index]
                $after = $protectedAfter[$index]
                if ($before.Exists -ne $after.Exists -or $before.Digest -cne $after.Digest) {
                    $failures.Add("Protected package state changed: $($before.Path)")
                }
            }
        }
        foreach ($watcher in $watcherEvidence) {
            if ($watcher.Errors.Count -ne 0) {
                $failures.Add("Protected-state watcher failed for $($watcher.Path).")
            }
            if ($watcher.Changes.Count -ne 0) {
                $failures.Add("Protected package state emitted change events: $($watcher.Path)")
            }
        }

        if ([IO.Directory]::Exists($canonicalLayout.Root) -or
            [IO.Directory]::Exists($stagingRoot)) {
            $failures.Add('One or more private transaction roots remain after cleanup.')
        }

        if ($null -ne $state) {
            $success = $failures.Count -eq 0
            $evidence = [pscustomobject][ordered]@{
                Schema = $script:PrivatePacmanSchema
                SessionId = $canonicalLayout.SessionId
                Nonce = $nonce
                StartedUtc = $startedUtc
                FinishedUtc = [DateTime]::UtcNow.ToString('O')
                Success = $success
                Failures = @($failures)
                Layout = $canonicalLayout
                Seed = $rootEvidence
                Ownership = $ownership.Evidence
                Packages = @($packageLocks | Select-Object Path, Identity, LinkCount, Sha256)
                Invocation = [pscustomobject][ordered]@{
                    Executable = $canonicalLayout.PacmanPath
                    Arguments = $arguments
                    Process = $processEvidence
                }
                ProtectedBefore = $protectedBefore
                ProtectedAfter = $protectedAfter
                Watchers = $watcherEvidence
                Cleanup = [pscustomobject][ordered]@{
                    RootRemoved = $rootRemoved
                    StagingRootRemoved = $stagingRemoved
                    RootAbsent = -not [IO.Directory]::Exists($canonicalLayout.Root)
                    StagingRootAbsent = -not [IO.Directory]::Exists($stagingRoot)
                    EvidencePreservedOutsideRoot = -not (Test-PrivatePacmanPathWithin `
                        -Path $canonicalLayout.EvidenceDirectory `
                        -Root $canonicalLayout.Root)
                }
            }

            try {
                Write-PrivatePacmanJson -Path $resultPath -Value $evidence
                $state.Sentinel.Status = if ($success) { 'complete' } else { 'failed' }
                $state.Sentinel.FinishedUtc = $evidence.FinishedUtc
                $state.Sentinel.Success = $success
                $state.Sentinel.ResultPath = $resultPath
                $state.Sentinel.ResultSha256 = Get-PrivatePacmanFileHash -Path $resultPath
                Set-PrivatePacmanLockedJson -Stream $state.Stream -Value $state.Sentinel
            }
            catch {
                $failures.Add("Unable to persist complete transaction evidence: $($_.Exception.Message)")
                $success = $false
                $evidence.Success = $false
                $evidence.Failures = @($failures)
                try {
                    Write-PrivatePacmanJson -Path $resultPath -Value $evidence
                }
                catch {
                    $failures.Add("Unable to rewrite failed transaction evidence: $($_.Exception.Message)")
                }
            }
            finally {
                $state.Stream.Dispose()
            }
        }
    }

    if ($failures.Count -ne 0) {
        $message = "Private pacman transaction failed closed."
        if ($null -ne $resultPath) {
            $message += " Evidence: $resultPath"
        }
        $message += "`n" + ($failures -join "`n")
        throw [InvalidOperationException]::new($message)
    }

    return Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
}

function Remove-PrivatePacmanSession {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [psobject] $Layout
    )

    $canonicalLayout = Assert-PrivatePacmanLayout -Layout $Layout
    $stateDirectory = Resolve-PrivatePacmanExistingPath `
        -Path $canonicalLayout.StateDirectory `
        -Kind Directory `
        -Name 'External session state'
    $ownerPath = Resolve-PrivatePacmanExistingPath `
        -Path $canonicalLayout.OwnerPath `
        -Kind File `
        -Name 'External session sentinel'

    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $ownerPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch {
        throw "Private pacman session is still active or its sentinel cannot be locked: $ownerPath"
    }

    try {
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $true, 4096, $true)
        try {
            $sentinel = $reader.ReadToEnd() | ConvertFrom-Json
        }
        finally {
            $reader.Dispose()
        }

        if ($sentinel.Schema -cne $script:PrivatePacmanSchema -or
            $sentinel.SessionId -cne $canonicalLayout.SessionId -or
            $sentinel.Root -cne $canonicalLayout.Root -or
            $sentinel.StateDirectory -cne $stateDirectory) {
            throw 'External session sentinel does not match the requested layout.'
        }

        if ([string]$sentinel.Nonce -notmatch '^[0-9a-f]{32}$') {
            throw 'External session sentinel contains an invalid ownership nonce.'
        }
        $expectedStagingRoot = [IO.Path]::Combine(
            $canonicalLayout.WorkspaceRoot,
            ".$($canonicalLayout.SessionId).$($sentinel.Nonce).creating"
        )
        if ([string]$sentinel.StagingRoot -cne $expectedStagingRoot) {
            throw 'External session sentinel contains a noncanonical staging root.'
        }

        if (-not $PSCmdlet.ShouldProcess($canonicalLayout.Root, 'Remove stale private pacman transaction roots')) {
            return
        }

        $removed = [Collections.Generic.List[string]]::new()
        foreach ($candidate in @($canonicalLayout.Root, $expectedStagingRoot)) {
            if (-not [string]::IsNullOrEmpty($candidate) -and [IO.Directory]::Exists($candidate)) {
                [void](Remove-OwnedPrivatePacmanRoot `
                    -Path $candidate `
                    -Layout $canonicalLayout `
                    -Nonce ([string]$sentinel.Nonce) `
                    -AllowedPath @($canonicalLayout.Root, $expectedStagingRoot))
                $removed.Add($candidate)
            }
        }

        $recovery = [pscustomobject][ordered]@{
            Schema = $script:PrivatePacmanSchema
            SessionId = $canonicalLayout.SessionId
            RecoveredUtc = [DateTime]::UtcNow.ToString('O')
            RemovedRoots = @($removed)
            WatcherContinuity = $false
            Result = 'cleaned-fail-closed'
            Note = 'The owner process ended before normal evidence closure; transient protected-state changes cannot be excluded.'
        }
        $recoveryPath = [IO.Path]::Combine($canonicalLayout.EvidenceDirectory, 'recovery.json')
        Write-PrivatePacmanJson -Path $recoveryPath -Value $recovery
        $sentinel.Status = 'recovered'
        $sentinel.FinishedUtc = $recovery.RecoveredUtc
        $sentinel.Success = $false
        $sentinel.RecoveryPath = $recoveryPath
        Set-PrivatePacmanLockedJson -Stream $stream -Value $sentinel
        return $recovery
    }
    finally {
        $stream.Dispose()
    }
}

Export-ModuleMember -Function @(
    'New-PrivatePacmanLayout',
    'New-PrivatePacmanOwnershipManifest',
    'Get-PrivatePacmanTreeSnapshot',
    'Invoke-PrivatePacmanUpgrade',
    'Remove-PrivatePacmanSession'
)

[CmdletBinding()]
param(
    [string[]]$Paths = @(),
    [string[]]$ForbiddenPaths = @(),
    [string]$OutputPath,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText(
        $Path,
        $Content,
        [Text.UTF8Encoding]::new($false))
}

function Get-PathVariants {
    param([Parameter(Mandatory = $true)][string]$Path)

    $variants = [Collections.Generic.List[string]]::new()
    $variants.Add($Path)
    $variants.Add($Path.Replace('\', '/'))
    $variants.Add($Path.Replace('/', '\'))
    $variants.Add($Path.Replace('\', '\\'))
    if ($Path -match '^(?<drive>[A-Za-z]):[\\/](?<rest>.*)$') {
        $drive = $Matches.drive.ToLowerInvariant()
        $rest = $Matches.rest.Replace('\', '/')
        $variants.Add("/$drive/$rest")
        $variants.Add("/cygdrive/$drive/$rest")
    }
    return @($variants | Where-Object { $_ } | Sort-Object -Unique)
}

if (-not ('MsysArm64PathScan.ByteScanner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace MsysArm64PathScan
{
    public sealed class Finding
    {
        public string Encoding { get; set; }
        public long Offset { get; set; }
        public string Kind { get; set; }
        public string ValueSha256 { get; set; }
    }

    public static class ByteScanner
    {
        private const int BufferSize = 1024 * 1024;

        private static string HashValue(string value)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(value));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        private static void FinishSequence(
            StringBuilder value,
            long offset,
            string encoding,
            string[] forbidden,
            Regex generic,
            List<Finding> findings)
        {
            if (value.Length < 4)
            {
                value.Clear();
                return;
            }

            string text = value.ToString();
            string kind = null;
            foreach (string candidate in forbidden)
            {
                if (text.IndexOf(candidate, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    kind = "forbidden-root";
                    break;
                }
            }
            if (kind == null && generic.IsMatch(text))
            {
                kind = "generic-private-root";
            }
            if (kind != null)
            {
                findings.Add(new Finding
                {
                    Encoding = encoding,
                    Offset = offset,
                    Kind = kind,
                    ValueSha256 = HashValue(text)
                });
            }
            value.Clear();
        }

        private static void ScanAscii(
            string path,
            string[] forbidden,
            Regex generic,
            List<Finding> findings)
        {
            byte[] buffer = new byte[BufferSize];
            StringBuilder value = new StringBuilder();
            long valueOffset = 0;
            long offset = 0;
            using (FileStream stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize,
                FileOptions.SequentialScan))
            {
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    for (int index = 0; index < count; index++, offset++)
                    {
                        byte current = buffer[index];
                        if (current >= 0x20 && current <= 0x7e)
                        {
                            if (value.Length == 0)
                            {
                                valueOffset = offset;
                            }
                            value.Append((char)current);
                        }
                        else
                        {
                            FinishSequence(
                                value, valueOffset, "ascii", forbidden, generic,
                                findings);
                        }
                    }
                }
            }
            FinishSequence(
                value, valueOffset, "ascii", forbidden, generic, findings);
        }

        private static void ScanUtf16(
            string path,
            bool littleEndian,
            int alignment,
            string[] forbidden,
            Regex generic,
            List<Finding> findings)
        {
            byte[] buffer = new byte[BufferSize];
            StringBuilder value = new StringBuilder();
            long valueOffset = 0;
            long offset = alignment;
            bool haveFirst = false;
            byte first = 0;
            long pairOffset = 0;
            string encoding = (littleEndian ? "utf16le-" : "utf16be-") + alignment;
            using (FileStream stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize,
                FileOptions.SequentialScan))
            {
                stream.Position = alignment;
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    for (int index = 0; index < count; index++, offset++)
                    {
                        if (!haveFirst)
                        {
                            first = buffer[index];
                            pairOffset = offset;
                            haveFirst = true;
                            continue;
                        }

                        byte second = buffer[index];
                        bool printable = littleEndian
                            ? first >= 0x20 && first <= 0x7e && second == 0
                            : first == 0 && second >= 0x20 && second <= 0x7e;
                        if (printable)
                        {
                            if (value.Length == 0)
                            {
                                valueOffset = pairOffset;
                            }
                            value.Append((char)(littleEndian ? first : second));
                        }
                        else
                        {
                            FinishSequence(
                                value, valueOffset, encoding, forbidden, generic,
                                findings);
                        }
                        haveFirst = false;
                    }
                }
            }
            FinishSequence(
                value, valueOffset, encoding, forbidden, generic, findings);
        }

        public static Finding[] ScanFile(
            string path,
            string[] forbidden,
            string genericPattern)
        {
            Regex generic = new Regex(
                genericPattern,
                RegexOptions.Compiled |
                RegexOptions.CultureInvariant |
                RegexOptions.IgnoreCase);
            List<Finding> findings = new List<Finding>();
            ScanAscii(path, forbidden, generic, findings);
            ScanUtf16(path, true, 0, forbidden, generic, findings);
            ScanUtf16(path, true, 1, forbidden, generic, findings);
            ScanUtf16(path, false, 0, forbidden, generic, findings);
            ScanUtf16(path, false, 1, forbidden, generic, findings);
            return findings.ToArray();
        }
    }
}
'@
}

function Invoke-PathScan {
    param(
        [Parameter(Mandatory = $true)][string[]]$ScanPaths,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Forbidden,
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [switch]$AllowLeaks
    )

    $files = [Collections.Generic.List[IO.FileInfo]]::new()
    foreach ($path in $ScanPaths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $files.Add((Get-Item -LiteralPath $path))
        }
        elseif (Test-Path -LiteralPath $path -PathType Container) {
            $entries = @(Get-ChildItem -LiteralPath $path -Recurse -Force)
            foreach ($entry in $entries | Where-Object {
                $_.Attributes -band [IO.FileAttributes]::ReparsePoint
            }) {
                throw "Path scanner refuses reparse input: $($entry.Name)"
            }
            foreach ($file in $entries | Where-Object {
                -not $_.PSIsContainer
            }) {
                $files.Add($file)
            }
        }
        else {
            throw "Path scanner input does not exist: $path"
        }
    }
    $files = @($files | Sort-Object FullName -Unique)

    $variants = @($Forbidden | ForEach-Object {
        Get-PathVariants -Path $_
    } | Sort-Object -Unique)
    $genericPattern =
        '(?:[A-Z]:(?:\\+|/)(?:Users|a)(?:\\+|/)|/(?:cygdrive/[a-z]|[a-z])/(?:Users|a)/|/(?:tmp|var/tmp|home)/)'
    $findings = [Collections.Generic.List[object]]::new()
    [long]$totalBytes = 0
    foreach ($file in $files) {
        $totalBytes += $file.Length
        foreach ($finding in [MsysArm64PathScan.ByteScanner]::ScanFile(
            $file.FullName,
            [string[]]$variants,
            $genericPattern)) {
            $findings.Add([ordered]@{
                file = $file.Name
                encoding = $finding.Encoding
                offset = $finding.Offset
                kind = $finding.Kind
                value_sha256 = $finding.ValueSha256
            })
        }
    }

    $report = [ordered]@{
        schema = 1
        scanner_sha256 = (
            Get-FileHash -Algorithm SHA256 $PSCommandPath
        ).Hash.ToLowerInvariant()
        files_enumerated = $files.Count
        files_scanned = $files.Count
        bytes_scanned = $totalBytes
        leak_count = $findings.Count
        unique_leak_values = @($findings | ForEach-Object {
            $_.value_sha256
        } | Sort-Object -Unique).Count
        encodings = @('ascii', 'utf16le', 'utf16be')
        result = if ($findings.Count -eq 0) { 'pass' } else { 'fail' }
        findings = @($findings)
    }
    Write-Utf8NoBom `
        -Path $ReportPath `
        -Content ($report | ConvertTo-Json -Depth 6)
    if ($findings.Count -ne 0 -and -not $AllowLeaks) {
        throw "Binary-safe path scan found $($findings.Count) private strings"
    }
    return $report
}

if ($SelfTest) {
    $temporaryRoot = if ($env:RUNNER_TEMP) {
        $env:RUNNER_TEMP
    }
    else {
        [IO.Path]::GetTempPath()
    }
    $testRoot = Join-Path $temporaryRoot `
        "libuuid-path-scanner-selftest-$([Guid]::NewGuid().ToString('N'))"
    $report = "$testRoot-report.json"
    $reparsePath = $null
    $reparseTarget = $null
    try {
        New-Item -ItemType Directory -Path $testRoot | Out-Null
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'ascii.bin'),
            [byte[]](
                @(0, 1, 2, 0) +
                [Text.Encoding]::ASCII.GetBytes(
                    'C:\Users\maintainer\private\object.o') +
                @(0, 255, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'utf16le.bin'),
            [byte[]](
                @(0, 255, 0) +
                [Text.Encoding]::Unicode.GetBytes(
                    '/c/Users/maintainer/private/source.c') +
                @(0, 255, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'utf16be.bin'),
            [byte[]](
                @(0, 255, 0) +
                [Text.Encoding]::BigEndianUnicode.GetBytes(
                    '/c/Users/maintainer/private/header.h') +
                @(0, 255, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'nul-rich.bin'),
            [byte[]](
                @(0, 0, 0, 0, 1, 0, 2, 0) +
                [Text.Encoding]::ASCII.GetBytes('/d/a/project/private') +
                @(0, 0, 0, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'msys-logical-alias.bin'),
            [byte[]](
                @(0, 5, 0) +
                [Text.Encoding]::ASCII.GetBytes(
                   '/tmp/libuuid-private/generated.obj') +
                @(0, 7, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'explicit-root.unknown'),
            [byte[]](
                @(0, 17, 0) +
                [Text.Encoding]::ASCII.GetBytes(
                    'Q:\sealed\private\generated.obj') +
                @(0, 19, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'json-escaped.bin'),
            [byte[]](
                @(0, 23, 0) +
                [Text.Encoding]::ASCII.GetBytes(
                    '{"path":"C:\\Users\\maintainer\\private\\object.o"}') +
                @(0, 29, 0)))
        [IO.File]::WriteAllBytes(
            (Join-Path $testRoot 'safe.bin'),
            [byte[]](0, 1, 2, 3, 65, 82, 77, 54, 52, 0))
        $testResult = Invoke-PathScan `
            -ScanPaths @($testRoot) `
            -Forbidden @('Q:\sealed\private') `
            -ReportPath $report `
            -AllowLeaks
        if ($testResult.files_enumerated -ne 8 -or
            $testResult.files_scanned -ne 8 -or
            $testResult.leak_count -lt 7 -or
            @($testResult.findings.encoding | Where-Object {
                $_ -eq 'ascii'
            }).Count -lt 4 -or
            @($testResult.findings.encoding | Where-Object {
                $_ -like 'utf16le-*'
            }).Count -lt 1 -or
            @($testResult.findings.encoding | Where-Object {
                $_ -like 'utf16be-*'
            }).Count -lt 1) {
            throw 'Binary-safe path scanner self-test failed'
        }

        $reparseTarget = "$testRoot-unclassified-target"
        $reparsePath = Join-Path $testRoot 'unclassified-input'
        New-Item -ItemType Directory -Path $reparseTarget | Out-Null
        New-Item -ItemType Junction -Path $reparsePath `
            -Target $reparseTarget | Out-Null
        $unclassifiedRejected = $false
        try {
            Invoke-PathScan `
                -ScanPaths @($testRoot) `
                -Forbidden @() `
                -ReportPath "$report-unclassified" |
                Out-Null
        }
        catch {
            $unclassifiedRejected =
                $_.Exception.Message -match 'refuses reparse input'
        }
        Remove-Item -LiteralPath $reparsePath -Force
        Remove-Item -LiteralPath $reparseTarget -Force
        if (-not $unclassifiedRejected) {
            throw 'Binary-safe path scanner accepted unclassified input'
        }

        $lockedPath = Join-Path $testRoot 'unreadable.bin'
        [IO.File]::WriteAllBytes(
            $lockedPath,
            [Text.Encoding]::ASCII.GetBytes('safe-content'))
        $lock = [IO.File]::Open(
            $lockedPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        $unreadableRejected = $false
        $unreadableMessage = $null
        try {
            Invoke-PathScan `
                -ScanPaths @($lockedPath) `
                -Forbidden @() `
                -ReportPath "$report-unreadable" |
                Out-Null
        }
        catch {
            $unreadableRejected = $true
            $unreadableMessage = $_.Exception.Message
        }
        finally {
            $lock.Dispose()
        }
        if (-not $unreadableRejected -or
            $unreadableMessage -notmatch
                'being used by another process|cannot access|access.*denied') {
            throw 'Binary-safe path scanner accepted an unreadable input'
        }
    }
    finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
        if (Test-Path -LiteralPath $report) {
            Remove-Item -LiteralPath $report -Force
        }
        if (Test-Path -LiteralPath "$report-unreadable") {
            Remove-Item -LiteralPath "$report-unreadable" -Force
        }
        if (Test-Path -LiteralPath "$report-unclassified") {
            Remove-Item -LiteralPath "$report-unclassified" -Force
        }
        if ($reparsePath -and (Test-Path -LiteralPath $reparsePath)) {
            Remove-Item -LiteralPath $reparsePath -Force
        }
        if ($reparseTarget -and (Test-Path -LiteralPath $reparseTarget)) {
            Remove-Item -LiteralPath $reparseTarget -Recurse -Force
        }
    }
}

if ($Paths.Count -ne 0) {
    if (-not $OutputPath) {
        throw 'OutputPath is required for a path scan'
    }
    Invoke-PathScan `
        -ScanPaths $Paths `
        -Forbidden $ForbiddenPaths `
        -ReportPath $OutputPath |
        Out-Null
}
elseif (-not $SelfTest) {
    throw 'Specify Paths or SelfTest'
}

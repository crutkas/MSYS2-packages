[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $InputPath,

    [Parameter(Mandatory = $true)]
    [string[]] $ForbiddenPath,

    [string] $Bsdtar = 'C:\msys64\usr\bin\bsdtar.exe',
    [string] $EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('GnuPGByteScanner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;

public static class GnuPGByteScanner
{
    private static byte LowerAscii(byte value)
    {
        return value >= 0x41 && value <= 0x5a ? (byte)(value + 0x20) : value;
    }

    public static bool ContainsAsciiCaseInsensitive(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length)
            return false;
        for (int offset = 0; offset <= haystack.Length - needle.Length; offset++)
        {
            bool matched = true;
            for (int index = 0; index < needle.Length; index++)
            {
                if (LowerAscii(haystack[offset + index]) != LowerAscii(needle[index]))
                {
                    matched = false;
                    break;
                }
            }
            if (matched)
                return true;
        }
        return false;
    }

    public static byte[] RemoveNuls(byte[] bytes)
    {
        int count = 0;
        foreach (byte value in bytes)
            if (value != 0)
                count++;
        byte[] result = new byte[count];
        int index = 0;
        foreach (byte value in bytes)
            if (value != 0)
                result[index++] = value;
        return result;
    }
}
'@
}

function Convert-AsciiLower {
    param([byte[]] $Bytes)
    $result = [byte[]]::new($Bytes.Length)
    for ($index = 0; $index -lt $Bytes.Length; $index++) {
        $value = $Bytes[$index]
        $result[$index] = if ($value -ge 0x41 -and $value -le 0x5a) {
            [byte] ($value + 0x20)
        }
        else {
            $value
        }
    }
    return $result
}

function Test-ByteSequence {
    param([byte[]] $Haystack, [byte[]] $Needle)
    return [GnuPGByteScanner]::ContainsAsciiCaseInsensitive($Haystack, $Needle)
}

function Convert-Utf16Be {
    param([string] $Text)
    $littleEndian = [Text.Encoding]::Unicode.GetBytes($Text)
    for ($index = 0; $index -lt $littleEndian.Length; $index += 2) {
        $temporary = $littleEndian[$index]
        $littleEndian[$index] = $littleEndian[$index + 1]
        $littleEndian[$index + 1] = $temporary
    }
    return $littleEndian
}

function Get-ForbiddenVariants {
    param([string] $Path)
    $full = $Path.Trim()
    if ([string]::IsNullOrWhiteSpace($full)) {
        throw 'Forbidden paths cannot be empty'
    }
    $variants = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void] $variants.Add($full)
    [void] $variants.Add($full.Replace('\', '/'))
    [void] $variants.Add($full.Replace('/', '\'))
    if ($full -match '^(?<drive>[A-Za-z]):[\\/](?<tail>.*)$') {
        [void] $variants.Add("/$($Matches.drive.ToLowerInvariant())/$($Matches.tail.Replace('\', '/'))")
    }
    return @($variants)
}

function Assert-SafeArchivePath {
    param([string] $Entry, [string] $Archive)
    $normalized = $Entry.Replace('\', '/')
    if ($normalized.StartsWith('/') -or $normalized.StartsWith('//') -or
        $normalized -match '^[A-Za-z]:' -or
        $normalized -match '(^|/)\.\.?(/|$)' -or
        $normalized -match '//') {
        throw "Unsafe package archive path in $Archive`: $Entry"
    }
}

function Assert-SafeLinkTarget {
    param(
        [string] $Entry,
        [string] $Target,
        [string] $Archive,
        [string] $Root,
        [switch] $HardLink
    )
    $normalized = $Target.Replace('\', '/')
    if ($normalized.StartsWith('/') -or $normalized.StartsWith('//') -or
        $normalized -match '^[A-Za-z]:' -or $normalized.StartsWith('\\?\') -or
        $normalized.StartsWith('\\.\')) {
        throw "Unsafe package link target in $Archive`: $Entry -> $Target"
    }
    $base = if ($HardLink) { $Root } else { Split-Path -Parent (Join-Path $Root $Entry) }
    $resolvedTarget = [IO.Path]::GetFullPath((Join-Path $base $Target))
    $rootPrefix = "$([IO.Path]::GetFullPath($Root).TrimEnd('\'))\"
    if (-not $resolvedTarget.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package link escapes extraction root in $Archive`: $Entry -> $Target"
    }
}

function Assert-CleanBytes {
    param(
        [byte[]] $Bytes,
        [string] $DisplayPath,
        [object[]] $Patterns
    )
    $withoutNuls = [GnuPGByteScanner]::RemoveNuls($Bytes)
    foreach ($pattern in $Patterns) {
        $checks = [ordered]@{
            ascii = $pattern.ascii
            utf16le = $pattern.utf16le
            utf16be = $pattern.utf16be
            nul_rich = $pattern.ascii
        }
        foreach ($mode in $checks.Keys) {
            $haystack = if ($mode -eq 'nul_rich') { $withoutNuls } else { $Bytes }
            if (Test-ByteSequence $haystack $checks[$mode]) {
                throw "Forbidden path '$($pattern.text)' found as $mode in $DisplayPath"
            }
        }
    }
}

$patterns = @(
    foreach ($path in $ForbiddenPath) {
        foreach ($variant in Get-ForbiddenVariants $path) {
            $lower = $variant.ToLowerInvariant()
            [pscustomobject]@{
                text = $variant
                ascii = Convert-AsciiLower ([Text.Encoding]::ASCII.GetBytes($lower))
                utf16le = Convert-AsciiLower ([Text.Encoding]::Unicode.GetBytes($lower))
                utf16be = Convert-AsciiLower (Convert-Utf16Be $lower)
            }
        }
    }
)

$temporaryRoots = [Collections.Generic.List[string]]::new()
$records = [Collections.Generic.List[object]]::new()
$inputRecords = [Collections.Generic.List[object]]::new()
try {
    foreach ($input in $InputPath) {
        $resolved = (Resolve-Path -LiteralPath $input).Path
        $scanRoot = $resolved
        if (Test-Path -LiteralPath $resolved -PathType Container) {
            $inputRecords.Add([ordered]@{
                path = $resolved
                type = 'directory'
            })
        }
        else {
            $archiveItem = Get-Item -LiteralPath $resolved
            $inputRecords.Add([ordered]@{
                path = $resolved
                type = 'archive'
                bytes = $archiveItem.Length
                sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
            })
            $listing = @(& $Bsdtar -tf $resolved)
            if ($LASTEXITCODE -ne 0) {
                throw "Unable to list package archive: $resolved"
            }
            $verboseListing = @(& $Bsdtar -tvf $resolved)
            if ($LASTEXITCODE -ne 0 -or $listing.Count -ne $verboseListing.Count) {
                throw "Unable to inspect package archive entry types: $resolved"
            }
            $containmentRoot = Join-Path ([IO.Path]::GetTempPath()) "gnupg-link-check-$([guid]::NewGuid().ToString('N'))"
            for ($index = 0; $index -lt $listing.Count; $index++) {
                $entry = $listing[$index]
                Assert-SafeArchivePath $entry $resolved
                if ($verboseListing[$index] -match ' -> (?<target>.+)$') {
                    Assert-SafeLinkTarget $entry $Matches.target $resolved $containmentRoot
                }
                elseif ($verboseListing[$index] -match ' link to (?<target>.+)$') {
                    Assert-SafeLinkTarget $entry $Matches.target $resolved $containmentRoot -HardLink
                }
            }
            Assert-CleanBytes ([Text.Encoding]::UTF8.GetBytes(($listing -join "`n"))) "$resolved archive listing" $patterns
            Assert-CleanBytes ([Text.Encoding]::UTF8.GetBytes(($verboseListing -join "`n"))) "$resolved verbose archive listing" $patterns
            $scanRoot = Join-Path ([IO.Path]::GetTempPath()) "gnupg-path-scan-$([guid]::NewGuid().ToString('N'))"
            New-Item -ItemType Directory -Path $scanRoot | Out-Null
            $temporaryRoots.Add($scanRoot)
            & $Bsdtar -xf $resolved -C $scanRoot
            if ($LASTEXITCODE -ne 0) {
                throw "Unable to extract package archive: $resolved"
            }
        }

        $rootWithSeparator = "$($scanRoot.TrimEnd('\'))\"
        foreach ($item in @(Get-ChildItem -LiteralPath $scanRoot -Force -Recurse)) {
            $relative = $item.FullName.Substring($rootWithSeparator.Length).Replace('\', '/')
            Assert-CleanBytes ([Text.Encoding]::UTF8.GetBytes($relative)) "$resolved path $relative" $patterns
            if ($item.LinkType) {
                $target = [string] $item.Target
                if ($item.LinkType -eq 'HardLink') {
                    foreach ($hardLinkTarget in @($item.Target)) {
                        $resolvedTarget = [IO.Path]::GetFullPath([string] $hardLinkTarget)
                        $rootPrefix = "$([IO.Path]::GetFullPath($scanRoot).TrimEnd('\'))\"
                        if (-not $resolvedTarget.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                            throw "Extracted hard link escapes package root: $relative -> $resolvedTarget"
                        }
                    }
                }
                else {
                    Assert-SafeLinkTarget $relative $target $resolved $scanRoot
                }
                Assert-CleanBytes ([Text.Encoding]::UTF8.GetBytes($target)) "$resolved link $relative" $patterns
                $records.Add([ordered]@{ input = $resolved; path = $relative; type = 'link'; bytes = $target.Length })
                continue
            }
            if ($item.PSIsContainer) {
                $records.Add([ordered]@{ input = $resolved; path = $relative; type = 'directory'; bytes = 0 })
                continue
            }
            $bytes = [IO.File]::ReadAllBytes($item.FullName)
            Assert-CleanBytes $bytes "$resolved file $relative" $patterns
            $records.Add([ordered]@{
                input = $resolved
                path = $relative
                type = 'file'
                bytes = $bytes.Length
                sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            })
        }
    }

    if ($EvidencePath) {
        $evidence = [ordered]@{
            schema_version = 1
            result = 'pass'
            encodings = @('ascii', 'utf16le', 'utf16be', 'nul_rich')
            forbidden_paths = @($ForbiddenPath)
            tools = [ordered]@{
                bsdtar_path = (Resolve-Path -LiteralPath $Bsdtar).Path
                bsdtar_sha256 = (Get-FileHash -LiteralPath $Bsdtar -Algorithm SHA256).Hash.ToLowerInvariant()
                bsdtar_version = (@(& $Bsdtar --version)[0]).Trim()
            }
            inputs = @($inputRecords)
            scanned_entries = @($records)
        }
        $parent = Split-Path -Parent $EvidencePath
        if ($parent) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM
    }
}
finally {
    foreach ($root in $temporaryRoots) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

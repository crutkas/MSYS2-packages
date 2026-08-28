<#
.SYNOPSIS
  Fail-closed safe-extraction preflight for every archive the admission workflow
  unpacks (candidate packages, private base, downloaded scanner bundles).

.DESCRIPTION
  Enumerates an archive with bsdtar and rejects the whole archive before a single
  byte is written to disk if any member is an absolute path, a Windows drive or
  UNC path, contains a ".." traversal segment, or is a special entry. Normal
  extraction permits only regular files and directories. Preflight-only mode can
  additionally admit relative symlinks/hardlinks whose resolved targets remain
  inside the archive root, as required by the immutable MSYS2 base archive.

  The core decision lives in Get-ArchiveEntryRejection, a pure function the
  companion test-safe-extract.ps1 harness drives with crafted hostile entries to
  prove the policy fails closed without any network or real archive.
#>
[CmdletBinding()]
param(
  [string] $Archive,
  [string] $Destination,
  [string] $Bsdtar = 'bsdtar',
  [switch] $PreflightOnly,
  [switch] $AllowInternalLinks
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# Maps the leading character of a bsdtar verbose mode string to a member kind.
$script:EntryKindByModeChar = @{
  '-' = 'file'
  'd' = 'dir'
  'l' = 'symlink'
  'h' = 'hardlink'
  'c' = 'chardev'
  'b' = 'blockdev'
  'p' = 'fifo'
  's' = 'socket'
}

function Get-ArchiveEntryRejection {
  <#
    Returns $null when the (Name, Kind) member is safe to extract, otherwise a
    human-readable rejection reason. Never touches the filesystem.
  #>
  [CmdletBinding()]
  param(
    [AllowEmptyString()][AllowNull()][string] $Name,
    [AllowEmptyString()][AllowNull()][string] $Kind,
    [AllowEmptyString()][AllowNull()][string] $LinkTarget,
    [switch] $AllowInternalLinks
  )

  if ([string]::IsNullOrWhiteSpace($Name)) {
    return 'empty member name'
  }
  if ([string]::IsNullOrWhiteSpace($Kind)) {
    return "unknown member kind for '$Name'"
  }

  if ($Name -match '[\x00-\x1f]') {
    return "control character in member name: '$Name'"
  }

  $normalized = $Name -replace '\\', '/'
  if ($normalized.StartsWith('/')) {
    return "absolute path member: '$Name'"
  }
  if ($normalized -match '^[A-Za-z]:(?:/|$)') {
    return "drive-letter path member: '$Name'"
  }
  if ($Name.StartsWith('\\') -or $normalized.StartsWith('//')) {
    return "UNC path member: '$Name'"
  }
  foreach ($segment in $normalized.Split('/')) {
    if ($segment -eq '..') {
      return "path traversal member: '$Name'"
    }
  }

  $kindNormalized = $Kind.ToLowerInvariant()
  if ($kindNormalized -in @('symlink', 'hardlink', 'link')) {
    if (-not $AllowInternalLinks) {
      return "link member is not permitted: '$Name' ($kindNormalized)"
    }
    if ([string]::IsNullOrWhiteSpace($LinkTarget) -or $LinkTarget -match '[\x00-\x1f]') {
      return "link target is missing or invalid: '$Name'"
    }
    $target = $LinkTarget -replace '\\', '/'
    if ($target.StartsWith('/') -or $target.StartsWith('//') -or
        $target -match '^[A-Za-z]:(?:/|$)') {
      return "absolute link target is not permitted: '$Name' -> '$LinkTarget'"
    }

    $resolved = [Collections.Generic.List[string]]::new()
    if ($kindNormalized -eq 'symlink') {
      $parts = @($normalized.Split('/'))
      foreach ($part in $parts[0..([Math]::Max(0, $parts.Count - 2))]) {
        if ($part -and $part -ne '.') { $resolved.Add($part) }
      }
      if ($parts.Count -eq 1) { $resolved.Clear() }
    }
    foreach ($segment in $target.Split('/')) {
      if (-not $segment -or $segment -eq '.') { continue }
      if ($segment -eq '..') {
        if ($resolved.Count -eq 0) {
          return "link target escapes archive root: '$Name' -> '$LinkTarget'"
        }
        $resolved.RemoveAt($resolved.Count - 1)
      }
      else {
        $resolved.Add($segment)
      }
    }
    return $null
  }
  if ($kindNormalized -in @('chardev', 'blockdev', 'device', 'fifo', 'socket')) {
    return "special/device member is not permitted: '$Name' ($kindNormalized)"
  }
  if ($kindNormalized -notin @('file', 'dir', 'directory', 'regular')) {
    return "unsupported member kind: '$Name' ($kindNormalized)"
  }

  return $null
}

function Get-ArchiveEntry {
  <#
    Enumerates archive members as [pscustomobject]@{ Name; Kind } using a bsdtar
    verbose listing. Symlink " -> target" and hardlink " link to target" suffixes
    are stripped so only the member path is validated.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Archive,
    [Parameter(Mandatory)][string] $Bsdtar
  )

  $listing = & $Bsdtar -tvf $Archive
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to list archive: $Archive"
  }

  foreach ($line in $listing) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }
    $fields = $line -split '\s+', 9
    if ($fields.Count -lt 9) {
      throw "Unrecognized bsdtar listing line: $line"
    }
    $mode = $fields[0]
    $name = $fields[8]
    $modeChar = $mode.Substring(0, 1)
    $kind = $script:EntryKindByModeChar[$modeChar]
    if (-not $kind) {
      $kind = "mode:$modeChar"
    }
    $target = $null
    if ($kind -eq 'symlink' -and $name -match '^(.*?) -> (.*)$') {
      $name = $Matches[1]
      $target = $Matches[2]
    }
    elseif ($kind -eq 'hardlink' -and $name -match '^(.*?) link to (.*)$') {
      $name = $Matches[1]
      $target = $Matches[2]
    }
    [pscustomobject]@{ Name = $name; Kind = $kind; LinkTarget = $target }
  }
}

function Assert-SafeArchive {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Archive,
    [Parameter(Mandatory)][string] $Bsdtar,
    [switch] $AllowInternalLinks
  )

  $count = 0
  foreach ($entry in Get-ArchiveEntry -Archive $Archive -Bsdtar $Bsdtar) {
    $reason = Get-ArchiveEntryRejection -Name $entry.Name -Kind $entry.Kind `
      -LinkTarget $entry.LinkTarget -AllowInternalLinks:$AllowInternalLinks
    if ($reason) {
      throw "Unsafe archive '$Archive' rejected: $reason"
    }
    $count++
  }
  if ($count -eq 0) {
    throw "Archive '$Archive' contained no members"
  }
  return $count
}

function Invoke-SafeExtract {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Archive,
    [Parameter(Mandatory)][string] $Destination,
    [Parameter(Mandatory)][string] $Bsdtar
  )

  $members = Assert-SafeArchive -Archive $Archive -Bsdtar $Bsdtar
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  $root = (Resolve-Path -LiteralPath $Destination).Path

  # -P is deliberately NOT passed, so bsdtar keeps its own absolute/".." guards
  # even though the preflight already rejected such members.
  & $Bsdtar --no-same-owner -x -f $Archive -C $root
  if ($LASTEXITCODE -ne 0) {
    throw "bsdtar extraction failed for $Archive"
  }

  $rootFull = [IO.Path]::GetFullPath($root + [IO.Path]::DirectorySeparatorChar)
  foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force) {
    if ($item.LinkType) {
      throw "Reparse/link point materialized during extraction: $($item.FullName)"
    }
    $full = [IO.Path]::GetFullPath($item.FullName)
    if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Extracted path escaped destination: $full"
    }
  }
  return $members
}

if ($PSBoundParameters.ContainsKey('Archive')) {
  if ($PreflightOnly) {
    $checked = Assert-SafeArchive -Archive $Archive -Bsdtar $Bsdtar `
      -AllowInternalLinks:$AllowInternalLinks
    Write-Output "Safely preflighted $checked member(s) from $Archive"
    return
  }
  if (-not $PSBoundParameters.ContainsKey('Destination')) {
    throw '-Destination is required when -Archive is supplied.'
  }
  $extracted = Invoke-SafeExtract -Archive $Archive -Destination $Destination -Bsdtar $Bsdtar
  Write-Output "Safely extracted $extracted member(s) from $Archive"
}

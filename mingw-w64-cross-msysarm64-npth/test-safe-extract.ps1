<#
.SYNOPSIS
  Offline negative/positive tests proving the safe-extraction policy in
  safe-extract.ps1 fails closed. Requires no network and no real archive.

.DESCRIPTION
  Dot-sources safe-extract.ps1 to obtain Get-ArchiveEntryRejection, then asserts
  that every hostile member class (absolute, drive, UNC, traversal, symlink,
  hardlink, device, FIFO, socket, control-character, empty) is rejected, and that
  benign regular files and directories are accepted. Exits non-zero on the first
  policy escape so CI treats any regression as fatal.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'safe-extract.ps1')

$failures = [System.Collections.Generic.List[string]]::new()

$rejectCases = @(
  @{ Name = '/etc/passwd';               Kind = 'file';     Class = 'absolute-posix' }
  @{ Name = '/';                         Kind = 'dir';      Class = 'absolute-root' }
  @{ Name = 'C:\Windows\system32';       Kind = 'file';     Class = 'drive-backslash' }
  @{ Name = 'C:/Windows/system32';       Kind = 'file';     Class = 'drive-forwardslash' }
  @{ Name = 'Z:';                        Kind = 'dir';      Class = 'drive-bare' }
  @{ Name = '\\server\share\evil';       Kind = 'file';     Class = 'unc-backslash' }
  @{ Name = '//server/share/evil';       Kind = 'file';     Class = 'unc-forwardslash' }
  @{ Name = '../escape.txt';             Kind = 'file';     Class = 'traversal-leading' }
  @{ Name = 'a/b/../../../escape.txt';   Kind = 'file';     Class = 'traversal-embedded' }
  @{ Name = 'a\..\..\escape.txt';        Kind = 'file';     Class = 'traversal-backslash' }
  @{ Name = 'link-to-secret';            Kind = 'symlink';  Class = 'symlink' }
  @{ Name = 'hard-to-secret';            Kind = 'hardlink'; Class = 'hardlink' }
  @{ Name = 'dev/null-ish';              Kind = 'chardev';  Class = 'chardev' }
  @{ Name = 'dev/sda-ish';               Kind = 'blockdev'; Class = 'blockdev' }
  @{ Name = 'pipe';                      Kind = 'fifo';     Class = 'fifo' }
  @{ Name = 'sock';                      Kind = 'socket';   Class = 'socket' }
  @{ Name = "evil`0.txt";                Kind = 'file';     Class = 'control-char' }
  @{ Name = '';                          Kind = 'file';     Class = 'empty-name' }
  @{ Name = 'mystery';                   Kind = 'mode:?';   Class = 'unknown-kind' }
)

foreach ($case in $rejectCases) {
  $reason = Get-ArchiveEntryRejection -Name $case.Name -Kind $case.Kind
  if (-not $reason) {
    $failures.Add("FAILED-OPEN: '$($case.Class)' member '$($case.Name)' was accepted")
  }
  else {
    Write-Output "rejected $($case.Class): $reason"
  }
}

$acceptCases = @(
  @{ Name = 'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll'; Kind = 'file' }
  @{ Name = 'opt/aarch64-pc-msys/usr/lib/libnpth.a';       Kind = 'file' }
  @{ Name = 'opt/aarch64-pc-msys/usr/include/';            Kind = 'dir' }
  @{ Name = '.PKGINFO';                                    Kind = 'file' }
  @{ Name = '.MTREE';                                      Kind = 'regular' }
)

foreach ($case in $acceptCases) {
  $reason = Get-ArchiveEntryRejection -Name $case.Name -Kind $case.Kind
  if ($reason) {
    $failures.Add("FALSE-POSITIVE: benign member '$($case.Name)' rejected: $reason")
  }
  else {
    Write-Output "accepted benign: $($case.Name)"
  }
}

$internalLinks = @(
  @{ Name = 'usr/bin/tool'; Kind = 'symlink'; LinkTarget = '../../bin/tool' }
  @{ Name = 'usr/lib/libfoo.a'; Kind = 'hardlink'; LinkTarget = 'usr/lib/libfoo-real.a' }
)
foreach ($case in $internalLinks) {
  $reason = Get-ArchiveEntryRejection -Name $case.Name -Kind $case.Kind `
    -LinkTarget $case.LinkTarget -AllowInternalLinks
  if ($reason) {
    $failures.Add("FALSE-POSITIVE: contained link '$($case.Name)' rejected: $reason")
  }
}
$escapingLink = Get-ArchiveEntryRejection -Name 'usr/bin/escape' -Kind symlink `
  -LinkTarget '../../../outside' -AllowInternalLinks
if (-not $escapingLink) {
  $failures.Add('FAILED-OPEN: escaping internal link was accepted')
}

if ($failures.Count -ne 0) {
  foreach ($failure in $failures) {
    [Console]::Error.WriteLine($failure)
  }
  throw "Safe-extraction policy is not fail-closed: $($failures.Count) violation(s)."
}

Write-Output 'Safe-extraction negative and positive fixtures passed.'

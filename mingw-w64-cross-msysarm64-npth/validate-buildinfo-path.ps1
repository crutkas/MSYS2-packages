[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string] $Path,

  [string] $ExpectedBuildDir =
    '/usr/src/debug/mingw-w64-cross-msysarm64-npth-1.8/build',

  [string] $ExpectedStartDir =
    '/usr/src/debug/mingw-w64-cross-msysarm64-npth-1.8/recipe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$content = Get-Content -Raw -LiteralPath $Path
function Assert-SinglePathField {
  param([string] $Field, [string] $Expected)
  $matches = [regex]::Matches(
    $content,
    "(?m)^$([regex]::Escape($Field)) = ([^`r`n]*)`r?$")
  if ($matches.Count -ne 1) {
    throw ".BUILDINFO must contain exactly one $Field field"
  }
  if ($matches[0].Groups[1].Value -cne $Expected) {
    throw ".BUILDINFO $Field does not bind deterministic path $Expected"
  }
}
Assert-SinglePathField 'builddir' $ExpectedBuildDir
Assert-SinglePathField 'startdir' $ExpectedStartDir

$forbidden = [ordered]@{
  'Windows drive path' = '(?<![A-Za-z0-9])[A-Za-z]:[\\/]'
  'Actions or user path' = '/(?:[A-Za-z]/[Uu]sers|[dD]/a)(?:/|$)'
  'cygdrive path' = '/cygdrive/[A-Za-z](?:/|$)'
  'home path' = '/home/[^/\s]'
  'Windows UNC path' = '\\\\[^\\\r\n]+\\'
  'POSIX UNC path' = '(?<!:)//[A-Za-z0-9_.-]+/'
}
foreach ($entry in $forbidden.GetEnumerator()) {
  if ($content -match $entry.Value) {
    throw ".BUILDINFO contains forbidden $($entry.Key): $($Matches[0])"
  }
}

Write-Output '.BUILDINFO uses only deterministic build and recipe directories.'

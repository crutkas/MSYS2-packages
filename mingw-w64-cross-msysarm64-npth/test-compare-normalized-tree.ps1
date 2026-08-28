$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$bsdtar = 'C:\Windows\System32\tar.exe'
if (-not (Test-Path -LiteralPath $bsdtar)) { $bsdtar = 'bsdtar' }
$compare = Join-Path $PSScriptRoot 'compare-normalized-tree.ps1'

$parent = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$root = Join-Path $parent "npth-compare-test-$PID"
New-Item -ItemType Directory -Force $root | Out-Null

function New-GzipBytes {
  param([byte[]] $Content, [uint32] $Mtime)
  $ms = [System.IO.MemoryStream]::new()
  $gz = [System.IO.Compression.GzipStream]::new(
    $ms, [System.IO.Compression.CompressionMode]::Compress, $true)
  $gz.Write($Content, 0, $Content.Length)
  $gz.Dispose()
  $bytes = $ms.ToArray()
  $ms.Dispose()
  # Overwrite the 4-byte gzip MTIME header field so two "builds" can carry
  # different framing yet identical decompressed content.
  [BitConverter]::GetBytes($Mtime).CopyTo($bytes, 4)
  return $bytes
}

function New-SyntheticPackage {
  param(
    [string] $Directory,
    [string] $Name,
    [hashtable] $Files,
    [uint32] $MtreeMtime
  )
  $payload = Join-Path $root "payload-$([Guid]::NewGuid().ToString('n'))"
  New-Item -ItemType Directory -Force $payload | Out-Null

  $mtreeContent = [Text.Encoding]::ASCII.GetBytes("#mtree`n./.PKGINFO time=0.0`n")
  [IO.File]::WriteAllBytes((Join-Path $payload '.MTREE'), (New-GzipBytes -Content $mtreeContent -Mtime $MtreeMtime))
  [IO.File]::WriteAllText((Join-Path $payload '.PKGINFO'), "pkgname = $Name`npkgver = 1.8-2`n", [Text.Encoding]::ASCII)
  [IO.File]::WriteAllText((Join-Path $payload '.BUILDINFO'), "format = 2`nbuilddir = /usr/src/debug/x`n", [Text.Encoding]::ASCII)

  foreach ($rel in $Files.Keys) {
    $dest = Join-Path $payload $rel
    New-Item -ItemType Directory -Force (Split-Path -Parent $dest) | Out-Null
    [IO.File]::WriteAllBytes($dest, $Files[$rel])
  }

  New-Item -ItemType Directory -Force $Directory | Out-Null
  $archive = Join-Path $Directory "$Name-1.8-2-x86_64.pkg.tar.zst"
  $members = @('.PKGINFO', '.BUILDINFO', '.MTREE') + @($Files.Keys | Sort-Object)
  Push-Location $payload
  try {
    & $bsdtar -acf $archive @members
    if ($LASTEXITCODE -ne 0) { throw "failed to build synthetic package $Name" }
  }
  finally { Pop-Location }
  Remove-Item -LiteralPath $payload -Recurse -Force
  return $archive
}

function Invoke-Compare {
  param([string] $A, [string] $B)
  $work = Join-Path $root "work-$([Guid]::NewGuid().ToString('n'))"
  try {
    & $compare -BuildA $A -BuildB $B -Bsdtar $bsdtar -WorkDir $work *> $null
    return $true
  }
  catch { return $false }
}

$failures = [System.Collections.Generic.List[string]]::new()
try {
  $dllA = [byte[]](1..64)
  $libA = [byte[]](65..160)
  $hdrA = [Text.Encoding]::ASCII.GetBytes('#include <npth.h>')

  # --- identical inner package bytes -> PASS ---
  $a = Join-Path $root 'buildA'
  $b = Join-Path $root 'buildB'
  New-SyntheticPackage -Directory $a -Name 'npth' -MtreeMtime 111 -Files @{
    'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = $dllA } | Out-Null
  New-SyntheticPackage -Directory $a -Name 'npth-devel' -MtreeMtime 111 -Files @{
    'opt/aarch64-pc-msys/usr/lib/libnpth.a'      = $libA
    'opt/aarch64-pc-msys/usr/include/npth.h'     = $hdrA } | Out-Null
  New-Item -ItemType Directory -Force $b | Out-Null
  Copy-Item -Path (Join-Path $a '*.pkg.tar.zst') -Destination $b
  if (-not (Invoke-Compare -A $a -B $b)) {
    $failures.Add('byte-identical package archives were reported as a mismatch')
  }

  # --- outer archive byte differs -> FAIL ---
  $bArchive = Join-Path $root 'buildB-archive'
  New-Item -ItemType Directory -Force $bArchive | Out-Null
  Copy-Item -Path (Join-Path $a '*.pkg.tar.zst') -Destination $bArchive
  $changedArchive = Join-Path $bArchive 'npth-1.8-2-x86_64.pkg.tar.zst'
  $archiveBytes = [IO.File]::ReadAllBytes($changedArchive)
  $archiveBytes[10] = $archiveBytes[10] -bxor 1
  [IO.File]::WriteAllBytes($changedArchive, $archiveBytes)
  if (Invoke-Compare -A $a -B $bArchive) {
    $failures.Add('an outer package archive byte difference was not detected')
  }

  # --- even a gzip .MTREE framing difference is an inner-byte mismatch -> FAIL ---
  $bFraming = Join-Path $root 'buildB-framing'
  New-SyntheticPackage -Directory $bFraming -Name 'npth' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = $dllA } | Out-Null
  New-SyntheticPackage -Directory $bFraming -Name 'npth-devel' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/lib/libnpth.a'      = $libA
    'opt/aarch64-pc-msys/usr/include/npth.h'     = $hdrA } | Out-Null
  if (Invoke-Compare -A $a -B $bFraming) {
    $failures.Add('a raw .MTREE framing difference was not detected')
  }

  # --- payload byte differs -> FAIL ---
  $b2 = Join-Path $root 'buildB-payload'
  $dllMutated = [byte[]](1..64); $dllMutated[10] = 200
  New-SyntheticPackage -Directory $b2 -Name 'npth' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = $dllMutated } | Out-Null
  New-SyntheticPackage -Directory $b2 -Name 'npth-devel' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/lib/libnpth.a'      = $libA
    'opt/aarch64-pc-msys/usr/include/npth.h'     = $hdrA } | Out-Null
  if (Invoke-Compare -A $a -B $b2) {
    $failures.Add('a one-byte payload difference was not detected')
  }

  # --- .MTREE decompressed content differs -> FAIL ---
  $b3 = Join-Path $root 'buildB-mtree'
  New-SyntheticPackage -Directory $b3 -Name 'npth' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = $dllA } | Out-Null
  # Rebuild devel with different mtree *content* by temporarily swapping the writer.
  $develMtreeDir = Join-Path $root 'devel-mtree-src'
  New-Item -ItemType Directory -Force $develMtreeDir | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $develMtreeDir '.MTREE'),
    (New-GzipBytes -Content ([Text.Encoding]::ASCII.GetBytes("#mtree`n./DIFFERENT time=0.0`n")) -Mtime 999))
  [IO.File]::WriteAllText((Join-Path $develMtreeDir '.PKGINFO'), "pkgname = npth-devel`npkgver = 1.8-2`n", [Text.Encoding]::ASCII)
  [IO.File]::WriteAllText((Join-Path $develMtreeDir '.BUILDINFO'), "format = 2`nbuilddir = /usr/src/debug/x`n", [Text.Encoding]::ASCII)
  $libDest = Join-Path $develMtreeDir 'opt/aarch64-pc-msys/usr/lib/libnpth.a'
  New-Item -ItemType Directory -Force (Split-Path -Parent $libDest) | Out-Null
  [IO.File]::WriteAllBytes($libDest, $libA)
  $hdrDest = Join-Path $develMtreeDir 'opt/aarch64-pc-msys/usr/include/npth.h'
  New-Item -ItemType Directory -Force (Split-Path -Parent $hdrDest) | Out-Null
  [IO.File]::WriteAllBytes($hdrDest, $hdrA)
  $develArchive = Join-Path $b3 'npth-devel-1.8-2-x86_64.pkg.tar.zst'
  New-Item -ItemType Directory -Force $b3 | Out-Null
  Push-Location $develMtreeDir
  try {
    & $bsdtar -acf $develArchive '.PKGINFO' '.BUILDINFO' '.MTREE' 'opt/aarch64-pc-msys/usr/lib/libnpth.a' 'opt/aarch64-pc-msys/usr/include/npth.h'
    if ($LASTEXITCODE -ne 0) { throw 'failed to build mtree-diff devel package' }
  }
  finally { Pop-Location }
  if (Invoke-Compare -A $a -B $b3) {
    $failures.Add('a difference in decompressed .MTREE content was not detected')
  }

  # --- extra member in one build -> FAIL ---
  $b4 = Join-Path $root 'buildB-extra'
  New-SyntheticPackage -Directory $b4 -Name 'npth' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = $dllA } | Out-Null
  New-SyntheticPackage -Directory $b4 -Name 'npth-devel' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/lib/libnpth.a'      = $libA
    'opt/aarch64-pc-msys/usr/include/npth.h'     = $hdrA
    'opt/aarch64-pc-msys/usr/lib/libnpth.dll.a'  = [byte[]](1..8) } | Out-Null
  if (Invoke-Compare -A $a -B $b4) {
    $failures.Add('an extra member in one build was not detected')
  }

  # --- different package file set -> FAIL ---
  $b5 = Join-Path $root 'buildB-set'
  New-SyntheticPackage -Directory $b5 -Name 'npth' -MtreeMtime 999 -Files @{
    'opt/aarch64-pc-msys/usr/bin/msys-npth-0.dll' = $dllA } | Out-Null
  if (Invoke-Compare -A $a -B $b5) {
    $failures.Add('a mismatched package file set was not detected')
  }
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force
}

if ($failures.Count -gt 0) {
  Write-Output 'compare-normalized-tree fixtures FAILED:'
  $failures | ForEach-Object { Write-Output "  - $_" }
  exit 1
}

Write-Output 'compare-normalized-tree fixtures passed (identical archives accepted; archive, payload, raw .MTREE, extra-member, and package-set differences rejected).'

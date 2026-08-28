<#
.SYNOPSIS
  Download the immutable admission inputs named in input-manifest.json, verifying
  size and SHA-256 before any file is used, and refusing any artifact that lands
  on the revocation deny-list.

.DESCRIPTION
  Every build/lifecycle/native job that needs immutable inputs dot-sources this
  script and calls Receive-ManifestInputs. The download plan is derived purely
  from the manifest so the single source of truth is never duplicated in YAML,
  and the pure planning helpers are exercised offline by test-receive-pinned.ps1
  without a network.

  There is no live repository sync: each file is fetched by its exact pinned URL
  and content-addressed. The upstream GnuPG signing-key bundle (needed so makepkg
  can verify the pinned npth source signature) is fetched by an explicit pinned
  URL + SHA-256 and is the only entry not carried in the package manifest.
#>
[CmdletBinding()]
param(
  [string] $Manifest,
  [string] $InputsDir,
  [string[]] $Include = @('host', 'target', 'source', 'scanner', 'base', 'signingkey'),
  [string] $Bsdtar = 'C:\Windows\System32\tar.exe'
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# The upstream GnuPG signing key bundle, pinned by byte size and SHA-256.
$script:SigningKey = [ordered]@{
  name   = 'signature_key.asc'
  url    = 'https://gnupg.org/signature_key.asc'
  sha256 = '6f57d0e17fefd2238bd037aebf03efa960641629dd61dd9d47f122a829f6e375'
  bytes  = 6466
}

function New-DownloadEntry {
  param(
    [Parameter(Mandatory)] [string] $Name,
    [Parameter(Mandatory)] [string] $Url,
    [Parameter(Mandatory)] [string] $Sha256,
    [long] $Bytes = -1
  )
  if ($Name -cne [IO.Path]::GetFileName($Name)) {
    throw "Unsafe input filename: $Name"
  }
  return [ordered]@{ name = $Name; url = $Url; sha256 = $Sha256.ToLowerInvariant(); bytes = $Bytes }
}

function Get-ManifestDownloadList {
  <# Pure: turns the manifest + an Include selection into an ordered, de-duplicated
     download plan. No network, no filesystem writes. #>
  param(
    [Parameter(Mandatory)] [object] $ManifestObject,
    [Parameter(Mandatory)] [string[]] $Include
  )

  $plan = [System.Collections.Generic.List[object]]::new()
  $known = @('host', 'target', 'source', 'scanner', 'base', 'signingkey')
  foreach ($token in $Include) {
    if ($known -notcontains $token) { throw "Unknown download group: $token" }
  }

  if ($Include -contains 'host') {
    foreach ($p in $ManifestObject.hostPackages) {
      $plan.Add((New-DownloadEntry -Name $p.name -Url $p.url -Sha256 $p.sha256 -Bytes ([long]$p.bytes)))
    }
  }
  if ($Include -contains 'target') {
    foreach ($p in $ManifestObject.targetInputs) {
      $plan.Add((New-DownloadEntry -Name $p.name -Url $p.url -Sha256 $p.sha256 -Bytes ([long]$p.bytes)))
    }
  }
  if ($Include -contains 'source') {
    $plan.Add((New-DownloadEntry -Name $ManifestObject.npthSource.tarball.name -Url $ManifestObject.npthSource.tarball.url -Sha256 $ManifestObject.npthSource.tarball.sha256 -Bytes ([long]$ManifestObject.npthSource.tarball.bytes)))
    $plan.Add((New-DownloadEntry -Name $ManifestObject.npthSource.signature.name -Url $ManifestObject.npthSource.signature.url -Sha256 $ManifestObject.npthSource.signature.sha256 -Bytes ([long]$ManifestObject.npthSource.signature.bytes)))
  }
  if ($Include -contains 'scanner') {
    $plan.Add((New-DownloadEntry -Name $ManifestObject.scanner.name -Url $ManifestObject.scanner.url -Sha256 $ManifestObject.scanner.sha256))
  }
  if ($Include -contains 'base') {
    $plan.Add((New-DownloadEntry -Name $ManifestObject.privateBase.archive.name -Url $ManifestObject.privateBase.archive.url -Sha256 $ManifestObject.privateBase.archive.sha256 -Bytes ([long]$ManifestObject.privateBase.archive.bytes)))
    $plan.Add((New-DownloadEntry -Name $ManifestObject.privateBase.signature.name -Url $ManifestObject.privateBase.signature.url -Sha256 $ManifestObject.privateBase.signature.sha256 -Bytes ([long]$ManifestObject.privateBase.signature.bytes)))
  }
  if ($Include -contains 'signingkey') {
    $plan.Add((New-DownloadEntry -Name $script:SigningKey.name -Url $script:SigningKey.url `
        -Sha256 $script:SigningKey.sha256 -Bytes ([long]$script:SigningKey.bytes)))
  }

  # De-duplicate by filename (target/host lists never overlap, but be defensive).
  $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $unique = [System.Collections.Generic.List[object]]::new()
  foreach ($entry in $plan) {
    if ($seen.Add($entry.name)) { $unique.Add($entry) }
  }
  return $unique
}

function Get-DenyRule {
  <# Pure: extracts the (prefix,bytes) revocation rules the download step must
     reject. #>
  param([Parameter(Mandatory)] [object] $ManifestObject)
  $rules = [System.Collections.Generic.List[object]]::new()
  foreach ($r in $ManifestObject.denyList.revoked) {
    $rules.Add([ordered]@{ prefix = ([string]$r.sha256Prefix).ToLowerInvariant(); bytes = [long]$r.bytes })
  }
  return $rules
}

function Test-DenyCollision {
  <# Pure: returns a rejection reason if (Sha256,Bytes) matches a revocation rule,
     otherwise $null. A revoked artifact is matched by SHA-256 prefix AND exact
     byte size. #>
  param(
    [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
    [Parameter(Mandatory)] [string] $Sha256,
    [Parameter(Mandatory)] [long] $Bytes
  )
  $lower = $Sha256.ToLowerInvariant()
  foreach ($rule in $Rules) {
    if ($lower.StartsWith($rule.prefix) -and $Bytes -eq $rule.bytes) {
      return "artifact matches revoked deny-list rule (prefix $($rule.prefix), $($rule.bytes) bytes)"
    }
  }
  return $null
}

function Test-ValidSignatureStatus {
  param(
    [Parameter(Mandatory)] [string] $StatusText,
    [Parameter(Mandatory)] [string] $Fingerprint
  )
  $expected = ($Fingerprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
  return [bool]($StatusText -match "(?m)^\[GNUPG:\] VALIDSIG $expected(?:\s|$)")
}

function ConvertTo-GitPosixPath {
  param([Parameter(Mandatory)] [string] $Path)
  $full = [IO.Path]::GetFullPath($Path)
  if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "GPG path is not an absolute drive path: $full"
  }
  return "/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"
}

function Assert-PinnedLocalFile {
  param(
    [Parameter(Mandatory)] [string] $Path,
    [Parameter(Mandatory)] [string] $Sha256,
    [Parameter(Mandatory)] [long] $Bytes
  )
  $item = Get-Item -LiteralPath $Path -ErrorAction Stop
  $actual = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($item.Length -ne $Bytes -or $actual -cne $Sha256.ToLowerInvariant()) {
    throw "Pinned local file mismatch for $Path"
  }
}

function Assert-PinnedDetachedSignature {
  param(
    [Parameter(Mandatory)] [string] $Archive,
    [Parameter(Mandatory)] [string] $Signature,
    [Parameter(Mandatory)] [string] $PublicKey,
    [Parameter(Mandatory)] [string] $Fingerprint,
    [string] $Gpg = 'C:\Program Files\Git\usr\bin\gpg.exe'
  )
  if (-not (Test-Path -LiteralPath $Gpg)) {
    throw "GPG verifier is missing: $Gpg"
  }
  $gpgHome = Join-Path ([IO.Path]::GetTempPath()) "npth-gpg-$PID-$([Guid]::NewGuid().ToString('N'))"
  New-Item -ItemType Directory -Force -Path $gpgHome | Out-Null
  $gpgHomeArg = ConvertTo-GitPosixPath $gpgHome
  $archiveArg = ConvertTo-GitPosixPath $Archive
  $signatureArg = ConvertTo-GitPosixPath $Signature
  $publicKeyArg = ConvertTo-GitPosixPath $PublicKey
  try {
    $importOutput = @(& $Gpg --batch --homedir $gpgHomeArg --import $publicKeyArg 2>&1)
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to import pinned signer key: $($importOutput -join "`n")"
    }
    $status = @(& $Gpg --batch --homedir $gpgHomeArg --status-fd 1 --verify $signatureArg $archiveArg 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        -not (Test-ValidSignatureStatus -StatusText ($status -join "`n") -Fingerprint $Fingerprint)) {
      throw "Detached signature is not valid for $Archive from signer $Fingerprint"
    }
  }
  finally {
    Remove-Item -LiteralPath $gpgHome -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Receive-PinnedFile {
  param(
    [Parameter(Mandatory)] [string] $Url,
    [Parameter(Mandatory)] [string] $Filename,
    [Parameter(Mandatory)] [string] $Sha256,
    [long] $Bytes = -1,
    [Parameter(Mandatory)] [string] $Destination,
    [AllowEmptyCollection()] [object[]] $DenyRules = @()
  )
  if ($Filename -cne [IO.Path]::GetFileName($Filename)) {
    throw "Unsafe input filename: $Filename"
  }
  $path = Join-Path $Destination $Filename
  & 'C:\Windows\System32\curl.exe' --fail --location --retry 3 --output $path $Url
  if ($LASTEXITCODE -ne 0) { throw "Unable to download $Url" }

  $item = Get-Item -LiteralPath $path
  $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -cne $Sha256.ToLowerInvariant()) {
    throw "SHA-256 mismatch for ${Filename}: expected $Sha256, got $actual"
  }
  if ($Bytes -ge 0 -and $item.Length -ne $Bytes) {
    throw "Byte-count mismatch for ${Filename}: expected $Bytes, got $($item.Length)"
  }
  $reason = Test-DenyCollision -Rules $DenyRules -Sha256 $actual -Bytes $item.Length
  if ($reason) { throw "Refusing revoked artifact ${Filename}: $reason" }

  return [ordered]@{ filename = $Filename; url = $Url; bytes = $item.Length; sha256 = $actual }
}

function Receive-ManifestInputs {
  param(
    [Parameter(Mandatory)] [string] $Manifest,
    [Parameter(Mandatory)] [string] $InputsDir,
    [Parameter(Mandatory)] [string[]] $Include
  )
  $manifestObject = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
  $plan = Get-ManifestDownloadList -ManifestObject $manifestObject -Include $Include
  $denyRules = @(Get-DenyRule -ManifestObject $manifestObject)
  New-Item -ItemType Directory -Force -Path $InputsDir | Out-Null

  $records = [System.Collections.Generic.List[object]]::new()
  foreach ($entry in $plan) {
    $records.Add((Receive-PinnedFile -Url $entry.url -Filename $entry.name -Sha256 $entry.sha256 `
          -Bytes ([long]$entry.bytes) -Destination $InputsDir -DenyRules $denyRules))
  }
  $sealPath = Join-Path $InputsDir 'input-download-seal.json'
  [ordered]@{ schema = 1; include = $Include; files = $records.ToArray() } |
    ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -LiteralPath $sealPath
  return $sealPath
}

if ($MyInvocation.InvocationName -ne '.' -and
    -not (Get-Variable -Name ReceivePinnedDotSource -Scope Global -ErrorAction SilentlyContinue)) {
  foreach ($name in 'Manifest', 'InputsDir') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $name -ValueOnly))) {
      throw "-$name is required when running receive-pinned.ps1 directly."
    }
  }
  $seal = Receive-ManifestInputs -Manifest $Manifest -InputsDir $InputsDir -Include $Include
  Write-Output "Download seal written to $seal"
  Write-Output 'NPTH-RECEIVE-PINNED-OK'
}

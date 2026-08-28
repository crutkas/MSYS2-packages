<#
  Offline unit test for receive-pinned.ps1 pure helpers. Validates the manifest
  download plan (group selection, de-duplication, signing-key injection) and the
  revocation deny-list logic against the real input-manifest.json. No network.
#>
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$global:ReceivePinnedDotSource = $true
. (Join-Path $PSScriptRoot 'receive-pinned.ps1')
Remove-Variable -Name ReceivePinnedDotSource -Scope Global -ErrorAction SilentlyContinue

$failures = [System.Collections.Generic.List[string]]::new()
function Assert($condition, $message) {
  if (-not $condition) { $script:failures.Add($message) }
}

$manifestObj = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'input-manifest.json') | ConvertFrom-Json

# --- Get-ManifestDownloadList: full plan ------------------------------------
$full = @(Get-ManifestDownloadList -ManifestObject $manifestObj -Include @('host', 'target', 'source', 'scanner', 'base', 'signingkey'))
$expected = $manifestObj.hostPackages.Count + $manifestObj.targetInputs.Count + 2 + 1 + 3 + 1
Assert ($full.Count -eq $expected) "full plan count $($full.Count) != expected $expected"
foreach ($entry in $full) {
  Assert (-not [string]::IsNullOrWhiteSpace($entry.name)) 'plan entry missing name'
  Assert ($entry.url -like 'https://*') "plan entry $($entry.name) url not https"
  if (-not ([Uri]$entry.url).Query) {
    Assert ($entry.url.EndsWith($entry.name)) "plan entry $($entry.name) url must end with its name"
  }
  Assert ($entry.sha256 -match '^[0-9a-f]{64}$') "plan entry $($entry.name) sha256 malformed"
}

# --- signing key injection --------------------------------------------------
$signing = @($full | Where-Object { $_.name -eq 'signature_key.asc' })
Assert ($signing.Count -eq 1) 'signing key must be present exactly once'
Assert ($signing[0].url -eq 'https://gnupg.org/signature_key.asc') 'signing key url wrong'
Assert ($signing[0].bytes -eq 6466) 'signing key size must be pinned'
Assert ($signing[0].sha256 -eq '6f57d0e17fefd2238bd037aebf03efa960641629dd61dd9d47f122a829f6e375') `
  'signing key hash must be pinned'

# --- detached signature status parser ---------------------------------------
$signer = $manifestObj.privateBase.signer
Assert (Test-ValidSignatureStatus -StatusText "[GNUPG:] VALIDSIG $signer 2026-06-11" -Fingerprint $signer) `
  'signature status parser must accept the pinned valid signer fingerprint'
Assert (-not (Test-ValidSignatureStatus -StatusText "[GNUPG:] GOODSIG $signer" -Fingerprint $signer)) `
  'signature status parser must reject non-VALIDSIG status'
Assert (-not (Test-ValidSignatureStatus -StatusText "[GNUPG:] VALIDSIG $('0' * 40)" -Fingerprint $signer)) `
  'signature status parser must reject a different signer fingerprint'

# --- base group selects archive, detached signature, and pinned signer key ---
$baseOnly = @(Get-ManifestDownloadList -ManifestObject $manifestObj -Include @('base'))
Assert ($baseOnly.Count -eq 3) 'base group must yield archive + signature + signer key'
Assert (@($baseOnly | Where-Object { $_.name -eq 'msys2-base-x86_64-20260611.tar.xz' }).Count -eq 1) 'base archive missing'
Assert (@($baseOnly | Where-Object { $_.name.EndsWith('.sig') }).Count -eq 1) 'base signature missing'
Assert (@($baseOnly | Where-Object { $_.name -eq $manifestObj.privateBase.signerKey.name }).Count -eq 1) `
  'base signer key missing'

# --- scanner group is the canonical pinned scanner --------------------------
$scannerOnly = @(Get-ManifestDownloadList -ManifestObject $manifestObj -Include @('scanner'))
Assert ($scannerOnly.Count -eq 1) 'scanner group must yield one file'
Assert ($scannerOnly[0].sha256 -eq '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') 'scanner sha wrong'

# --- target group carries the real cygwin libstdc++ headers -----------------
$targetOnly = @(Get-ManifestDownloadList -ManifestObject $manifestObj -Include @('target'))
Assert (@($targetOnly | Where-Object { $_.name -eq 'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' }).Count -eq 1) `
  'target group missing the real cygwin libstdc++ headers'

# --- unknown group fails closed ---------------------------------------------
$threw = $false
try { Get-ManifestDownloadList -ManifestObject $manifestObj -Include @('bogus') } catch { $threw = $true }
Assert $threw 'unknown download group must be rejected'

# --- New-DownloadEntry rejects path-shaped filenames ------------------------
$threw = $false
try { New-DownloadEntry -Name 'a/b.zst' -Url 'https://x/a/b.zst' -Sha256 ('0' * 64) } catch { $threw = $true }
Assert $threw 'New-DownloadEntry must reject a filename containing a path separator'

# --- deny-list rules + collision detection ----------------------------------
$rules = @(Get-DenyRule -ManifestObject $manifestObj)
Assert ($rules.Count -eq 2) 'expected two revocation rules'

$revokedSha = '97237a' + ('0' * 58)   # 64 hex chars starting with the revoked prefix
Assert ((Test-DenyCollision -Rules $rules -Sha256 $revokedSha -Bytes 13629) -ne $null) `
  'revoked runtime (prefix+size) must be rejected'
Assert ((Test-DenyCollision -Rules $rules -Sha256 $revokedSha -Bytes 99999) -eq $null) `
  'revoked prefix with a different size must NOT be rejected (size is part of the rule)'

# A genuine input must never collide.
$runtime = $manifestObj.targetInputs | Where-Object { $_.role -eq 'runtime' }
Assert ((Test-DenyCollision -Rules $rules -Sha256 $runtime.sha256 -Bytes ([long]$runtime.bytes)) -eq $null) `
  'a genuine admission input must not collide with the deny-list'

if ($failures.Count -gt 0) {
  Write-Error ("receive-pinned unit test FAILED:`n - " + ($failures -join "`n - "))
  exit 1
}
Write-Output 'receive-pinned unit test passed (manifest download plan, signing-key injection, deny-list collision logic).'

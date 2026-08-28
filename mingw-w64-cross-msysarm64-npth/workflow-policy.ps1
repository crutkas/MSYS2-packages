# Reusable forbidden-token / action-pin policy scanner for the npth admission
# workflow. Both the workflow's static-policy job and the offline
# test-workflow-policy.ps1 fixtures dot-source this file and call the same
# functions, so the gate that guards CI is exactly the gate covered by tests.
#
# Every forbidden literal below is assembled by concatenation so that scanning
# this scanner (or the test that imports it) can never self-match a token.

Set-StrictMode -Version 3

function Get-WorkflowPolicyViolation {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)

  $violations = [System.Collections.Generic.List[string]]::new()
  $shared = 'C:' + '\' + 'msys64'

  # Unique forbidden substrings. Bootstrap helpers, dependency-relaxation flags,
  # shared-runner tool invocations, and publish/release verbs.
  $forbidden = @(
    ('msys2/' + 'setup-msys2'),
    ('egor-tensin/' + 'setup-mingw'),
    ('--assume' + '-installed'),
    ('--nod' + 'eps'),
    ($shared + '\usr\bin\pacman'),
    ($shared + '\usr\bin\makepkg'),
    ($shared + '\usr\bin\bash'),
    ($shared + '\usr\bin\sh.exe'),
    ($shared + '\usr\bin\bsdtar'),
    ($shared + '\usr\bin\gcc'),
    ($shared + '\usr\bin\ar.exe'),
    ($shared + '\usr\bin\ranlib'),
    ($shared + '\usr\bin\ld'),
    ($shared + '\usr\bin\objdump'),
    ($shared + '\usr\bin\nm.exe'),
    ($shared + '\msys2_shell'),
    ($shared + '\msys2.exe'),
    ('softprops/' + 'action-gh-release'),
    ('actions/' + 'create-release'),
    ('ncipollo/' + 'release-action'),
    ('gh' + ' release ' + 'create'),
    ('gh' + ' release ' + 'upload'),
    ('gh' + ' release ' + 'edit')
  )
  foreach ($token in $forbidden) {
    if ($Text.Contains($token)) {
      $violations.Add("forbidden token: $token")
    }
  }

  # Live-repository sync is forbidden: every pacman transaction must be a local
  # -U/-R/-Q against explicit databases. Any pacman line that reaches for the
  # sync database (-S, -Sy, -Su, -Syu, -Syyu, ...) is a violation.
  foreach ($line in ($Text -split "`n")) {
    $normalized = $line.TrimEnd("`r")
    if ($normalized -match 'pacman' -and $normalized -match '\s-S(\s|[yuwp])') {
      $violations.Add("forbidden live sync: $($normalized.Trim())")
    }
  }

  # Every `uses:` reference must be pinned to a 40-character commit SHA. Floating
  # tags (@v4, @main, @master, @latest, @<branch>) fail closed.
  foreach ($line in ($Text -split "`n")) {
    $normalized = $line.TrimEnd("`r")
    if ($normalized -match '(^|\s)uses:\s*[''"]?([^\s@''"]+)@([^\s''"]+)') {
      $ref = $Matches[3]
      if ($ref -notmatch '^[0-9a-f]{40}$') {
        $violations.Add("unpinned action ref: $($normalized.Trim())")
      }
    }
  }

  return $violations
}

function Assert-WorkflowPolicy {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string] $Path,
    [string[]] $RequiredPin = @(
      'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
      'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
      'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'
    )
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Workflow not found for policy scan: $Path"
  }
  $text = Get-Content -LiteralPath $Path -Raw
  $violations = @(Get-WorkflowPolicyViolation -Text $text)
  if ($violations.Count -gt 0) {
    throw "Workflow policy violations in ${Path}:`n  " + ($violations -join "`n  ")
  }
  foreach ($pin in $RequiredPin) {
    if (-not $text.Contains($pin)) {
      throw "Workflow ${Path} is missing required immutable action pin: $pin"
    }
  }
}

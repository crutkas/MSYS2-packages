$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

. (Join-Path $PSScriptRoot 'workflow-policy.ps1')

$failures = [System.Collections.Generic.List[string]]::new()
function Fail([string] $Message) { $script:failures.Add($Message) }

# A representative clean snippet: pinned actions, and a fully-explicit local
# pacman -U transaction. It must produce zero violations.
$sha = '11d5960a326750d5838078e36cf38b85af677262'
$clean = @"
jobs:
  build:
    runs-on: windows-2025
    steps:
      - uses: actions/checkout@$sha
      - run: |
          & `$pacman -U --root `$root --dbpath `$db --cachedir `$cache ``
            --logfile `$log --config `$conf --hookdir `$hook --gpgdir `$gpg ``
            `$candidate
"@
$cleanViolations = @(Get-WorkflowPolicyViolation -Text $clean)
if ($cleanViolations.Count -ne 0) {
  Fail "clean fixture unexpectedly flagged: $($cleanViolations -join '; ')"
}

# Each negative fixture embeds exactly one forbidden construct, assembled by
# concatenation so this test's own literals never trip the scanner.
$shared = 'C:' + '\' + 'msys64'
$negativeCases = @(
  @{ Name = 'setup-msys2';       Text = 'uses: ' + 'msys2/' + 'setup-msys2@' + $sha },
  @{ Name = 'assume-installed';  Text = 'run: pacman -U pkg ' + '--assume' + '-installed=glibc' },
  @{ Name = 'nodeps';            Text = 'run: pacman -U ' + '--nod' + 'eps pkg' },
  @{ Name = 'shared-pacman';     Text = 'run: & ' + $shared + '\usr\bin\pacman -Q' },
  @{ Name = 'shared-bash';       Text = 'run: & ' + $shared + '\usr\bin\bash -lc id' },
  @{ Name = 'shared-objdump';    Text = 'run: & ' + $shared + '\usr\bin\objdump -p a.exe' },
  @{ Name = 'release-create';    Text = 'run: ' + 'gh' + ' release ' + 'create v1' },
  @{ Name = 'gh-release-action'; Text = 'uses: ' + 'softprops/' + 'action-gh-release@' + $sha },
  @{ Name = 'sync-Syu';          Text = 'run: pacman ' + '-S' + 'yu' },
  @{ Name = 'sync-Sy';           Text = 'run: pacman ' + '-S' + 'y pkg' },
  @{ Name = 'sync-S';            Text = 'run: pacman ' + '-S' + ' pkg' },
  @{ Name = 'floating-v4';       Text = 'uses: actions/checkout@' + 'v4' },
  @{ Name = 'floating-main';     Text = 'uses: actions/checkout@' + 'main' }
)
foreach ($case in $negativeCases) {
  $violations = @(Get-WorkflowPolicyViolation -Text $case.Text)
  if ($violations.Count -eq 0) {
    Fail "negative fixture '$($case.Name)' was not rejected"
  }
}

# A pacman line that only reads local databases must not look like a sync.
$localOnly = 'run: pacman -U --root r --dbpath d pkg.zst; pacman -Q --dbpath d'
if ((@(Get-WorkflowPolicyViolation -Text $localOnly)).Count -ne 0) {
  Fail 'local pacman -U/-Q transaction was misclassified as a sync'
}

# Sealing the shared runner DB/log by path (never its tools) must stay allowed.
$seal = 'run: Get-FileHash ' + $shared + '\var\lib\pacman\local\ALPM_DB_VERSION'
if ((@(Get-WorkflowPolicyViolation -Text $seal)).Count -ne 0) {
  Fail 'sealing the shared runner database path was wrongly forbidden'
}

# --noconfirm is standard for a non-interactive local -U/-R and must stay allowed.
$noconfirm = 'run: pacman -U --root r --dbpath d ' + '--no' + 'confirm pkg.zst'
if ((@(Get-WorkflowPolicyViolation -Text $noconfirm)).Count -ne 0) {
  Fail 'a local pacman -U --noconfirm transaction was wrongly forbidden'
}

# When the real workflow exists, it must pass the identical gate.
$workflow = Join-Path (Split-Path -Parent $PSScriptRoot) '.github\workflows\arm64-msys-npth-admission.yml'
if (Test-Path -LiteralPath $workflow) {
  try {
    Assert-WorkflowPolicy -Path $workflow
    Write-Output "Scanned real workflow: $workflow (clean, pins present)."
  }
  catch {
    Fail "real workflow failed policy: $($_.Exception.Message)"
  }
}
else {
  Write-Output "NOTE: workflow not present yet; scanner logic validated against fixtures only."
}

if ($failures.Count -gt 0) {
  Write-Output 'workflow policy fixtures FAILED:'
  $failures | ForEach-Object { Write-Output "  - $_" }
  exit 1
}

Write-Output "workflow policy fixtures passed ($($negativeCases.Count) forbidden constructs rejected, clean + seal + local-only allowed)."

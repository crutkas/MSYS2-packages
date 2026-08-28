<#
  Offline unit test for native-verify.ps1 pure helpers. Runs on any Windows host
  (including x64) with no network and no ARM64 runner: it exercises the PE
  machine parser, the architecture gate, the exit-marker contract, the module
  architecture policy, and the live WOW64 / module-enumeration helpers against
  synthetic PEs and the current process.
#>
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$global:NativeVerifyDotSource = $true
. (Join-Path $PSScriptRoot 'native-verify.ps1')
Remove-Variable -Name NativeVerifyDotSource -Scope Global -ErrorAction SilentlyContinue

$failures = [Collections.Generic.List[string]]::new()
function Assert($condition, $message) {
  if (-not $condition) { $script:failures.Add($message) }
}
function Assert-Throws([scriptblock] $Action, [string] $Message) {
  try { & $Action; $script:failures.Add("Expected throw: $Message") }
  catch { }
}

$tmp = Join-Path $PSScriptRoot '.native-test-tmp'
if (Test-Path -LiteralPath $tmp) { Remove-Item -Recurse -Force -LiteralPath $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function New-SyntheticPe {
  param([Parameter(Mandatory)] [int] $Machine, [Parameter(Mandatory)] [string] $Path)
  $bytes = [byte[]]::new(0x90)
  $bytes[0] = 0x4D; $bytes[1] = 0x5A                      # 'MZ'
  [BitConverter]::GetBytes([uint32] 0x80).CopyTo($bytes, 0x3C)  # e_lfanew
  $bytes[0x80] = 0x50; $bytes[0x81] = 0x45               # 'PE'
  $bytes[0x82] = 0x00; $bytes[0x83] = 0x00               # \0\0
  [BitConverter]::GetBytes([uint16] $Machine).CopyTo($bytes, 0x84)
  [IO.File]::WriteAllBytes($Path, $bytes)
  return $Path
}

try {
  # --- Get-PeMachineType: synthetic PEs decode to the right architecture ---
  $arm = New-SyntheticPe -Machine 0xAA64 -Path (Join-Path $tmp 'arm64.dll')
  $x64 = New-SyntheticPe -Machine 0x8664 -Path (Join-Path $tmp 'x64.dll')
  $x86 = New-SyntheticPe -Machine 0x14C -Path (Join-Path $tmp 'x86.dll')
  Assert ((Get-PeMachineType -Path $arm).machine_name -eq 'arm64') 'ARM64 PE not decoded as arm64'
  Assert ((Get-PeMachineType -Path $arm).machine -eq '0xaa64') 'ARM64 machine hex wrong'
  Assert ((Get-PeMachineType -Path $x64).machine_name -eq 'x64') 'x64 PE not decoded as x64'
  Assert ((Get-PeMachineType -Path $x86).machine_name -eq 'x86') 'x86 PE not decoded as x86'

  # A non-PE file must be rejected.
  $garbage = Join-Path $tmp 'garbage.bin'
  [IO.File]::WriteAllBytes($garbage, ([byte[]](1..64)))
  Assert-Throws { Get-PeMachineType -Path $garbage } 'non-PE accepted by Get-PeMachineType'

  # --- Assert-NativeArm64: fails closed on anything but ARM64 ---
  Assert ((Assert-NativeArm64 -Architecture 'ARM64') -eq $true) 'ARM64 architecture rejected'
  Assert-Throws { Assert-NativeArm64 -Architecture 'AMD64' } 'AMD64 accepted as native'
  Assert-Throws { Assert-NativeArm64 -Architecture 'x86' } 'x86 accepted as native'
  Assert-Throws { Assert-NativeArm64 -Architecture '' } 'empty architecture accepted'
  Assert-Throws { Assert-NativeArm64 -Architecture $null } 'null architecture accepted'

  # --- Test-ExitMarker: exit code AND marker are both required ---
  Assert (Test-ExitMarker -ExitCode 0 -Output @('hello', 'NPTH-DYNAMIC-OK') -Marker 'NPTH-DYNAMIC-OK') 'valid marker rejected'
  Assert (-not (Test-ExitMarker -ExitCode 1 -Output @('NPTH-DYNAMIC-OK') -Marker 'NPTH-DYNAMIC-OK')) 'nonzero exit accepted'
  Assert (-not (Test-ExitMarker -ExitCode 0 -Output @('nope') -Marker 'NPTH-DYNAMIC-OK')) 'missing marker accepted'
  Assert (-not (Test-ExitMarker -ExitCode 0 -Output $null -Marker 'NPTH-DYNAMIC-OK')) 'null output accepted'

  # --- Get-NpthThreadMarker: exact PID and one nonzero worker TID required ---
  $thread = Get-NpthThreadMarker -Output @(
    'NPTH-DYNAMIC-READY',
    'NPTH-DYNAMIC-THREAD pid=123 tid=456'
  ) -ExpectedProcessId 123
  Assert ($thread.process_id -eq 123 -and $thread.worker_thread_id -eq 456) `
    'valid worker thread marker rejected'
  Assert-Throws {
    Get-NpthThreadMarker -Output @('NPTH-DYNAMIC-THREAD pid=999 tid=456') -ExpectedProcessId 123
  } 'worker marker with wrong process ID accepted'
  Assert-Throws {
    Get-NpthThreadMarker -Output @('NPTH-DYNAMIC-THREAD pid=123 tid=0') -ExpectedProcessId 123
  } 'worker marker with zero thread ID accepted'

  # --- Test-ModuleArchitecture: any non-arm64 module is an offender ---
  $clean = @(
    [ordered]@{ name = 'msys-npth-0.dll'; machine = 'arm64'; sha256 = ('a' * 64) },
    [ordered]@{ name = 'msys-2.0.dll'; machine = 'arm64'; sha256 = ('b' * 64) }
  )
  $dirty = @(
    [ordered]@{ name = 'msys-npth-0.dll'; machine = 'arm64'; sha256 = ('a' * 64) },
    [ordered]@{ name = 'msys-2.0.dll'; machine = 'x64'; sha256 = ('b' * 64) }
  )
  $missingHash = @(
    [ordered]@{ name = 'msys-npth-0.dll'; machine = 'arm64'; sha256 = $null }
  )
  Assert (@(Test-ModuleArchitecture -Modules $clean).Count -eq 0) 'clean modules flagged'
  $offenders = @(Test-ModuleArchitecture -Modules $dirty)
  Assert ($offenders.Count -eq 1 -and $offenders[0] -eq 'msys-2.0.dll=x64') 'x64 module not flagged'
  $hashOffenders = @(Test-ModuleArchitecture -Modules $missingHash)
  Assert ($hashOffenders.Count -eq 1 -and $hashOffenders[0] -eq 'msys-npth-0.dll=missing-or-invalid-sha256') `
    'missing module hash not flagged'

  # --- Assert-FileHashes: mutation after initial trust binding is rejected ---
  $trusted = Join-Path $tmp 'trusted-tool.exe'
  [IO.File]::WriteAllBytes($trusted, [byte[]](1..16))
  $trustedHash = (Get-FileHash -LiteralPath $trusted -Algorithm SHA256).Hash.ToLowerInvariant()
  Assert-FileHashes -ExpectedHashes ([ordered]@{ $trusted = $trustedHash })
  [IO.File]::WriteAllBytes($trusted, [byte[]](2..17))
  Assert-Throws {
    Assert-FileHashes -ExpectedHashes ([ordered]@{ $trusted = $trustedHash })
  } 'trusted file mutation was accepted'

  # --- Get-Wow64Evidence: returns a consistent shape on any Windows host ---
  $wow = Get-Wow64Evidence
  Assert ($null -ne $wow.process_machine) 'wow64 process_machine missing'
  Assert ($null -ne $wow.native_machine) 'wow64 native_machine missing'
  Assert ($wow.is_emulated -is [bool]) 'wow64 is_emulated not boolean'

  # --- Get-ProcessModuleEvidence: enumerates the current process cleanly ---
  $mods = @(Get-ProcessModuleEvidence -ProcessId $PID)
  Assert ($mods.Count -gt 0) 'current process reported zero modules'
  $first = $mods[0]
  Assert ($first.Contains('path')) 'module record missing path'
  Assert ($first.Contains('machine')) 'module record missing machine'
  Assert ($first.Contains('sha256')) 'module record missing sha256'
}
finally {
  Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
  Write-Error ("native-verify unit test FAILED:`n - " + ($failures -join "`n - "))
  exit 1
}
Write-Output 'native-verify unit test passed (PE machine parsing, ARM64 gate, exit markers, module policy, WOW64 + module enumeration).'

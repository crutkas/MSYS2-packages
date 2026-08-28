<#
.SYNOPSIS
  Genuine windows-11-arm native verification for the npth admission workflow.

.DESCRIPTION
  Consumes ONLY the smoke bundle produced from the comparison-approved packages
  and proves, on real AArch64 silicon, that:
    * the runner is native ARM64 (no x64 / WOW64 fallback is tolerated),
    * the dynamic and static npth consumers execute and emit explicit markers,
    * every module the dynamic consumer loads is an AArch64 image whose path and
      SHA-256 are captured,
    * the canonical pseudo-reloc scanner (downloaded and hash-pinned by the
      caller) accepts the shipped msys-npth DLL using package-owned objdump/nm.

  All heavy lifting lives in pure, dot-sourceable functions so the offline test
  can exercise the policy logic on an x64 host without an ARM64 runner or a
  network. The orchestration body only runs when the script is invoked directly.
#>
[CmdletBinding()]
param(
  [string] $BundlePath,
  [string] $Objdump,
  [string] $Nm,
  [string] $Scanner,
  [string] $OutputPath,
  [string] $ProcessorArchitecture = $env:PROCESSOR_ARCHITECTURE
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# PE machine identifiers (IMAGE_FILE_HEADER.Machine).
$script:PeMachine = @{
  0x8664 = 'x64'
  0xAA64 = 'arm64'
  0x14C  = 'x86'
  0x1C0  = 'arm'
  0x1C4  = 'armnt'
}

function Get-PeMachineType {
  <# Reads IMAGE_FILE_HEADER.Machine straight from the PE on disk. This is the
     ground truth for an image's target architecture and does not depend on the
     loader, so it works for offline inspection of any PE. #>
  param([Parameter(Mandatory)] [string] $Path)

  $resolved = (Resolve-Path -LiteralPath $Path).Path
  $stream = [IO.File]::OpenRead($resolved)
  try {
    $reader = [IO.BinaryReader]::new($stream)
    if ($stream.Length -lt 0x40) {
      throw "File is too small to be a PE image: $resolved"
    }
    if ($reader.ReadUInt16() -ne 0x5A4D) {
      throw "Missing MZ signature: $resolved"
    }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadUInt32()
    if (($peOffset + 6) -gt $stream.Length) {
      throw "PE header offset is out of range: $resolved"
    }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) {
      throw "Missing PE\0\0 signature: $resolved"
    }
    $machine = $reader.ReadUInt16()
  }
  finally {
    $stream.Dispose()
  }

  $name = if ($script:PeMachine.ContainsKey([int] $machine)) {
    $script:PeMachine[[int] $machine]
  } else {
    'unknown'
  }
  return [ordered]@{
    machine      = ('0x{0:x4}' -f $machine)
    machine_name = $name
  }
}

function Assert-NativeArm64 {
  <# The native job must fail closed on anything but genuine ARM64 silicon.
     Rejects a null/empty value and any non-ARM64 architecture, including the
     WOW64 emulation markers, so an x64 runner can never satisfy the gate. #>
  param([string] $Architecture)

  if ([string]::IsNullOrWhiteSpace($Architecture)) {
    throw 'PROCESSOR_ARCHITECTURE is not set; refusing to run native checks.'
  }
  if ($Architecture -cne 'ARM64') {
    throw "Native verification requires ARM64, found '$Architecture' (no x64 fallback)."
  }
  return $true
}

$script:Wow64Signature = @'
using System;
using System.Runtime.InteropServices;
public static class NpthWow64 {
  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool IsWow64Process2(IntPtr hProcess, out ushort processMachine, out ushort nativeMachine);
  [DllImport("kernel32.dll")]
  static extern IntPtr GetCurrentProcess();
  public static ushort[] Current() {
    ushort processMachine;
    ushort nativeMachine;
    if (!IsWow64Process2(GetCurrentProcess(), out processMachine, out nativeMachine)) {
      throw new InvalidOperationException("IsWow64Process2 failed: " + Marshal.GetLastWin32Error());
    }
    return new ushort[] { processMachine, nativeMachine };
  }
}
'@

function Get-Wow64Evidence {
  <# Calls IsWow64Process2 on the current process. processMachine == 0 (IMAGE_
     FILE_MACHINE_UNKNOWN) means the process is NOT running under emulation;
     nativeMachine reports the host silicon. On ARM64 hardware nativeMachine
     must be 0xAA64. #>
  if (-not ('NpthWow64' -as [type])) {
    Add-Type -TypeDefinition $script:Wow64Signature -ErrorAction Stop | Out-Null
  }
  $pair = [NpthWow64]::Current()
  $processMachine = [int] $pair[0]
  $nativeMachine = [int] $pair[1]
  $nativeName = if ($script:PeMachine.ContainsKey($nativeMachine)) {
    $script:PeMachine[$nativeMachine]
  } else {
    'unknown'
  }
  return [ordered]@{
    process_machine   = ('0x{0:x4}' -f $processMachine)
    native_machine    = ('0x{0:x4}' -f $nativeMachine)
    native_name       = $nativeName
    is_emulated       = ($processMachine -ne 0)
  }
}

function Test-ExitMarker {
  <# Confirms a consumer both exited cleanly and printed its contract marker.
     Returns $true only when the exit code is zero and the marker line is
     present verbatim in captured output. #>
  param(
    [int] $ExitCode,
    [AllowNull()] [object] $Output,
    [Parameter(Mandatory)] [string] $Marker
  )
  if ($ExitCode -ne 0) { return $false }
  $lines = @($Output | ForEach-Object { "$_" })
  return [bool]($lines -contains $Marker)
}

function Invoke-NativeConsumer {
  <# Runs a bundled consumer, captures combined output, and enforces the exit
     marker contract. Emits a structured evidence record. #>
  param(
    [Parameter(Mandatory)] [string] $ExePath,
    [Parameter(Mandatory)] [string] $Marker
  )
  $resolved = (Resolve-Path -LiteralPath $ExePath).Path
  $output = @(& $resolved 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  if (-not (Test-ExitMarker -ExitCode $code -Output $output -Marker $Marker)) {
    throw "Consumer $([IO.Path]::GetFileName($resolved)) failed: exit=$code marker='$Marker' output=$($output -join '|')"
  }

  return [ordered]@{
    exe        = [IO.Path]::GetFileName($resolved)
    exit_code  = $code
    marker     = $Marker
    machine    = (Get-PeMachineType -Path $resolved).machine_name
    sha256     = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    output     = $output
  }
}

function Get-NpthThreadMarker {
  param(
    [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Output,
    [Parameter(Mandatory)] [int] $ExpectedProcessId
  )

  $markerLines = @($Output | Where-Object {
      "$_" -match '^NPTH-DYNAMIC-THREAD pid=([0-9]+) tid=([0-9]+)$'
    })
  if ($markerLines.Count -ne 1) {
    throw "Expected exactly one NPTH worker thread marker, found $($markerLines.Count)."
  }
  [void]("$($markerLines[0])" -match '^NPTH-DYNAMIC-THREAD pid=([0-9]+) tid=([0-9]+)$')
  $processId = [int]$Matches[1]
  $threadId = [int]$Matches[2]
  if ($processId -ne $ExpectedProcessId -or $threadId -le 0) {
    throw "Invalid NPTH worker marker pid=$processId tid=$threadId (expected pid $ExpectedProcessId)."
  }
  return [ordered]@{ process_id = $processId; worker_thread_id = $threadId }
}

function Invoke-NativeDynamicConsumer {
  <# Keeps the dynamic consumer alive after its READY marker, captures that
     process's real module list, then requires its final success marker. #>
  param(
    [Parameter(Mandatory)] [string] $ExePath,
    [Parameter(Mandatory)] [string] $ReadyMarker,
    [Parameter(Mandatory)] [string] $SuccessMarker
  )

  $resolved = (Resolve-Path -LiteralPath $ExePath).Path
  $stdout = Join-Path ([IO.Path]::GetTempPath()) "npth-dynamic-$PID.stdout"
  $stderr = Join-Path ([IO.Path]::GetTempPath()) "npth-dynamic-$PID.stderr"
  Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
  $process = Start-Process -FilePath $resolved `
    -WorkingDirectory (Split-Path -Parent $resolved) `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru
  try {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
      Start-Sleep -Milliseconds 100
      $lines = if (Test-Path -LiteralPath $stdout) {
        @(Get-Content -LiteralPath $stdout)
      } else {
        @()
      }
      $hasThreadMarker = [bool]($lines | Where-Object {
          "$_" -match '^NPTH-DYNAMIC-THREAD pid=[0-9]+ tid=[0-9]+$'
        })
      if ($lines -contains $ReadyMarker -and $hasThreadMarker) { break }
      if ($process.HasExited) {
        throw "Dynamic consumer exited before '$ReadyMarker' (exit $($process.ExitCode))."
      }
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($lines -notcontains $ReadyMarker -or -not $hasThreadMarker) {
      throw "Dynamic consumer did not emit ready and worker-thread markers before the capture deadline."
    }

    $threadMarker = Get-NpthThreadMarker -Output $lines -ExpectedProcessId $process.Id
    $liveThreadIds = @($process.Threads | ForEach-Object { $_.Id })
    if ($liveThreadIds.Count -lt 2 -or
        $threadMarker.worker_thread_id -notin $liveThreadIds) {
      throw "NPTH worker thread $($threadMarker.worker_thread_id) was not live during capture."
    }
    $modules = @(Get-ProcessModuleEvidence -ProcessId $process.Id)
    $process.WaitForExit()
    $output = @(
      Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue
      Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue
    )
    if (-not (Test-ExitMarker -ExitCode $process.ExitCode -Output $output -Marker $SuccessMarker)) {
      throw "Dynamic consumer failed: exit=$($process.ExitCode) marker='$SuccessMarker' output=$($output -join '|')"
    }
    return [ordered]@{
      consumer = [ordered]@{
        exe       = [IO.Path]::GetFileName($resolved)
        exit_code = $process.ExitCode
        marker    = $SuccessMarker
        machine   = (Get-PeMachineType -Path $resolved).machine_name
        sha256    = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        output    = $output
        process_id = $threadMarker.process_id
        worker_thread_id = $threadMarker.worker_thread_id
        live_thread_ids = $liveThreadIds
      }
      modules = $modules
    }
  }
  finally {
    if (-not $process.HasExited) {
      $process.Kill($true)
      $process.WaitForExit()
    }
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
  }
}

function Get-ProcessModuleEvidence {
  <# Enumerates the modules currently mapped into a process and, for each,
     records the on-disk path, PE machine type, and SHA-256. Used to prove the
     dynamic consumer only ever loaded AArch64 images. #>
  param([Parameter(Mandatory)] [int] $ProcessId)

  $process = Get-Process -Id $ProcessId -ErrorAction Stop
  $records = [Collections.Generic.List[object]]::new()
  foreach ($module in @($process.Modules)) {
    $path = $module.FileName
    $machine = (Get-PeMachineType -Path $path).machine_name
    $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $records.Add([ordered]@{
        name    = $module.ModuleName
        path    = $path
        machine = $machine
        sha256  = $sha
      })
  }
  return $records.ToArray()
}

function Test-ModuleArchitecture {
  <# Fails closed if any captured module is not an AArch64 image. Modules whose
     machine could not be read are treated as violations. #>
  param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Modules)

  $offenders = [Collections.Generic.List[string]]::new()
  foreach ($module in $Modules) {
    if ($module.machine -ne 'arm64') {
      $offenders.Add("$($module.name)=$($module.machine)")
    }
    if ([string]::IsNullOrWhiteSpace($module.sha256) -or
        $module.sha256 -notmatch '^[0-9a-f]{64}$') {
      $offenders.Add("$($module.name)=missing-or-invalid-sha256")
    }
  }
  return $offenders
}

function Assert-FileHashes {
  param([Parameter(Mandatory)] [Collections.IDictionary] $ExpectedHashes)

  foreach ($path in $ExpectedHashes.Keys) {
    $currentSha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentSha -ne $ExpectedHashes[$path]) {
      throw "Trusted admission file changed after initial verification: $path"
    }
  }
}

function Invoke-NativeVerification {
  <# Full native orchestration: architecture gate, consumer execution, loaded-
     module capture, and the canonical scanner over the shipped DLL. Returns the
     complete evidence object; throws on any policy failure. #>
  param(
    [Parameter(Mandatory)] [string] $BundlePath,
    [Parameter(Mandatory)] [string] $Objdump,
    [Parameter(Mandatory)] [string] $Nm,
    [Parameter(Mandatory)] [string] $Scanner,
    [string] $Architecture = $env:PROCESSOR_ARCHITECTURE
  )

  Assert-NativeArm64 -Architecture $Architecture | Out-Null

  # Resolve and hash all scanner inputs before any candidate-linked code runs.
  $scannerPath = (Resolve-Path -LiteralPath $Scanner).Path
  $objdumpPath = (Resolve-Path -LiteralPath $Objdump).Path
  $nmPath = (Resolve-Path -LiteralPath $Nm).Path
  $scannerSha = (Get-FileHash -LiteralPath $scannerPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($scannerSha -ne '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9') {
    throw "Canonical scanner identity mismatch: $scannerSha"
  }
  $objdumpSha = (Get-FileHash -LiteralPath $objdumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $nmSha = (Get-FileHash -LiteralPath $nmPath -Algorithm SHA256).Hash.ToLowerInvariant()

  $bundle = (Resolve-Path -LiteralPath $BundlePath).Path
  $dynamic = Join-Path $bundle 'npth-dynamic-smoke.exe'
  $static = Join-Path $bundle 'npth-static-smoke.exe'
  $dll = @(Get-ChildItem -LiteralPath $bundle -Filter 'msys-npth-*.dll')
  if ($dll.Count -ne 1) {
    throw "Expected exactly one msys-npth DLL in the bundle, found $($dll.Count)."
  }
  foreach ($required in @($dynamic, $static)) {
    if (-not (Test-Path -LiteralPath $required)) {
      throw "Native bundle is missing $([IO.Path]::GetFileName($required))."
    }
  }
  $trustedHashes = [ordered]@{
    $scannerPath = $scannerSha
    $objdumpPath = $objdumpSha
    $nmPath = $nmSha
    $dynamic = (Get-FileHash -LiteralPath $dynamic -Algorithm SHA256).Hash.ToLowerInvariant()
    $static = (Get-FileHash -LiteralPath $static -Algorithm SHA256).Hash.ToLowerInvariant()
    $dll[0].FullName = (Get-FileHash -LiteralPath $dll[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }

  # The dynamic consumer resolves msys-npth / msys-2.0 from the bundle.
  $priorPath = $env:PATH
  $env:PATH = "$bundle;$priorPath"
  try {
    $evidence = [ordered]@{
      schema                 = 1
      processor_architecture = $Architecture
      dotnet_process_arch    = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
      os_architecture        = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
      wow64                  = Get-Wow64Evidence
      npth_dll               = [ordered]@{
        name    = $dll[0].Name
        machine = (Get-PeMachineType -Path $dll[0].FullName).machine_name
        sha256  = (Get-FileHash -LiteralPath $dll[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      }
      consumers              = @()
      loaded_modules         = @()
      module_violations      = @()
      scanner                = $null
      result                 = 'error'
    }

    if ($evidence.wow64.is_emulated) {
      throw 'Process is running under emulation; native ARM64 required.'
    }
    if ($evidence.dotnet_process_arch -ne 'Arm64') {
      throw "RuntimeInformation.ProcessArchitecture is $($evidence.dotnet_process_arch), expected Arm64."
    }

    $dynamicRun = Invoke-NativeDynamicConsumer `
      -ExePath $dynamic `
      -ReadyMarker 'NPTH-DYNAMIC-READY' `
      -SuccessMarker 'NPTH-DYNAMIC-OK'
    $dynamicEvidence = $dynamicRun.consumer
    $staticEvidence = Invoke-NativeConsumer -ExePath $static -Marker 'NPTH-STATIC-OK'
    $evidence.consumers = @($dynamicEvidence, $staticEvidence)

    $modules = @($dynamicRun.modules)
    if ($modules.Count -eq 0) {
      throw 'Dynamic consumer module capture returned no modules.'
    }
    $evidence.loaded_modules = $modules
    $evidence.module_violations = @(Test-ModuleArchitecture -Modules $modules)
    if ($evidence.module_violations.Count -ne 0) {
      throw "Non-AArch64 modules loaded: $($evidence.module_violations -join ', ')"
    }
    $moduleNames = @($modules | ForEach-Object { $_.name.ToLowerInvariant() })
    if ('msys-2.0.dll' -notin $moduleNames -or
        -not ($moduleNames | Where-Object { $_ -like 'msys-npth-*.dll' })) {
      throw 'Dynamic consumer module capture is missing msys-2.0.dll or msys-npth.'
    }

    Assert-FileHashes -ExpectedHashes $trustedHashes
    $scanRecords = @()
    foreach ($input in @($dll[0].FullName, $dynamic, $static)) {
      Assert-FileHashes -ExpectedHashes $trustedHashes
      $scannerOutput = Join-Path $bundle "$([IO.Path]::GetFileName($input)).pseudo-reloc.json"
      & (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive `
        -File $scannerPath -PePath $input -OutputPath $scannerOutput `
        -Objdump $objdumpPath -Nm $nmPath
      if ($LASTEXITCODE -ne 0) {
        throw "Canonical pseudo-reloc scanner rejected $input (exit $LASTEXITCODE)."
      }
      $scannerReport = Get-Content -Raw -LiteralPath $scannerOutput | ConvertFrom-Json
      if ($scannerReport.result -ne 'pass') {
        throw "Scanner result for $input is '$($scannerReport.result)', expected 'pass'."
      }
      $scanRecords += [ordered]@{
        input_name       = [IO.Path]::GetFileName($input)
        input_sha256     = (Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash.ToLowerInvariant()
        output_sha256    = (Get-FileHash -LiteralPath $scannerOutput -Algorithm SHA256).Hash.ToLowerInvariant()
        result           = $scannerReport.result
        record_count     = $scannerReport.record_count
        policy_violations = @($scannerReport.policy_violations)
      }
    }
    $evidence.scanner = [ordered]@{
      sha256        = $scannerSha
      objdump_path  = $objdumpPath
      objdump_sha256 = $objdumpSha
      nm_path       = $nmPath
      nm_sha256     = $nmSha
      inputs        = $scanRecords
    }
    $evidence.result = 'pass'
    return $evidence
  }
  finally {
    $env:PATH = $priorPath
  }
}

if ($MyInvocation.InvocationName -ne '.' -and
    -not (Get-Variable -Name NativeVerifyDotSource -Scope Global -ErrorAction SilentlyContinue)) {
  foreach ($name in 'BundlePath', 'Objdump', 'Nm', 'Scanner') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $name -ValueOnly))) {
      throw "-$name is required when running native-verify.ps1 directly."
    }
  }
  $result = Invoke-NativeVerification `
    -BundlePath $BundlePath `
    -Objdump $Objdump `
    -Nm $Nm `
    -Scanner $Scanner `
    -Architecture $ProcessorArchitecture
  $json = $result | ConvertTo-Json -Depth 8
  if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $json | Set-Content -LiteralPath $OutputPath -Encoding utf8
  }
  Write-Output $json
  Write-Output 'NPTH-NATIVE-VERIFY-OK'
}

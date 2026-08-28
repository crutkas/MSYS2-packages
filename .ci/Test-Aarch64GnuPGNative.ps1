[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CandidateRoot,

    [Parameter(Mandatory = $true)]
    [string] $GitPath,

    [Parameter(Mandatory = $true)]
    [string] $TransactionEvidencePath,

    [Parameter(Mandatory = $true)]
    [string] $EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:MSYS = 'winsymlinks:sys'

function Get-CanonicalSnapshot {
    param([string] $SharedRoot)
    $database = Join-Path $SharedRoot 'var\lib\pacman\local'
    $log = Join-Path $SharedRoot 'var\log\pacman.log'
    $rows = @(
        Get-ChildItem -LiteralPath $database -Recurse -File |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($database.Length + 1).Replace('\', '/')
                "$relative`t$($_.Length)`t$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
            }
    )
    $manifestBytes = [Text.Encoding]::UTF8.GetBytes(($rows -join "`n") + "`n")
    return [ordered]@{
        database_file_count = $rows.Count
        database_canonical_manifest_sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($manifestBytes)).ToLowerInvariant()
        pacman_log_bytes = (Get-Item -LiteralPath $log).Length
        pacman_log_sha256 = (Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

if (-not ('GnuPGJobTracker' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class GnuPGJobTracker : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct AssociateCompletionPort
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int informationClass, ref AssociateCompletionPort information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateIoCompletionPort(
        IntPtr fileHandle, IntPtr existingCompletionPort, UIntPtr completionKey, uint threads);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetQueuedCompletionStatus(
        IntPtr completionPort, out uint message, out UIntPtr completionKey,
        out IntPtr processId, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        IntPtr job, int informationClass, out BasicAccountingInformation information,
        uint length, IntPtr returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const int JobObjectAssociateCompletionPortInformation = 7;
    private const int JobObjectBasicAccountingInformation = 1;
    private const uint JobObjectMessageNewProcess = 6;
    private const uint JobObjectMessageExitProcess = 7;
    private const uint JobObjectMessageAbnormalExitProcess = 8;
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    private readonly IntPtr job;
    private readonly IntPtr completionPort;
    private readonly Thread reader;
    private volatile bool stopping;
    private readonly ConcurrentDictionary<uint, byte> started = new ConcurrentDictionary<uint, byte>();
    private readonly ConcurrentDictionary<uint, byte> stopped = new ConcurrentDictionary<uint, byte>();

    public uint CurrentProcessId { get; private set; }

    public GnuPGJobTracker()
    {
        CurrentProcessId = (uint)Process.GetCurrentProcess().Id;
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
        completionPort = CreateIoCompletionPort(InvalidHandleValue, IntPtr.Zero, UIntPtr.Zero, 1);
        if (completionPort == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateIoCompletionPort failed");
        var association = new AssociateCompletionPort {
            CompletionKey = new IntPtr(1),
            CompletionPort = completionPort
        };
        if (!SetInformationJobObject(
            job, JobObjectAssociateCompletionPortInformation, ref association,
            (uint)Marshal.SizeOf(typeof(AssociateCompletionPort))))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Job completion-port association failed");
        if (!AssignProcessToJobObject(job, Process.GetCurrentProcess().Handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Native test process could not enter a non-breakaway job");
        reader = new Thread(ReadNotifications) { IsBackground = true };
        reader.Start();
    }

    private void ReadNotifications()
    {
        while (!stopping)
        {
            uint message;
            UIntPtr key;
            IntPtr processId;
            if (!GetQueuedCompletionStatus(completionPort, out message, out key, out processId, 100))
                continue;
            uint pid = unchecked((uint)processId.ToInt64());
            if (message == JobObjectMessageNewProcess)
                started.TryAdd(pid, 0);
            else if (message == JobObjectMessageExitProcess || message == JobObjectMessageAbnormalExitProcess)
                stopped.TryAdd(pid, 0);
        }
    }

    public uint[] StartedProcessIds()
    {
        return new System.Collections.Generic.List<uint>(started.Keys).ToArray();
    }

    public uint[] StoppedProcessIds()
    {
        return new System.Collections.Generic.List<uint>(stopped.Keys).ToArray();
    }

    public void WaitForQuiescence(int milliseconds)
    {
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline)
        {
            BasicAccountingInformation accounting;
            if (!QueryInformationJobObject(
                job, JobObjectBasicAccountingInformation, out accounting,
                (uint)Marshal.SizeOf(typeof(BasicAccountingInformation)), IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Job accounting query failed");

            if (accounting.ActiveProcesses == 1 &&
                started.Count == accounting.TotalProcesses &&
                stopped.Count == accounting.TotalProcesses - 1)
                return;
            Thread.Sleep(50);
        }
        throw new TimeoutException("Native test job did not reach complete process quiescence");
    }

    public IntPtr LoadModuleBarrier(string path)
    {
        var module = LoadLibraryEx(path, IntPtr.Zero, 0);
        if (module == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Telemetry barrier module load failed");
        return module;
    }

    public void FreeModuleBarrier(IntPtr module)
    {
        if (!FreeLibrary(module))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Telemetry barrier module unload failed");
    }

    public void Dispose()
    {
        stopping = true;
        reader.Join(1000);
        CloseHandle(completionPort);
        CloseHandle(job);
    }
}
'@
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string] $Path)
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw "Not a PE file: $Path"
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Invalid PE signature: $Path"
        }
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Assert-Arm64Pe {
    param([string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $machine = Get-PeMachine $Path
    $isCandidate = $script:CandidatePolicyRoot -and
        $fullPath.StartsWith($script:CandidatePolicyRoot, [StringComparison]::OrdinalIgnoreCase)
    $isGit = $script:GitPolicyRoot -and
        $fullPath.StartsWith($script:GitPolicyRoot, [StringComparison]::OrdinalIgnoreCase)
    $isSystem = $script:SystemPolicyRoot -and
        $fullPath.StartsWith($script:SystemPolicyRoot, [StringComparison]::OrdinalIgnoreCase)
    if (-not ($isCandidate -or $isGit -or $isSystem)) {
        throw "Module escaped candidate, Git, and Windows roots: $fullPath"
    }
    if (($isCandidate -or $isGit) -and $machine -ne 0xaa64) {
        throw "Candidate or Git PE is not plain ARM64: $fullPath (0x$($machine.ToString('x4')))"
    }
    if ($isSystem -and $machine -notin @(0xaa64, 0xa641, 0xa64e)) {
        throw "x64 or non-ARM64 PE in native workflow: $Path (0x$($machine.ToString('x4')))"
    }
}

$trace = [Collections.Generic.List[object]]::new()
function Invoke-Traced {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [string[]] $Arguments = @(),
        [string] $WorkingDirectory = $CandidateRoot,
        [string] $StandardInput
    )

    Assert-Arm64Pe $FilePath
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $null -ne $StandardInput
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    $processRecords = @{}
    $moduleRecords = @{}

    function Save-ProcessTreeSnapshot {
        $pending = [Collections.Generic.Queue[uint32]]::new()
        $pending.Enqueue([uint32] $process.Id)
        while ($pending.Count -ne 0) {
            $parentId = $pending.Dequeue()
            $rows = @(
                Get-CimInstance Win32_Process |
                    Where-Object { $_.ProcessId -eq $parentId -or $_.ParentProcessId -eq $parentId }
            )
            foreach ($row in $rows) {
                if ([string]::IsNullOrWhiteSpace($row.ExecutablePath)) {
                    throw "Unable to resolve executable for traced PID $($row.ProcessId)"
                }
                Assert-Arm64Pe $row.ExecutablePath
                $processRecords["$($row.ProcessId)"] = [ordered]@{
                    pid = $row.ProcessId
                    parent_pid = $row.ParentProcessId
                    path = $row.ExecutablePath
                    machine = ('0x{0:x4}' -f (Get-PeMachine $row.ExecutablePath))
                }
                $nativeProcess = Get-Process -Id $row.ProcessId
                foreach ($module in $nativeProcess.Modules) {
                    Assert-Arm64Pe $module.FileName
                    $moduleRecords[$module.FileName.ToLowerInvariant()] = [ordered]@{
                        path = $module.FileName
                        machine = ('0x{0:x4}' -f (Get-PeMachine $module.FileName))
                    }
                }
                foreach ($child in @($rows | Where-Object ParentProcessId -eq $row.ProcessId)) {
                    $pending.Enqueue([uint32] $child.ProcessId)
                }
            }
        }
    }

    Save-ProcessTreeSnapshot
    if ($null -ne $StandardInput) {
        $process.StandardInput.Write($StandardInput)
        $process.StandardInput.Close()
    }
    while (-not $process.HasExited) {
        Save-ProcessTreeSnapshot
        Start-Sleep -Milliseconds 20
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $trace.Add([ordered]@{
        root_pid = $process.Id
        executable = $FilePath
        arguments = $Arguments
        exit_code = $process.ExitCode
        processes = @($processRecords.Values)
        modules = @($moduleRecords.Values)
    })
    if ($process.ExitCode -ne 0) {
        throw "$FilePath failed with exit code $($process.ExitCode): $stderr"
    }
    return $stdout
}

$root = (Resolve-Path -LiteralPath $CandidateRoot).Path
$gpg = Join-Path $root 'usr\bin\gpg.exe'
$gpgconf = Join-Path $root 'usr\bin\gpgconf.exe'
$pinentry = Join-Path $root 'usr\bin\pinentry.exe'
$git = (Resolve-Path -LiteralPath $GitPath).Path
$gitDirectory = Split-Path -Parent $git
$gitRoot = if ((Split-Path -Leaf $gitDirectory) -in @('bin', 'cmd')) {
    Split-Path -Parent $gitDirectory
}
else {
    $gitDirectory
}
$script:CandidatePolicyRoot = "$($root.TrimEnd('\'))\"
$script:GitPolicyRoot = "$($gitRoot.TrimEnd('\'))\"
$script:SystemPolicyRoot = "$($env:SystemRoot.TrimEnd('\'))\"
foreach ($path in @($gpg, $gpgconf, $pinentry, $git)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing native test executable: $path"
    }
    Assert-Arm64Pe $path
}

$transactionEvidence = Get-Content -LiteralPath $TransactionEvidencePath -Raw | ConvertFrom-Json
if ($transactionEvidence.result -ne 'pass' -or
    ($transactionEvidence.shared_before | ConvertTo-Json -Compress) -ne
    ($transactionEvidence.shared_after | ConvertTo-Json -Compress)) {
    throw 'Native execution requires a passing private transaction with unchanged shared state'
}
$sharedBefore = Get-CanonicalSnapshot 'C:\msys64'

$work = Join-Path ([IO.Path]::GetTempPath()) "gnupg-native-$([guid]::NewGuid().ToString('N'))"
$home = Join-Path $work 'home'
$importHome = Join-Path $work 'import-home'
$repo = Join-Path $work 'repo'
New-Item -ItemType Directory -Force -Path $home, $importHome, $repo | Out-Null
$env:GNUPGHOME = $home
$env:PATH = @(
    (Join-Path $root 'bin')
    (Join-Path $root 'usr\bin')
    $gitDirectory
    (Join-Path $env:SystemRoot 'System32')
    $env:SystemRoot
) -join ';'

$processEventSource = "gnupg-process-start-$([guid]::NewGuid().ToString('N'))"
$jobTracker = [GnuPGJobTracker]::new()
$processStartQueue = [Collections.Concurrent.ConcurrentQueue[object]]::new()
$processEventJob = Register-CimIndicationEvent `
    -Namespace root/cimv2 `
    -Query 'SELECT * FROM Win32_ProcessStartTrace' `
    -SourceIdentifier $processEventSource `
    -MessageData $processStartQueue `
    -Action {
        $started = $Event.SourceEventArgs.NewEvent
        $row = @(
            Get-CimInstance Win32_Process -Filter "ProcessId = $($started.ProcessID)"
        )
        $path = if ($row.Count -eq 1) { $row[0].ExecutablePath } else { $null }
        $Event.MessageData.Enqueue([pscustomobject]@{
            ProcessID = [uint32] $started.ProcessID
            ParentProcessID = [uint32] $started.ParentProcessID
            ProcessName = $started.ProcessName
            ExecutablePath = $path
        })
    }

$moduleEventSource = "gnupg-module-load-$([guid]::NewGuid().ToString('N'))"
$moduleLoadQueue = [Collections.Concurrent.ConcurrentQueue[object]]::new()
$moduleEventJob = Register-CimIndicationEvent `
    -Namespace root/cimv2 `
    -Query 'SELECT * FROM Win32_ModuleLoadTrace' `
    -SourceIdentifier $moduleEventSource `
    -MessageData $moduleLoadQueue `
    -Action {
        $loaded = $Event.SourceEventArgs.NewEvent
        $Event.MessageData.Enqueue([pscustomobject]@{
            ProcessID = [uint32] $loaded.ProcessID
            FileName = [string] $loaded.FileName
        })
    }

$stopEventSource = "gnupg-process-stop-$([guid]::NewGuid().ToString('N'))"
$processStopQueue = [Collections.Concurrent.ConcurrentQueue[object]]::new()
$stopEventJob = Register-CimIndicationEvent `
    -Namespace root/cimv2 `
    -Query 'SELECT * FROM Win32_ProcessStopTrace' `
    -SourceIdentifier $stopEventSource `
    -MessageData $processStopQueue `
    -Action {
        $stopped = $Event.SourceEventArgs.NewEvent
        $Event.MessageData.Enqueue([pscustomobject]@{
            ProcessID = [uint32] $stopped.ProcessID
            ProcessName = [string] $stopped.ProcessName
        })
    }

$scenarios = [Collections.Generic.List[object]]::new()
function Complete-Scenario {
    param([string] $Id, [hashtable] $Details = @{})
    $scenarios.Add([ordered]@{ id = $Id; result = 'pass'; details = $Details })
}

Complete-Scenario 'machine-architecture' @{
    gpg = ('0x{0:x4}' -f (Get-PeMachine $gpg))
    git = ('0x{0:x4}' -f (Get-PeMachine $git))
}
$version = Invoke-Traced $gpg @('--version')
if ($version -notmatch '^gpg \(GnuPG\) 2\.4\.7') {
    throw "Unexpected gpg version: $version"
}
Complete-Scenario 'gpg-version' @{ output = ($version -split "`r?`n")[0] }

$batch = @'
Key-Type: RSA
Key-Length: 2048
Name-Real: ARM64 GnuPG CI
Name-Email: arm64-gnupg-ci@example.invalid
Expire-Date: 0
%no-protection
%commit
'@
$batchPath = Join-Path $work 'key.batch'
[IO.File]::WriteAllText($batchPath, $batch, [Text.UTF8Encoding]::new($false))
Invoke-Traced $gpg @('--batch', '--homedir', $home, '--generate-key', $batchPath) | Out-Null
$keys = Invoke-Traced $gpg @('--batch', '--homedir', $home, '--with-colons', '--list-secret-keys')
$fingerprint = @($keys -split "`r?`n" | Where-Object { $_ -like 'fpr:*' })[0].Split(':')[9]
if ($fingerprint -notmatch '^[0-9A-F]{40}$') {
    throw 'Key generation did not produce a fingerprint'
}
Complete-Scenario 'key-generation' @{ fingerprint = $fingerprint }

$plain = Join-Path $work 'message.txt'
$detached = "$plain.sig"
$clear = Join-Path $work 'message.asc'
$cipher = Join-Path $work 'message.gpg'
$decrypted = Join-Path $work 'message.out'
[IO.File]::WriteAllText($plain, "native ARM64 GnuPG`n", [Text.UTF8Encoding]::new($false))
Invoke-Traced $gpg @('--batch', '--homedir', $home, '--local-user', $fingerprint, '--detach-sign', '--output', $detached, $plain) | Out-Null
Invoke-Traced $gpg @('--batch', '--homedir', $home, '--verify', $detached, $plain) | Out-Null
Complete-Scenario 'detach-sign-verify'
Invoke-Traced $gpg @('--batch', '--homedir', $home, '--local-user', $fingerprint, '--clearsign', '--output', $clear, $plain) | Out-Null
Invoke-Traced $gpg @('--batch', '--homedir', $home, '--verify', $clear) | Out-Null
Complete-Scenario 'clear-sign-verify'
Invoke-Traced $gpg @('--batch', '--yes', '--trust-model', 'always', '--homedir', $home, '--recipient', $fingerprint, '--encrypt', '--output', $cipher, $plain) | Out-Null
Invoke-Traced $gpg @('--batch', '--yes', '--homedir', $home, '--decrypt', '--output', $decrypted, $cipher) | Out-Null
if ((Get-FileHash $plain).Hash -ne (Get-FileHash $decrypted).Hash) {
    throw 'Encrypt/decrypt roundtrip changed the plaintext'
}
Complete-Scenario 'encrypt-decrypt'

$export = Join-Path $work 'public.gpg'
$exportText = Invoke-Traced $gpg @('--batch', '--armor', '--homedir', $home, '--export', $fingerprint)
[IO.File]::WriteAllText($export, $exportText, [Text.Encoding]::ASCII)
Invoke-Traced $gpg @('--batch', '--homedir', $importHome, '--import', $export) | Out-Null
$imported = Invoke-Traced $gpg @('--batch', '--homedir', $importHome, '--with-colons', '--list-keys', $fingerprint)
if ($imported -notmatch [regex]::Escape($fingerprint)) {
    throw 'Imported key fingerprint was not found'
}
Complete-Scenario 'import-export'

Invoke-Traced $gpgconf @('--homedir', $home, '--launch', 'gpg-agent') | Out-Null
$agentRows = @(
    Get-CimInstance Win32_Process -Filter "Name = 'gpg-agent.exe'" |
        Where-Object ExecutablePath -eq (Join-Path $root 'usr\bin\gpg-agent.exe')
)
if ($agentRows.Count -eq 0) {
    throw 'gpg-agent did not launch'
}
foreach ($agentRow in $agentRows) {
    Assert-Arm64Pe $agentRow.ExecutablePath
    $agentModules = @()
    foreach ($module in (Get-Process -Id $agentRow.ProcessId).Modules) {
        Assert-Arm64Pe $module.FileName
        $agentModules += [ordered]@{
            path = $module.FileName
            machine = ('0x{0:x4}' -f (Get-PeMachine $module.FileName))
        }
    }
    if ($agentModules.Count -eq 0) {
        throw 'gpg-agent module trace is empty'
    }
    $trace.Add([ordered]@{
        root_pid = $agentRow.ProcessId
        executable = $agentRow.ExecutablePath
        arguments = @('--daemon')
        exit_code = $null
        processes = @([ordered]@{
            pid = $agentRow.ProcessId
            parent_pid = $agentRow.ParentProcessId
            path = $agentRow.ExecutablePath
            machine = ('0x{0:x4}' -f (Get-PeMachine $agentRow.ExecutablePath))
        })
        modules = $agentModules
    })
}
Invoke-Traced $gpgconf @('--homedir', $home, '--kill', 'gpg-agent') | Out-Null
Complete-Scenario 'agent-lifecycle' @{ executables = @($agentRows.ExecutablePath) }

$pinentryOutput = Invoke-Traced $pinentry @() $root "OPTION no-grab`nGETINFO pid`nBYE`n"
if ($pinentryOutput -notmatch '(?m)^OK' -or $pinentryOutput -notmatch '(?m)^D \d+') {
    throw 'Pinentry did not satisfy the non-secret Assuan contract'
}
Complete-Scenario 'pinentry-contract'

Invoke-Traced $git @('init', '--quiet', $repo) $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'config', 'user.name', 'ARM64 GnuPG CI') $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'config', 'user.email', 'arm64-gnupg-ci@example.invalid') $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'config', 'user.signingkey', $fingerprint) $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'config', 'gpg.program', $gpg) $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'config', 'commit.gpgsign', 'true') $repo | Out-Null
[IO.File]::WriteAllText((Join-Path $repo 'signed.txt'), "signed`n", [Text.UTF8Encoding]::new($false))
Invoke-Traced $git @('-C', $repo, 'add', 'signed.txt') $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'commit', '--quiet', '-m', 'signed ARM64 commit') $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'verify-commit', 'HEAD') $repo | Out-Null
Complete-Scenario 'git-commit-signing'
Invoke-Traced $git @('-C', $repo, 'tag', '-s', 'signed-tag', '-m', 'signed ARM64 tag') $repo | Out-Null
Invoke-Traced $git @('-C', $repo, 'verify-tag', 'signed-tag') $repo | Out-Null
Complete-Scenario 'git-tag-signing'

$jobTracker.WaitForQuiescence(30000)
$jobProcessIds = @(
    $jobTracker.StartedProcessIds() |
        Where-Object { $_ -ne $jobTracker.CurrentProcessId }
)
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    $startCoverage = @($processStartQueue.ToArray() | ForEach-Object { [uint32] $_.ProcessID })
    $stopCoverage = @($processStopQueue.ToArray() | ForEach-Object { [uint32] $_.ProcessID })
    $jobStoppedCoverage = @($jobTracker.StoppedProcessIds())
    $telemetryComplete = @($jobProcessIds | Where-Object {
        $_ -notin $startCoverage -or $_ -notin $stopCoverage -or $_ -notin $jobStoppedCoverage
    }).Count -eq 0
    if (-not $telemetryComplete) {
        Start-Sleep -Milliseconds 50
    }
} while (-not $telemetryComplete -and [DateTime]::UtcNow -lt $deadline)
if (-not $telemetryComplete) {
    throw 'Process start/stop telemetry did not drain after Job Object quiescence'
}

$telemetryBarrier = Join-Path $work "telemetry-barrier-$([guid]::NewGuid().ToString('N')).dll"
Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\version.dll') -Destination $telemetryBarrier
$barrierModule = $jobTracker.LoadModuleBarrier($telemetryBarrier)
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $moduleBarrierObserved = @($moduleLoadQueue.ToArray() | Where-Object {
            [uint32] $_.ProcessID -eq $jobTracker.CurrentProcessId -and
            [string]::Equals(
                [IO.Path]::GetFullPath($_.FileName),
                [IO.Path]::GetFullPath($telemetryBarrier),
                [StringComparison]::OrdinalIgnoreCase)
        }).Count -eq 1
        if (-not $moduleBarrierObserved) {
            Start-Sleep -Milliseconds 50
        }
    } while (-not $moduleBarrierObserved -and [DateTime]::UtcNow -lt $deadline)
    if (-not $moduleBarrierObserved) {
        throw 'Module-load telemetry did not reach the deterministic drain barrier'
    }
}
finally {
    $jobTracker.FreeModuleBarrier($barrierModule)
}

$startEvents = @($processStartQueue.ToArray())
$moduleEvents = @($moduleLoadQueue.ToArray())
$stopEvents = @($processStopQueue.ToArray())
$eventErrors = @(
    @($processEventJob, $moduleEventJob, $stopEventJob).ChildJobs |
        ForEach-Object Error |
        Where-Object { $null -ne $_ }
)
Unregister-Event -SourceIdentifier $processEventSource
Unregister-Event -SourceIdentifier $moduleEventSource
Unregister-Event -SourceIdentifier $stopEventSource
Remove-Job -Job $processEventJob, $moduleEventJob, $stopEventJob -Force
if ($eventErrors.Count -ne 0) {
    throw "Process-start telemetry failed: $($eventErrors -join [Environment]::NewLine)"
}
if ($startEvents.Count -eq 0) {
    throw 'Process-start telemetry is empty'
}

$knownPids = [Collections.Generic.HashSet[uint32]]::new()
foreach ($processId in $jobProcessIds) {
    [void] $knownPids.Add([uint32] $processId)
}
foreach ($entry in $trace) {
    [void] $knownPids.Add([uint32] $entry.root_pid)
    foreach ($process in $entry.processes) {
        [void] $knownPids.Add([uint32] $process.pid)
    }
}
$descendants = [Collections.Generic.List[object]]::new()
$added = $true
while ($added) {
    $added = $false
    foreach ($event in $startEvents) {
        if ($knownPids.Contains([uint32] $event.ParentProcessID) -and
            $knownPids.Add([uint32] $event.ProcessID)) {
            $descendants.Add($event)
            $added = $true
        }
    }
}
foreach ($event in $descendants) {
    if ([string]::IsNullOrWhiteSpace($event.ExecutablePath)) {
        throw "Telemetry could not capture the actual path for descendant PID $($event.ProcessID) ($($event.ProcessName))"
    }
    Assert-Arm64Pe $event.ExecutablePath
    if ([uint32] $event.ProcessID -notin $jobProcessIds) {
        throw "Descendant escaped the non-breakaway native test job: $($event.ProcessID)"
    }
}

$knownProcessIds = @($knownPids)
$relevantModuleEvents = @($moduleEvents | Where-Object { [uint32] $_.ProcessID -in $knownProcessIds })
foreach ($processId in $knownProcessIds) {
    if (@($relevantModuleEvents | Where-Object ProcessID -eq $processId).Count -eq 0) {
        throw "Image-load telemetry is incomplete for traced PID $processId"
    }
}
$jobStoppedIds = @($jobTracker.StoppedProcessIds())
foreach ($event in $relevantModuleEvents) {
    if ([string]::IsNullOrWhiteSpace($event.FileName)) {
        throw "Image-load telemetry omitted a module path for PID $($event.ProcessID)"
    }
    Assert-Arm64Pe $event.FileName
}
$stoppedIds = @($stopEvents | ForEach-Object { [uint32] $_.ProcessID })
foreach ($processId in $knownProcessIds) {
    if ($processId -notin $stoppedIds -or $processId -notin $jobStoppedIds) {
        throw "Traced process did not produce termination evidence: $processId"
    }
}

$tracedModules = @($trace | ForEach-Object modules)
if ($tracedModules.Count -eq 0) {
    throw 'Process/module trace did not capture any loaded module'
}
$gitGpgChildren = @(
    $trace |
        Where-Object { $_.executable -eq $git } |
        ForEach-Object processes |
        Where-Object { $_.path -eq $gpg }
)
if ($gitGpgChildren.Count -lt 2) {
    throw 'Git commit/tag signing did not trace the configured candidate gpg.exe'
}
Complete-Scenario 'process-module-trace' @{
    process_count = @($trace | ForEach-Object processes).Count + $descendants.Count
    module_count = $tracedModules.Count
    forbidden_machine = '0x8664'
    x64_found = $false
    image_load_event_count = $relevantModuleEvents.Count
    process_stop_event_count = @($stopEvents | Where-Object { [uint32] $_.ProcessID -in $knownProcessIds }).Count
    process_start_telemetry = @(
        $descendants | ForEach-Object {
            [ordered]@{
                pid = $_.ProcessID
                parent_pid = $_.ParentProcessID
                name = $_.ProcessName
                executable_path = $_.ExecutablePath
            }
        }
    )
}
Complete-Scenario 'process-image-load-stop-closure' @{
    non_breakaway_job = $true
    job_quiescent = $true
    telemetry_barrier = $telemetryBarrier
    traced_process_ids = $knownProcessIds
    image_load_events = @(
        $relevantModuleEvents | ForEach-Object {
            [ordered]@{
                pid = $_.ProcessID
                path = $_.FileName
                machine = ('0x{0:x4}' -f (Get-PeMachine $_.FileName))
            }
        }
    )
    stopped_process_ids = @(
        $stopEvents |
            Where-Object { [uint32] $_.ProcessID -in $knownProcessIds } |
            ForEach-Object { [uint32] $_.ProcessID }
    )
}
$sharedAfter = Get-CanonicalSnapshot 'C:\msys64'
if (($sharedBefore | ConvertTo-Json -Compress) -ne ($sharedAfter | ConvertTo-Json -Compress)) {
    throw 'Shared pacman database or log changed during native execution'
}
Complete-Scenario 'shared-state-unchanged' @{
    transaction_evidence = (Resolve-Path -LiteralPath $TransactionEvidencePath).Path
    native_before = $sharedBefore
    native_after = $sharedAfter
}
$jobTracker.Dispose()

$required = @(
    (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\mingw-w64-cross-msysarm64-gnupg\inventory.json') -Raw |
        ConvertFrom-Json).native_evidence_required
)
$completed = @($scenarios | ForEach-Object id)
if (Compare-Object ($required | Sort-Object) ($completed | Sort-Object)) {
    throw 'Native evidence is incomplete'
}

$evidence = [ordered]@{
    schema_version = 1
    result = 'pass'
    root = $root
    scenarios = $scenarios
    process_module_trace = $trace
}
$parent = Split-Path -Parent $EvidencePath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

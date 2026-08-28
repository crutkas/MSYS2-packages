[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Root,
    [Parameter(Mandatory = $true)]
    [string] $EvidencePath,
    [Parameter(Mandatory = $true)]
    [string] $Arm64GitRoot,
    [Parameter(Mandatory = $true)]
    [string] $BusyBoxRoot,
    [Parameter(Mandatory = $true)]
    [string] $SemanticProofRoot,
    [Parameter(Mandatory = $true)]
    [string] $SmokeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64') {
    throw 'native smoke requires a Windows 11 ARM64 runner'
}
if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
    'Arm64') {
    throw 'native smoke requires an ARM64 PowerShell process'
}

$Root = (Resolve-Path -LiteralPath $Root).Path
$Arm64GitRoot = (Resolve-Path -LiteralPath $Arm64GitRoot).Path
$BusyBoxRoot = (Resolve-Path -LiteralPath $BusyBoxRoot).Path
$SemanticProofRoot = (Resolve-Path -LiteralPath $SemanticProofRoot).Path
$SmokeRoot = (Resolve-Path -LiteralPath $SmokeRoot).Path
$targetBin = Join-Path $Root 'opt\aarch64-pc-msys\usr\bin'
$runtimeBin = Join-Path $Root 'opt\aarch64-pc-msys\bin'
$gccBin = Join-Path $Root 'opt\lib\gcc\aarch64-pc-msys\15.0.1'
$git = Join-Path $Arm64GitRoot 'cmd\git.exe'
$gitSh = Join-Path $Arm64GitRoot 'usr\bin\sh.exe'
$manifestPath = Join-Path $Root (
    'usr\share\mingw-w64-cross-msysarm64-coreutils\path-manifest.json')

foreach ($required in @(
    (Join-Path $targetBin 'b2sum.exe'),
    (Join-Path $targetBin 'basenc.exe'),
    (Join-Path $targetBin 'csplit.exe'),
    (Join-Path $targetBin 'hostname.exe'),
    (Join-Path $targetBin 'stdbuf.exe'),
    (Join-Path $runtimeBin 'msys-2.0.dll'),
    $manifestPath,
    $git,
    $gitSh,
    (Join-Path $SmokeRoot 'abi-probe.exe'),
    (Join-Path $SmokeRoot 'gmp-dynamic-probe.exe'),
    (Join-Path $SmokeRoot 'gmp-static-probe.exe'),
    (Join-Path $SmokeRoot 'stdbuf-behavior-probe.exe')
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required native input is missing: $required"
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw "not a PE image: $Path"
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "invalid PE signature: $Path"
        }
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Assert-Arm64Pe {
    param([Parameter(Mandatory = $true)][string] $Path)

    $machine = Get-PeMachine -Path $Path
    if ($machine -ne 0xaa64) {
        throw ('x64/foreign PE detected: {0} machine=0x{1:x4}' -f $Path, $machine)
    }
}

function Assert-NativePe {
    param([Parameter(Mandatory = $true)][string] $Path)

    $machine = Get-PeMachine -Path $Path
    if ($machine -notin @(0xaa64, 0xa641, 0xa64e)) {
        throw ('x64/foreign PE detected: {0} machine=0x{1:x4}' -f $Path, $machine)
    }
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string] $File,
        [string[]] $Arguments = @(),
        [int] $ExpectedExit = 0
    )

    Assert-Arm64Pe -Path $File
    $output = @(& $File @Arguments 2>&1)
    if ($LASTEXITCODE -ne $ExpectedExit) {
        throw "$File exited $LASTEXITCODE, expected $ExpectedExit`: $output"
    }
    return @($output | ForEach-Object { $_.ToString() })
}

function Invoke-NativeWithInput {
    param(
        [Parameter(Mandatory = $true)][string] $File,
        [string[]] $Arguments = @(),
        [Parameter(Mandatory = $true)][string] $InputText
    )

    Assert-Arm64Pe -Path $File
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $File
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    $process.StandardInput.Write($InputText)
    $process.StandardInput.Close()
    $output = $process.StandardOutput.ReadToEnd()
    $errorOutput = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "$File exited $($process.ExitCode): $errorOutput"
    }
    return $output
}

function Invoke-StdbufNegative {
    param(
        [Parameter(Mandatory = $true)][string] $Stdbuf,
        [Parameter(Mandatory = $true)][string] $Command
    )

    Assert-Arm64Pe -Path $Stdbuf
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Stdbuf
    $start.ArgumentList.Add('-o0')
    $start.ArgumentList.Add($Command)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.ReadToEnd()
    $errorOutput = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -eq 0) {
        throw "stdbuf executed the wrapped command with an invalid DLL: $output"
    }
    if ($output.Length -ne 0) {
        throw "wrapped command produced output despite an invalid DLL: $output"
    }
    if ($errorOutput -notmatch
        '(?is)(libstdbuf.*(load|preload|not found|invalid|format)|' +
        '(load|preload).*(libstdbuf))') {
        throw "missing specific libstdbuf loader failure: $errorOutput"
    }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$nativePaths = @($manifest.native_coreutils.paths)
$busyboxPaths = @($manifest.busybox.paths)
$semanticPaths = @($manifest.busybox_semantic_proof.paths)
if ($nativePaths.Count -ne 30 -or $busyboxPaths.Count -ne 59 -or
    $semanticPaths.Count -ne 24) {
    throw 'path contract count mismatch'
}
foreach ($path in $nativePaths) {
    Assert-Arm64Pe -Path (Join-Path $Root (
        "opt\aarch64-pc-msys\" + $path.Replace('/', '\')))
}
Assert-Arm64Pe -Path $git
Assert-Arm64Pe -Path $gitSh
$busyboxFiles = @{}
foreach ($path in $busyboxPaths) {
    $file = Join-Path $BusyBoxRoot $path.Replace('/', '\')
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "BusyBox contract path is missing: $path"
    }
    Assert-Arm64Pe -Path $file
    $busyboxFiles[$path] = $file
}
$semanticFiles = @{}
foreach ($path in $semanticPaths) {
    $file = Join-Path $SemanticProofRoot $path.Replace('/', '\')
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "semantic proof contract path is missing: $path"
    }
    Assert-Arm64Pe -Path $file
    $semanticFiles[$path] = $file
}

$env:MSYSTEM = 'MSYS'
$env:MSYS = 'winsymlinks:sys'
$env:PATH = "$targetBin;$runtimeBin;$gccBin;$($env:PATH)"
$work = Join-Path $env:RUNNER_TEMP "coreutils-native-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
$cases = [Collections.Generic.List[string]]::new()
$moduleRecords = [Collections.Generic.List[object]]::new()
$foreignRecords = [Collections.Generic.List[object]]::new()

function Add-ProcessModuleAudit {
    param([Parameter(Mandatory = $true)][Diagnostics.Process] $Process)

    foreach ($module in $Process.Modules) {
        if (-not (Test-Path -LiteralPath $module.FileName -PathType Leaf)) {
            continue
        }
        $machine = Get-PeMachine -Path $module.FileName
        $record = [ordered]@{
            process_id = $Process.Id
            process = $Process.ProcessName
            path = $module.FileName
            machine = ('0x{0:x4}' -f $machine)
        }
        $moduleRecords.Add($record)
        if ($machine -notin @(0xaa64, 0xa641, 0xa64e)) {
            $foreignRecords.Add($record)
        }
    }
    if ($foreignRecords.Count -ne 0) {
        throw "x64/foreign process module detected for PID $($Process.Id)"
    }
}

function Add-ProcessTreeAudit {
    param([Parameter(Mandatory = $true)][Diagnostics.Process] $RootProcess)

    $pending = [Collections.Generic.Queue[int]]::new()
    $pending.Enqueue($RootProcess.Id)
    $observed = [Collections.Generic.List[string]]::new()
    while ($pending.Count -ne 0) {
        $parentId = $pending.Dequeue()
        try {
            $process = [Diagnostics.Process]::GetProcessById($parentId)
            Add-ProcessModuleAudit -Process $process
            $observed.Add($process.ProcessName)
        }
        catch [ArgumentException] {
            continue
        }
        foreach ($child in Get-CimInstance Win32_Process -Filter (
            "ParentProcessId = $parentId")) {
            $pending.Enqueue([int]$child.ProcessId)
        }
    }
    return @($observed)
}

try {
    Add-ProcessModuleAudit -Process ([Diagnostics.Process]::GetCurrentProcess())
    foreach ($probe in @(
        (Join-Path $SmokeRoot 'abi-probe.exe'),
        (Join-Path $SmokeRoot 'gmp-dynamic-probe.exe'),
        (Join-Path $SmokeRoot 'gmp-static-probe.exe')
    )) {
        Invoke-Native $probe | Out-Null
    }
    $cases.Add('linked-consumers')
    $spaced = Join-Path $work 'utf8 space'
    New-Item -ItemType Directory -Path $spaced | Out-Null
    $utf8File = Join-Path $spaced ([char]0x03bb + '-file.txt')
    [IO.File]::WriteAllText($utf8File, "alpha`nbeta`n",
        [Text.UTF8Encoding]::new($false))

    $stat = $semanticFiles['usr/bin/stat.exe']
    $chmod = $semanticFiles['usr/bin/chmod.exe']
    $readlink = $semanticFiles['usr/bin/readlink.exe']
    $realpath = $semanticFiles['usr/bin/realpath.exe']
    $install = $semanticFiles['usr/bin/install.exe']
    $ls = $semanticFiles['usr/bin/ls.exe']
    $timeout = $semanticFiles['usr/bin/timeout.exe']
    $sleep = $semanticFiles['usr/bin/sleep.exe']
    $stdbuf = Join-Path $targetBin 'stdbuf.exe'
    $hostname = Join-Path $targetBin 'hostname.exe'
    $stdbufProbe = Join-Path $SmokeRoot 'stdbuf-behavior-probe.exe'
    $stdbufDll = Join-Path $Root (
        'opt\aarch64-pc-msys\usr\lib\coreutils\libstdbuf.dll')
    Assert-Arm64Pe -Path $stdbufDll
    $stdbufStart = [Diagnostics.ProcessStartInfo]::new()
    $stdbufStart.FileName = $stdbuf
    foreach ($argument in @('-oL', $stdbufProbe)) {
        $stdbufStart.ArgumentList.Add($argument)
    }
    $stdbufStart.UseShellExecute = $false
    $stdbufStart.RedirectStandardOutput = $true
    $stdbufStart.RedirectStandardError = $true
    $stdbufProcess = [Diagnostics.Process]::Start($stdbufStart)
    $readyTask = $stdbufProcess.StandardOutput.ReadLineAsync()
    if (-not $readyTask.Wait(1000) -or $readyTask.Result -ne 'ready') {
        if (-not $stdbufProcess.HasExited) {
            $stdbufProcess.Kill()
            $stdbufProcess.WaitForExit()
        }
        throw 'stdbuf did not line-buffer the native stdio probe'
    }
    Add-ProcessTreeAudit -RootProcess $stdbufProcess | Out-Null
    $loadedStdbuf = @($moduleRecords | Where-Object {
        [IO.Path]::GetFileName($_.path) -eq 'libstdbuf.dll'
    })
    if ($loadedStdbuf.Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($loadedStdbuf[0].path),
            [IO.Path]::GetFullPath($stdbufDll),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "stdbuf did not load exactly its private package DLL: $(
            $loadedStdbuf.path -join ', ')"
    }
    $stdbufProcess.Kill()
    $stdbufProcess.WaitForExit()
    $cases.Add('stdbuf-loader-closure')

    $missingDll = "$stdbufDll.missing-negative"
    Move-Item -LiteralPath $stdbufDll -Destination $missingDll
    try {
        Invoke-StdbufNegative -Stdbuf $stdbuf -Command $hostname
    }
    finally {
        Move-Item -LiteralPath $missingDll -Destination $stdbufDll
    }
    $cases.Add('stdbuf-missing-dll-negative')

    $originalDll = [IO.File]::ReadAllBytes($stdbufDll)
    try {
        [IO.File]::WriteAllBytes(
            $stdbufDll, [Text.Encoding]::ASCII.GetBytes('corrupt'))
        Invoke-StdbufNegative -Stdbuf $stdbuf -Command $hostname
    }
    finally {
        [IO.File]::WriteAllBytes($stdbufDll, $originalDll)
    }
    $cases.Add('stdbuf-corrupt-dll-negative')

    $metadata = Invoke-Native $stat @('--printf=%s:%F', $utf8File)
    if (($metadata -join '') -notmatch '11:regular file') {
        throw "stat metadata mismatch: $metadata"
    }
    $cases.Add('filesystem-metadata')

    Invoke-Native $chmod @('640', $utf8File) | Out-Null
    $mode = Invoke-Native $stat @('--printf=%a', $utf8File)
    if (($mode -join '') -ne '640') {
        throw "permission mode mismatch: $mode"
    }
    $cases.Add('permissions')

    $hardlink = Join-Path $spaced 'hardlink.txt'
    New-Item -ItemType HardLink -Path $hardlink -Target $utf8File | Out-Null
    $links = Invoke-Native $stat @('--printf=%h', $utf8File)
    if ([int]($links -join '') -lt 2) {
        throw "hardlink count mismatch: $links"
    }
    $cases.Add('hardlinks')

    $symlink = Join-Path $spaced 'symlink.txt'
    New-Item -ItemType SymbolicLink -Path $symlink -Target $utf8File | Out-Null
    $linkValue = Invoke-Native $readlink @($symlink)
    if (-not ($linkValue -join '').Contains('file.txt')) {
        throw "readlink mismatch: $linkValue"
    }
    $resolved = Invoke-Native $realpath @($symlink)
    if (-not ($resolved -join '').Contains('file.txt')) {
        throw "realpath mismatch: $resolved"
    }
    $cases.Add('symlinks')
    $cases.Add('stat-realpath-readlink')

    $sparse = Join-Path $work 'sparse.bin'
    [IO.File]::WriteAllBytes($sparse, [byte[]]::new(1MB))
    $fsutil = (Get-Command fsutil.exe -CommandType Application).Source
    Assert-NativePe -Path $fsutil
    & $fsutil sparse setflag $sparse | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to mark sparse file' }
    & $fsutil sparse setrange $sparse 0 1048576 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to create sparse range' }
    $blocks = Invoke-Native $stat @('--printf=%b:%B:%s', $sparse)
    if (($blocks -join '') -notmatch '^\d+:\d+:1048576$') {
        throw "sparse stat mismatch: $blocks"
    }
    $cases.Add('sparse-files')

    $installed = Join-Path $work 'installed file.txt'
    Invoke-Native $install @('-m', '600', $utf8File, $installed) | Out-Null
    if (-not (Test-Path -LiteralPath $installed)) {
        throw 'install did not copy the file'
    }
    $busyboxCopy = Join-Path $work 'busybox-copy.txt'
    $busyboxMoved = Join-Path $work 'busybox-moved.txt'
    Invoke-Native $busyboxFiles['usr/bin/cp.exe'] @(
        $utf8File, $busyboxCopy) | Out-Null
    Invoke-Native $busyboxFiles['usr/bin/mv.exe'] @(
        $busyboxCopy, $busyboxMoved) | Out-Null
    Invoke-Native $busyboxFiles['usr/bin/rm.exe'] @(
        $busyboxMoved) | Out-Null
    if (Test-Path -LiteralPath $busyboxMoved) {
        throw 'BusyBox cp/mv/rm edge probe left its output behind'
    }
    $cases.Add('install-cp-mv-rm')

    $textInput = Join-Path $work 'text-input.txt'
    [IO.File]::WriteAllText($textInput, "beta`nalpha`nalpha`n",
        [Text.UTF8Encoding]::new($false))
    $sorted = Invoke-Native $busyboxFiles['usr/bin/sort.exe'] @($textInput)
    if (($sorted | ForEach-Object { $_.Trim() }) -join ',' -ne
        'alpha,alpha,beta') {
        throw "BusyBox sort mismatch: $sorted"
    }
    $uniq = Invoke-Native $busyboxFiles['usr/bin/uniq.exe'] @($textInput)
    if (($uniq | ForEach-Object { $_.Trim() }) -join ',' -ne 'beta,alpha') {
        throw "BusyBox uniq mismatch: $uniq"
    }
    $csv = Join-Path $work 'fields.csv'
    [IO.File]::WriteAllText($csv, "left,right`n",
        [Text.UTF8Encoding]::new($false))
    $cut = Invoke-Native $busyboxFiles['usr/bin/cut.exe'] @(
        '-d,', '-f2', $csv)
    if (($cut -join '').Trim() -ne 'right') {
        throw "BusyBox cut mismatch: $cut"
    }
    $translated = Invoke-NativeWithInput `
        -File $busyboxFiles['usr/bin/tr.exe'] `
        -Arguments @('a-z', 'A-Z') `
        -InputText 'arm64'
    if ($translated -ne 'ARM64') {
        throw "BusyBox tr mismatch: $translated"
    }
    $octets = Invoke-Native $busyboxFiles['usr/bin/od.exe'] @(
        '-An', '-tx1', $utf8File)
    if (($octets -join ' ') -notmatch '61 6c 70 68 61') {
        throw "BusyBox od mismatch: $octets"
    }
    $encoded = Invoke-Native $busyboxFiles['usr/bin/base64.exe'] @($utf8File)
    $expectedBase64 = [Convert]::ToBase64String(
        [IO.File]::ReadAllBytes($utf8File))
    if (($encoded -join '').Trim() -ne $expectedBase64) {
        throw "BusyBox base64 mismatch: $encoded"
    }
    $cases.Add('busybox-text-delegation')

    $listing = Invoke-Native $ls @('-1', $spaced)
    if (-not (($listing -join "`n").Contains([char]0x03bb))) {
        throw 'UTF-8 path was not preserved'
    }
    $cases.Add('text-encoding')
    $cases.Add('path-spaces-globs')

    Invoke-Native $timeout @('0.1', $sleep, '5') 124 | Out-Null
    $cases.Add('pipes-signals-exit-codes')

    $repo = Join-Path $work 'repo'
    New-Item -ItemType Directory -Path $repo | Out-Null
    Invoke-Native $git @('-C', $repo, 'init', '--quiet') | Out-Null
    $hook = Join-Path $repo '.git\hooks\pre-commit'
    $hookContent = @"
#!/bin/sh
"$($sleep.Replace('\', '/'))" 2
"$($stat.Replace('\', '/'))" --printf=%s "$($utf8File.Replace('\', '/'))" >/dev/null
"@
    [IO.File]::WriteAllText(
        $hook,
        $hookContent.Replace("`r`n", "`n").TrimStart(),
        [Text.UTF8Encoding]::new($false)
    )
    & $git -C $repo config user.email arm64@example.invalid
    & $git -C $repo config user.name arm64
    Copy-Item $utf8File (Join-Path $repo 'tracked.txt')
    & $git -C $repo add tracked.txt
    $commitStart = [Diagnostics.ProcessStartInfo]::new()
    $commitStart.FileName = $git
    foreach ($argument in @('-C', $repo, 'commit', '--quiet', '-m', 'probe')) {
        $commitStart.ArgumentList.Add($argument)
    }
    $commitStart.UseShellExecute = $false
    $commitStart.RedirectStandardOutput = $true
    $commitStart.RedirectStandardError = $true
    $commitProcess = [Diagnostics.Process]::Start($commitStart)
    Start-Sleep -Milliseconds 500
    $hookProcesses = @(Add-ProcessTreeAudit -RootProcess $commitProcess)
    if (-not ($hookProcesses -match 'sh') -or
        -not ($hookProcesses -match 'sleep')) {
        throw "Git hook process trace incomplete: $hookProcesses"
    }
    $commitProcess.WaitForExit()
    if ($commitProcess.ExitCode -ne 0) {
        throw "ARM64 Git hook compatibility probe failed: $(
            $commitProcess.StandardError.ReadToEnd())"
    }
    $cases.Add('git-hook')

    $buildScript = Join-Path $work 'build-probe.ps1'
    @"
& '$stat' --printf=%s '$utf8File'
if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }
"@ | Set-Content -LiteralPath $buildScript
$pwsh = ([Diagnostics.Process]::GetCurrentProcess()).MainModule.FileName
Assert-NativePe -Path $pwsh
& $pwsh -NoProfile -File $buildScript | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'build script compatibility probe failed'
    }
    $cases.Add('build-script')

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $sleep
    $start.ArgumentList.Add('3')
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    Start-Sleep -Milliseconds 300
    Add-ProcessTreeAudit -RootProcess $process | Out-Null
    $process.Kill()
    $process.WaitForExit()

    $gitStart = [Diagnostics.ProcessStartInfo]::new()
    $gitStart.FileName = $git
    $gitStart.ArgumentList.Add('-C')
    $gitStart.ArgumentList.Add($repo)
    $gitStart.ArgumentList.Add('cat-file')
    $gitStart.ArgumentList.Add('--batch')
    $gitStart.UseShellExecute = $false
    $gitStart.RedirectStandardInput = $true
    $gitStart.RedirectStandardOutput = $true
    $gitStart.RedirectStandardError = $true
    $gitProcess = [Diagnostics.Process]::Start($gitStart)
    Start-Sleep -Milliseconds 300
    Add-ProcessTreeAudit -RootProcess $gitProcess | Out-Null
    $gitProcess.StandardInput.Close()
    $gitProcess.WaitForExit()
    if ($gitProcess.ExitCode -ne 0) {
        throw "ARM64 Git process trace failed: $($gitProcess.StandardError.ReadToEnd())"
    }

    $evidence = [ordered]@{
        schema_version = 1
        host_architecture = 'Arm64'
        target = 'aarch64-pc-msys'
        native_path_count = $nativePaths.Count
        busybox_delegated_path_count = $busyboxPaths.Count
        busybox_audited_path_count = $busyboxFiles.Count
        semantic_proof_path_count = $semanticPaths.Count
        semantic_proof_audited_path_count = $semanticFiles.Count
        cases = @($cases | Sort-Object -Unique)
        process_modules = @($moduleRecords)
        x64_process_or_module_count = $foreignRecords.Count
        result = 'pass'
    }
    $evidence | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $EvidencePath -Encoding utf8
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

[CmdletBinding()]
param(
    [string] $ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'PrivatePacman.psm1'
Import-Module $modulePath -Force
$module = Get-Module PrivatePacman

$results = [Collections.Generic.List[object]]::new()
$createdJobs = [Collections.Generic.List[Management.Automation.Job]]::new()
$createdProcesses = [Collections.Generic.List[Diagnostics.Process]]::new()
$testEnvironmentNames = @(
    'PRIVATE_PACMAN_TEST_ARGV',
    'PRIVATE_PACMAN_TEST_CONFIG',
    'PRIVATE_PACMAN_TEST_MODE',
    'PRIVATE_PACMAN_TEST_READY',
    'PRIVATE_PACMAN_TEST_GO'
)

function Assert-PrivatePacmanTest {
    param(
        [Parameter(Mandatory)]
        [bool] $Condition,

        [Parameter(Mandatory)]
        [string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-PrivatePacmanEqual {
    param(
        [AllowNull()]
        [object] $Expected,

        [AllowNull()]
        [object] $Actual,

        [Parameter(Mandatory)]
        [string] $Message
    )

    if (-not [object]::Equals($Expected, $Actual)) {
        throw "$Message Expected: <$Expected>; actual: <$Actual>."
    }
}

function Assert-PrivatePacmanSequence {
    param(
        [Parameter(Mandatory)]
        [object[]] $Expected,

        [Parameter(Mandatory)]
        [object[]] $Actual,

        [Parameter(Mandatory)]
        [string] $Message
    )

    if ($Expected.Count -ne $Actual.Count) {
        throw "$Message Expected $($Expected.Count) entries; actual $($Actual.Count)."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (-not [StringComparer]::Ordinal.Equals(
            [string]$Expected[$index],
            [string]$Actual[$index])) {
            throw "$Message Entry $index expected <$($Expected[$index])>; actual <$($Actual[$index])>."
        }
    }
}

function Assert-PrivatePacmanThrows {
    param(
        [Parameter(Mandatory)]
        [scriptblock] $Operation,

        [Parameter(Mandatory)]
        [string] $Pattern
    )

    $caught = $null
    try {
        $null = & $Operation
    }
    catch {
        $caught = $_
    }

    if ($null -eq $caught) {
        throw "Expected a terminating error matching <$Pattern>, but no error was raised."
    }
    if ($caught.Exception.Message -notmatch $Pattern) {
        throw "Error did not match <$Pattern>: $($caught.Exception.Message)"
    }
    return $caught
}

function Invoke-PrivatePacmanTestCase {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [scriptblock] $Test
    )

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Test
        $stopwatch.Stop()
        $results.Add([pscustomobject][ordered]@{
            Name = $Name
            Passed = $true
            DurationMilliseconds = $stopwatch.ElapsedMilliseconds
            Error = $null
        })
        Write-Host "PASS $Name"
    }
    catch {
        $stopwatch.Stop()
        $results.Add([pscustomobject][ordered]@{
            Name = $Name
            Passed = $false
            DurationMilliseconds = $stopwatch.ElapsedMilliseconds
            Error = $_.Exception.ToString()
        })
        Write-Host "FAIL $Name`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-PrivatePacmanTestEnvironment {
    foreach ($name in $testEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
}

function Wait-PrivatePacmanPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [int] $TimeoutSeconds = 20
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not [IO.File]::Exists($Path)) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Timed out waiting for test signal: $Path"
        }
        [Threading.Thread]::Sleep(50)
    }
}

function Read-PrivatePacmanRecordedArguments {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    return @(
        [IO.File]::ReadAllLines($Path) | ForEach-Object {
            [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
        }
    )
}

function New-PrivatePacmanRecorder {
    param(
        [Parameter(Mandatory)]
        [string] $Directory
    )

    [void][IO.Directory]::CreateDirectory($Directory)
    $sourcePath = Join-Path $Directory 'PrivatePacmanRecorder.cs'
    $executablePath = Join-Path $Directory 'PrivatePacmanRecorder.exe'
    $source = @'
using System;
using System.IO;
using System.Text;
using System.Threading;

public static class PrivatePacmanRecorder
{
    private static string Env(string name)
    {
        return Environment.GetEnvironmentVariable(name);
    }

    private static string FindValue(string[] args, string name)
    {
        for (int index = 0; index + 1 < args.Length; index++)
        {
            if (String.Equals(args[index], name, StringComparison.Ordinal))
            {
                return args[index + 1];
            }
        }
        return null;
    }

    private static void WriteSignal(string path, string value)
    {
        if (String.IsNullOrEmpty(path))
        {
            return;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        File.WriteAllText(path, value, new UTF8Encoding(false));
    }

    public static int Main(string[] args)
    {
        string argvPath = Env("PRIVATE_PACMAN_TEST_ARGV");
        if (!String.IsNullOrEmpty(argvPath))
        {
            string[] encoded = new string[args.Length];
            for (int index = 0; index < args.Length; index++)
            {
                encoded[index] = Convert.ToBase64String(Encoding.UTF8.GetBytes(args[index]));
            }
            Directory.CreateDirectory(Path.GetDirectoryName(argvPath));
            File.WriteAllLines(argvPath, encoded, new UTF8Encoding(false));
        }

        string configCapture = Env("PRIVATE_PACMAN_TEST_CONFIG");
        if (!String.IsNullOrEmpty(configCapture))
        {
            File.Copy(FindValue(args, "--config"), configCapture, true);
        }

        string mode = Env("PRIVATE_PACMAN_TEST_MODE") ?? "success";
        if (String.Equals(mode, "exit-7", StringComparison.Ordinal))
        {
            return 7;
        }
        if (String.Equals(mode, "crash", StringComparison.Ordinal))
        {
            Environment.FailFast("intentional private-pacman contract crash");
        }
        if (String.Equals(mode, "timeout", StringComparison.Ordinal))
        {
            Thread.Sleep(TimeSpan.FromMinutes(2));
            return 0;
        }
        if (String.Equals(mode, "wait", StringComparison.Ordinal))
        {
            WriteSignal(Env("PRIVATE_PACMAN_TEST_READY"), System.Diagnostics.Process.GetCurrentProcess().Id.ToString());
            string goPath = Env("PRIVATE_PACMAN_TEST_GO");
            DateTime deadline = DateTime.UtcNow.AddSeconds(60);
            while (!File.Exists(goPath))
            {
                if (DateTime.UtcNow >= deadline)
                {
                    return 9;
                }
                Thread.Sleep(25);
            }
        }
        return 0;
    }
}
'@
    [IO.File]::WriteAllText($sourcePath, $source, [Text.UTF8Encoding]::new($false))

    $compilerCandidates = @(
        "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    )
    $compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($null -eq $compiler) {
        throw 'The inbox .NET Framework C# compiler is required for the source-only argv recorder.'
    }

    & $compiler /nologo /target:exe "/out:$executablePath" $sourcePath
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($executablePath)) {
        throw "Unable to compile the source-only argv recorder (exit $LASTEXITCODE)."
    }
    return $executablePath
}

function New-PrivatePacmanFixture {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $SuiteRoot,

        [Parameter(Mandatory)]
        [string] $RecorderPath
    )

    $safeName = $Name -replace '[^A-Za-z0-9-]', '-'
    $base = Join-Path $SuiteRoot "$safeName-$([guid]::NewGuid().ToString('N'))"
    $workspace = Join-Path $base 'workspace'
    $seed = Join-Path $base 'seed'
    $packageRoot = Join-Path $base 'packages'
    $protectedRoot = Join-Path $base 'shared-state'
    foreach ($directory in @(
        $workspace,
        (Join-Path $seed 'usr\bin'),
        $packageRoot,
        (Join-Path $protectedRoot 'var\lib\pacman\local'),
        (Join-Path $protectedRoot 'var\log')
    )) {
        [void][IO.Directory]::CreateDirectory($directory)
    }

    [IO.File]::Copy($RecorderPath, (Join-Path $seed 'usr\bin\pacman.exe'))
    $packageRelativePath = 'sample package.pkg.tar.zst'
    $packagePath = Join-Path $packageRoot $packageRelativePath
    [IO.File]::WriteAllText($packagePath, "package-$Name", [Text.UTF8Encoding]::new($false))
    $sharedFile = Join-Path $protectedRoot 'var\lib\pacman\local\state'
    [IO.File]::WriteAllText($sharedFile, "shared-$Name", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $protectedRoot 'var\log\pacman.log'),
        "log-$Name",
        [Text.UTF8Encoding]::new($false)
    )

    $sessionId = "test-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    $layout = New-PrivatePacmanLayout -WorkspaceRoot $workspace -SessionId $sessionId
    return [pscustomobject][ordered]@{
        Base = $base
        Workspace = $workspace
        Seed = $seed
        PackageRoot = $packageRoot
        PackageRelativePath = $packageRelativePath
        PackagePath = $packagePath
        ProtectedRoot = $protectedRoot
        SharedFile = $sharedFile
        Layout = $layout
        ArgvPath = Join-Path $base 'argv.txt'
        ConfigCapturePath = Join-Path $base 'pacman.conf'
        ReadyPath = Join-Path $base 'ready.txt'
        GoPath = Join-Path $base 'go.txt'
    }
}

function Set-PrivatePacmanFixtureEnvironment {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [string] $Mode = 'success'
    )

    $env:PRIVATE_PACMAN_TEST_ARGV = $Fixture.ArgvPath
    $env:PRIVATE_PACMAN_TEST_CONFIG = $Fixture.ConfigCapturePath
    $env:PRIVATE_PACMAN_TEST_MODE = $Mode
    $env:PRIVATE_PACMAN_TEST_READY = $Fixture.ReadyPath
    $env:PRIVATE_PACMAN_TEST_GO = $Fixture.GoPath
}

function Invoke-PrivatePacmanFixture {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [int] $TimeoutSeconds = 30
    )

    Invoke-PrivatePacmanUpgrade `
        -Layout $Fixture.Layout `
        -SeedRoot $Fixture.Seed `
        -PackageRoot $Fixture.PackageRoot `
        -PackagePath @($Fixture.PackageRelativePath) `
        -ProtectedRoot @($Fixture.ProtectedRoot) `
        -TimeoutSeconds $TimeoutSeconds
}

function Start-PrivatePacmanFixtureJob {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [Parameter(Mandatory)]
        [string] $Mode
    )

    $job = Start-Job `
        -Name "private-pacman-$([guid]::NewGuid().ToString('N'))" `
        -ArgumentList @(
            $modulePath,
            $Fixture.Layout,
            $Fixture.Seed,
            $Fixture.PackageRoot,
            $Fixture.PackageRelativePath,
            $Fixture.ProtectedRoot,
            $Fixture.ArgvPath,
            $Fixture.ConfigCapturePath,
            $Fixture.ReadyPath,
            $Fixture.GoPath,
            $Mode
        ) `
        -ScriptBlock {
            param(
                $ModulePath,
                $Layout,
                $Seed,
                $PackageRoot,
                $PackageRelativePath,
                $ProtectedRoot,
                $ArgvPath,
                $ConfigCapturePath,
                $ReadyPath,
                $GoPath,
                $Mode
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'
            $env:PRIVATE_PACMAN_TEST_ARGV = $ArgvPath
            $env:PRIVATE_PACMAN_TEST_CONFIG = $ConfigCapturePath
            $env:PRIVATE_PACMAN_TEST_READY = $ReadyPath
            $env:PRIVATE_PACMAN_TEST_GO = $GoPath
            $env:PRIVATE_PACMAN_TEST_MODE = $Mode
            Import-Module $ModulePath -Force
            Invoke-PrivatePacmanUpgrade `
                -Layout $Layout `
                -SeedRoot $Seed `
                -PackageRoot $PackageRoot `
                -PackagePath @($PackageRelativePath) `
                -ProtectedRoot @($ProtectedRoot) `
                -TimeoutSeconds 30
        }
    $createdJobs.Add($job)
    return $job
}

function Wait-PrivatePacmanFixtureJob {
    param(
        [Parameter(Mandatory)]
        [Management.Automation.Job] $Job,

        [Parameter(Mandatory)]
        [ValidateSet('Completed', 'Failed')]
        [string] $ExpectedState,

        [int] $TimeoutSeconds = 40
    )

    $null = Wait-Job -Job $Job -Timeout $TimeoutSeconds
    if ($Job.State -eq 'Running') {
        Stop-Job -Job $Job
        throw "Background contract invocation timed out: $($Job.Name)"
    }
    $output = @(Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue -ErrorVariable jobErrors)
    if ($Job.State.ToString() -cne $ExpectedState) {
        $errorText = @($jobErrors | ForEach-Object { $_.ToString() }) -join "`n"
        throw "Background invocation state was $($Job.State), expected $ExpectedState. $errorText"
    }
    return $output
}

$suiteRoot = Join-Path ([IO.Path]::GetTempPath()) "private-pacman-v2-$([guid]::NewGuid().ToString('N'))"
[void][IO.Directory]::CreateDirectory($suiteRoot)
$sharedBefore = Get-PrivatePacmanTreeSnapshot -Path 'C:\msys64' -AllowMissing
$sharedAfter = $null
$recorderPath = $null

try {
    $recorderPath = New-PrivatePacmanRecorder -Directory (Join-Path $suiteRoot 'recorder')

    Invoke-PrivatePacmanTestCase -Name 'contract workflow pins exact-head source actions' -Test {
        $workflowPath = Join-Path (Split-Path $PSScriptRoot -Parent) '.github\workflows\private-pacman-contract.yml'
        $workflow = [IO.File]::ReadAllText($workflowPath)
        $uses = @(
            [regex]::Matches($workflow, '(?m)^\s*uses:\s*(?<value>\S+)\s*$') |
                ForEach-Object { $_.Groups['value'].Value }
        )
        Assert-PrivatePacmanSequence @(
            'actions/checkout@11d5960a326750d5838078e36cf38b85af677262'
            'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
        ) $uses 'Contract workflow action set or pins changed.'
        foreach ($action in $uses) {
            Assert-PrivatePacmanTest `
                ($action -match '^[^@\s]+@[0-9a-f]{40}$') `
                "External action is not pinned to a full commit: $action"
        }
        Assert-PrivatePacmanTest `
            ($workflow -match "github\.event\.pull_request\.head\.repo\.full_name == github\.repository") `
            'Contract workflow does not gate pull requests to same-repository heads.'
        Assert-PrivatePacmanTest `
            ($workflow -match 'ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha \|\| github\.sha\s*\}\}') `
            'Contract workflow does not check out the exact event head.'
        Assert-PrivatePacmanTest `
            ($workflow -match '\$actual -cne \$expected') `
            'Contract workflow does not verify the checked-out commit.'
        Assert-PrivatePacmanTest `
            ($workflow -notmatch '(?i)\.pkg\.tar|gh\s+release|setup-msys2|download-artifact') `
            'Contract workflow consumes, installs, downloads, or publishes package material.'
    }

    Invoke-PrivatePacmanTestCase -Name 'repository-free argv is completely isolated' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'argv' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-PrivatePacmanFixtureEnvironment -Fixture $fixture
        try {
            $before = Get-PrivatePacmanTreeSnapshot -Path $fixture.ProtectedRoot
            $result = Invoke-PrivatePacmanFixture -Fixture $fixture
            $after = Get-PrivatePacmanTreeSnapshot -Path $fixture.ProtectedRoot

            Assert-PrivatePacmanTest $result.Success 'Successful recorder transaction was not reported as successful.'
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Protected test state changed.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Private root survived successful cleanup.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath $fixture.Layout.OwnerPath) 'External owner sentinel was not preserved.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json')) 'Result evidence was not preserved.'
            Assert-PrivatePacmanTest (-not $fixture.Layout.OwnerPath.StartsWith(
                $fixture.Layout.Root + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) 'Owner sentinel was placed inside the disposable private root.'

            $recorded = Read-PrivatePacmanRecordedArguments -Path $fixture.ArgvPath
            $expected = @(
                '--root', $fixture.Layout.Root,
                '--dbpath', $fixture.Layout.DatabasePath,
                '--cachedir', $fixture.Layout.CachePath,
                '--logfile', $fixture.Layout.LogPath,
                '--config', $fixture.Layout.ConfigPath,
                '--hookdir', $fixture.Layout.HookPath,
                '--gpgdir', $fixture.Layout.GpgPath,
                '--noconfirm',
                '--noscriptlet',
                '-U',
                '--',
                $fixture.PackagePath
            )
            Assert-PrivatePacmanSequence $expected $recorded 'Native argv did not match the closed contract.'
            foreach ($required in @(
                '--root', '--dbpath', '--cachedir', '--logfile',
                '--config', '--hookdir', '--gpgdir'
            )) {
                Assert-PrivatePacmanEqual 1 @($recorded | Where-Object { $_ -ceq $required }).Count "Isolation switch $required was not unique."
            }

            $config = [IO.File]::ReadAllText($fixture.ConfigCapturePath)
            Assert-PrivatePacmanTest ($config -match '(?m)^\[options\]$') 'Generated config lacks an options section.'
            Assert-PrivatePacmanTest ($config -notmatch '(?im)^\s*(Server|Include)\s*=') 'Generated config can reach a repository or include external config.'
            Assert-PrivatePacmanEqual 0 @([regex]::Matches($config, '(?m)^\[(?!options\])')).Count 'Generated config contains a repository section.'

            $canonicalEvidence = @($result.ProtectedBefore | Where-Object IsCanonicalSharedRoot)
            Assert-PrivatePacmanEqual 1 $canonicalEvidence.Count 'Canonical C:\msys64 evidence is missing or duplicated.'
            $canonicalAfter = @($result.ProtectedAfter | Where-Object IsCanonicalSharedRoot)
            Assert-PrivatePacmanEqual $canonicalEvidence[0].Digest $canonicalAfter[0].Digest 'Canonical C:\msys64 state changed.'
        }
        finally {
            Clear-PrivatePacmanTestEnvironment
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'traversal is rejected before state creation' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'traversal' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $null = Assert-PrivatePacmanThrows {
            New-PrivatePacmanLayout -WorkspaceRoot $fixture.Workspace -SessionId '..\escape'
        } 'SessionId|traversal'
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanUpgrade `
                -Layout $fixture.Layout `
                -SeedRoot $fixture.Seed `
                -PackageRoot $fixture.PackageRoot `
                -PackagePath @('..\escape.pkg.tar.zst') `
                -ProtectedRoot @($fixture.ProtectedRoot)
        } 'noncanonical|PackagePath'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.StateDirectory)) 'Traversal rejection created external state.'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Traversal rejection created a private root.'
    }

    Invoke-PrivatePacmanTestCase -Name 'UNC device provider and share paths are rejected' -Test {
        $paths = @(
            '\\localhost\c$\private-pacman',
            '\\?\C:\private-pacman',
            '\\.\C:\private-pacman',
            'Microsoft.PowerShell.Core\FileSystem::C:\private-pacman',
            'C:/private-pacman'
        )
        foreach ($path in $paths) {
            $null = Assert-PrivatePacmanThrows {
                New-PrivatePacmanLayout -WorkspaceRoot $path -SessionId 'test-path'
            } 'DOS drive path|UNC|device|provider|share'
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'junction workspace and seed escapes are rejected' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'junction' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $workspaceTarget = Join-Path $fixture.Base 'workspace-target'
        [void][IO.Directory]::CreateDirectory($workspaceTarget)
        $workspaceJunction = Join-Path $fixture.Base 'workspace-junction'
        $null = New-Item -ItemType Junction -Path $workspaceJunction -Target $workspaceTarget
        try {
            $null = Assert-PrivatePacmanThrows {
                New-PrivatePacmanLayout -WorkspaceRoot $workspaceJunction -SessionId 'test-junction'
            } 'reparse|junction|symbolic'
        }
        finally {
            [IO.Directory]::Delete($workspaceJunction, $false)
        }

        $outside = Join-Path $fixture.Base 'outside-seed'
        [void][IO.Directory]::CreateDirectory($outside)
        [IO.File]::WriteAllText((Join-Path $outside 'canary'), 'do-not-touch')
        $seedJunction = Join-Path $fixture.Seed 'usr\escape'
        $null = New-Item -ItemType Junction -Path $seedJunction -Target $outside
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanUpgrade `
                    -Layout $fixture.Layout `
                    -SeedRoot $fixture.Seed `
                    -PackageRoot $fixture.PackageRoot `
                    -PackagePath @($fixture.PackageRelativePath) `
                    -ProtectedRoot @($fixture.ProtectedRoot)
            } 'seed.*reparse|reparse point'
            Assert-PrivatePacmanEqual 'do-not-touch' ([IO.File]::ReadAllText((Join-Path $outside 'canary'))) 'Seed escape target was modified.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Failed seed copy left a private root.'
        }
        finally {
            if ([IO.Directory]::Exists($seedJunction)) {
                [IO.Directory]::Delete($seedJunction, $false)
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'package symbolic links are rejected' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'symlink' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $target = Join-Path $fixture.PackageRoot 'target.pkg.tar.zst'
        [IO.File]::WriteAllText($target, 'target')
        [IO.File]::Delete($fixture.PackagePath)
        $null = New-Item -ItemType SymbolicLink -Path $fixture.PackagePath -Target $target
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanUpgrade `
                    -Layout $fixture.Layout `
                    -SeedRoot $fixture.Seed `
                    -PackageRoot $fixture.PackageRoot `
                    -PackagePath @($fixture.PackageRelativePath) `
                    -ProtectedRoot @($fixture.ProtectedRoot)
            } 'reparse|symbolic|alias'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.StateDirectory)) 'Symlink rejection created external state.'
        }
        finally {
            [IO.File]::Delete($fixture.PackagePath)
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'root aliases and drive mismatches fail closed' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'aliases' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $null = Assert-PrivatePacmanThrows {
            New-PrivatePacmanLayout -WorkspaceRoot "$($fixture.Workspace)\." -SessionId 'test-alias'
        } 'noncanonical|traversal|segment'

        $forged = $fixture.Layout.PSObject.Copy()
        $forged.Root = [IO.Path]::Combine($fixture.Workspace, 'other', '..', $fixture.Layout.SessionId)
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanUpgrade `
                -Layout $forged `
                -SeedRoot $fixture.Seed `
                -PackageRoot $fixture.PackageRoot `
                -PackagePath @($fixture.PackageRelativePath) `
                -ProtectedRoot @($fixture.ProtectedRoot)
        } 'Layout property Root|canonical'

        $null = Assert-PrivatePacmanThrows {
            & $module {
                Assert-PrivatePacmanSameDrive `
                    -First 'C:\private-one' `
                    -Second 'D:\private-two' `
                    -Description 'test inputs'
            }
        } 'same fixed drive'
    }

    Invoke-PrivatePacmanTestCase -Name 'atomic root collision preserves foreign data' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'collision' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        [void][IO.Directory]::CreateDirectory($fixture.Layout.Root)
        $canary = Join-Path $fixture.Layout.Root 'foreign-canary'
        [IO.File]::WriteAllText($canary, 'foreign')
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $fixture
            } 'already exists'
            Assert-PrivatePacmanEqual 'foreign' ([IO.File]::ReadAllText($canary)) 'Foreign collision data was changed.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.StateDirectory)) 'Collision rejection created a sentinel.'
        }
        finally {
            [IO.File]::Delete($canary)
            [IO.Directory]::Delete($fixture.Layout.Root)
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'sentinel package config and root locks block races' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'locks' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $job = Start-PrivatePacmanFixtureJob -Fixture $fixture -Mode 'wait'
        try {
            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $fixture
            } 'already exists|sentinel'
            $null = Assert-PrivatePacmanThrows {
                [IO.File]::WriteAllText($fixture.PackagePath, 'race')
            } 'used by another process|access|sharing'
            $null = Assert-PrivatePacmanThrows {
                [IO.File]::WriteAllText($fixture.Layout.ConfigPath, 'race')
            } 'used by another process|access|sharing'
            $movedRoot = "$($fixture.Layout.Root)-moved"
            $null = Assert-PrivatePacmanThrows {
                [IO.Directory]::Move($fixture.Layout.Root, $movedRoot)
            } 'used by another process|access|denied'

            [IO.File]::WriteAllText($fixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Completed
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Locked transaction root survived cleanup.'
        }
        finally {
            if (-not [IO.File]::Exists($fixture.GoPath)) {
                [IO.File]::WriteAllText($fixture.GoPath, 'go')
            }
            if ($job.State -eq 'Running') {
                $null = Wait-Job -Job $job -Timeout 10
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'transient protected-state races invalidate evidence' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'drift' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $original = [IO.File]::ReadAllBytes($fixture.SharedFile)
        $job = Start-PrivatePacmanFixtureJob -Fixture $fixture -Mode 'wait'
        try {
            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            [IO.File]::WriteAllText($fixture.SharedFile, 'transient-drift')
            [IO.File]::WriteAllBytes($fixture.SharedFile, $original)
            [Threading.Thread]::Sleep(150)
            [IO.File]::WriteAllText($fixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Failed

            $resultPath = Join-Path $fixture.Layout.EvidenceDirectory 'result.json'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath $resultPath) 'Drift failure did not preserve result evidence.'
            $evidence = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
            Assert-PrivatePacmanTest (-not $evidence.Success) 'Transient drift was reported as success.'
            $before = @($evidence.ProtectedBefore | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            $after = @($evidence.ProtectedAfter | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Transient drift test did not restore byte identity.'
            $changeCount = @($evidence.Watchers | ForEach-Object { $_.Changes }).Count
            Assert-PrivatePacmanTest ($changeCount -gt 0) 'Transient drift emitted no watcher evidence.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Drift failure left a private root.'
        }
        finally {
            if (-not [IO.File]::Exists($fixture.GoPath)) {
                [IO.File]::WriteAllText($fixture.GoPath, 'go')
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'changes during the monitored before snapshot remain fatal' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'before-snapshot-drift' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $bulk = Join-Path $fixture.ProtectedRoot 'bulk'
        [void][IO.Directory]::CreateDirectory($bulk)
        $bytes = [byte[]]::new(262144)
        for ($index = 0; $index -lt 256; $index++) {
            $bytes[0] = [byte]($index % 251)
            [IO.File]::WriteAllBytes((Join-Path $bulk ("file-{0:D4}.bin" -f $index)), $bytes)
        }

        $original = [IO.File]::ReadAllBytes($fixture.SharedFile)
        $job = Start-PrivatePacmanFixtureJob -Fixture $fixture -Mode 'wait'
        try {
            $firstManifest = Join-Path $fixture.Layout.EvidenceDirectory 'protected-0-before.json'
            $protectedManifest = Join-Path $fixture.Layout.EvidenceDirectory 'protected-1-before.json'
            Wait-PrivatePacmanPath -Path $firstManifest
            Assert-PrivatePacmanTest `
                (-not [IO.File]::Exists($protectedManifest)) `
                'Protected before snapshot completed before the injected race.'
            for ($index = 0; $index -lt 3; $index++) {
                [IO.File]::WriteAllText($fixture.SharedFile, "before-snapshot-drift-$index")
                [IO.File]::WriteAllBytes($fixture.SharedFile, $original)
                [Threading.Thread]::Sleep(10)
            }

            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            [IO.File]::WriteAllText($fixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Failed

            $evidence = Get-Content `
                -Raw `
                -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json') |
                    ConvertFrom-Json
            Assert-PrivatePacmanTest ($null -ne $evidence.Invocation.Process) 'Before-snapshot drift prevented the recorder from exercising the monitored boundary.'
            $before = @($evidence.ProtectedBefore | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            $after = @($evidence.ProtectedAfter | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Before-snapshot drift test did not restore byte identity.'
            $raceEvents = @(
                $evidence.Watchers |
                    Where-Object Path -EQ $fixture.ProtectedRoot |
                    ForEach-Object { $_.Changes } |
                    Where-Object Path -EQ $fixture.SharedFile
            )
            Assert-PrivatePacmanTest ($raceEvents.Count -gt 0) 'No injected protected-state event survived the monitored before snapshot.'
            Assert-PrivatePacmanTest (-not $evidence.Success) 'Before-snapshot drift was reported as success.'
        }
        finally {
            [IO.File]::WriteAllBytes($fixture.SharedFile, $original)
            if (-not [IO.File]::Exists($fixture.GoPath)) {
                [IO.File]::WriteAllText($fixture.GoPath, 'go')
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'child crashes fail closed and clean up' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'child-crash' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-PrivatePacmanFixtureEnvironment -Fixture $fixture -Mode 'crash'
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $fixture
            } 'exited with code|failed closed'
            $resultPath = Join-Path $fixture.Layout.EvidenceDirectory 'result.json'
            $evidence = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
            Assert-PrivatePacmanTest (-not $evidence.Success) 'Child crash was reported as success.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath $fixture.ArgvPath) 'Child crash test never crossed the native process boundary.'
            Assert-PrivatePacmanTest ($null -ne $evidence.Invocation.Process) 'Child crash produced no process evidence.'
            Assert-PrivatePacmanTest ($evidence.Invocation.Process.ExitCode -ne 0) 'Child crash did not produce a failing native exit code.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Child crash left a private root.'
            Assert-PrivatePacmanTest $evidence.Cleanup.RootAbsent 'Crash evidence does not prove root cleanup.'
        }
        finally {
            Clear-PrivatePacmanTestEnvironment
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'timeouts kill the child and clean up' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'timeout' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-PrivatePacmanFixtureEnvironment -Fixture $fixture -Mode 'timeout'
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $fixture -TimeoutSeconds 1
            } 'timed out|failed closed'
            $evidence = Get-Content -Raw -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json') | ConvertFrom-Json
            Assert-PrivatePacmanTest `
                ($null -ne $evidence.Invocation.Process) `
                "Timeout produced no process evidence: $($evidence.Failures -join '; ')"
            Assert-PrivatePacmanTest $evidence.Invocation.Process.TimedOut 'Timeout evidence did not record the process kill.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Timed-out child left a private root.'
        }
        finally {
            Clear-PrivatePacmanTestEnvironment
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'cleanup never follows junctions or file symlinks' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'cleanup-links' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $outsideDirectory = Join-Path $fixture.Base 'outside-cleanup'
        [void][IO.Directory]::CreateDirectory($outsideDirectory)
        $outsideFile = Join-Path $outsideDirectory 'canary'
        [IO.File]::WriteAllText($outsideFile, 'preserve-me')

        $job = Start-PrivatePacmanFixtureJob -Fixture $fixture -Mode 'wait'
        try {
            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            $null = New-Item `
                -ItemType Junction `
                -Path (Join-Path $fixture.Layout.Root 'directory-link') `
                -Target $outsideDirectory
            $null = New-Item `
                -ItemType SymbolicLink `
                -Path (Join-Path $fixture.Layout.Root 'file-link') `
                -Target $outsideFile
            [IO.File]::WriteAllText($fixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Completed
            Assert-PrivatePacmanEqual 'preserve-me' ([IO.File]::ReadAllText($outsideFile)) 'Cleanup followed a reparse target.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Link cleanup left the private root.'
        }
        finally {
            if (-not [IO.File]::Exists($fixture.GoPath)) {
                [IO.File]::WriteAllText($fixture.GoPath, 'go')
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'parent-process crashes leave recoverable owned state' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'parent-crash' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $wrapperPath = Join-Path $fixture.Base 'invoke-wrapper.ps1'
        $wrapper = @'
param(
    [string] $ModulePath,
    [string] $Workspace,
    [string] $SessionId,
    [string] $Seed,
    [string] $PackageRoot,
    [string] $PackageRelativePath,
    [string] $ProtectedRoot
)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$layout = New-PrivatePacmanLayout -WorkspaceRoot $Workspace -SessionId $SessionId
Invoke-PrivatePacmanUpgrade `
    -Layout $layout `
    -SeedRoot $Seed `
    -PackageRoot $PackageRoot `
    -PackagePath @($PackageRelativePath) `
    -ProtectedRoot @($ProtectedRoot) `
    -TimeoutSeconds 120
'@
        [IO.File]::WriteAllText($wrapperPath, $wrapper, [Text.UTF8Encoding]::new($false))

        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = (Get-Process -Id $PID).Path
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $wrapperPath,
            '-ModulePath', $modulePath,
            '-Workspace', $fixture.Workspace,
            '-SessionId', $fixture.Layout.SessionId,
            '-Seed', $fixture.Seed,
            '-PackageRoot', $fixture.PackageRoot,
            '-PackageRelativePath', $fixture.PackageRelativePath,
            '-ProtectedRoot', $fixture.ProtectedRoot
        )) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
        $startInfo.Environment['PRIVATE_PACMAN_TEST_ARGV'] = $fixture.ArgvPath
        $startInfo.Environment['PRIVATE_PACMAN_TEST_CONFIG'] = $fixture.ConfigCapturePath
        $startInfo.Environment['PRIVATE_PACMAN_TEST_MODE'] = 'wait'
        $startInfo.Environment['PRIVATE_PACMAN_TEST_READY'] = $fixture.ReadyPath
        $startInfo.Environment['PRIVATE_PACMAN_TEST_GO'] = $fixture.GoPath

        $parent = [Diagnostics.Process]::new()
        $parent.StartInfo = $startInfo
        [void]$parent.Start()
        $createdProcesses.Add($parent)
        try {
            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            $childProcessId = [int][IO.File]::ReadAllText($fixture.ReadyPath)
            Stop-Process -Id $parent.Id -Force
            $parent.WaitForExit()
            [IO.File]::WriteAllText($fixture.GoPath, 'go')

            $deadline = [DateTime]::UtcNow.AddSeconds(20)
            while ($null -ne (Get-Process -Id $childProcessId -ErrorAction SilentlyContinue)) {
                if ([DateTime]::UtcNow -ge $deadline) {
                    Stop-Process -Id $childProcessId -Force
                    throw 'Orphaned argv recorder did not exit after its release signal.'
                }
                [Threading.Thread]::Sleep(50)
            }

            Assert-PrivatePacmanTest (Test-Path -LiteralPath $fixture.Layout.Root) 'Parent crash unexpectedly ran normal cleanup.'
            $foreignRecoveryRoot = Join-Path $fixture.Base 'foreign-recovery-root'
            [void][IO.Directory]::CreateDirectory($foreignRecoveryRoot)
            $foreignCanary = Join-Path $foreignRecoveryRoot 'canary'
            [IO.File]::WriteAllText($foreignCanary, 'foreign-recovery-data')
            $sentinel = Get-Content -Raw -LiteralPath $fixture.Layout.OwnerPath | ConvertFrom-Json
            $expectedStagingRoot = [string]$sentinel.StagingRoot
            $sentinel.StagingRoot = $foreignRecoveryRoot
            [IO.File]::WriteAllText(
                $fixture.Layout.OwnerPath,
                ($sentinel | ConvertTo-Json -Depth 10),
                [Text.UTF8Encoding]::new($false)
            )
            $null = Assert-PrivatePacmanThrows {
                Remove-PrivatePacmanSession -Layout $fixture.Layout -Confirm:$false
            } 'noncanonical staging root'
            Assert-PrivatePacmanEqual 'foreign-recovery-data' ([IO.File]::ReadAllText($foreignCanary)) 'Recovery touched an unowned path from a tampered sentinel.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath $fixture.Layout.Root) 'Rejected recovery removed the owned root.'

            $sentinel.StagingRoot = $expectedStagingRoot
            [IO.File]::WriteAllText(
                $fixture.Layout.OwnerPath,
                ($sentinel | ConvertTo-Json -Depth 10),
                [Text.UTF8Encoding]::new($false)
            )
            $recovery = Remove-PrivatePacmanSession -Layout $fixture.Layout -Confirm:$false
            Assert-PrivatePacmanEqual 'cleaned-fail-closed' $recovery.Result 'Crash recovery did not remain fail closed.'
            Assert-PrivatePacmanTest (-not $recovery.WatcherContinuity) 'Crash recovery incorrectly claimed watcher continuity.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Crash recovery left the owned private root.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'recovery.json')) 'Crash recovery evidence is missing.'
        }
        finally {
            if (-not $parent.HasExited) {
                Stop-Process -Id $parent.Id -Force
                $parent.WaitForExit()
            }
        }
    }
}
finally {
    Clear-PrivatePacmanTestEnvironment
    foreach ($job in $createdJobs) {
        if ($job.State -eq 'Running') {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    foreach ($process in $createdProcesses) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $process.Dispose()
    }

    if ([IO.Directory]::Exists($suiteRoot)) {
        Remove-Item -LiteralPath $suiteRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    $sharedAfter = Get-PrivatePacmanTreeSnapshot -Path 'C:\msys64' -AllowMissing
}

$sharedIdentical = (
    $sharedBefore.Exists -eq $sharedAfter.Exists -and
    $sharedBefore.Digest -ceq $sharedAfter.Digest
)
if (-not $sharedIdentical) {
    $results.Add([pscustomobject][ordered]@{
        Name = 'canonical C:\msys64 is byte-identical before and after the suite'
        Passed = $false
        DurationMilliseconds = 0
        Error = 'Canonical shared package state changed during the contract suite.'
    })
}
else {
    $results.Add([pscustomobject][ordered]@{
        Name = 'canonical C:\msys64 is byte-identical before and after the suite'
        Passed = $true
        DurationMilliseconds = 0
        Error = $null
    })
    Write-Host 'PASS canonical C:\msys64 is byte-identical before and after the suite'
}

$failed = @($results | Where-Object { -not $_.Passed })
$report = [pscustomobject][ordered]@{
    Schema = 'private-pacman-contract-tests/v2'
    StartedFrom = $PSScriptRoot
    PowerShell = $PSVersionTable.PSVersion.ToString()
    CanonicalSharedState = [pscustomobject][ordered]@{
        Path = 'C:\msys64'
        ExistedBefore = $sharedBefore.Exists
        ExistedAfter = $sharedAfter.Exists
        BeforeDigest = $sharedBefore.Digest
        AfterDigest = $sharedAfter.Digest
        ByteIdentical = $sharedIdentical
    }
    Passed = $results.Count - $failed.Count
    Failed = $failed.Count
    Tests = @($results)
}

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $reportDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ReportPath))
    [void][IO.Directory]::CreateDirectory($reportDirectory)
    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($ReportPath),
        ($report | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
}

Write-Host "$($report.Passed) passed, $($report.Failed) failed"
if ($failed.Count -ne 0) {
    throw "$($failed.Count) private pacman contract test(s) failed."
}

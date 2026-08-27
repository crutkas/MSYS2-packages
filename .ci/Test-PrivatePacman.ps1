[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'PrivatePacman.psm1') -Force

$script:Passed = 0
$script:Failed = 0

function Assert-True {
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

function Assert-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock] $Action,

        [Parameter(Mandatory)]
        [string] $Pattern
    )

    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "Expected error matching '$Pattern', got '$($_.Exception.Message)'."
        }
        return
    }
    throw "Expected error matching '$Pattern', but no error was thrown."
}

function Invoke-Test {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [scriptblock] $Test
    )

    try {
        & $Test
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$testRoot = Join-Path $env:TEMP "private-pacman-tests-$([guid]::NewGuid().ToString('N'))"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$sharedRoot = Join-Path $testRoot 'shared'
$recorderProject = Join-Path $testRoot 'PacmanArgvRecorder'
$fakePacman = Join-Path $recorderProject 'bin\Release\net8.0\PacmanArgvRecorder.exe'
$packageRoot = Join-Path $testRoot 'packages'

try {
    New-Item -ItemType Directory -Path (Join-Path $sharedRoot 'var\log') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $sharedRoot 'var\lib\pacman\local\base-1') -Force | Out-Null
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sharedRoot 'var\log\pacman.log') -Value 'baseline'
    Set-Content -LiteralPath (Join-Path $sharedRoot 'var\lib\pacman\local\base-1\desc') -Value 'base'
    Set-Content -LiteralPath (Join-Path $packageRoot 'sample.pkg.tar.zst') -Value 'not a real package'

    New-Item -ItemType Directory -Path $recorderProject | Out-Null
    @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $recorderProject 'PacmanArgvRecorder.csproj') -Encoding utf8
    @'
using System;
using System.IO;

public static class PacmanArgvRecorder
{
    public static int Main(string[] args)
    {
        File.WriteAllLines(Environment.GetEnvironmentVariable("PACMAN_ARG_RECORD"), args);

        string stdin = Console.In.ReadToEnd();
        string stdinRecord = Environment.GetEnvironmentVariable("PACMAN_STDIN_RECORD");
        if (!String.IsNullOrEmpty(stdinRecord))
        {
            File.WriteAllText(stdinRecord, stdin.Length.ToString());
        }

        string environmentRecord = Environment.GetEnvironmentVariable("PACMAN_ENV_RECORD");
        if (!String.IsNullOrEmpty(environmentRecord))
        {
            File.WriteAllLines(environmentRecord, new[] {
                "POSIXLY_CORRECT=" + (Environment.GetEnvironmentVariable("POSIXLY_CORRECT") ?? "<absent>"),
                "MSYS=" + (Environment.GetEnvironmentVariable("MSYS") ?? "<absent>")
            });
        }

        TryMutation(
            Environment.GetEnvironmentVariable("PACMAN_MUTATE_CONFIG"),
            Environment.GetEnvironmentVariable("PACMAN_CONFIG_LOCK_RECORD"));
        TryMutation(
            Environment.GetEnvironmentVariable("PACMAN_MUTATE_PACKAGE"),
            Environment.GetEnvironmentVariable("PACMAN_PACKAGE_LOCK_RECORD"));
        TryDirectoryRename(
            Environment.GetEnvironmentVariable("PACMAN_RENAME_DIRECTORY"),
            Environment.GetEnvironmentVariable("PACMAN_DIRECTORY_LOCK_RECORD"));
        TryDirectoryWrite(
            Environment.GetEnvironmentVariable("PACMAN_WRITE_DIRECTORY"),
            Environment.GetEnvironmentVariable("PACMAN_DIRECTORY_WRITE_RECORD"));

        string driftLog = Environment.GetEnvironmentVariable("PACMAN_DRIFT_LOG");
        if (!String.IsNullOrEmpty(driftLog))
        {
            File.AppendAllText(driftLog, "drift" + Environment.NewLine);
        }

        return Int32.Parse(Environment.GetEnvironmentVariable("PACMAN_EXIT_CODE") ?? "0");
    }

    private static void TryMutation(string path, string record)
    {
        if (String.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            File.AppendAllText(path, "unexpected mutation");
            File.WriteAllText(record, "unlocked");
        }
        catch (IOException)
        {
            File.WriteAllText(record, "locked");
        }
        catch (UnauthorizedAccessException)
        {
            File.WriteAllText(record, "locked");
        }
    }

    private static void TryDirectoryRename(string path, string record)
    {
        if (String.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            Directory.Move(path, path + "-moved");
            File.WriteAllText(record, "unlocked");
        }
        catch (IOException)
        {
            File.WriteAllText(record, "locked");
        }
        catch (UnauthorizedAccessException)
        {
            File.WriteAllText(record, "locked");
        }
    }

    private static void TryDirectoryWrite(string path, string record)
    {
        if (String.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            File.WriteAllText(Path.Combine(path, "recorder-write"), "private");
            File.WriteAllText(record, "written");
        }
        catch (Exception error)
        {
            File.WriteAllText(record, error.GetType().Name);
        }
    }
}
'@ | Set-Content -LiteralPath (Join-Path $recorderProject 'Program.cs') -Encoding utf8
    & dotnet build $recorderProject -c Release --nologo --verbosity quiet
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $fakePacman -PathType Leaf)) {
        throw 'Unable to compile native pacman argv recorder.'
    }

    function New-TestContext {
        param(
            [Parameter(Mandatory)]
            [string] $Name,

            [hashtable] $Override = @{}
        )

        $root = Join-Path $testRoot $Name
        $parameters = @{
            Root = $root
            DbPath = Join-Path $root 'var\lib\pacman'
            CacheDir = Join-Path $root 'var\cache\pacman\pkg'
            LogFile = Join-Path $root 'var\log\pacman.log'
            ConfigFile = Join-Path $root 'etc\pacman.conf'
            HookDir = Join-Path $root 'etc\pacman.d\hooks'
            GpgDir = Join-Path $root 'etc\pacman.d\gnupg'
            EvidenceDir = Join-Path $root 'evidence'
            PacmanPath = $fakePacman
            RepositoryRoot = $repositoryRoot
            SessionId = "session-$Name"
            SharedRoot = $sharedRoot
        }
        foreach ($key in $Override.Keys) {
            $parameters[$key] = $Override[$key]
        }
        if (-not $Override.ContainsKey('PacmanPath')) {
            $parameters.PacmanPath = Join-Path $parameters.Root 'usr\bin\PacmanArgvRecorder.exe'
        }
        $context = New-PrivatePacmanContext @parameters
        if (-not $Override.ContainsKey('PacmanPath')) {
            Get-ChildItem -LiteralPath (Split-Path -Parent $fakePacman) -File |
                Copy-Item -Destination (Split-Path -Parent $context.PacmanPath)
        }
        return $context
    }

    Invoke-Test 'omitted isolation argument is rejected' {
        $root = Join-Path $testRoot 'omitted'
        Assert-Throws -Pattern 'HookDir' -Action {
            New-PrivatePacmanContext `
                -Root $root `
                -DbPath (Join-Path $root 'db') `
                -CacheDir (Join-Path $root 'cache') `
                -LogFile (Join-Path $root 'pacman.log') `
                -ConfigFile (Join-Path $root 'pacman.conf') `
                -EvidenceDir (Join-Path $root 'evidence') `
                -PacmanPath $fakePacman `
                -RepositoryRoot $repositoryRoot `
                -SessionId 'omitted' `
                -SharedRoot $sharedRoot
        }
    }

    Invoke-Test 'shared root is rejected' {
        Assert-Throws -Pattern 'shared MSYS2 root' -Action {
            New-TestContext -Name 'shared-root' -Override @{
                Root = $sharedRoot
                DbPath = Join-Path $sharedRoot 'db'
                CacheDir = Join-Path $sharedRoot 'cache'
                LogFile = Join-Path $sharedRoot 'log'
                ConfigFile = Join-Path $sharedRoot 'config'
                HookDir = Join-Path $sharedRoot 'hooks'
                GpgDir = Join-Path $sharedRoot 'gpg'
                EvidenceDir = Join-Path $sharedRoot 'evidence'
            }
        }
    }

    Invoke-Test 'shared root prefix is not treated as shared' {
        $prefixRoot = "$sharedRoot-other"
        $context = New-TestContext -Name 'prefix' -Override @{
            Root = $prefixRoot
            DbPath = Join-Path $prefixRoot 'db'
            CacheDir = Join-Path $prefixRoot 'cache'
            LogFile = Join-Path $prefixRoot 'log\pacman.log'
            ConfigFile = Join-Path $prefixRoot 'etc\pacman.conf'
            HookDir = Join-Path $prefixRoot 'hooks'
            GpgDir = Join-Path $prefixRoot 'gpg'
            EvidenceDir = Join-Path $prefixRoot 'evidence'
        }
        Assert-True ($context.Root -eq $prefixRoot) 'Prefix-bypass-safe path was unexpectedly rewritten.'
    }

    Invoke-Test 'isolation paths must all remain under root' {
        foreach ($property in @(
                'DbPath',
                'CacheDir',
                'LogFile',
                'ConfigFile',
                'HookDir',
                'GpgDir',
                'EvidenceDir'
            )) {
            $outside = Join-Path $testRoot "outside-$property"
            Assert-Throws -Pattern 'must resolve inside private root' -Action {
                New-TestContext -Name "outside-root-$property" -Override @{ $property = $outside }
            }
        }
    }

    Invoke-Test 'junction escape to shared root is rejected' {
        $junction = Join-Path $testRoot 'shared-junction'
        New-Item -ItemType Junction -Path $junction -Target $sharedRoot | Out-Null
        Assert-Throws -Pattern 'Trusted private-root parent|shared MSYS2 root' -Action {
            New-TestContext -Name 'junction' -Override @{
                Root = Join-Path $junction 'private'
                DbPath = Join-Path $junction 'private\db'
                CacheDir = Join-Path $junction 'private\cache'
                LogFile = Join-Path $junction 'private\log\pacman.log'
                ConfigFile = Join-Path $junction 'private\etc\pacman.conf'
                HookDir = Join-Path $junction 'private\hooks'
                GpgDir = Join-Path $junction 'private\gpg'
                EvidenceDir = Join-Path $junction 'private\evidence'
            }
        }
        Remove-Item -LiteralPath $junction -Force
    }

    Invoke-Test 'case alias of shared root is rejected' {
        $caseRoot = $sharedRoot.ToUpperInvariant() + '\private'
        Assert-Throws -Pattern 'shared MSYS2 root' -Action {
            New-TestContext -Name 'case-alias' -Override @{
                Root = $caseRoot
                DbPath = Join-Path $caseRoot 'db'
                CacheDir = Join-Path $caseRoot 'cache'
                LogFile = Join-Path $caseRoot 'log\pacman.log'
                ConfigFile = Join-Path $caseRoot 'etc\pacman.conf'
                HookDir = Join-Path $caseRoot 'hooks'
                GpgDir = Join-Path $caseRoot 'gpg'
                EvidenceDir = Join-Path $caseRoot 'evidence'
            }
        }
    }

    Invoke-Test 'UNC private root is rejected before resolution' {
        $uncRoot = '\\localhost\c$\msys64\private'
        Assert-Throws -Pattern 'local drive path' -Action {
            New-TestContext -Name 'unc' -Override @{
                Root = $uncRoot
                DbPath = Join-Path $uncRoot 'db'
                CacheDir = Join-Path $uncRoot 'cache'
                LogFile = Join-Path $uncRoot 'log\pacman.log'
                ConfigFile = Join-Path $uncRoot 'etc\pacman.conf'
                HookDir = Join-Path $uncRoot 'hooks'
                GpgDir = Join-Path $uncRoot 'gpg'
                EvidenceDir = Join-Path $uncRoot 'evidence'
            }
        }
    }

    Invoke-Test 'reparse ancestor for fresh root is rejected' {
        $realParent = Join-Path $testRoot 'real-parent'
        $linkedParent = Join-Path $testRoot 'linked-parent'
        New-Item -ItemType Directory -Path $realParent | Out-Null
        New-Item -ItemType Junction -Path $linkedParent -Target $realParent | Out-Null
        $linkedRoot = Join-Path $linkedParent 'private'
        Assert-Throws -Pattern 'Trusted private-root parent' -Action {
            New-TestContext -Name 'linked-parent-test' -Override @{
                Root = $linkedRoot
                DbPath = Join-Path $linkedRoot 'db'
                CacheDir = Join-Path $linkedRoot 'cache'
                LogFile = Join-Path $linkedRoot 'log\pacman.log'
                ConfigFile = Join-Path $linkedRoot 'etc\pacman.conf'
                HookDir = Join-Path $linkedRoot 'hooks'
                GpgDir = Join-Path $linkedRoot 'gpg'
                EvidenceDir = Join-Path $linkedRoot 'evidence'
            }
        }
        Remove-Item -LiteralPath $linkedParent -Force
    }

    Invoke-Test 'device namespace path is rejected' {
        $deviceRoot = '\\?\' + $sharedRoot + '\private'
        Assert-Throws -Pattern 'device namespace' -Action {
            New-TestContext -Name 'device' -Override @{
                Root = $deviceRoot
                DbPath = Join-Path $deviceRoot 'db'
                CacheDir = Join-Path $deviceRoot 'cache'
                LogFile = Join-Path $deviceRoot 'log\pacman.log'
                ConfigFile = Join-Path $deviceRoot 'etc\pacman.conf'
                HookDir = Join-Path $deviceRoot 'hooks'
                GpgDir = Join-Path $deviceRoot 'gpg'
                EvidenceDir = Join-Path $deviceRoot 'evidence'
            }
        }
    }

    Invoke-Test 'read-only query receives complete isolation arguments' {
        $context = New-TestContext -Name 'query'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'query.args'
        $env:PACMAN_EXIT_CODE = '0'
        $result = Invoke-PrivatePacman -Context $context -ArgumentList @('-Q', 'base')
        $arguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        Assert-True ($result.OperationKind.ToString() -eq 'ReadOnly') 'Query was not classified read-only.'
        foreach ($required in @(
                '--root',
                '--dbpath',
                '--cachedir',
                '--logfile',
                '--config',
                '--hookdir',
                '--gpgdir'
            )) {
            Assert-True ($required -in $arguments) "Missing required argument '$required'."
        }
        Assert-True ('--noscriptlet' -notin $arguments) `
            'Query received a transaction-only --noscriptlet option.'
    }

    Invoke-Test 'native argv preserves spaces and closes stdin' {
        $context = New-TestContext -Name 'native-argv'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'native-argv.args'
        $env:PACMAN_STDIN_RECORD = Join-Path $testRoot 'native-argv.stdin'
        $env:PACMAN_ENV_RECORD = Join-Path $testRoot 'native-argv.env'
        $env:PACMAN_EXIT_CODE = '0'
        $env:POSIXLY_CORRECT = '1'
        Invoke-PrivatePacman -Context $context -ArgumentList @('-Q', 'package with spaces') | Out-Null
        $arguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        $environment = Get-Content -LiteralPath $env:PACMAN_ENV_RECORD
        Assert-True ('package with spaces' -in $arguments) 'Native argv split an argument containing spaces.'
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_STDIN_RECORD -Raw) -eq '0') `
            'Child standard input was not closed.'
        Assert-True ('POSIXLY_CORRECT=<absent>' -in $environment) `
            'POSIXLY_CORRECT leaked into the child process.'
        Assert-True ('MSYS=winsymlinks:nativestrict' -in $environment) `
            'Child MSYS setting was not controlled.'
        Remove-Item Env:POSIXLY_CORRECT
        Remove-Item Env:PACMAN_STDIN_RECORD
        Remove-Item Env:PACMAN_ENV_RECORD
    }

    Invoke-Test 'isolation paths with spaces remain single native arguments' {
        $spacedRoot = Join-Path $testRoot 'private root with spaces'
        $context = New-TestContext -Name 'spaced-root' -Override @{
            Root = $spacedRoot
            DbPath = Join-Path $spacedRoot 'database path'
            CacheDir = Join-Path $spacedRoot 'cache path'
            LogFile = Join-Path $spacedRoot 'log path\pacman.log'
            ConfigFile = Join-Path $spacedRoot 'config path\pacman.conf'
            HookDir = Join-Path $spacedRoot 'hooks path'
            GpgDir = Join-Path $spacedRoot 'gpg path'
            EvidenceDir = Join-Path $spacedRoot 'evidence path'
        }
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'spaced-root.args'
        $env:PACMAN_EXIT_CODE = '0'
        Invoke-PrivatePacman -Context $context -ArgumentList @('-Q') | Out-Null
        $arguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        foreach ($path in @(
                $context.Root,
                $context.DbPath,
                $context.CacheDir,
                $context.LogFile,
                $context.ConfigFile,
                $context.HookDir,
                $context.GpgDir
            )) {
            Assert-True ($path -in $arguments) "Isolation path was split in native argv: '$path'."
        }
        $unsafeConfig = Get-Content -LiteralPath $context.ConfigFile |
            Where-Object { $_ -match '^\s*(Include|RootDir|DBPath|CacheDir|LogFile|HookDir|GPGDir)\s*=' }
        Assert-True ($null -eq $unsafeConfig) 'Generated config contains a destination or Include directive.'
    }

    Invoke-Test 'ambiguous later help token remains mutating' {
        $kind = Get-PacmanOperationKind -ArgumentList @('-S', '--logfile', '--help', 'example')
        Assert-True ($kind.ToString() -eq 'Mutating') 'A later option value bypassed mutating classification.'
    }

    Invoke-Test 'operation selector must be exact and first' {
        foreach ($arguments in @(
                @('--noconfirm', '-S', 'example'),
                @('--upg', 'example.pkg.tar.zst'),
                @('-S', '--query', 'example')
            )) {
            $context = New-TestContext -Name "command-shape-$([guid]::NewGuid().ToString('N'))"
            $env:PACMAN_ARG_RECORD = Join-Path $testRoot "$([guid]::NewGuid()).args"
            $env:PACMAN_EXIT_CODE = '0'
            Assert-Throws -Pattern 'operation selector|First argument' -Action {
                Invoke-PrivatePacman -Context $context -ArgumentList $arguments
            }
            Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
                "Fake pacman ran for invalid command shape '$($arguments -join ' ')'."
        }
    }

    Invoke-Test 'pacman short options are parsed case-sensitively' {
        $queryContext = New-TestContext -Name 'case-sensitive-query'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'case-sensitive-query.args'
        $env:PACMAN_EXIT_CODE = '0'
        $queryResult = Invoke-PrivatePacman -Context $queryContext -ArgumentList @('-Qs', 'example')
        $queryArguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        Assert-True ($queryResult.OperationKind.ToString() -eq 'ReadOnly') '-Qs was not read-only.'
        Assert-True ('--noscriptlet' -notin $queryArguments) '-Qs received transaction options.'

        $syncContext = New-TestContext -Name 'case-sensitive-sync'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'case-sensitive-sync.args'
        $syncResult = Invoke-PrivatePacman -Context $syncContext -ArgumentList @('-Syu')
        $syncArguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        Assert-True ($syncResult.OperationKind.ToString() -eq 'Mutating') '-Syu was not mutating.'
        Assert-True ('--noscriptlet' -in $syncArguments) '-Syu did not disable scriptlets.'
    }

    Invoke-Test 'caller isolation overrides are rejected before invocation' {
        $context = New-TestContext -Name 'override'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'override.args'
        $env:PACMAN_EXIT_CODE = '0'
        foreach ($override in @(
                '--root=C:\msys64',
                '--roo=C:\msys64',
                '--dbpath',
                '--dbp=C:\msys64\var\lib\pacman',
                '--cachedir=C:\msys64\cache',
                '--cache=C:\msys64\cache',
                '--logfile',
                '--log=C:\msys64\var\log\pacman.log',
                '--config=C:\msys64\etc\pacman.conf',
                '--conf=C:\msys64\etc\pacman.conf',
                '--hookdir',
                '--hook=C:\msys64\etc\pacman.d\hooks',
                '--gpgdir=C:\msys64\etc\pacman.d\gnupg',
                '--gpg=C:\msys64\etc\pacman.d\gnupg',
                '--sysroot=C:\msys64',
                '--sysr=C:\msys64',
                '-rC:\msys64',
                '-bC:\msys64\var\lib\pacman'
            )) {
            Assert-Throws -Pattern 'cannot override pacman isolation' -Action {
                Invoke-PrivatePacman -Context $context -ArgumentList @('-S', $override, 'example')
            }
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman was invoked for an isolation override.'
    }

    Invoke-Test 'download-only sync remains isolated and mutating' {
        $context = New-TestContext -Name 'download-only'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'download-only.args'
        $env:PACMAN_EXIT_CODE = '0'
        $result = Invoke-PrivatePacman -Context $context -ArgumentList @('-Sw', 'example')
        $evidence = Get-Content -LiteralPath $result.EvidenceFile -Raw | ConvertFrom-Json
        Assert-True ($result.OperationKind.ToString() -eq 'Mutating') '-Sw was not classified mutating.'
        Assert-True ($null -ne $evidence.sharedStateBefore) '-Sw did not capture shared state.'
        Assert-True ($null -ne $evidence.sharedStateAfter) '-Sw did not compare shared state.'
        Assert-True ($null -ne $evidence.sharedStateBefore.protectedRoot) `
            '-Sw did not fingerprint the complete shared root.'
        $arguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        Assert-True ('--noscriptlet' -in $arguments) '-Sw did not disable scriptlets.'
        Assert-True (
            [array]::IndexOf($arguments, '--root') -lt [array]::IndexOf($arguments, '-Sw')
        ) 'Isolation options did not precede the -Sw operation.'
    }

    Invoke-Test 'mutating operation rejects a shared bootstrap client' {
        $context = New-TestContext -Name 'external-pacman' -Override @{
            PacmanPath = $fakePacman
        }
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'external-pacman.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'PacmanPath itself' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-Sw', 'example')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'External pacman client ran for a mutating operation.'
    }

    Invoke-Test 'sync clean keeps isolation options before operation' {
        $context = New-TestContext -Name 'sync-clean'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'sync-clean.args'
        $env:PACMAN_EXIT_CODE = '0'
        Invoke-PrivatePacman -Context $context -ArgumentList @('-Sc', '--noconfirm') | Out-Null
        $arguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        Assert-True (
            [array]::IndexOf($arguments, '--root') -lt [array]::IndexOf($arguments, '-Sc')
        ) 'Isolation options did not precede the -Sc operation.'
    }

    Invoke-Test 'uppercase remove operation is not a root override' {
        $context = New-TestContext -Name 'remove-operation'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'remove-operation.args'
        $env:PACMAN_EXIT_CODE = '0'
        $result = Invoke-PrivatePacman -Context $context -ArgumentList @('-R', 'example')
        $arguments = Get-Content -LiteralPath $env:PACMAN_ARG_RECORD
        Assert-True ($result.OperationKind.ToString() -eq 'Mutating') '-R was not mutating.'
        Assert-True ('--noscriptlet' -in $arguments) '-R did not disable scriptlets.'
    }

    Invoke-Test 'fully isolated mutation succeeds with sentinel' {
        $context = New-TestContext -Name 'mutation'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'mutation.args'
        $env:PACMAN_EXIT_CODE = '0'
        $package = Join-Path $packageRoot 'sample.pkg.tar.zst'
        $result = Invoke-PrivatePacman `
            -Context $context `
            -ArgumentList @('-U', '--noconfirm') `
            -PackageRoot $packageRoot `
            -PackagePath $package
        Assert-True ($result.OperationKind.ToString() -eq 'Mutating') 'Upgrade was not classified mutating.'
        Assert-True (Test-Path -LiteralPath $result.EvidenceFile) 'Transaction evidence was not written.'
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_ARG_RECORD) -contains $package) `
            'Canonical package path was not passed to pacman.'
    }

    Invoke-Test 'constructor seed is applied before managed config' {
        $seed = Join-Path $testRoot 'private-pacman-seed'
        $seedBin = Join-Path $seed 'usr\bin'
        $seedEtc = Join-Path $seed 'etc'
        New-Item -ItemType Directory -Path $seedBin -Force | Out-Null
        New-Item -ItemType Directory -Path $seedEtc -Force | Out-Null
        Get-ChildItem -LiteralPath (Split-Path -Parent $fakePacman) -File |
            Copy-Item -Destination $seedBin
        Set-Content -LiteralPath (Join-Path $seedEtc 'pacman.conf') -Value 'Include = unsafe'

        $context = New-TestContext -Name 'seeded-context' -Override @{
            PrivatePacmanSeed = $seed
        }
        Assert-True (Test-Path -LiteralPath $context.PacmanPath -PathType Leaf) `
            'Constructor seed did not provide the private pacman executable.'
        Assert-True (
            (Get-Content -LiteralPath $context.ConfigFile -Raw) -notmatch 'Include'
        ) 'Seed overwrote the sealed managed config.'
    }

    Invoke-Test 'package traversal is rejected' {
        $context = New-TestContext -Name 'package-traversal'
        $outsidePackage = Join-Path $testRoot 'outside.pkg.tar.zst'
        Set-Content -LiteralPath $outsidePackage -Value 'outside'
        Assert-Throws -Pattern 'escapes PackageRoot' -Action {
            Invoke-PrivatePacman `
                -Context $context `
                -ArgumentList @('-U') `
                -PackageRoot $packageRoot `
                -PackagePath $outsidePackage
        }
    }

    Invoke-Test 'stdin package target is rejected' {
        $context = New-TestContext -Name 'stdin-package'
        Assert-Throws -Pattern 'standard input' -Action {
            Invoke-PrivatePacman `
                -Context $context `
                -ArgumentList @('-U') `
                -PackageRoot $packageRoot `
                -PackagePath '-'
        }
    }

    Invoke-Test 'stdin target is rejected for non-upgrade operations' {
        $context = New-TestContext -Name 'stdin-sync'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'stdin-sync.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'standard input' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-Syu', '-')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman ran with a standard-input target.'
    }

    Invoke-Test 'dash-prefixed package target cannot bypass PackagePath' {
        $context = New-TestContext -Name 'dash-package'
        Assert-Throws -Pattern "operation selector|helper owns option termination|only through PackagePath" -Action {
            Invoke-PrivatePacman `
                -Context $context `
                -ArgumentList @('-U', '--', '-outside.pkg.tar.zst') `
                -PackageRoot $packageRoot `
                -PackagePath (Join-Path $packageRoot 'sample.pkg.tar.zst')
        }
    }

    Invoke-Test 'mutation without root sentinel is rejected' {
        $context = New-TestContext -Name 'missing-sentinel'
        Remove-Item -LiteralPath (Join-Path $context.Root '.private-pacman-root.json') -Force
        Assert-Throws -Pattern 'requires root sentinel' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-S', 'example')
        }
    }

    Invoke-Test 'configured and system pacman hooks must remain empty' {
        foreach ($hookKind in @('configured', 'system')) {
            $context = New-TestContext -Name "nonempty-$hookKind-hooks"
            $hookPath = if ($hookKind -eq 'configured') {
                $context.HookDir
            }
            else {
                Join-Path $context.Root 'usr\share\libalpm\hooks'
            }
            New-Item -ItemType Directory -Path $hookPath -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $hookPath 'unsafe.hook') -Value '[Trigger]'
            $env:PACMAN_ARG_RECORD = Join-Path $testRoot "nonempty-$hookKind-hooks.args"
            $env:PACMAN_EXIT_CODE = '0'
            Assert-Throws -Pattern 'hook directory must be empty' -Action {
                Invoke-PrivatePacman -Context $context -ArgumentList @('-S', 'example')
            }
            Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
                "Fake pacman ran with nonempty $hookKind hooks."
        }
    }

    Invoke-Test 'config edits and Include directives are rejected' {
        $context = New-TestContext -Name 'config-edit'
        Add-Content -LiteralPath $context.ConfigFile -Value 'Include = C:\msys64\etc\pacman.conf'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'config-edit.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'config changed' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-Q')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman ran with an edited config.'
    }

    Invoke-Test 'Include remains rejected even if caller updates the expected hash' {
        $context = New-TestContext -Name 'config-include'
        Add-Content -LiteralPath $context.ConfigFile -Value 'Include = C:\msys64\etc\pacman.conf'
        $context.ConfigHash = (Get-FileHash -LiteralPath $context.ConfigFile -Algorithm SHA256).Hash
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'config-include.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'recursive directive' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-Q')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman ran with an Include directive.'
    }

    Invoke-Test 'config and package files remain locked during launch' {
        $context = New-TestContext -Name 'file-locks'
        $package = Join-Path $packageRoot 'sample.pkg.tar.zst'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'file-locks.args'
        $env:PACMAN_EXIT_CODE = '0'
        $env:PACMAN_MUTATE_CONFIG = $context.ConfigFile
        $env:PACMAN_CONFIG_LOCK_RECORD = Join-Path $testRoot 'config.lock'
        $env:PACMAN_MUTATE_PACKAGE = $package
        $env:PACMAN_PACKAGE_LOCK_RECORD = Join-Path $testRoot 'package.lock'
        Invoke-PrivatePacman `
            -Context $context `
            -ArgumentList @('-U') `
            -PackageRoot $packageRoot `
            -PackagePath $package | Out-Null
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_CONFIG_LOCK_RECORD -Raw) -eq 'locked') `
            'Pacman config was writable during process execution.'
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_PACKAGE_LOCK_RECORD -Raw) -eq 'locked') `
            'Package file was writable during process execution.'
        Remove-Item Env:PACMAN_MUTATE_CONFIG
        Remove-Item Env:PACMAN_CONFIG_LOCK_RECORD
        Remove-Item Env:PACMAN_MUTATE_PACKAGE
        Remove-Item Env:PACMAN_PACKAGE_LOCK_RECORD
    }

    Invoke-Test 'nested junction escape is rejected before mutation' {
        $context = New-TestContext -Name 'nested-junction'
        $sharedTarget = Join-Path $sharedRoot 'usr'
        New-Item -ItemType Directory -Path $sharedTarget -Force | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $context.Root 'escape') -Target $sharedTarget | Out-Null
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'nested-junction.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'escapes private root' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-S', 'example')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman was invoked with an escaping root junction.'
    }

    Invoke-Test 'Cygwin magic-file symlink is rejected before mutation' {
        $context = New-TestContext -Name 'cygwin-link'
        Remove-Item -LiteralPath $context.CacheDir -Recurse -Force
        $linkBytes = [System.Text.Encoding]::ASCII.GetBytes(
            '!<symlink>C:\msys64\var\cache\pacman\pkg'
        )
        [System.IO.File]::WriteAllBytes($context.CacheDir, $linkBytes)
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'cygwin-link.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'Cygwin magic-file symlinks' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-Sw', 'example')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman ran with a Cygwin magic-file destination.'
    }

    Invoke-Test 'shortcut link is rejected before mutation' {
        $context = New-TestContext -Name 'shortcut-link'
        Set-Content -LiteralPath (Join-Path $context.Root 'escape.lnk') -Value 'shortcut fixture'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'shortcut-link.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'shortcut links' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-S', 'example')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman ran with a shortcut-link fixture.'
    }

    Invoke-Test 'destination directories remain locked during launch' {
        $context = New-TestContext -Name 'directory-locks'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'directory-locks.args'
        $env:PACMAN_EXIT_CODE = '0'
        $env:PACMAN_RENAME_DIRECTORY = $context.CacheDir
        $env:PACMAN_DIRECTORY_LOCK_RECORD = Join-Path $testRoot 'directory.lock'
        $env:PACMAN_WRITE_DIRECTORY = $context.CacheDir
        $env:PACMAN_DIRECTORY_WRITE_RECORD = Join-Path $testRoot 'directory-write.lock'
        Invoke-PrivatePacman -Context $context -ArgumentList @('-Sw', 'example') | Out-Null
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_DIRECTORY_LOCK_RECORD -Raw) -eq 'locked') `
            'Private cache directory could be renamed during process execution.'
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_DIRECTORY_WRITE_RECORD -Raw) -eq 'written') `
            'Directory identity lock blocked intended writes inside the private cache.'
        Remove-Item Env:PACMAN_RENAME_DIRECTORY
        Remove-Item Env:PACMAN_DIRECTORY_LOCK_RECORD
        Remove-Item Env:PACMAN_WRITE_DIRECTORY
        Remove-Item Env:PACMAN_DIRECTORY_WRITE_RECORD
    }

    Invoke-Test 'nonzero pacman exit is propagated' {
        $context = New-TestContext -Name 'nonzero'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'nonzero.args'
        $env:PACMAN_EXIT_CODE = '23'
        Assert-Throws -Pattern 'code 23' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-Q', 'base')
        }
    }

    Invoke-Test 'shared sentinel drift fails without rollback' {
        $context = New-TestContext -Name 'drift'
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'drift.args'
        $env:PACMAN_EXIT_CODE = '0'
        $env:PACMAN_DRIFT_LOG = Join-Path $sharedRoot 'var\log\pacman.log'
        Assert-Throws -Pattern 'Shared MSYS2 state changed' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-S', 'example')
        }
        Assert-True ((Get-Content -LiteralPath $env:PACMAN_DRIFT_LOG -Raw) -match 'drift') `
            'The drift fixture was unexpectedly rolled back.'
        Remove-Item Env:PACMAN_DRIFT_LOG
    }

    Invoke-Test 'shared fingerprint includes directory reparse targets' {
        $targetA = Join-Path $sharedRoot 'target-a'
        $targetB = Join-Path $sharedRoot 'target-b'
        $link = Join-Path $sharedRoot 'retargetable'
        New-Item -ItemType Directory -Path $targetA -Force | Out-Null
        New-Item -ItemType Directory -Path $targetB -Force | Out-Null
        New-Item -ItemType Junction -Path $link -Target $targetA | Out-Null
        $before = Get-SharedPacmanState -SharedRoot $sharedRoot
        Remove-Item -LiteralPath $link -Force
        New-Item -ItemType Junction -Path $link -Target $targetB | Out-Null
        $after = Get-SharedPacmanState -SharedRoot $sharedRoot
        Assert-True (
            $before.protectedRoot.manifestHash -cne $after.protectedRoot.manifestHash
        ) 'Shared-root fingerprint ignored a directory reparse retarget.'
        Remove-Item -LiteralPath $link -Force
    }
}
finally {
    Remove-Item Env:PACMAN_ARG_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_EXIT_CODE -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_DRIFT_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_STDIN_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_ENV_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:POSIXLY_CORRECT -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_MUTATE_CONFIG -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_CONFIG_LOCK_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_MUTATE_PACKAGE -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_PACKAGE_LOCK_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_RENAME_DIRECTORY -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_DIRECTORY_LOCK_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_WRITE_DIRECTORY -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_DIRECTORY_WRITE_RECORD -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "$script:Passed passed; $script:Failed failed"
if ($script:Failed -ne 0) {
    exit 1
}

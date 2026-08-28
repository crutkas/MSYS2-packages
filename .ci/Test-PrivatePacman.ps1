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
    'PRIVATE_PACMAN_TEST_ENVIRONMENT',
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
            Status = 'Passed'
            Passed = $true
            Failed = $false
            Skipped = $false
            DurationMilliseconds = $stopwatch.ElapsedMilliseconds
            Error = $null
            SkipReason = $null
        })
        Write-Host "PASS $Name"
    }
    catch {
        $stopwatch.Stop()
        $results.Add([pscustomobject][ordered]@{
            Name = $Name
            Status = 'Failed'
            Passed = $false
            Failed = $true
            Skipped = $false
            DurationMilliseconds = $stopwatch.ElapsedMilliseconds
            Error = $_.Exception.ToString()
            SkipReason = $null
        })
        Write-Host "FAIL $Name`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Add-PrivatePacmanSkippedTestCase {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Reason
    )

    $results.Add([pscustomobject][ordered]@{
        Name = $Name
        Status = 'Skipped'
        Passed = $false
        Failed = $false
        Skipped = $true
        DurationMilliseconds = [int64]0
        Error = $null
        SkipReason = $Reason
    })
    Write-Host "SKIP $Name`: $Reason"
}

function Clear-PrivatePacmanTestEnvironment {
    foreach ($name in $testEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    & $module {
        $script:TestChildEnvironment = $null
    }
}

function Set-PrivatePacmanTestCanonicalSharedRoot {
    param(
        [Parameter(Mandatory)]
        [Management.Automation.PSModuleInfo] $Module,

        [Parameter(Mandatory)]
        [string] $Path
    )

    & $Module {
        param([string] $CanonicalSharedRoot)
        $script:CanonicalSharedRoot = $CanonicalSharedRoot
    } $Path
}

function Wait-PrivatePacmanPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [int] $TimeoutSeconds = 120
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

function Read-PrivatePacmanRecordedEnvironment {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    return @(
        [IO.File]::ReadAllLines($Path) | ForEach-Object {
            $fields = $_.Split(':')
            if ($fields.Count -ne 2) {
                throw "Recorded child environment line is malformed: $_"
            }
            [pscustomobject][ordered]@{
                Name = [Text.Encoding]::UTF8.GetString(
                    [Convert]::FromBase64String($fields[0])
                )
                Value = [Text.Encoding]::UTF8.GetString(
                    [Convert]::FromBase64String($fields[1])
                )
            }
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
using System.Collections;
using System.Collections.Generic;
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

    private static void WriteEnvironment(string path)
    {
        if (String.IsNullOrEmpty(path))
        {
            return;
        }
        IDictionary environment = Environment.GetEnvironmentVariables();
        List<string> names = new List<string>();
        foreach (DictionaryEntry entry in environment)
        {
            names.Add((string)entry.Key);
        }
        names.Sort(StringComparer.Ordinal);
        string[] encoded = new string[names.Count];
        for (int index = 0; index < names.Count; index++)
        {
            string name = names[index];
            string value = (string)environment[name];
            encoded[index] =
                Convert.ToBase64String(Encoding.UTF8.GetBytes(name)) + ":" +
                Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        }
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        File.WriteAllLines(path, encoded, new UTF8Encoding(false));
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
        WriteEnvironment(Env("PRIVATE_PACMAN_TEST_ENVIRONMENT"));

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
    $ownershipRoot = Join-Path $base 'ownership'
    foreach ($directory in @(
        $workspace,
        (Join-Path $seed 'usr\bin'),
        $packageRoot,
        $ownershipRoot,
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
    Set-Acl -LiteralPath $sharedFile -AclObject (Get-Acl -LiteralPath $sharedFile)
    [IO.File]::WriteAllText(
        (Join-Path $protectedRoot 'var\log\pacman.log'),
        "log-$Name",
        [Text.UTF8Encoding]::new($false)
    )

    $sessionId = "test-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    $layout = New-PrivatePacmanLayout -WorkspaceRoot $workspace -SessionId $sessionId
    $owner = "arm64-contract:$safeName"
    $manifestPath = Join-Path $ownershipRoot 'packages.ownership.json'
    $signaturePath = Join-Path $ownershipRoot 'packages.ownership.sig'
    $publicKeyPath = Join-Path $ownershipRoot 'packages.ownership.pem'
    $manifest = New-PrivatePacmanOwnershipManifest `
        -PackageRoot $packageRoot `
        -Owner $owner `
        -SessionId $sessionId `
        -OutputPath $manifestPath
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $signatureBytes = $script:signingKey.SignData(
        $manifestBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )
    [IO.File]::WriteAllText(
        $signaturePath,
        [Convert]::ToBase64String($signatureBytes) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        $publicKeyPath,
        $script:signingKey.ExportSubjectPublicKeyInfoPem(),
        [Text.UTF8Encoding]::new($false)
    )
    $publicKeySha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($publicKeyPath))
    ).ToLowerInvariant()

    return [pscustomobject][ordered]@{
        Base = $base
        Workspace = $workspace
        Seed = $seed
        PackageRoot = $packageRoot
        PackageRelativePath = $packageRelativePath
        PackagePath = $packagePath
        Owner = $owner
        OwnershipManifestPath = $manifestPath
        OwnershipSignaturePath = $signaturePath
        OwnershipPublicKeyPath = $publicKeyPath
        ExpectedManifestSha256 = $manifest.Sha256
        ExpectedPublicKeySha256 = $publicKeySha256
        PackageSetSha256 = $manifest.PackageSetSha256
        ProtectedRoot = $protectedRoot
        SharedFile = $sharedFile
        Layout = $layout
        ArgvPath = Join-Path $base 'argv.txt'
        ConfigCapturePath = Join-Path $base 'pacman.conf'
        EnvironmentPath = Join-Path $base 'environment.txt'
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

    $environment = [ordered]@{
        PRIVATE_PACMAN_TEST_ARGV = $Fixture.ArgvPath
        PRIVATE_PACMAN_TEST_CONFIG = $Fixture.ConfigCapturePath
        PRIVATE_PACMAN_TEST_ENVIRONMENT = $Fixture.EnvironmentPath
        PRIVATE_PACMAN_TEST_GO = $Fixture.GoPath
        PRIVATE_PACMAN_TEST_MODE = $Mode
        PRIVATE_PACMAN_TEST_READY = $Fixture.ReadyPath
    }
    & $module {
        param([Collections.IDictionary] $Values)
        $script:TestChildEnvironment = $Values
    } $environment
}

function Set-PrivatePacmanFixtureManifest {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [Parameter(Mandatory)]
        [string] $ManifestText
    )

    [IO.File]::WriteAllText(
        $Fixture.OwnershipManifestPath,
        $ManifestText,
        [Text.UTF8Encoding]::new($false)
    )
    $manifestBytes = [IO.File]::ReadAllBytes($Fixture.OwnershipManifestPath)
    $signatureBytes = $script:signingKey.SignData(
        $manifestBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )
    [IO.File]::WriteAllText(
        $Fixture.OwnershipSignaturePath,
        [Convert]::ToBase64String($signatureBytes) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    $Fixture.ExpectedManifestSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($manifestBytes)
    ).ToLowerInvariant()
}

function Set-PrivatePacmanFixturePublicKeyText {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    [IO.File]::WriteAllText(
        $Fixture.OwnershipPublicKeyPath,
        $Text,
        [Text.UTF8Encoding]::new($false)
    )
    $Fixture.ExpectedPublicKeySha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [IO.File]::ReadAllBytes($Fixture.OwnershipPublicKeyPath)
        )
    ).ToLowerInvariant()
}

function Set-PrivatePacmanFixtureSigningKey {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [Parameter(Mandatory)]
        [Security.Cryptography.ECDsa] $SigningKey
    )

    Set-PrivatePacmanFixturePublicKeyText `
        -Fixture $Fixture `
        -Text $SigningKey.ExportSubjectPublicKeyInfoPem()
    $signatureBytes = $SigningKey.SignData(
        [IO.File]::ReadAllBytes($Fixture.OwnershipManifestPath),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )
    [IO.File]::WriteAllText(
        $Fixture.OwnershipSignaturePath,
        [Convert]::ToBase64String($signatureBytes) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-PrivatePacmanNoncanonicalBase64 {
    param(
        [Parameter(Mandatory)]
        [string] $Canonical
    )

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    $padding = if ($Canonical.EndsWith('==', [StringComparison]::Ordinal)) {
        2
    }
    elseif ($Canonical.EndsWith('=', [StringComparison]::Ordinal)) {
        1
    }
    else {
        0
    }
    if ($padding -eq 0) {
        throw 'A padded canonical base64 value is required for this regression.'
    }
    $index = $Canonical.Length - $padding - 1
    $value = $alphabet.IndexOf($Canonical[$index])
    if ($value -lt 0) {
        throw 'Canonical base64 contains an unexpected character.'
    }
    $replacement = $alphabet[$value -bor 1]
    return $Canonical.Substring(0, $index) +
        $replacement +
        $Canonical.Substring($index + 1)
}

function Set-PrivatePacmanTestMetadataMutation {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $originalAcl = Get-Acl -LiteralPath $Path
    $originalAttributes = [IO.File]::GetAttributes($Path)
    $modifiedAcl = Get-Acl -LiteralPath $Path
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent().User,
        [Security.AccessControl.FileSystemRights]::ReadAttributes,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$modifiedAcl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $modifiedAcl

    $attributeMask = (
        [IO.FileAttributes]::Hidden -bor
        [IO.FileAttributes]::System -bor
        [IO.FileAttributes]::ReadOnly
    )
    [IO.File]::SetAttributes($Path, $originalAttributes -bxor $attributeMask)
    return [pscustomobject][ordered]@{
        Acl = $originalAcl
        Attributes = $originalAttributes
    }
}

function Restore-PrivatePacmanTestMetadata {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [psobject] $Original
    )

    Set-Acl -LiteralPath $Path -AclObject $Original.Acl
    [IO.File]::SetAttributes($Path, [IO.FileAttributes]$Original.Attributes)
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
        -OwnershipManifestPath $Fixture.OwnershipManifestPath `
        -OwnershipSignaturePath $Fixture.OwnershipSignaturePath `
        -OwnershipPublicKeyPath $Fixture.OwnershipPublicKeyPath `
        -ExpectedManifestSha256 $Fixture.ExpectedManifestSha256 `
        -ExpectedPublicKeySha256 $Fixture.ExpectedPublicKeySha256 `
        -ExpectedOwner $Fixture.Owner `
        -ProtectedRoot @($Fixture.ProtectedRoot) `
        -TimeoutSeconds $TimeoutSeconds
}

function Start-PrivatePacmanFixtureJob {
    param(
        [Parameter(Mandatory)]
        [psobject] $Fixture,

        [Parameter(Mandatory)]
        [string] $Mode,

        [string] $SnapshotBarrierRoot = '',

        [string] $SnapshotBarrierEnteredPath = '',

        [string] $SnapshotBarrierReleasePath = ''
    )

    $job = Start-Job `
        -Name "private-pacman-$([guid]::NewGuid().ToString('N'))" `
        -ArgumentList @(
            $modulePath,
            $Fixture.Layout,
            $Fixture.Seed,
            $Fixture.PackageRoot,
            $Fixture.OwnershipManifestPath,
            $Fixture.OwnershipSignaturePath,
            $Fixture.OwnershipPublicKeyPath,
            $Fixture.ExpectedManifestSha256,
            $Fixture.ExpectedPublicKeySha256,
            $Fixture.Owner,
            $Fixture.ProtectedRoot,
            $Fixture.ArgvPath,
            $Fixture.ConfigCapturePath,
            $Fixture.EnvironmentPath,
            $Fixture.ReadyPath,
            $Fixture.GoPath,
            $Mode,
            $script:testCanonicalSharedRoot,
            $SnapshotBarrierRoot,
            $SnapshotBarrierEnteredPath,
            $SnapshotBarrierReleasePath
        ) `
        -ScriptBlock {
            param(
                $ModulePath,
                $Layout,
                $Seed,
                $PackageRoot,
                $OwnershipManifestPath,
                $OwnershipSignaturePath,
                $OwnershipPublicKeyPath,
                $ExpectedManifestSha256,
                $ExpectedPublicKeySha256,
                $ExpectedOwner,
                $ProtectedRoot,
                $ArgvPath,
                $ConfigCapturePath,
                $EnvironmentPath,
                $ReadyPath,
                $GoPath,
                $Mode,
                $CanonicalSharedRoot,
                $BarrierRoot,
                $BarrierEnteredPath,
                $BarrierReleasePath
            )
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'
            $jobModule = Import-Module $ModulePath -Force -PassThru
            & $jobModule {
                param([Collections.IDictionary] $Values)
                $script:TestChildEnvironment = $Values
            } ([ordered]@{
                PRIVATE_PACMAN_TEST_ARGV = $ArgvPath
                PRIVATE_PACMAN_TEST_CONFIG = $ConfigCapturePath
                PRIVATE_PACMAN_TEST_ENVIRONMENT = $EnvironmentPath
                PRIVATE_PACMAN_TEST_GO = $GoPath
                PRIVATE_PACMAN_TEST_MODE = $Mode
                PRIVATE_PACMAN_TEST_READY = $ReadyPath
            })
            & $jobModule {
                param([string] $Path)
                $script:CanonicalSharedRoot = $Path
            } $CanonicalSharedRoot
            if (-not [string]::IsNullOrEmpty($BarrierRoot)) {
                & $jobModule {
                    param(
                        [string] $Root,
                        [string] $EnteredPath,
                        [string] $ReleasePath
                    )
                    $script:TestSnapshotBarrier = [pscustomobject][ordered]@{
                        Root = $Root
                        EnteredPath = $EnteredPath
                        ReleasePath = $ReleasePath
                        SkipMatches = 1
                    }
                } $BarrierRoot $BarrierEnteredPath $BarrierReleasePath
            }
            Invoke-PrivatePacmanUpgrade `
                -Layout $Layout `
                -SeedRoot $Seed `
                -PackageRoot $PackageRoot `
                -OwnershipManifestPath $OwnershipManifestPath `
                -OwnershipSignaturePath $OwnershipSignaturePath `
                -OwnershipPublicKeyPath $OwnershipPublicKeyPath `
                -ExpectedManifestSha256 $ExpectedManifestSha256 `
                -ExpectedPublicKeySha256 $ExpectedPublicKeySha256 `
                -ExpectedOwner $ExpectedOwner `
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

        [int] $TimeoutSeconds = 120
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

function Get-PrivatePacmanGuardedTreeSnapshot {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $AllowMissing
    )

    try {
        return [pscustomobject][ordered]@{
            Snapshot = Get-PrivatePacmanTreeSnapshot -Path $Path -AllowMissing:$AllowMissing
            Error = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Snapshot = $null
            Error = $_.Exception.ToString()
        }
    }
}

function Invoke-PrivatePacmanStrictSnapshotReparseCase {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Junction', 'SymbolicLink')]
        [string] $ItemType,

        [Parameter(Mandatory)]
        [ValidateSet('Directory', 'File')]
        [string] $TargetKind,

        [Parameter(Mandatory)]
        [string] $SuiteRoot
    )

    $caseRoot = Join-Path $SuiteRoot "strict-reparse-$([guid]::NewGuid().ToString('N'))"
    $snapshotRoot = Join-Path $caseRoot 'snapshot'
    $targetRoot = Join-Path $caseRoot 'target'
    [void][IO.Directory]::CreateDirectory($snapshotRoot)
    if ($TargetKind -ceq 'Directory') {
        [void][IO.Directory]::CreateDirectory($targetRoot)
        $canary = Join-Path $targetRoot 'canary'
    }
    else {
        [void][IO.Directory]::CreateDirectory($targetRoot)
        $canary = Join-Path $targetRoot 'canary'
    }
    [IO.File]::WriteAllText(
        $canary,
        'strict-snapshot-target',
        [Text.UTF8Encoding]::new($false)
    )
    $target = if ($TargetKind -ceq 'Directory') { $targetRoot } else { $canary }
    $linkName = if ($TargetKind -ceq 'Directory') {
        'directory-link'
    }
    else {
        'file-link'
    }
    $link = Join-Path $snapshotRoot $linkName
    try {
        try {
            $null = New-Item -ItemType $ItemType -Path $link -Target $target
        }
        catch {
            Add-PrivatePacmanSkippedTestCase `
                -Name $Name `
                -Reason "$ItemType $TargetKind creation is unavailable: $($_.Exception.Message)"
            return
        }

        Invoke-PrivatePacmanTestCase -Name $Name -Test {
            $caught = Assert-PrivatePacmanThrows {
                Get-PrivatePacmanTreeSnapshot -Path $snapshotRoot
            } 'Reparse points are forbidden in strict package-state snapshots'
            $errorId = ($caught.FullyQualifiedErrorId -split ',')[0]
            Assert-PrivatePacmanEqual `
                'PrivatePacman.ReparsePointRejected' `
                $errorId `
                'Strict snapshot reparse error ID changed.'
            Assert-PrivatePacmanEqual `
                $link `
                ([string]$caught.TargetObject) `
                'Strict snapshot reparse error target changed.'
            Assert-PrivatePacmanEqual `
                'strict-snapshot-target' `
                ([IO.File]::ReadAllText($canary)) `
                'Strict snapshot followed or changed a reparse target.'
        }
    }
    finally {
        if ([IO.Directory]::Exists($link)) {
            [IO.Directory]::Delete($link, $false)
        }
        elseif ([IO.File]::Exists($link)) {
            [IO.File]::Delete($link)
        }
        if ([IO.Directory]::Exists($caseRoot)) {
            Remove-Item -LiteralPath $caseRoot -Recurse -Force
        }
    }
}

$temporaryBase = [PrivatePacmanV2.NativePath]::GetFinalPath(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
)
$suiteRoot = Join-Path $temporaryBase "private-pacman-v2-$([guid]::NewGuid().ToString('N'))"
[void][IO.Directory]::CreateDirectory($suiteRoot)
$sharedBeforeCapture = Get-PrivatePacmanGuardedTreeSnapshot -Path 'C:\msys64' -AllowMissing
$sharedAfterCapture = $null
$suiteCleanupError = $null
$script:populatedSharedEvidence = $null
$script:canonicalTransactionEvidence = $null
$recorderPath = $null
$script:testCanonicalSharedRoot = Join-Path $suiteRoot 'synthetic-canonical-shared-root'
[void][IO.Directory]::CreateDirectory((Join-Path $script:testCanonicalSharedRoot 'var\lib\pacman'))
[IO.File]::WriteAllText(
    (Join-Path $script:testCanonicalSharedRoot 'var\lib\pacman\local-state'),
    'synthetic-canonical-shared-state',
    [Text.UTF8Encoding]::new($false)
)
$script:signingKey = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256
)

try {
    $recorderPath = New-PrivatePacmanRecorder -Directory (Join-Path $suiteRoot 'recorder')

    Invoke-PrivatePacmanTestCase -Name 'repository contains no tracked package candidate bytes' -Test {
        $repositoryRoot = Split-Path $PSScriptRoot -Parent
        $trackedCandidateBytes = @(& git -C $repositoryRoot ls-files '*.pkg.tar.*')
        Assert-PrivatePacmanEqual 0 $trackedCandidateBytes.Count 'Tracked package candidate bytes are present.'
    }

    Invoke-PrivatePacmanTestCase -Name 'candidate workflow remains pinned diagnostic-only and coverage-aware' -Test {
        $workflowPath = Join-Path (
            Split-Path $PSScriptRoot -Parent
        ) '.github\workflows\private-pacman-contract.yml'
        $workflow = [IO.File]::ReadAllText($workflowPath)
        $uses = @(
            [regex]::Matches($workflow, '(?m)^\s*uses:\s*(?<Action>\S+)\s*$') |
                ForEach-Object { $_.Groups['Action'].Value }
        )
        Assert-PrivatePacmanSequence @(
            'actions/checkout@11d5960a326750d5838078e36cf38b85af677262'
            'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
        ) $uses 'Candidate workflow action pins changed.'
        Assert-PrivatePacmanTest `
            ($workflow -match '(?m)^permissions:\n\s+contents: read$') `
            'Candidate workflow permissions are not read-only.'
        Assert-PrivatePacmanTest `
            ($workflow -notmatch '(?m)^\s*(push|pull_request_target):') `
            'Candidate workflow gained a privileged or push trigger.'
        Assert-PrivatePacmanTest `
            ($workflow -match 'Unsupported fork head' -and
             $workflow -match 'PR_HEAD_REPOSITORY -cne \$env:GITHUB_REPOSITORY') `
            'Candidate workflow no longer fails unsupported fork heads.'
        Assert-PrivatePacmanTest `
            ($workflow -match 'persist-credentials: false' -and
             $workflow -match 'ref: \$\{\{ github\.event\.pull_request\.head\.sha') `
            'Candidate workflow no longer pins the exact uncredentialed head.'
        Assert-PrivatePacmanTest `
            ($workflow -match 'self-reported-diagnostic-only' -and
             $workflow -match 'AdmissionReady -ne \$false' -and
             $workflow -match 'CoverageStatus') `
            'Candidate workflow does not validate diagnostic authority and coverage.'
        Assert-PrivatePacmanTest `
            ($workflow -match 'path: \$\{\{ runner\.temp \}\}/private-pacman-contract\.json' -and
             $workflow -match 'if-no-files-found: error') `
            'Candidate workflow artifact is not the required JSON-only evidence.'
        Assert-PrivatePacmanEqual `
            1 `
            @([regex]::Matches($workflow, '(?m)^\s*uses:\s*actions/upload-artifact@')).Count `
            'Candidate workflow gained another artifact publication surface.'
    }

    Invoke-PrivatePacmanTestCase -Name 'suite temporary root is canonical' -Test {
        $resolvedSuiteRoot = & $module {
            param([string] $Path)
            Resolve-PrivatePacmanExistingPath -Path $Path -Kind Directory -Name 'Test suite root'
        } $suiteRoot
        Assert-PrivatePacmanEqual $suiteRoot $resolvedSuiteRoot 'Test suite root is not its final canonical path.'
    }

    Invoke-PrivatePacmanTestCase -Name 'repository-free argv is completely isolated' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'argv' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $hostileNames = @(
            'ALL_PROXY',
            'BASH_ENV',
            'COMSPEC',
            'CYGWIN',
            'ENV',
            'GIT_CONFIG',
            'GIT_CONFIG_COUNT',
            'GNUPGHOME',
            'HTTPS_PROXY',
            'HTTP_PROXY',
            'LD_PRELOAD',
            'MSYS',
            'NO_PROXY',
            'PATH',
            'POSIXLY_CORRECT',
            'SystemRoot',
            'TEMP',
            'TMP',
            'TMPDIR',
            'WINDIR'
        )
        $originalEnvironment = @{}
        foreach ($name in $hostileNames) {
            $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable(
                $name,
                'Process'
            )
            [Environment]::SetEnvironmentVariable(
                $name,
                "hostile-parent-$name",
                'Process'
            )
        }
        Set-PrivatePacmanFixtureEnvironment -Fixture $fixture
        try {
            $before = Get-PrivatePacmanTreeSnapshot -Path $fixture.ProtectedRoot
            $result = Invoke-PrivatePacmanFixture -Fixture $fixture
            $after = Get-PrivatePacmanTreeSnapshot -Path $fixture.ProtectedRoot

            Assert-PrivatePacmanTest $result.Success 'Successful recorder transaction was not reported as successful.'
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Protected test state changed.'
            Assert-PrivatePacmanEqual $fixture.Owner $result.Ownership.Owner 'Ownership evidence lost the expected owner.'
            Assert-PrivatePacmanEqual $fixture.Layout.SessionId $result.Ownership.SessionId 'Ownership evidence lost the session binding.'
            Assert-PrivatePacmanEqual $fixture.ExpectedManifestSha256 $result.Ownership.ManifestSha256 'Ownership manifest hash changed.'
            Assert-PrivatePacmanEqual $fixture.ExpectedPublicKeySha256 $result.Ownership.PublicKeySha256 'Ownership public-key hash changed.'
            Assert-PrivatePacmanEqual '1.2.840.10045.3.1.7' $result.Ownership.PublicKeyCurveOid 'Ownership curve OID changed.'
            Assert-PrivatePacmanEqual 'subject-public-key-info-pem/v1' $result.Ownership.PublicKeyFormat 'Ownership public-key format changed.'
            Assert-PrivatePacmanEqual 'base64-rfc4648-der-lf/v1' $result.Ownership.SignatureEncoding 'Ownership signature encoding changed.'
            Assert-PrivatePacmanEqual 'private-pacman-package-set/v1' $result.Ownership.PackageSetCanonicalization 'Package-set canonicalization changed.'
            Assert-PrivatePacmanEqual $fixture.PackageSetSha256 $result.Ownership.PackageSetSha256 'Deterministic package-set hash changed.'
            Assert-PrivatePacmanEqual ([int64]1) ([int64]$result.Ownership.PackageCount) 'Ownership evidence has the wrong package count.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Private root survived successful cleanup.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath $fixture.Layout.OwnerPath) 'External owner sentinel was not preserved.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json')) 'Result evidence was not preserved.'
            Assert-PrivatePacmanTest (-not $fixture.Layout.OwnerPath.StartsWith(
                $fixture.Layout.Root + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) 'Owner sentinel was placed inside the disposable private root.'
            foreach ($jsonPath in @(
                $fixture.Layout.OwnerPath,
                (Join-Path $fixture.Layout.EvidenceDirectory 'invocation.json'),
                (Join-Path $fixture.Layout.EvidenceDirectory 'result.json')
            )) {
                $jsonBytes = [IO.File]::ReadAllBytes($jsonPath)
                Assert-PrivatePacmanTest `
                    ($jsonBytes.Length -gt 0 -and
                     $jsonBytes[-1] -eq 0x0a -and
                     ($jsonBytes.Length -eq 1 -or $jsonBytes[-2] -ne 0x0a) -and
                     $jsonBytes -notcontains 0x0d -and
                     $jsonBytes -notcontains 0x00 -and
                     -not (
                         $jsonBytes.Length -ge 3 -and
                         $jsonBytes[0] -eq 0xef -and
                         $jsonBytes[1] -eq 0xbb -and
                         $jsonBytes[2] -eq 0xbf
                     )) `
                    "JSON evidence is not strict UTF-8 LF-only framing: $jsonPath"
                $null = [Text.UTF8Encoding]::new($false, $true).
                    GetString($jsonBytes) |
                        ConvertFrom-Json
            }

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
            Assert-PrivatePacmanEqual `
                1 `
                @([regex]::Matches(
                    $config,
                    '(?m)^LocalFileSigLevel = Optional$'
                )).Count `
                'Diagnostic config changed native local package-signature policy.'

            $recordedEnvironment = Read-PrivatePacmanRecordedEnvironment `
                -Path $fixture.EnvironmentPath
            $environmentEvidence = $result.Invocation.Environment
            Assert-PrivatePacmanEqual `
                'private-pacman-child-environment/v1' `
                $environmentEvidence.Schema `
                'Child environment evidence schema changed.'
            Assert-PrivatePacmanSequence `
                @($environmentEvidence.Entries | ForEach-Object {
                    "$($_.Name)=$($_.Value)"
                }) `
                @($recordedEnvironment | ForEach-Object {
                    "$($_.Name)=$($_.Value)"
                }) `
                'Recorded child environment does not match complete invocation evidence.'
            $environmentNames = @($recordedEnvironment | ForEach-Object Name)
            $sortedEnvironmentNames = [string[]]$environmentNames.Clone()
            [Array]::Sort($sortedEnvironmentNames, [StringComparer]::Ordinal)
            Assert-PrivatePacmanSequence `
                $sortedEnvironmentNames `
                $environmentNames `
                'Child environment names are not sorted ordinally.'

            $environmentMap = @{}
            foreach ($entry in $recordedEnvironment) {
                $environmentMap.Add([string]$entry.Name, [string]$entry.Value)
            }
            $systemDirectory = [PrivatePacmanV2.NativePath]::GetFinalPath(
                [Environment]::SystemDirectory
            )
            $windowsRoot = [PrivatePacmanV2.NativePath]::GetFinalPath(
                [IO.Directory]::GetParent($systemDirectory).FullName
            )
            $expectedEnvironment = [ordered]@{
                COMSPEC = [IO.Path]::Combine($systemDirectory, 'cmd.exe')
                GNUPGHOME = $fixture.Layout.GpgPath
                HOME = [IO.Path]::Combine($fixture.Layout.Root, 'home')
                LANG = 'C.UTF-8'
                LC_ALL = 'C.UTF-8'
                MSYS = 'winsymlinks:nativestrict'
                MSYSTEM = 'MSYS'
                MSYSTEM_PREFIX = '/usr'
                PATH = [string]::Join(
                    [IO.Path]::PathSeparator,
                    @(
                        [IO.Path]::Combine($fixture.Layout.Root, 'usr\bin'),
                        $systemDirectory,
                        $windowsRoot
                    )
                )
                PRIVATE_PACMAN_TEST_ARGV = $fixture.ArgvPath
                PRIVATE_PACMAN_TEST_CONFIG = $fixture.ConfigCapturePath
                PRIVATE_PACMAN_TEST_ENVIRONMENT = $fixture.EnvironmentPath
                PRIVATE_PACMAN_TEST_GO = $fixture.GoPath
                PRIVATE_PACMAN_TEST_MODE = 'success'
                PRIVATE_PACMAN_TEST_READY = $fixture.ReadyPath
                SystemRoot = $windowsRoot
                TEMP = [IO.Path]::Combine($fixture.Layout.Root, 'tmp')
                TMP = [IO.Path]::Combine($fixture.Layout.Root, 'tmp')
                TMPDIR = [IO.Path]::Combine($fixture.Layout.Root, 'tmp')
                WINDIR = $windowsRoot
            }
            Assert-PrivatePacmanEqual `
                $expectedEnvironment.Count `
                $environmentMap.Count `
                'Child environment contains inherited or missing names.'
            foreach ($entry in $expectedEnvironment.GetEnumerator()) {
                Assert-PrivatePacmanTest `
                    $environmentMap.ContainsKey($entry.Key) `
                    "Child environment omitted $($entry.Key)."
                Assert-PrivatePacmanEqual `
                    $entry.Value `
                    $environmentMap[$entry.Key] `
                    "Child environment value changed for $($entry.Key)."
            }
            foreach ($name in @(
                'ALL_PROXY', 'BASH_ENV', 'CYGWIN', 'ENV', 'GIT_CONFIG',
                'GIT_CONFIG_COUNT', 'HTTPS_PROXY', 'HTTP_PROXY', 'LD_PRELOAD',
                'NO_PROXY', 'POSIXLY_CORRECT'
            )) {
                Assert-PrivatePacmanTest `
                    (-not $environmentMap.ContainsKey($name)) `
                    "Hostile inherited child environment variable survived: $name"
            }
            $environmentCanonicalLines = [Collections.Generic.List[string]]::new()
            $environmentCanonicalLines.Add('private-pacman-child-environment/v1')
            $environmentCanonicalLines.Add(
                $recordedEnvironment.Count.ToString(
                    [Globalization.CultureInfo]::InvariantCulture
                )
            )
            foreach ($entry in $recordedEnvironment) {
                $environmentCanonicalLines.Add(
                    [Convert]::ToBase64String(
                        [Text.Encoding]::UTF8.GetBytes($entry.Name)
                    ) +
                    [string][char]9 +
                    [Convert]::ToBase64String(
                        [Text.Encoding]::UTF8.GetBytes($entry.Value)
                    )
                )
            }
            $environmentCanonical = (
                [string]::Join("`n", $environmentCanonicalLines) + "`n"
            )
            $environmentSha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData(
                    [Text.UTF8Encoding]::new($false).GetBytes(
                        $environmentCanonical
                    )
                )
            ).ToLowerInvariant()
            Assert-PrivatePacmanEqual `
                $environmentSha256 `
                $environmentEvidence.Sha256 `
                'Child environment evidence hash is not canonical.'

            $canonicalEvidence = @($result.ProtectedBefore | Where-Object IsCanonicalSharedRoot)
            Assert-PrivatePacmanEqual 1 $canonicalEvidence.Count 'Canonical C:\msys64 evidence is missing or duplicated.'
            $canonicalAfter = @($result.ProtectedAfter | Where-Object IsCanonicalSharedRoot)
            Assert-PrivatePacmanEqual 'C:\msys64' $canonicalEvidence[0].Path 'The production canonical root was not protected by the argv transaction.'
            Assert-PrivatePacmanEqual $canonicalEvidence[0].Digest $canonicalAfter[0].Digest 'Canonical C:\msys64 state changed.'
            Assert-PrivatePacmanEqual $canonicalEvidence[0].EntryCount $canonicalAfter[0].EntryCount 'Canonical C:\msys64 entry count changed.'
            $coverageStatus = if (
                $canonicalEvidence[0].Exists -and
                $canonicalAfter[0].Exists
            ) {
                'Covered'
            }
            else {
                'NotCovered'
            }
            $script:canonicalTransactionEvidence = [pscustomobject][ordered]@{
                Path = [string]$canonicalEvidence[0].Path
                CoverageStatus = $coverageStatus
                ExistedBefore = [bool]$canonicalEvidence[0].Exists
                ExistedAfter = [bool]$canonicalAfter[0].Exists
                EntryCountBefore = [int64]$canonicalEvidence[0].EntryCount
                EntryCountAfter = [int64]$canonicalAfter[0].EntryCount
                BeforeDigest = [string]$canonicalEvidence[0].Digest
                AfterDigest = [string]$canonicalAfter[0].Digest
                BeforeContentDigest = [string]$canonicalEvidence[0].ContentDigest
                AfterContentDigest = [string]$canonicalAfter[0].ContentDigest
                ByteAndMetadataIdentical = if ($coverageStatus -ceq 'Covered') {
                    (
                        $canonicalEvidence[0].Digest -ceq $canonicalAfter[0].Digest -and
                        $canonicalEvidence[0].ContentDigest -ceq
                            $canonicalAfter[0].ContentDigest -and
                        [int64]$canonicalEvidence[0].EntryCount -eq
                            [int64]$canonicalAfter[0].EntryCount
                    )
                }
                else {
                    $null
                }
            }
        }
        finally {
            Clear-PrivatePacmanTestEnvironment
            foreach ($name in $hostileNames) {
                [Environment]::SetEnvironmentVariable(
                    $name,
                    $originalEnvironment[$name],
                    'Process'
                )
            }
        }
    }

    if ($null -eq $script:canonicalTransactionEvidence) {
        Invoke-PrivatePacmanTestCase `
            -Name 'literal C:\msys64 transaction coverage is countable' `
            -Test {
                throw 'The transaction did not publish literal-root coverage evidence.'
            }
    }
    elseif ($script:canonicalTransactionEvidence.CoverageStatus -ceq 'NotCovered') {
        Add-PrivatePacmanSkippedTestCase `
            -Name 'literal C:\msys64 transaction coverage is countable' `
            -Reason 'C:\msys64 does not exist; missing state is not literal-root coverage.'
    }
    else {
        Invoke-PrivatePacmanTestCase `
            -Name 'literal C:\msys64 transaction coverage is countable' `
            -Test {
                Assert-PrivatePacmanEqual `
                    'Covered' `
                    $script:canonicalTransactionEvidence.CoverageStatus `
                    'Literal transaction coverage status is invalid.'
                Assert-PrivatePacmanTest `
                    ([int64]$script:canonicalTransactionEvidence.EntryCountBefore -ge 0) `
                    'Literal transaction before count is negative.'
                Assert-PrivatePacmanEqual `
                    ([int64]$script:canonicalTransactionEvidence.EntryCountBefore) `
                    ([int64]$script:canonicalTransactionEvidence.EntryCountAfter) `
                    'Literal transaction entry counts changed.'
                Assert-PrivatePacmanTest `
                    ([bool]$script:canonicalTransactionEvidence.ByteAndMetadataIdentical) `
                    'Literal transaction snapshot evidence is not identical.'
            }
    }

    Set-PrivatePacmanTestCanonicalSharedRoot `
        -Module $module `
        -Path $script:testCanonicalSharedRoot

    Invoke-PrivatePacmanTestCase -Name 'populated protected state exposes complete preservation evidence' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'populated-shared' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-PrivatePacmanFixtureEnvironment -Fixture $fixture
        try {
            $result = Invoke-PrivatePacmanFixture -Fixture $fixture
            $before = @($result.ProtectedBefore | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            $after = @($result.ProtectedAfter | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            Assert-PrivatePacmanTest $before.Exists 'Populated protected root was reported missing before invocation.'
            Assert-PrivatePacmanTest $after.Exists 'Populated protected root was reported missing after invocation.'
            Assert-PrivatePacmanTest ($before.EntryCount -ge 5) 'Populated protected-root entry count is incomplete.'
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Populated protected metadata digest changed.'
            Assert-PrivatePacmanEqual $before.ContentDigest $after.ContentDigest 'Populated protected content digest changed.'
            Assert-PrivatePacmanTest (-not [string]::IsNullOrWhiteSpace($before.RootOwnerSid)) 'Protected-root owner is absent from evidence.'
            Assert-PrivatePacmanTest (-not [string]::IsNullOrWhiteSpace($before.RootSecurityDescriptorSddl)) 'Protected-root security descriptor is absent from evidence.'
            Assert-PrivatePacmanTest ([int64]$before.RootChangeTimeFileTime -gt 0) 'Protected-root change time is absent from evidence.'
            Assert-PrivatePacmanTest (-not [string]::IsNullOrWhiteSpace($before.RootIdentity)) 'Protected-root identity is absent from evidence.'
            Assert-PrivatePacmanEqual 'forbidden' $before.AlternateDataStreams 'Protected-root ADS policy is absent from evidence.'

            $manifest = Get-Content `
                -Raw `
                -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory $before.Manifest) |
                    ConvertFrom-Json
            $sharedRelativePath = [IO.Path]::GetRelativePath($fixture.ProtectedRoot, $fixture.SharedFile)
            $sharedEntry = @($manifest.Entries | Where-Object RelativePath -CEQ $sharedRelativePath)[0]
            Assert-PrivatePacmanTest (-not [string]::IsNullOrWhiteSpace($sharedEntry.OwnerSid)) 'Protected file owner is absent from canonical evidence.'
            Assert-PrivatePacmanTest (-not [string]::IsNullOrWhiteSpace($sharedEntry.SecurityDescriptorSddl)) 'Protected file security descriptor is absent from canonical evidence.'
            Assert-PrivatePacmanTest ($null -ne $sharedEntry.Attributes) 'Protected file attributes are absent from canonical evidence.'
            Assert-PrivatePacmanTest ([int64]$sharedEntry.ChangeTimeFileTime -gt 0) 'Protected file change time is absent from canonical evidence.'
            Assert-PrivatePacmanTest (-not [string]::IsNullOrWhiteSpace($sharedEntry.Identity)) 'Protected file identity is absent from canonical evidence.'
            Assert-PrivatePacmanEqual 0 @($sharedEntry.AlternateStreams).Count 'Protected evidence admitted an alternate stream.'

            $script:populatedSharedEvidence = [pscustomobject][ordered]@{
                Kind = 'synthetic-populated-fixed-drive-root'
                ExistedBefore = [bool]$before.Exists
                ExistedAfter = [bool]$after.Exists
                EntryCountBefore = [int]$before.EntryCount
                EntryCountAfter = [int]$after.EntryCount
                BeforeDigest = [string]$before.Digest
                AfterDigest = [string]$after.Digest
                BeforeContentDigest = [string]$before.ContentDigest
                AfterContentDigest = [string]$after.ContentDigest
                ByteAndMetadataIdentical = (
                    $before.Digest -ceq $after.Digest -and
                    $before.ContentDigest -ceq $after.ContentDigest
                )
                OwnerAndDaclBound = $true
                AttributesBound = $true
                AlternateDataStreams = 'forbidden'
            }
        }
        finally {
            Clear-PrivatePacmanTestEnvironment
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'permanent ACL and attribute changes alter protected digest evidence' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'permanent-metadata' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $job = Start-PrivatePacmanFixtureJob -Fixture $fixture -Mode 'wait'
        $original = $null
        try {
            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            $original = Set-PrivatePacmanTestMetadataMutation -Path $fixture.SharedFile
            [IO.File]::WriteAllText($fixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Failed

            $evidence = Get-Content `
                -Raw `
                -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json') |
                    ConvertFrom-Json
            $before = @($evidence.ProtectedBefore | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            $after = @($evidence.ProtectedAfter | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            Assert-PrivatePacmanTest ($before.Digest -cne $after.Digest) 'Permanent metadata drift did not change the canonical digest.'
            Assert-PrivatePacmanEqual $before.ContentDigest $after.ContentDigest 'Metadata-only drift changed the content digest.'

            $beforeManifest = Get-Content -Raw -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory $before.Manifest) | ConvertFrom-Json
            $afterManifest = Get-Content -Raw -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory $after.Manifest) | ConvertFrom-Json
            $relative = [IO.Path]::GetRelativePath($fixture.ProtectedRoot, $fixture.SharedFile)
            $beforeEntry = @($beforeManifest.Entries | Where-Object RelativePath -CEQ $relative)[0]
            $afterEntry = @($afterManifest.Entries | Where-Object RelativePath -CEQ $relative)[0]
            Assert-PrivatePacmanTest ($beforeEntry.Attributes -ne $afterEntry.Attributes) 'Permanent file attributes were not bound.'
            Assert-PrivatePacmanTest ($beforeEntry.SecurityDescriptorSddl -cne $afterEntry.SecurityDescriptorSddl) 'Permanent DACL mutation was not bound.'
            Assert-PrivatePacmanEqual $beforeEntry.OwnerSid $afterEntry.OwnerSid 'DACL-only test unexpectedly changed owner identity.'
            Assert-PrivatePacmanTest (-not $evidence.Success) 'Permanent metadata drift was reported as success.'
        }
        finally {
            if ($null -ne $original) {
                Restore-PrivatePacmanTestMetadata -Path $fixture.SharedFile -Original $original
            }
            if (-not [IO.File]::Exists($fixture.GoPath)) {
                [IO.File]::WriteAllText($fixture.GoPath, 'go')
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'restored ACL and attribute changes remain fatal watcher evidence' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'restored-metadata' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $job = Start-PrivatePacmanFixtureJob -Fixture $fixture -Mode 'wait'
        $original = $null
        try {
            Wait-PrivatePacmanPath -Path $fixture.ReadyPath
            $original = Set-PrivatePacmanTestMetadataMutation -Path $fixture.SharedFile
            Restore-PrivatePacmanTestMetadata -Path $fixture.SharedFile -Original $original
            $original = $null
            [Threading.Thread]::Sleep(150)
            [IO.File]::WriteAllText($fixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Failed

            $evidence = Get-Content `
                -Raw `
                -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json') |
                    ConvertFrom-Json
            $before = @($evidence.ProtectedBefore | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            $after = @($evidence.ProtectedAfter | Where-Object Path -EQ $fixture.ProtectedRoot)[0]
            Assert-PrivatePacmanTest ($before.Digest -cne $after.Digest) 'Restored metadata did not advance canonical change-time evidence.'
            Assert-PrivatePacmanEqual $before.ContentDigest $after.ContentDigest 'Restored metadata changed protected bytes.'
            $events = @(
                $evidence.Watchers |
                    Where-Object Path -EQ $fixture.ProtectedRoot |
                    ForEach-Object Changes |
                    Where-Object Path -EQ $fixture.SharedFile
            )
            Assert-PrivatePacmanTest ($events.Count -gt 0) 'Restored ACL/attribute mutation emitted no retained event.'
            Assert-PrivatePacmanTest (-not $evidence.Success) 'Restored metadata drift was reported as success.'
        }
        finally {
            if ($null -ne $original) {
                Restore-PrivatePacmanTestMetadata -Path $fixture.SharedFile -Original $original
            }
            if (-not [IO.File]::Exists($fixture.GoPath)) {
                [IO.File]::WriteAllText($fixture.GoPath, 'go')
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'alternate data streams are forbidden and transient writes are observed' -Test {
        $packageFixture = New-PrivatePacmanFixture -Name 'package-ads' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-Content -LiteralPath $packageFixture.PackagePath -Stream contract -Value 'synthetic-stream'
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $packageFixture
            } 'Alternate data streams are forbidden'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $packageFixture.Layout.StateDirectory)) 'Package ADS rejection created session state.'
        }
        finally {
            Remove-Item -LiteralPath $packageFixture.PackagePath -Stream contract -ErrorAction SilentlyContinue
        }

        $directoryFixture = New-PrivatePacmanFixture -Name 'directory-ads' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-Content -LiteralPath $directoryFixture.ProtectedRoot -Stream contract -Value 'synthetic-directory-stream'
        try {
            $null = Assert-PrivatePacmanThrows {
                Get-PrivatePacmanTreeSnapshot -Path $directoryFixture.ProtectedRoot
            } 'Alternate data streams are forbidden'
        }
        finally {
            [IO.File]::Delete($directoryFixture.ProtectedRoot + ':contract')
        }

        $protectedFixture = New-PrivatePacmanFixture -Name 'protected-ads' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        Set-Content -LiteralPath $protectedFixture.SharedFile -Stream contract -Value 'synthetic-stream'
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $protectedFixture
            } 'Alternate data streams are forbidden'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $protectedFixture.Layout.Root)) 'Protected ADS rejection created a private root.'
            $captureFailureEvidence = Get-Content `
                -Raw `
                -LiteralPath (
                    Join-Path $protectedFixture.Layout.EvidenceDirectory 'result.json'
                ) |
                    ConvertFrom-Json
            foreach ($phase in @(
                @($captureFailureEvidence.ProtectedBefore |
                    Where-Object Path -CEQ $protectedFixture.ProtectedRoot)[0],
                @($captureFailureEvidence.ProtectedAfter |
                    Where-Object Path -CEQ $protectedFixture.ProtectedRoot)[0]
            )) {
                Assert-PrivatePacmanEqual `
                    'CaptureFailed' `
                    $phase.CoverageStatus `
                    'Strict protected-root capture failure was not explicit.'
                Assert-PrivatePacmanTest `
                    (-not [string]::IsNullOrWhiteSpace([string]$phase.CaptureError)) `
                    'Strict protected-root capture failure omitted its error.'
            }
            Assert-PrivatePacmanTest `
                (-not $captureFailureEvidence.Success) `
                'Strict protected-root capture failure shaped success.'
        }
        finally {
            Remove-Item -LiteralPath $protectedFixture.SharedFile -Stream contract -ErrorAction SilentlyContinue
        }

        $transientFixture = New-PrivatePacmanFixture -Name 'transient-ads' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $job = Start-PrivatePacmanFixtureJob -Fixture $transientFixture -Mode 'wait'
        try {
            Wait-PrivatePacmanPath -Path $transientFixture.ReadyPath
            Set-Content -LiteralPath $transientFixture.SharedFile -Stream contract -Value 'synthetic-stream'
            Remove-Item -LiteralPath $transientFixture.SharedFile -Stream contract
            [Threading.Thread]::Sleep(150)
            [IO.File]::WriteAllText($transientFixture.GoPath, 'go')
            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Failed
            $evidence = Get-Content `
                -Raw `
                -LiteralPath (Join-Path $transientFixture.Layout.EvidenceDirectory 'result.json') |
                    ConvertFrom-Json
            $before = @($evidence.ProtectedBefore | Where-Object Path -EQ $transientFixture.ProtectedRoot)[0]
            $after = @($evidence.ProtectedAfter | Where-Object Path -EQ $transientFixture.ProtectedRoot)[0]
            Assert-PrivatePacmanTest ($before.Digest -cne $after.Digest) 'Transient ADS did not advance canonical change-time evidence.'
            Assert-PrivatePacmanEqual $before.ContentDigest $after.ContentDigest 'Transient ADS changed default-stream bytes.'
            $events = @(
                $evidence.Watchers |
                    Where-Object Path -EQ $transientFixture.ProtectedRoot |
                    ForEach-Object Changes |
                    Where-Object Path -EQ $transientFixture.SharedFile
            )
            Assert-PrivatePacmanTest ($events.Count -gt 0) 'Transient ADS writes emitted no retained event.'
        }
        finally {
            Remove-Item -LiteralPath $transientFixture.SharedFile -Stream contract -ErrorAction SilentlyContinue
            if (-not [IO.File]::Exists($transientFixture.GoPath)) {
                [IO.File]::WriteAllText($transientFixture.GoPath, 'go')
            }
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'ownership manifests are canonical complete and deterministic' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'manifest-determinism' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        foreach ($name in @(
            'Zlib-tool.pkg.tar.zst',
            'perl-Algorithm-Diff.pkg.tar.zst',
            'perl-authen-sasl.pkg.tar.zst'
        )) {
            [IO.File]::WriteAllText((Join-Path $fixture.PackageRoot $name), "synthetic-$name")
        }
        $ownershipRoot = Split-Path $fixture.OwnershipManifestPath -Parent
        $firstPath = Join-Path $ownershipRoot 'packages-ordered.ownership.json'
        $secondPath = Join-Path $ownershipRoot 'packages-repeat.ownership.json'
        $first = New-PrivatePacmanOwnershipManifest `
            -PackageRoot $fixture.PackageRoot `
            -Owner $fixture.Owner `
            -SessionId $fixture.Layout.SessionId `
            -OutputPath $firstPath
        $second = New-PrivatePacmanOwnershipManifest `
            -PackageRoot $fixture.PackageRoot `
            -Owner $fixture.Owner `
            -SessionId $fixture.Layout.SessionId `
            -OutputPath $secondPath
        Assert-PrivatePacmanEqual `
            ([IO.File]::ReadAllText($firstPath)) `
            ([IO.File]::ReadAllText($secondPath)) `
            'Repeated ownership manifests are not byte deterministic.'
        Assert-PrivatePacmanEqual $first.Sha256 $second.Sha256 'Repeated manifest hash changed.'
        Assert-PrivatePacmanEqual $first.PackageSetSha256 $second.PackageSetSha256 'Repeated package-set hash changed.'

        $parsed = Get-Content -Raw -LiteralPath $secondPath | ConvertFrom-Json
        Assert-PrivatePacmanEqual 'private-pacman-package-ownership/v3' $parsed.Schema 'Ownership schema changed.'
        Assert-PrivatePacmanEqual 'ecdsa-p256-sha256' $parsed.SignatureAlgorithm 'Ownership signature algorithm changed.'
        Assert-PrivatePacmanEqual 'private-pacman-package-set/v1' $parsed.PackageSetCanonicalization 'Package-set canonicalization changed.'
        Assert-PrivatePacmanSequence @(
            'Zlib-tool.pkg.tar.zst'
            'perl-Algorithm-Diff.pkg.tar.zst'
            'perl-authen-sasl.pkg.tar.zst'
            $fixture.PackageRelativePath
        ) @($parsed.Packages | ForEach-Object Path) 'Ownership manifest does not use ordinal package ordering.'
    }

    Invoke-PrivatePacmanTestCase -Name 'package-set framing is versioned injective and field-canonical' -Test {
        $hash = 'a' * 64
        $entry = [pscustomobject][ordered]@{
            Path = 'nested\space name.pkg.tar.zst'
            Length = [int64]42
            Sha256 = $hash
        }
        $canonical = & $module {
            param([object[]] $Package)
            Get-PrivatePacmanPackageSetCanonicalText -Package $Package
        } (, $entry)
        $encodedPath = [Convert]::ToBase64String(
            [Text.UTF8Encoding]::new($false, $true).GetBytes($entry.Path)
        )
        $expected = (
            "private-pacman-package-set/v1`n1`n" +
            $encodedPath +
            [string][char]9 +
            "42" +
            [string][char]9 +
            $hash +
            "`n"
        )
        Assert-PrivatePacmanEqual $expected $canonical 'Package-set canonical bytes changed.'
        $canonicalDigest = & $module {
            param([object[]] $Package)
            Get-PrivatePacmanPackageSetSha256 -Package $Package
        } (, $entry)
        Assert-PrivatePacmanEqual `
            'f02820028481ecd880570e9568d1e898edfbccfc89a531b1b3c548e3eb6e45f5' `
            $canonicalDigest `
            'Versioned package-set digest vector changed.'
        Assert-PrivatePacmanTest `
            (-not $canonical.Contains('`t', [StringComparison]::Ordinal)) `
            'Package-set framing contains a literal backtick-t separator.'
        $record = $canonical.Split("`n")[2].Split([char]9)
        Assert-PrivatePacmanEqual 3 $record.Count 'Package-set record framing is ambiguous.'
        Assert-PrivatePacmanEqual `
            $entry.Path `
            ([Text.UTF8Encoding]::new($false, $true).GetString(
                [Convert]::FromBase64String($record[0])
            )) `
            'Package-set base64 path did not round trip.'
        Assert-PrivatePacmanEqual '42' $record[1] 'Package-set Int64 field changed.'
        Assert-PrivatePacmanEqual $hash $record[2] 'Package-set SHA-256 field changed.'

        $variants = @(
            [pscustomobject][ordered]@{
                Path = 'nested\space-name.pkg.tar.zst'
                Length = [int64]42
                Sha256 = $hash
            },
            [pscustomobject][ordered]@{
                Path = $entry.Path
                Length = [int64]43
                Sha256 = $hash
            },
            [pscustomobject][ordered]@{
                Path = $entry.Path
                Length = [int64]42
                Sha256 = 'b' * 64
            }
        )
        foreach ($variant in $variants) {
            $variantCanonical = & $module {
                param([object[]] $Package)
                Get-PrivatePacmanPackageSetCanonicalText -Package $Package
            } (, $variant)
            Assert-PrivatePacmanTest `
                ($variantCanonical -cne $canonical) `
                'Distinct package fields produced identical canonical framing.'
        }

        $invalidEntries = @(
            [pscustomobject][ordered]@{
                Value = [pscustomobject][ordered]@{
                    Path = "bad`tfield.pkg.tar.zst"
                    Length = [int64]1
                    Sha256 = $hash
                }
                Pattern = 'Path|control|canonical'
            },
            [pscustomobject][ordered]@{
                Value = [pscustomobject][ordered]@{
                    Path = $entry.Path
                    Length = [int32]1
                    Sha256 = $hash
                }
                Pattern = 'nonnegative Int64'
            },
            [pscustomobject][ordered]@{
                Value = [pscustomobject][ordered]@{
                    Path = $entry.Path
                    Length = [int64]-1
                    Sha256 = $hash
                }
                Pattern = 'nonnegative Int64'
            },
            [pscustomobject][ordered]@{
                Value = [pscustomobject][ordered]@{
                    Path = $entry.Path
                    Length = [int64]1
                    Sha256 = $hash.ToUpperInvariant()
                }
                Pattern = 'lowercase SHA-256'
            }
        )
        foreach ($invalid in $invalidEntries) {
            $null = Assert-PrivatePacmanThrows {
                & $module {
                    param([object[]] $Package)
                    Get-PrivatePacmanPackageSetCanonicalText -Package $Package
                } (, $invalid.Value)
            } $invalid.Pattern
        }
    }

    Invoke-PrivatePacmanTestCase -Name 'public key curve and ownership text framing are exact' -Test {
        $nistText = $script:signingKey.ExportSubjectPublicKeyInfoPem()
        $nistRecord = & $module {
            param([byte[]] $Bytes)
            Open-PrivatePacmanCanonicalPublicKey -Bytes $Bytes
        } ([Text.UTF8Encoding]::new($false, $true).GetBytes($nistText))
        try {
            Assert-PrivatePacmanEqual `
                '1.2.840.10045.3.1.7' `
                $nistRecord.CurveOid `
                'Canonical NIST P-256 key was not accepted with the exact curve OID.'
        }
        finally {
            $nistRecord.Key.Dispose()
        }

        $brainpool = [Security.Cryptography.ECDsa]::Create(
            [Security.Cryptography.ECCurve]::CreateFromFriendlyName(
                'brainpoolP256r1'
            )
        )
        try {
            $brainpoolFixture = New-PrivatePacmanFixture `
                -Name 'brainpool-key' `
                -SuiteRoot $suiteRoot `
                -RecorderPath $recorderPath
            Set-PrivatePacmanFixtureSigningKey `
                -Fixture $brainpoolFixture `
                -SigningKey $brainpool
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $brainpoolFixture
            } 'curve OID.*1\.2\.840\.10045\.3\.1\.7'
            Assert-PrivatePacmanTest `
                (-not (Test-Path -LiteralPath $brainpoolFixture.Layout.StateDirectory)) `
                'Brainpool curve rejection created session state.'
        }
        finally {
            $brainpool.Dispose()
        }

        $keyCases = @(
            [pscustomobject][ordered]@{
                Name = 'private-key-label'
                Text = $script:signingKey.ExportPkcs8PrivateKeyPem()
            },
            [pscustomobject][ordered]@{
                Name = 'ec-private-key-label'
                Text = $script:signingKey.ExportECPrivateKeyPem()
            },
            [pscustomobject][ordered]@{
                Name = 'multiple-public-objects'
                Text = $nistText + "`n" + $nistText
            },
            [pscustomobject][ordered]@{
                Name = 'trailing-newline'
                Text = $nistText + "`n"
            },
            [pscustomobject][ordered]@{
                Name = 'trailing-payload'
                Text = $nistText + "payload"
            },
            [pscustomobject][ordered]@{
                Name = 'unsupported-public-label'
                Text = $nistText.Replace('PUBLIC KEY', 'EC PUBLIC KEY')
            },
            [pscustomobject][ordered]@{
                Name = 'malformed-public-base64'
                Text = $nistText.Replace("MFkw", "MFk!")
            }
        )
        foreach ($keyCase in $keyCases) {
            $fixture = New-PrivatePacmanFixture `
                -Name $keyCase.Name `
                -SuiteRoot $suiteRoot `
                -RecorderPath $recorderPath
            Set-PrivatePacmanFixturePublicKeyText `
                -Fixture $fixture `
                -Text $keyCase.Text
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $fixture
            } 'one canonical LF-only PUBLIC KEY PEM object|canonical subject-public-key-info'
            Assert-PrivatePacmanTest `
                (-not (Test-Path -LiteralPath $fixture.Layout.StateDirectory)) `
                "Rejected public-key form created session state: $($keyCase.Name)"
        }

        $signatureCases = @(
            [pscustomobject][ordered]@{
                Name = 'signature-extra-newline'
                Transform = { param($Base64) $Base64 + "`n`n" }
            },
            [pscustomobject][ordered]@{
                Name = 'signature-crlf'
                Transform = { param($Base64) $Base64 + "`r`n" }
            },
            [pscustomobject][ordered]@{
                Name = 'signature-missing-lf'
                Transform = { param($Base64) $Base64 }
            },
            [pscustomobject][ordered]@{
                Name = 'signature-trailing-payload'
                Transform = { param($Base64) $Base64 + "`nextra" }
            }
        )
        foreach ($signatureCase in $signatureCases) {
            $fixture = New-PrivatePacmanFixture `
                -Name $signatureCase.Name `
                -SuiteRoot $suiteRoot `
                -RecorderPath $recorderPath
            $base64 = [IO.File]::ReadAllText(
                $fixture.OwnershipSignaturePath
            ).TrimEnd("`n")
            [IO.File]::WriteAllText(
                $fixture.OwnershipSignaturePath,
                (& $signatureCase.Transform $base64),
                [Text.UTF8Encoding]::new($false)
            )
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $fixture
            } 'canonical base64 value followed by one LF'
            Assert-PrivatePacmanTest `
                (-not (Test-Path -LiteralPath $fixture.Layout.StateDirectory)) `
                "Rejected signature framing created session state: $($signatureCase.Name)"
        }

        $noncanonicalFixture = New-PrivatePacmanFixture `
            -Name 'signature-noncanonical-base64' `
            -SuiteRoot $suiteRoot `
            -RecorderPath $recorderPath
        $canonicalBase64 = $null
        for ($attempt = 0; $attempt -lt 16; $attempt++) {
            $signature = $script:signingKey.SignData(
                [IO.File]::ReadAllBytes($noncanonicalFixture.OwnershipManifestPath),
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
            )
            $candidate = [Convert]::ToBase64String($signature)
            if ($candidate.EndsWith('=', [StringComparison]::Ordinal)) {
                $canonicalBase64 = $candidate
                break
            }
        }
        Assert-PrivatePacmanTest `
            ($null -ne $canonicalBase64) `
            'Unable to generate a padded DER signature for the noncanonical base64 regression.'
        $noncanonicalBase64 = Get-PrivatePacmanNoncanonicalBase64 `
            -Canonical $canonicalBase64
        Assert-PrivatePacmanSequence `
            ([byte[]][Convert]::FromBase64String($canonicalBase64)) `
            ([byte[]][Convert]::FromBase64String($noncanonicalBase64)) `
            'Noncanonical base64 vector did not preserve raw signature bytes.'
        [IO.File]::WriteAllText(
            $noncanonicalFixture.OwnershipSignaturePath,
            $noncanonicalBase64 + "`n",
            [Text.UTF8Encoding]::new($false)
        )
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $noncanonicalFixture
        } 'not in canonical RFC 4648 form'
    }

    Invoke-PrivatePacmanTestCase -Name 'ownership hash signature key owner completeness and traversal are enforced' -Test {
        $hashFixture = New-PrivatePacmanFixture -Name 'manifest-hash' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        [IO.File]::AppendAllText($hashFixture.OwnershipManifestPath, " ")
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $hashFixture
        } 'ExpectedManifestSha256'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $hashFixture.Layout.StateDirectory)) 'Manifest-hash rejection created session state.'

        $signatureFixture = New-PrivatePacmanFixture -Name 'manifest-signature' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $wrongSignature = $script:signingKey.SignData(
            [Text.Encoding]::UTF8.GetBytes('wrong manifest bytes'),
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
        )
        [IO.File]::WriteAllText(
            $signatureFixture.OwnershipSignaturePath,
            [Convert]::ToBase64String($wrongSignature) + "`n",
            [Text.UTF8Encoding]::new($false)
        )
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $signatureFixture
        } 'signature is invalid'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $signatureFixture.Layout.StateDirectory)) 'Signature rejection created session state.'

        $keyFixture = New-PrivatePacmanFixture -Name 'manifest-key' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $keyFixture.ExpectedPublicKeySha256 = '0' * 64
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $keyFixture
        } 'ExpectedPublicKeySha256'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $keyFixture.Layout.StateDirectory)) 'Public-key rejection created session state.'

        $uppercaseHashFixture = New-PrivatePacmanFixture -Name 'manifest-uppercase-hash' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $uppercaseHashFixture.ExpectedManifestSha256 = $uppercaseHashFixture.ExpectedManifestSha256.ToUpperInvariant()
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $uppercaseHashFixture
        } 'lowercase SHA-256'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $uppercaseHashFixture.Layout.StateDirectory)) 'Uppercase-hash rejection created session state.'

        $duplicateFixture = New-PrivatePacmanFixture -Name 'manifest-duplicate-key' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $duplicateText = [IO.File]::ReadAllText(
            $duplicateFixture.OwnershipManifestPath
        )
        $ownerField = '"Owner":"' + $duplicateFixture.Owner + '"'
        $duplicateText = $duplicateText.Replace(
            $ownerField,
            $ownerField + ',' + $ownerField
        )
        Set-PrivatePacmanFixtureManifest `
            -Fixture $duplicateFixture `
            -ManifestText $duplicateText
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $duplicateFixture
        } 'canonical deterministic form|property set'
        Assert-PrivatePacmanTest `
            (-not (Test-Path -LiteralPath $duplicateFixture.Layout.StateDirectory)) `
            'Duplicate-key rejection created session state.'

        $typeFixture = New-PrivatePacmanFixture -Name 'manifest-field-type' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $typeManifest = Get-Content `
            -Raw `
            -LiteralPath $typeFixture.OwnershipManifestPath |
                ConvertFrom-Json
        $typeManifest.Packages[0].Length = [string]$typeManifest.Packages[0].Length
        Set-PrivatePacmanFixtureManifest `
            -Fixture $typeFixture `
            -ManifestText (($typeManifest | ConvertTo-Json -Depth 8 -Compress) + "`n")
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $typeFixture
        } 'noncanonical JSON field types'
        Assert-PrivatePacmanTest `
            (-not (Test-Path -LiteralPath $typeFixture.Layout.StateDirectory)) `
            'JSON field-type rejection created session state.'

        $algorithmFixture = New-PrivatePacmanFixture -Name 'manifest-algorithm' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $algorithmManifest = Get-Content `
            -Raw `
            -LiteralPath $algorithmFixture.OwnershipManifestPath |
                ConvertFrom-Json
        $algorithmManifest.SignatureAlgorithm = 'ecdsa-p384-sha384'
        Set-PrivatePacmanFixtureManifest `
            -Fixture $algorithmFixture `
            -ManifestText (
                ($algorithmManifest | ConvertTo-Json -Depth 8 -Compress) + "`n"
            )
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $algorithmFixture
        } 'signature algorithm.*unsupported'
        Assert-PrivatePacmanTest `
            (-not (Test-Path -LiteralPath $algorithmFixture.Layout.StateDirectory)) `
            'Signature-algorithm rejection created session state.'

        $utf8Fixture = New-PrivatePacmanFixture -Name 'manifest-invalid-utf8' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $validBytes = [IO.File]::ReadAllBytes($utf8Fixture.OwnershipManifestPath)
        $invalidBytes = [byte[]]::new($validBytes.Length + 1)
        [Array]::Copy($validBytes, 0, $invalidBytes, 0, $validBytes.Length - 1)
        $invalidBytes[$validBytes.Length - 1] = 0xff
        $invalidBytes[$validBytes.Length] = 0x0a
        [IO.File]::WriteAllBytes(
            $utf8Fixture.OwnershipManifestPath,
            $invalidBytes
        )
        $invalidSignature = $script:signingKey.SignData(
            $invalidBytes,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
        )
        [IO.File]::WriteAllText(
            $utf8Fixture.OwnershipSignaturePath,
            [Convert]::ToBase64String($invalidSignature) + "`n",
            [Text.UTF8Encoding]::new($false)
        )
        $utf8Fixture.ExpectedManifestSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($invalidBytes)
        ).ToLowerInvariant()
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $utf8Fixture
        } 'Unable to translate bytes|UTF-8|invalid'
        Assert-PrivatePacmanTest `
            (-not (Test-Path -LiteralPath $utf8Fixture.Layout.StateDirectory)) `
            'Invalid UTF-8 rejection created session state.'

        $ownerFixture = New-PrivatePacmanFixture -Name 'manifest-owner' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $ownerFixture.Owner = 'other-owner'
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $ownerFixture
        } 'owner or session binding'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $ownerFixture.Layout.StateDirectory)) 'Owner rejection created session state.'

        $completeFixture = New-PrivatePacmanFixture -Name 'manifest-complete' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        [IO.File]::WriteAllText(
            (Join-Path $completeFixture.PackageRoot 'unlisted.pkg.tar.zst'),
            'unlisted synthetic bytes'
        )
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $completeFixture
        } 'complete PackageRoot inventory'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $completeFixture.Layout.StateDirectory)) 'Completeness rejection created session state.'

        $traversalFixture = New-PrivatePacmanFixture -Name 'manifest-traversal' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $traversalManifest = Get-Content -Raw -LiteralPath $traversalFixture.OwnershipManifestPath | ConvertFrom-Json
        $traversalManifest.Packages[0].Path = '..\escape.pkg.tar.zst'
        Set-PrivatePacmanFixtureManifest `
            -Fixture $traversalFixture `
            -ManifestText (($traversalManifest | ConvertTo-Json -Depth 8 -Compress) + "`n")
        $null = Assert-PrivatePacmanThrows {
            Invoke-PrivatePacmanFixture -Fixture $traversalFixture
        } 'noncanonical|segment'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $traversalFixture.Layout.StateDirectory)) 'Signed traversal rejection created session state.'
    }

    Invoke-PrivatePacmanTestCase -Name 'traversal is rejected before state creation' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'traversal' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $null = Assert-PrivatePacmanThrows {
            New-PrivatePacmanLayout -WorkspaceRoot $fixture.Workspace -SessionId '..\escape'
        } 'SessionId|traversal'
        $null = Assert-PrivatePacmanThrows {
            & $module {
                ConvertTo-PrivatePacmanRelativePath `
                    -Path '..\escape.pkg.tar.zst' `
                    -Name 'PackagePath'
            }
        } 'noncanonical|PackagePath|segment'
        foreach ($reserved in @(
            'CONIN$.pkg.tar.zst',
            'CONOUT$.pkg.tar.zst'
        )) {
            $null = Assert-PrivatePacmanThrows {
                & $module {
                    param([string] $Path)
                    ConvertTo-PrivatePacmanRelativePath `
                        -Path $Path `
                        -Name 'PackagePath'
                } $reserved
            } 'noncanonical|reserved|segment'
        }
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.StateDirectory)) 'Traversal rejection created external state.'
        Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $fixture.Layout.Root)) 'Traversal rejection created a private root.'
    }

    Invoke-PrivatePacmanTestCase -Name 'package archive extension matching is deliberately case-sensitive' -Test {
        $fixture = New-PrivatePacmanFixture `
            -Name 'package-extension-case' `
            -SuiteRoot $suiteRoot `
            -RecorderPath $recorderPath
        $uppercaseZ = Join-Path $fixture.PackageRoot 'legacy.pkg.tar.Z'
        [IO.File]::WriteAllText(
            $uppercaseZ,
            'synthetic-uppercase-Z',
            [Text.UTF8Encoding]::new($false)
        )
        $acceptedPath = Join-Path (
            [IO.Path]::GetDirectoryName($fixture.OwnershipManifestPath)
        ) 'accepted-extension.ownership.json'
        $accepted = New-PrivatePacmanOwnershipManifest `
            -PackageRoot $fixture.PackageRoot `
            -Owner $fixture.Owner `
            -SessionId $fixture.Layout.SessionId `
            -OutputPath $acceptedPath
        Assert-PrivatePacmanEqual `
            ([int64]2) `
            ([int64]$accepted.PackageCount) `
            'The explicitly supported uppercase .Z extension was rejected.'

        [IO.File]::WriteAllText(
            (Join-Path $fixture.PackageRoot 'ambiguous.pkg.tar.ZST'),
            'synthetic-uppercase-zst',
            [Text.UTF8Encoding]::new($false)
        )
        $rejectedPath = Join-Path (
            [IO.Path]::GetDirectoryName($fixture.OwnershipManifestPath)
        ) 'rejected-extension.ownership.json'
        $null = Assert-PrivatePacmanThrows {
            New-PrivatePacmanOwnershipManifest `
                -PackageRoot $fixture.PackageRoot `
                -Owner $fixture.Owner `
                -SessionId $fixture.Layout.SessionId `
                -OutputPath $rejectedPath
        } 'unowned non-package file'
    }

    Invoke-PrivatePacmanTestCase -Name 'strict snapshots bind ordinary directory and file entries' -Test {
        $fixture = New-PrivatePacmanFixture `
            -Name 'strict-snapshot-regular' `
            -SuiteRoot $suiteRoot `
            -RecorderPath $recorderPath
        $snapshot = Get-PrivatePacmanTreeSnapshot -Path $fixture.ProtectedRoot
        Assert-PrivatePacmanEqual `
            'private-pacman-tree-snapshot/v3' `
            $snapshot.Schema `
            'Strict snapshot schema changed.'
        Assert-PrivatePacmanEqual `
            'reject' `
            $snapshot.ReparsePointPolicy `
            'Strict snapshot reparse policy changed.'
        Assert-PrivatePacmanEqual `
            ([int64]$snapshot.Entries.Count) `
            ([int64]$snapshot.EntryCount) `
            'Strict snapshot entry count is internally inconsistent.'
        Assert-PrivatePacmanTest `
            ([int64]$snapshot.EntryCount -ge 5) `
            'Strict snapshot omitted ordinary directory or file entries.'
        Assert-PrivatePacmanTest `
            (@($snapshot.Entries | Where-Object Kind -CEQ 'directory').Count -gt 0) `
            'Strict snapshot omitted directories.'
        Assert-PrivatePacmanTest `
            (@($snapshot.Entries | Where-Object Kind -CEQ 'file').Count -gt 0) `
            'Strict snapshot omitted files.'
    }

    Invoke-PrivatePacmanStrictSnapshotReparseCase `
        -Name 'strict snapshots reject junctions without target following' `
        -ItemType Junction `
        -TargetKind Directory `
        -SuiteRoot $suiteRoot
    Invoke-PrivatePacmanStrictSnapshotReparseCase `
        -Name 'strict snapshots reject directory symlinks without target following' `
        -ItemType SymbolicLink `
        -TargetKind Directory `
        -SuiteRoot $suiteRoot
    Invoke-PrivatePacmanStrictSnapshotReparseCase `
        -Name 'strict snapshots reject file symlinks without target following' `
        -ItemType SymbolicLink `
        -TargetKind File `
        -SuiteRoot $suiteRoot

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

    Invoke-PrivatePacmanTestCase -Name 'workspace seed and protected reparse escapes are rejected' -Test {
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
                    -OwnershipManifestPath $fixture.OwnershipManifestPath `
                    -OwnershipSignaturePath $fixture.OwnershipSignaturePath `
                    -OwnershipPublicKeyPath $fixture.OwnershipPublicKeyPath `
                    -ExpectedManifestSha256 $fixture.ExpectedManifestSha256 `
                    -ExpectedPublicKeySha256 $fixture.ExpectedPublicKeySha256 `
                    -ExpectedOwner $fixture.Owner `
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

        $protectedFixture = New-PrivatePacmanFixture -Name 'protected-reparse' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
        $protectedTarget = Join-Path $protectedFixture.Base 'outside-protected'
        [void][IO.Directory]::CreateDirectory($protectedTarget)
        $protectedCanary = Join-Path $protectedTarget 'canary'
        [IO.File]::WriteAllText($protectedCanary, 'protected-target')
        $protectedJunction = Join-Path $protectedFixture.ProtectedRoot 'escape'
        $null = New-Item -ItemType Junction -Path $protectedJunction -Target $protectedTarget
        try {
            $null = Assert-PrivatePacmanThrows {
                Invoke-PrivatePacmanFixture -Fixture $protectedFixture
            } 'Reparse points are forbidden'
            Assert-PrivatePacmanEqual 'protected-target' ([IO.File]::ReadAllText($protectedCanary)) 'Protected reparse target was modified.'
            Assert-PrivatePacmanTest (-not (Test-Path -LiteralPath $protectedFixture.Layout.Root)) 'Protected reparse rejection created a private root.'
        }
        finally {
            if ([IO.Directory]::Exists($protectedJunction)) {
                [IO.Directory]::Delete($protectedJunction, $false)
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
                    -OwnershipManifestPath $fixture.OwnershipManifestPath `
                    -OwnershipSignaturePath $fixture.OwnershipSignaturePath `
                    -OwnershipPublicKeyPath $fixture.OwnershipPublicKeyPath `
                    -ExpectedManifestSha256 $fixture.ExpectedManifestSha256 `
                    -ExpectedPublicKeySha256 $fixture.ExpectedPublicKeySha256 `
                    -ExpectedOwner $fixture.Owner `
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
                -OwnershipManifestPath $fixture.OwnershipManifestPath `
                -OwnershipSignaturePath $fixture.OwnershipSignaturePath `
                -OwnershipPublicKeyPath $fixture.OwnershipPublicKeyPath `
                -ExpectedManifestSha256 $fixture.ExpectedManifestSha256 `
                -ExpectedPublicKeySha256 $fixture.ExpectedPublicKeySha256 `
                -ExpectedOwner $fixture.Owner `
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
            Assert-PrivatePacmanTest ($before.Digest -cne $after.Digest) 'Transient drift did not advance canonical change-time evidence.'
            Assert-PrivatePacmanEqual $before.ContentDigest $after.ContentDigest 'Transient drift did not restore default-stream bytes.'
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
        $original = [IO.File]::ReadAllBytes($fixture.SharedFile)
        $barrierEntered = Join-Path $fixture.Base 'before-snapshot-entered'
        $barrierRelease = Join-Path $fixture.Base 'before-snapshot-release'
        $job = Start-PrivatePacmanFixtureJob `
            -Fixture $fixture `
            -Mode 'wait' `
            -SnapshotBarrierRoot $fixture.ProtectedRoot `
            -SnapshotBarrierEnteredPath $barrierEntered `
            -SnapshotBarrierReleasePath $barrierRelease
        try {
            $protectedManifest = Join-Path $fixture.Layout.EvidenceDirectory 'protected-1-before.json'
            Wait-PrivatePacmanPath -Path $barrierEntered
            Assert-PrivatePacmanTest `
                (-not [IO.File]::Exists($protectedManifest)) `
                'Protected before snapshot escaped its deterministic test barrier.'
            for ($index = 0; $index -lt 3; $index++) {
                [IO.File]::WriteAllText($fixture.SharedFile, "before-snapshot-drift-$index")
                [IO.File]::WriteAllBytes($fixture.SharedFile, $original)
            }
            [IO.File]::WriteAllText($barrierRelease, 'release')

            $null = Wait-PrivatePacmanFixtureJob -Job $job -ExpectedState Failed

            $evidence = Get-Content `
                -Raw `
                -LiteralPath (Join-Path $fixture.Layout.EvidenceDirectory 'result.json') |
                    ConvertFrom-Json
            Assert-PrivatePacmanTest ($null -eq $evidence.Invocation.Process) 'Unstable before evidence reached the native process boundary.'
            Assert-PrivatePacmanTest (
                @($evidence.Failures | Where-Object { $_ -match 'not stable before monitoring' }).Count -eq 1
            ) 'Before-snapshot drift did not fail the preflight-to-authoritative digest comparison.'
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
            if (-not [IO.File]::Exists($barrierRelease)) {
                [IO.File]::WriteAllText($barrierRelease, 'release')
            }
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
                Invoke-PrivatePacmanFixture -Fixture $fixture -TimeoutSeconds 120
            } 'exited with code|failed closed'
            $resultPath = Join-Path $fixture.Layout.EvidenceDirectory 'result.json'
            $evidence = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
            Assert-PrivatePacmanTest (-not $evidence.Success) 'Child crash was reported as success.'
            Assert-PrivatePacmanTest (Test-Path -LiteralPath $fixture.ArgvPath) 'Child crash test never crossed the native process boundary.'
            Assert-PrivatePacmanTest ($null -ne $evidence.Invocation.Process) 'Child crash produced no process evidence.'
            Assert-PrivatePacmanTest (-not $evidence.Invocation.Process.TimedOut) 'Child crash degraded into the timeout path.'
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
    [string] $OwnershipManifestPath,
    [string] $OwnershipSignaturePath,
    [string] $OwnershipPublicKeyPath,
    [string] $ExpectedManifestSha256,
    [string] $ExpectedPublicKeySha256,
    [string] $ExpectedOwner,
    [string] $ProtectedRoot,
    [string] $CanonicalSharedRoot,
    [string] $ArgvPath,
    [string] $ConfigCapturePath,
    [string] $EnvironmentPath,
    [string] $ReadyPath,
    [string] $GoPath
)
$ErrorActionPreference = 'Stop'
$privatePacmanModule = Import-Module $ModulePath -Force -PassThru
& $privatePacmanModule {
    param([string] $Path)
    $script:CanonicalSharedRoot = $Path
} $CanonicalSharedRoot
& $privatePacmanModule {
    param([Collections.IDictionary] $Values)
    $script:TestChildEnvironment = $Values
} ([ordered]@{
    PRIVATE_PACMAN_TEST_ARGV = $ArgvPath
    PRIVATE_PACMAN_TEST_CONFIG = $ConfigCapturePath
    PRIVATE_PACMAN_TEST_ENVIRONMENT = $EnvironmentPath
    PRIVATE_PACMAN_TEST_GO = $GoPath
    PRIVATE_PACMAN_TEST_MODE = 'wait'
    PRIVATE_PACMAN_TEST_READY = $ReadyPath
})
$layout = New-PrivatePacmanLayout -WorkspaceRoot $Workspace -SessionId $SessionId
Invoke-PrivatePacmanUpgrade `
    -Layout $layout `
    -SeedRoot $Seed `
    -PackageRoot $PackageRoot `
    -OwnershipManifestPath $OwnershipManifestPath `
    -OwnershipSignaturePath $OwnershipSignaturePath `
    -OwnershipPublicKeyPath $OwnershipPublicKeyPath `
    -ExpectedManifestSha256 $ExpectedManifestSha256 `
    -ExpectedPublicKeySha256 $ExpectedPublicKeySha256 `
    -ExpectedOwner $ExpectedOwner `
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
            '-OwnershipManifestPath', $fixture.OwnershipManifestPath,
            '-OwnershipSignaturePath', $fixture.OwnershipSignaturePath,
            '-OwnershipPublicKeyPath', $fixture.OwnershipPublicKeyPath,
            '-ExpectedManifestSha256', $fixture.ExpectedManifestSha256,
            '-ExpectedPublicKeySha256', $fixture.ExpectedPublicKeySha256,
            '-ExpectedOwner', $fixture.Owner,
            '-ProtectedRoot', $fixture.ProtectedRoot,
            '-CanonicalSharedRoot', $script:testCanonicalSharedRoot,
            '-ArgvPath', $fixture.ArgvPath,
            '-ConfigCapturePath', $fixture.ConfigCapturePath,
            '-EnvironmentPath', $fixture.EnvironmentPath,
            '-ReadyPath', $fixture.ReadyPath,
            '-GoPath', $fixture.GoPath
        )) {
            [void]$startInfo.ArgumentList.Add($argument)
        }

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
    $script:signingKey.Dispose()

    if ([IO.Directory]::Exists($suiteRoot)) {
        try {
            Remove-Item -LiteralPath $suiteRoot -Recurse -Force -ErrorAction Stop
        }
        catch {
            $suiteCleanupError = $_.Exception.ToString()
        }
    }
    if ([IO.Directory]::Exists($suiteRoot)) {
        $residue = "Suite directory remains after cleanup: $suiteRoot"
        $suiteCleanupError = if ([string]::IsNullOrWhiteSpace($suiteCleanupError)) {
            $residue
        }
        else {
            $suiteCleanupError + "`n" + $residue
        }
    }
    $sharedAfterCapture = Get-PrivatePacmanGuardedTreeSnapshot -Path 'C:\msys64' -AllowMissing
}

$sharedBefore = $sharedBeforeCapture.Snapshot
$sharedAfter = $sharedAfterCapture.Snapshot
$sharedCaptureErrors = @(
    if (-not [string]::IsNullOrWhiteSpace([string]$sharedBeforeCapture.Error)) {
        "Before snapshot failed: $($sharedBeforeCapture.Error)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$sharedAfterCapture.Error)) {
        "After snapshot failed: $($sharedAfterCapture.Error)"
    }
)
$sharedCoverageStatus = if (
    $sharedCaptureErrors.Count -ne 0 -or
    $null -eq $sharedBefore -or
    $null -eq $sharedAfter
) {
    'CaptureFailed'
}
elseif ($sharedBefore.Exists -or $sharedAfter.Exists) {
    'Covered'
}
else {
    'NotCovered'
}
$sharedIdentical = if ($sharedCoverageStatus -ceq 'Covered') {
    (
        $sharedBefore.Exists -and
        $sharedAfter.Exists -and
        [int64]$sharedBefore.EntryCount -eq [int64]$sharedAfter.EntryCount -and
        $sharedBefore.Digest -ceq $sharedAfter.Digest -and
        $sharedBefore.ContentDigest -ceq $sharedAfter.ContentDigest
    )
}
else {
    $null
}

if (-not [string]::IsNullOrWhiteSpace($suiteCleanupError)) {
    Invoke-PrivatePacmanTestCase -Name 'suite leaves no private temporary root' -Test {
        throw $suiteCleanupError
    }
}
else {
    Invoke-PrivatePacmanTestCase -Name 'suite leaves no private temporary root' -Test {
        Assert-PrivatePacmanTest `
            (-not [IO.Directory]::Exists($suiteRoot)) `
            'Suite temporary root remains after cleanup.'
    }
}

if ($sharedCoverageStatus -ceq 'CaptureFailed') {
    Invoke-PrivatePacmanTestCase `
        -Name 'literal C:\msys64 suite coverage is strict and countable' `
        -Test {
            throw ($sharedCaptureErrors -join "`n")
        }
}
elseif ($sharedCoverageStatus -ceq 'NotCovered') {
    Add-PrivatePacmanSkippedTestCase `
        -Name 'literal C:\msys64 suite coverage is strict and countable' `
        -Reason 'C:\msys64 does not exist; missing state is reported as not covered.'
}
else {
    Invoke-PrivatePacmanTestCase `
        -Name 'literal C:\msys64 suite coverage is strict and countable' `
        -Test {
            Assert-PrivatePacmanTest `
                ([int64]$sharedBefore.EntryCount -ge 0) `
                'Literal shared-root before count is negative.'
            Assert-PrivatePacmanEqual `
                ([int64]$sharedBefore.Entries.Count) `
                ([int64]$sharedBefore.EntryCount) `
                'Literal shared-root before count is internally inconsistent.'
            Assert-PrivatePacmanEqual `
                ([int64]$sharedAfter.Entries.Count) `
                ([int64]$sharedAfter.EntryCount) `
                'Literal shared-root after count is internally inconsistent.'
            Assert-PrivatePacmanEqual `
                ([int64]$sharedBefore.EntryCount) `
                ([int64]$sharedAfter.EntryCount) `
                'Literal shared-root entry count changed during the suite.'
            Assert-PrivatePacmanTest `
                ([bool]$sharedIdentical) `
                'Literal shared package state changed during the contract suite.'
        }
}

if ($null -eq $script:populatedSharedEvidence) {
    Invoke-PrivatePacmanTestCase `
        -Name 'populated shared-state report evidence is present' `
        -Test {
            throw 'The populated protected-root test did not publish report evidence.'
        }
}

if ($null -eq $script:canonicalTransactionEvidence) {
    $script:canonicalTransactionEvidence = [pscustomobject][ordered]@{
        Path = 'C:\msys64'
        CoverageStatus = 'CaptureFailed'
        ExistedBefore = $null
        ExistedAfter = $null
        EntryCountBefore = $null
        EntryCountAfter = $null
        BeforeDigest = $null
        AfterDigest = $null
        BeforeContentDigest = $null
        AfterContentDigest = $null
        ByteAndMetadataIdentical = $null
    }
    Invoke-PrivatePacmanTestCase `
        -Name 'canonical C:\msys64 transaction evidence is present' `
        -Test {
            throw 'The native-boundary transaction did not publish canonical shared-root evidence.'
        }
}

$passed = @($results | Where-Object Status -CEQ 'Passed')
$failed = @($results | Where-Object Status -CEQ 'Failed')
$skipped = @($results | Where-Object Status -CEQ 'Skipped')
$report = [pscustomobject][ordered]@{
    Schema = 'private-pacman-contract-tests/v3'
    EvidenceAuthority = 'self-reported-diagnostic-only'
    AdmissionReady = $false
    StartedFrom = $PSScriptRoot
    PowerShell = $PSVersionTable.PSVersion.ToString()
    CanonicalSharedState = [pscustomobject][ordered]@{
        Path = 'C:\msys64'
        CoverageStatus = $sharedCoverageStatus
        BeforeCaptureSucceeded = $null -ne $sharedBefore
        AfterCaptureSucceeded = $null -ne $sharedAfter
        BeforeCaptureError = $sharedBeforeCapture.Error
        AfterCaptureError = $sharedAfterCapture.Error
        ExistedBefore = if ($null -ne $sharedBefore) { $sharedBefore.Exists } else { $null }
        ExistedAfter = if ($null -ne $sharedAfter) { $sharedAfter.Exists } else { $null }
        EntryCountBefore = if ($null -ne $sharedBefore) {
            [int64]$sharedBefore.EntryCount
        }
        else {
            $null
        }
        EntryCountAfter = if ($null -ne $sharedAfter) {
            [int64]$sharedAfter.EntryCount
        }
        else {
            $null
        }
        BeforeDigest = if ($null -ne $sharedBefore) { $sharedBefore.Digest } else { $null }
        AfterDigest = if ($null -ne $sharedAfter) { $sharedAfter.Digest } else { $null }
        BeforeContentDigest = if ($null -ne $sharedBefore) { $sharedBefore.ContentDigest } else { $null }
        AfterContentDigest = if ($null -ne $sharedAfter) { $sharedAfter.ContentDigest } else { $null }
        ByteAndMetadataIdentical = $sharedIdentical
    }
    CanonicalTransactionState = $script:canonicalTransactionEvidence
    PopulatedSharedState = $script:populatedSharedEvidence
    Summary = [pscustomobject][ordered]@{
        Total = $results.Count
        Passed = $passed.Count
        Failed = $failed.Count
        Skipped = $skipped.Count
        LiteralCoverageStatus = $sharedCoverageStatus
        TransactionCoverageStatus = $script:canonicalTransactionEvidence.CoverageStatus
    }
    Passed = $passed.Count
    Failed = $failed.Count
    Skipped = $skipped.Count
    Tests = @($results)
}

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $reportDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ReportPath))
    [void][IO.Directory]::CreateDirectory($reportDirectory)
    $reportJson = (
        ($report | ConvertTo-Json -Depth 10).
            Replace("`r`n", "`n").
            Replace("`r", "`n") +
        "`n"
    )
    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($ReportPath),
        $reportJson,
        [Text.UTF8Encoding]::new($false)
    )
}

Write-Host "CANONICAL_SHARED_STATE CoverageStatus=$($report.CanonicalSharedState.CoverageStatus) BeforeCaptureSucceeded=$($report.CanonicalSharedState.BeforeCaptureSucceeded) AfterCaptureSucceeded=$($report.CanonicalSharedState.AfterCaptureSucceeded) ExistedBefore=$($report.CanonicalSharedState.ExistedBefore) ExistedAfter=$($report.CanonicalSharedState.ExistedAfter) EntryCountBefore=$($report.CanonicalSharedState.EntryCountBefore) EntryCountAfter=$($report.CanonicalSharedState.EntryCountAfter) BeforeDigest=$($report.CanonicalSharedState.BeforeDigest) AfterDigest=$($report.CanonicalSharedState.AfterDigest)"
if ($null -ne $report.CanonicalTransactionState) {
    Write-Host "CANONICAL_TRANSACTION_STATE CoverageStatus=$($report.CanonicalTransactionState.CoverageStatus) ExistedBefore=$($report.CanonicalTransactionState.ExistedBefore) ExistedAfter=$($report.CanonicalTransactionState.ExistedAfter) EntryCountBefore=$($report.CanonicalTransactionState.EntryCountBefore) EntryCountAfter=$($report.CanonicalTransactionState.EntryCountAfter) BeforeDigest=$($report.CanonicalTransactionState.BeforeDigest) AfterDigest=$($report.CanonicalTransactionState.AfterDigest)"
}
if ($null -ne $report.PopulatedSharedState) {
    Write-Host "POPULATED_SHARED_STATE ExistedBefore=$($report.PopulatedSharedState.ExistedBefore) ExistedAfter=$($report.PopulatedSharedState.ExistedAfter) EntryCountBefore=$($report.PopulatedSharedState.EntryCountBefore) EntryCountAfter=$($report.PopulatedSharedState.EntryCountAfter) BeforeDigest=$($report.PopulatedSharedState.BeforeDigest) AfterDigest=$($report.PopulatedSharedState.AfterDigest)"
}
Write-Host "$($report.Passed) passed, $($report.Failed) failed, $($report.Skipped) skipped"
if ($failed.Count -ne 0) {
    throw "$($failed.Count) private pacman contract test(s) failed."
}

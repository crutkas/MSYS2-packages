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
        [string] $Mode
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
                $OwnershipManifestPath,
                $OwnershipSignaturePath,
                $OwnershipPublicKeyPath,
                $ExpectedManifestSha256,
                $ExpectedPublicKeySha256,
                $ExpectedOwner,
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
$script:populatedSharedEvidence = $null
$recorderPath = $null
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

    Invoke-PrivatePacmanTestCase -Name 'repository-free argv is completely isolated' -Test {
        $fixture = New-PrivatePacmanFixture -Name 'argv' -SuiteRoot $suiteRoot -RecorderPath $recorderPath
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
            Assert-PrivatePacmanEqual $fixture.PackageSetSha256 $result.Ownership.PackageSetSha256 'Deterministic package-set hash changed.'
            Assert-PrivatePacmanEqual ([int64]1) ([int64]$result.Ownership.PackageCount) 'Ownership evidence has the wrong package count.'
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
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Restored metadata did not return to the original canonical digest.'
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
            Assert-PrivatePacmanEqual $before.Digest $after.Digest 'Transient ADS test did not restore canonical state.'
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
        Assert-PrivatePacmanEqual 'private-pacman-package-ownership/v2' $parsed.Schema 'Ownership schema changed.'
        Assert-PrivatePacmanEqual 'ecdsa-p256-sha256' $parsed.SignatureAlgorithm 'Ownership signature algorithm changed.'
        Assert-PrivatePacmanSequence @(
            'Zlib-tool.pkg.tar.zst'
            'perl-Algorithm-Diff.pkg.tar.zst'
            'perl-authen-sasl.pkg.tar.zst'
            $fixture.PackageRelativePath
        ) @($parsed.Packages | ForEach-Object Path) 'Ownership manifest does not use ordinal package ordering.'
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
    [string] $OwnershipManifestPath,
    [string] $OwnershipSignaturePath,
    [string] $OwnershipPublicKeyPath,
    [string] $ExpectedManifestSha256,
    [string] $ExpectedPublicKeySha256,
    [string] $ExpectedOwner,
    [string] $ProtectedRoot
)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
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
    $script:signingKey.Dispose()

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

if ($null -eq $script:populatedSharedEvidence) {
    $results.Add([pscustomobject][ordered]@{
        Name = 'populated shared-state report evidence is present'
        Passed = $false
        DurationMilliseconds = 0
        Error = 'The populated protected-root test did not publish report evidence.'
    })
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
        BeforeContentDigest = $sharedBefore.ContentDigest
        AfterContentDigest = $sharedAfter.ContentDigest
        ByteAndMetadataIdentical = $sharedIdentical
    }
    PopulatedSharedState = $script:populatedSharedEvidence
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

Write-Host "CANONICAL_SHARED_STATE ExistedBefore=$($report.CanonicalSharedState.ExistedBefore) ExistedAfter=$($report.CanonicalSharedState.ExistedAfter) BeforeDigest=$($report.CanonicalSharedState.BeforeDigest) AfterDigest=$($report.CanonicalSharedState.AfterDigest)"
if ($null -ne $report.PopulatedSharedState) {
    Write-Host "POPULATED_SHARED_STATE ExistedBefore=$($report.PopulatedSharedState.ExistedBefore) ExistedAfter=$($report.PopulatedSharedState.ExistedAfter) EntryCountBefore=$($report.PopulatedSharedState.EntryCountBefore) EntryCountAfter=$($report.PopulatedSharedState.EntryCountAfter) BeforeDigest=$($report.PopulatedSharedState.BeforeDigest) AfterDigest=$($report.PopulatedSharedState.AfterDigest)"
}
Write-Host "$($report.Passed) passed, $($report.Failed) failed"
if ($failed.Count -ne 0) {
    throw "$($failed.Count) private pacman contract test(s) failed."
}

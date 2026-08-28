[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# THIS IS NOT A PESTER FILE. It is a standalone assertion script and must be run
# directly:
#     pwsh -NoProfile -File .github/policy/tests/private-root.tests.ps1
# Invoke-Pester discovers ZERO tests here and reports "Tests Passed: 0" with
# EXIT CODE 0 -- a CI job wired through Pester would report success while
# running nothing at all. The guard below makes that mistake loud instead of
# silent.
if ($null -ne (Get-Module -Name Pester)) {
    throw 'private-root.tests.ps1 is a standalone assertion script, not a Pester file; run it directly with pwsh -File. Pester discovers zero tests here and would report success while running nothing.'
}

$modulePath = (Resolve-Path (Join-Path $PSScriptRoot '..\PrivateRoot.psm1')).Path
Import-Module $modulePath -Force -ErrorAction Stop

$script:assertions = 0

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool] $Condition,

        [Parameter(Mandatory)]
        [string] $Label
    )

    $script:assertions++
    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock] $Action,

        [Parameter(Mandatory)]
        [string] $Label,

        # Optional substring the rejection reason must contain. Without it a
        # fixture that throws for an unrelated reason would look like a kill,
        # which is how a masked guard survives unnoticed.
        [string] $Match
    )

    $script:assertions++
    $threw = $false
    $reason = ''
    try {
        & $Action | Out-Null
    }
    catch {
        $threw = $true
        $reason = $_.Exception.Message
    }
    if (-not $threw) {
        throw "Expected rejection: $Label"
    }
    if ($Match -and ($reason -notlike "*$Match*")) {
        throw "Rejected for the wrong reason: $Label -- wanted '$Match', got '$reason'"
    }
}

$canonicalTemp = (Get-Item -LiteralPath $env:TEMP -Force).FullName.TrimEnd('\')
$testRoot = Join-Path $canonicalTemp "policy-root-tests-$PID-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null

try {
    Assert-Throws -Label 'relative path' -Action {
        Assert-PolicyLexicalPath -Path 'relative\path' -Label 'test'
    }
    Assert-Throws -Label 'UNC path' -Action {
        Assert-PolicyLexicalPath -Path '\\server\share\root' -Label 'test'
    }
    Assert-Throws -Label 'device path' -Action {
        Assert-PolicyLexicalPath -Path '\\?\C:\root' -Label 'test'
    }
    Assert-Throws -Label 'dot traversal' -Action {
        Assert-PolicyLexicalPath -Path 'C:\safe\..\escape' -Label 'test'
    }
    Assert-Throws -Label 'forward slash' -Action {
        Assert-PolicyLexicalPath -Path 'C:\safe/path' -Label 'test'
    }
    Assert-Throws -Label 'non-NFC component' -Action {
        $decomposed = "C:\cafe$([char]0x0301)"
        Assert-PolicyLexicalPath -Path $decomposed -Label 'test'
    }
    Assert-Throws -Label 'synthetic 8.3 alias' -Action {
        Assert-PolicyExistingDirectory -Path 'C:\PROGRA~1' -Label 'test'
    }

    $lastComponent = Split-Path -Leaf $testRoot
    $wrongCase = Join-Path (Split-Path -Parent $testRoot) $lastComponent.ToUpperInvariant()
    if ($wrongCase -ceq $testRoot) {
        $wrongCase = Join-Path (Split-Path -Parent $testRoot) $lastComponent.ToLowerInvariant()
    }
    Assert-Throws -Label 'case alias' -Action {
        Assert-PolicyExistingDirectory -Path $wrongCase -Label 'test'
    }

    $physical = Join-Path $testRoot 'physical'
    $junction = Join-Path $testRoot 'junction'
    New-Item -ItemType Directory -Path $physical -ErrorAction Stop | Out-Null
    New-Item -ItemType Junction -Path $junction -Target $physical -ErrorAction Stop | Out-Null
    Assert-Throws -Label 'reparse point' -Action {
        Assert-PolicyExistingDirectory -Path $junction -Label 'test'
    }

    $matrixOne = Get-PolicyMatrixDigest -MatrixDiscriminator '{"arch":"arm64"}'
    $matrixTwo = Get-PolicyMatrixDigest -MatrixDiscriminator '{"arch":"x64"}'
    Assert-True -Condition ($matrixOne -cmatch '^[0-9a-f]{64}$') -Label 'matrix digest shape'
    Assert-True -Condition ($matrixOne -cne $matrixTwo) -Label 'matrix discriminator binding'

    $firstPath = Get-PolicyPrivateRootPath `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '1001' `
        -RunAttempt '1' `
        -JobName 'verify' `
        -MatrixDiscriminator '{"arch":"arm64"}'
    $jobPath = Get-PolicyPrivateRootPath `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '1001' `
        -RunAttempt '1' `
        -JobName 'verify_other' `
        -MatrixDiscriminator '{"arch":"arm64"}'
    $attemptPath = Get-PolicyPrivateRootPath `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '1001' `
        -RunAttempt '2' `
        -JobName 'verify' `
        -MatrixDiscriminator '{"arch":"arm64"}'
    Assert-True -Condition ($firstPath -cne $jobPath) -Label 'job binding'
    Assert-True -Condition ($firstPath -cne $attemptPath) -Label 'attempt binding'
    Assert-True -Condition ($firstPath.Contains('\run-1001\attempt-1\job-verify\matrix-')) -Label 'root dimensions'

    New-Item -ItemType Directory -Path $firstPath -Force -ErrorAction Stop | Out-Null
    Assert-Throws -Label 'preexisting root' -Action {
        New-PolicyPrivateRoot `
            -RunnerTemp $testRoot `
            -RepositoryId '1333319488' `
            -RunId '1001' `
            -RunAttempt '1' `
            -JobName 'verify' `
            -MatrixDiscriminator '{"arch":"arm64"}'
    }

    $created = New-PolicyPrivateRoot `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '2002' `
        -RunAttempt '3' `
        -JobName 'verify' `
        -MatrixDiscriminator 'none'
    Assert-True -Condition ([IO.Directory]::Exists($created)) -Label 'private root created'
    Assert-True -Condition ([IO.File]::Exists((Join-Path $created '.policy-root'))) -Label 'exclusive claim'
    Assert-True -Condition ($created.StartsWith("$testRoot\", [StringComparison]::Ordinal)) -Label 'runner.temp containment'
    Assert-Throws -Label 'same root cannot be reused' -Action {
        New-PolicyPrivateRoot `
            -RunnerTemp $testRoot `
            -RepositoryId '1333319488' `
            -RunId '2002' `
            -RunAttempt '3' `
            -JobName 'verify' `
            -MatrixDiscriminator 'none'
    }

    # The created root must already be protected: no inherited rules, and only
    # the runner identity, SYSTEM, and Administrators may appear.
    $createdAcl = Get-Acl -LiteralPath $created
    Assert-True -Condition ($createdAcl.AreAccessRulesProtected) -Label 'private root ACL is protected'
    $expectedSids = @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18',
        'S-1-5-32-544'
    )
    $actualSids = @(
        $createdAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            ForEach-Object { $_.IdentityReference.Value }
    )
    Assert-True -Condition ($actualSids.Count -ge 1) -Label 'private root has explicit rules'
    $unexpected = @($actualSids | Where-Object { $expectedSids -notcontains $_ })
    Assert-True -Condition ($unexpected.Count -eq 0) -Label 'private root grants no extra principal'
    $inherited = @(
        $createdAcl.GetAccessRules($false, $true, [Security.Principal.SecurityIdentifier])
    )
    Assert-True -Condition ($inherited.Count -eq 0) -Label 'private root inherits nothing'
    Assert-PolicyPrivateAcl -Path $created | Out-Null

    # The ACL is applied by the create call itself, so the directory is never
    # observable with inherited permissions.
    # Exclusive publication: the ACL-at-create API is NOT exclusive by itself
    # (it neither throws nor applies the descriptor over an existing path), so
    # the module stages under an unguessable name and publishes with a rename
    # that fails on preexistence.
    $atomicRoot = Join-Path $testRoot 'atomic-root'
    $wasAtomic = New-PolicyPrivateDirectory -Path $atomicRoot
    Assert-True -Condition ([IO.Directory]::Exists($atomicRoot)) -Label 'exclusive directory created'
    Assert-True -Condition ([bool] $wasAtomic) -Label 'exclusive create path was taken'
    Assert-PolicyPrivateDacl -Path $atomicRoot
    $atomicAcl = Get-Acl -LiteralPath $atomicRoot
    Assert-True -Condition ($atomicAcl.AreAccessRulesProtected) -Label 'created ACL is protected'
    Assert-True -Condition (@(Get-ChildItem -LiteralPath (Split-Path -Parent $atomicRoot) -Force -Filter '.policy-staging-*').Count -eq 0) -Label 'no staging directory is left behind'

    Assert-Throws -Label 'second publication is rejected' -Action {
        New-PolicyPrivateDirectory -Path $atomicRoot
    }
    # A failed publication must leave no staging directory behind.
    $stagingParent = Split-Path -Parent $atomicRoot
    $leftovers = @(Get-ChildItem -LiteralPath $stagingParent -Force -Filter '.policy-staging-*')
    Assert-True -Condition ($leftovers.Count -eq 0) -Label 'failed publication leaves no staging directory'

    # Isolate the inheritance and owner checks on a hand-built descriptor.
    $flatRoot = Join-Path $testRoot 'flat-acl'
    $flatAcl = [Security.AccessControl.DirectorySecurity]::new()
    $flatAcl.SetAccessRuleProtection($true, $false)
    $selfSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $flatAcl.SetOwner($selfSid)
    $flatAcl.SetGroup($selfSid)
    foreach ($sid in @($selfSid,
                       [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
                       [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        [void] $flatAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]::None,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
    }
    $ext = [Type]::GetType('System.IO.FileSystemAclExtensions, System.IO.FileSystem.AccessControl')
    $mk = $ext.GetMethod('Create', [Type[]]@([IO.DirectoryInfo], [Security.AccessControl.DirectorySecurity]))
    [void] $mk.Invoke($null, @([IO.DirectoryInfo]::new($flatRoot), $flatAcl))
    Assert-Throws -Label 'non-inheriting ACE is rejected' -Action {
        Assert-PolicyPrivateDacl -Path $flatRoot
    }

    # NOTE: the owner guard cannot be mutation-killed on an unprivileged runner,
    # because manufacturing a foreign-owned directory requires SeRestorePrivilege.
    # It is asserted positively above (the created root is owned by the policy
    # identity) and is declared as such in the report.

    # Nonce replacement must be detected on a root that really has a claim.
    $claimRoot = New-PolicyPrivateRoot `
        -RunnerTemp $testRoot `
        -RepositoryId '1333319488' `
        -RunId '4004' `
        -RunAttempt '1' `
        -JobName 'verify' `
        -MatrixDiscriminator 'none'
    $claimText = [IO.File]::ReadAllText((Join-Path $claimRoot '.policy-root')) | ConvertFrom-Json
    Assert-True -Condition ($claimText.nonce -cmatch '^[0-9a-f]{64}$') -Label 'claim carries a 256-bit nonce'
    Assert-PolicyPrivateAcl -Path $claimRoot -ExpectedNonce $claimText.nonce | Out-Null
    Assert-Throws -Label 'wrong nonce is rejected on a claimed root' -Action {
        Assert-PolicyPrivateAcl -Path $claimRoot -ExpectedNonce ('b' * 64)
    }

    # A non-canonical trusted image entry must be refused.
    $psm = Get-Module PrivateRoot
    $psModule = $psm
    $savedImages = & $psModule { $script:PolicyTrustedGitImages }
    try {
        $imageDir = Split-Path -Parent (Get-PolicyGitImage)
        $imageLeaf = Split-Path -Leaf (Get-PolicyGitImage)
        $noncanonical = Join-Path (Join-Path $imageDir '..') (Join-Path (Split-Path -Leaf $imageDir) $imageLeaf)
        & $psModule { param($v) $script:PolicyTrustedGitImages = $v } @($noncanonical)
        Assert-Throws -Label 'non-canonical git image is refused' -Action {
            Get-PolicyGitImage
        }
        & $psModule { param($v) $script:PolicyTrustedGitImages = $v } @('git.exe', './git')
        Assert-Throws -Label 'relative git image is refused' -Action {
            Get-PolicyGitImage
        }
        # A UNC image would be served by a remote host over the redirector, and
        # an extended-length prefix bypasses normalisation. Both resolve to
        # themselves, so a drive-letter root is required as well.
        $real = $savedImages | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1
        if ($real) {
            foreach ($bad in @(
                    ('\\localhost\C$' + $real.Substring(2)),
                    ('\\?\' + $real),
                    ('\\.\' + $real),
                    ('//localhost/C$' + $real.Substring(2).Replace('\', '/')))) {
                & $psModule { param($v) $script:PolicyTrustedGitImages = $v } @($bad)
                Assert-Throws -Label 'UNC or device git image is refused' -Action {
                    Get-PolicyGitImage
                }
            }
        }
    }
    finally {
        & $psModule { param($v) $script:PolicyTrustedGitImages = $v } $savedImages
    }
    foreach ($shipped in $savedImages) {
        Assert-True -Condition ($shipped -cmatch '^[A-Za-z]:\\') -Label 'shipped image is drive-letter rooted'
        Assert-True -Condition (-not $shipped.Contains('\\\\')) -Label 'shipped image is not UNC'
    }

    # An attacker-planted permissive directory must be REFUSED, and must not be
    # silently adopted or "fixed up".
    $planted = Join-Path $testRoot 'planted-root'
    [void] [IO.Directory]::CreateDirectory($planted)
    $loose = Get-Acl -LiteralPath $planted
    $loose.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $planted -AclObject $loose
    Assert-Throws -Label 'planted directory is refused' -Action {
        New-PolicyPrivateDirectory -Path $planted
    }
    Assert-True -Condition (-not (Get-Acl -LiteralPath $planted).AreAccessRulesProtected) -Label 'planted directory was not adopted'

    # Identity: volume serial plus a secret nonce detects replacement.
    $identity = Get-PolicyDirectoryIdentity -Path $atomicRoot
    Assert-True -Condition ($identity.VolumeSerial -cmatch '^[0-9A-Fa-f]{4,16}$') -Label 'identity captures a volume serial'
    Assert-PolicyPrivateAcl -Path $atomicRoot -ExpectedVolumeSerial $identity.VolumeSerial | Out-Null
    Assert-Throws -Label 'different volume serial is rejected' -Action {
        Assert-PolicyPrivateAcl -Path $atomicRoot -ExpectedVolumeSerial 'DEADBEEF'
    }
    Assert-Throws -Label 'missing nonce is rejected' -Action {
        Assert-PolicyPrivateAcl -Path $atomicRoot -ExpectedNonce ('a' * 64)
    }

    $ownerAcl = Get-Acl -LiteralPath $atomicRoot
    $expectedOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $actualOwner = $ownerAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Assert-True -Condition ($actualOwner -ceq $expectedOwner) -Label 'private root owner is the policy identity'

    # Child inheritance: a file created inside must receive the protected ACEs.
    $child = Join-Path $atomicRoot 'child.txt'
    [IO.File]::WriteAllText($child, 'x')
    $childAcl = Get-Acl -LiteralPath $child
    $childSids = @(
        $childAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            ForEach-Object { $_.IdentityReference.Value }
    )
    $expectedSids2 = Get-PolicyExpectedPrincipal
    $unexpectedChild = @($childSids | Where-Object { $expectedSids2 -notcontains $_ })
    Assert-True -Condition ($unexpectedChild.Count -eq 0) -Label 'child inherits only policy principals'

    # A permissive directory must be rejected by the reverification helper.
    $loose2 = Join-Path $testRoot 'loose-root'
    [void] [IO.Directory]::CreateDirectory($loose2)
    Assert-Throws -Label 'inherited ACL is rejected' -Action {
        Assert-PolicyPrivateDacl -Path $loose2
    }

    # A reparse point must never be accepted as the private root.
    $reparse = Join-Path $testRoot 'reparse-root'
    New-Item -ItemType Junction -Path $reparse -Target $physical -ErrorAction Stop | Out-Null
    Assert-Throws -Label 'reparse point root is rejected' -Action {
        Get-PolicyDirectoryIdentity -Path $reparse
    }

    # --- Exploit-derived: the Git image must be trusted and PATH-independent ---
    $image = Get-PolicyGitImage
    Assert-True -Condition ([IO.Path]::IsPathFullyQualified($image)) -Label 'git image is absolute'
    Assert-True -Condition ([IO.File]::Exists($image)) -Label 'git image exists'
    Assert-True -Condition ($image.EndsWith('git.exe', [StringComparison]::Ordinal)) -Label 'git image is a git binary'

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    $realHead = Invoke-PolicyGit -WorkingDirectory $repoRoot -GitArguments @('rev-parse', '--verify', 'HEAD')
    Assert-True -Condition ($realHead -cmatch '^[0-9a-f]{40}$') -Label 'trusted git returns a real HEAD'

    # A hostile Git environment must not reach the child process.
    $savedDir = $env:GIT_DIR
    $savedWork = $env:GIT_WORK_TREE
    $savedCount = $env:GIT_CONFIG_COUNT
    try {
        $env:GIT_DIR = 'C:\attacker\.git'
        $env:GIT_WORK_TREE = 'C:\attacker'
        $env:GIT_CONFIG_COUNT = '1'
        $env:GIT_CONFIG_KEY_0 = 'core.pager'
        $env:GIT_CONFIG_VALUE_0 = 'cmd.exe /c echo pwned'
        $env:GIT_SSH_COMMAND = 'cmd.exe'
        $hostileHead = Invoke-PolicyGit -WorkingDirectory $repoRoot -GitArguments @('rev-parse', '--verify', 'HEAD')
        Assert-True -Condition ($hostileHead -ceq $realHead) -Label 'hostile Git environment does not reach the child'
    }
    finally {
        foreach ($name in @('GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT',
                            'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0',
                            'GIT_SSH_COMMAND')) {
            if (Test-Path "Env:$name") { Remove-Item "Env:$name" }
        }
        if ($null -ne $savedDir -and $savedDir -ne '') { $env:GIT_DIR = $savedDir }
        if ($null -ne $savedWork -and $savedWork -ne '') { $env:GIT_WORK_TREE = $savedWork }
        if ($null -ne $savedCount -and $savedCount -ne '') { $env:GIT_CONFIG_COUNT = $savedCount }
    }

    # A non-repository must fail closed, not be forged into a clean checkout.
    $notARepo = Join-Path $testRoot 'not-a-repo'
    [void] [IO.Directory]::CreateDirectory($notARepo)
    Assert-Throws -Label 'non-repository base checkout fails closed' -Action {
        Assert-PolicyBaseCheckout `
            -Workspace $notARepo `
            -Repository 'crutkas/MSYS2-packages' `
            -ExpectedCommit ('0' * 40)
    }

    # --- C-3: a checkout-controlled git config must not execute a process ---
    $cfgRoot = Join-Path $testRoot 'cfgrepo'
    [void] [IO.Directory]::CreateDirectory($cfgRoot)
    $gitImage = Get-PolicyGitImage
    # Build fixtures with a clean Git environment of our own.
    function Invoke-FixtureGit {
        param([string] $Root, [string[]] $GitArgs)
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $gitImage
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.CreateNoWindow = $true
        foreach ($a in (@('-C', $Root) + $GitArgs)) { [void] $info.ArgumentList.Add($a) }
        $info.EnvironmentVariables.Clear()
        $info.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
        $info.EnvironmentVariables['PATH'] = (Join-Path $env:SystemRoot 'System32')
        $info.EnvironmentVariables['HOME'] = ''
        $info.EnvironmentVariables['GIT_CONFIG_NOSYSTEM'] = '1'
        $p = [Diagnostics.Process]::Start($info)
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        [void] $p.WaitForExit(30000)
        [void] [Threading.Tasks.Task]::WaitAll(@($o, $e), 5000)
        $code = $p.ExitCode
        $p.Dispose()
        if ($code -ne 0) { throw "fixture git $($GitArgs -join ' ') failed: $($e.Result)" }
    }
    Invoke-FixtureGit -Root $cfgRoot -GitArgs @('init', '-q')
    Invoke-FixtureGit -Root $cfgRoot -GitArgs @('remote', 'add', 'origin', 'https://github.com/crutkas/MSYS2-packages')
    [IO.File]::WriteAllText((Join-Path $cfgRoot 'tracked.txt'), "hello`n")
    [IO.File]::WriteAllText((Join-Path $cfgRoot '.gitattributes'), "tracked.txt filter=evil`n")
    Invoke-FixtureGit -Root $cfgRoot -GitArgs @('add', '-A')
    Invoke-FixtureGit -Root $cfgRoot -GitArgs @('-c', 'user.email=a@b.c', '-c', 'user.name=a', 'commit', '-qm', 'x')

    # A pristine checkout passes the scan.
    Assert-PolicyInertLocalConfig -Workspace $cfgRoot

    $evidence = Join-Path $testRoot 'ps-evidence.txt'
    $evidencePosix = $evidence.Replace('\', '/')
    Add-Content -LiteralPath (Join-Path $cfgRoot '.git\config') -Value @"

[filter "evil"]
	clean = C:/Windows/System32/cmd.exe /c echo pwned> $evidencePosix
"@
    Assert-Throws -Label 'checkout-controlled filter config is denied' -Action {
        Assert-PolicyInertLocalConfig -Workspace $cfgRoot
    }
    Assert-True -Condition (-not [IO.File]::Exists($evidence)) -Label 'no process ran before the verdict'
    # Use the REAL head commit so the guard cannot be masked by a HEAD mismatch:
    # without the config scan running first, `status` would execute the filter.
    $realHead = Invoke-PolicyGit -WorkingDirectory $cfgRoot `
        -GitArguments @('-C', $cfgRoot, '--no-pager', 'rev-parse', '--verify', '--end-of-options', 'HEAD')
    Assert-Throws -Label 'base checkout with executable config is denied' -Action {
        Assert-PolicyBaseCheckout -Workspace $cfgRoot -Repository 'crutkas/MSYS2-packages' -ExpectedCommit $realHead
    }
    Assert-True -Condition (-not [IO.File]::Exists($evidence)) -Label 'still no process after base checkout guard'

    foreach ($block in @(
            "[core]`n`tfsmonitor = cmd`n",
            "[core]`n`thooksPath = /tmp/h`n",
            "[core]`n`tsshCommand = cmd`n",
            "[credential]`n`thelper = cmd`n",
            "[alias]`n`tx = !cmd`n",
            "[include]`n`tpath = /tmp/evil`n",
            "[diff `"e`"]`n`ttextconv = cmd`n")) {
        $family = Join-Path $testRoot ("cfg-" + [Guid]::NewGuid().ToString('N'))
        [void] [IO.Directory]::CreateDirectory($family)
        Invoke-FixtureGit -Root $family -GitArgs @('init', '-q')
        Add-Content -LiteralPath (Join-Path $family '.git\config') -Value "`n$block"
        Assert-Throws -Label 'command-executing config family denied' -Action {
            Assert-PolicyInertLocalConfig -Workspace $family
        }
    }

    # NC-1: a per-checkout configuration scope is honoured by Git but invisible
    # to a single-scope listing. The scan must be scope-aware.
    $wtMain = Join-Path $testRoot 'wt-main'
    [void] [IO.Directory]::CreateDirectory($wtMain)
    Invoke-FixtureGit -Root $wtMain -GitArgs @('init', '-q')
    [IO.File]::WriteAllText((Join-Path $wtMain 'f.txt'), "hello`n")
    Invoke-FixtureGit -Root $wtMain -GitArgs @('add', '-A')
    Invoke-FixtureGit -Root $wtMain -GitArgs @('-c', 'user.email=a@b.c', '-c', 'user.name=a', 'commit', '-qm', 'x')
    Invoke-FixtureGit -Root $wtMain -GitArgs @('config', '--local', 'extensions.worktreeConfig', 'true')
    $wtLinked = Join-Path $testRoot 'wt-linked'
    Invoke-FixtureGit -Root $wtMain -GitArgs @('worktree', 'add', '-q', $wtLinked)
    Invoke-FixtureGit -Root $wtLinked -GitArgs @('config', '--worktree', 'filter.evil.clean', 'cmd.exe /c echo')
    Assert-Throws -Label 'per-checkout scope key is denied' -Action {
        Assert-PolicyInertLocalConfig -Workspace $wtLinked
    }
    # Prove the SCOPE scan is the control, not the extension omission: permit
    # the extension and the scoped key must still be refused.
    $savedAllow = & $psm { $script:PolicyConfigKeyAllowList }
    try {
        & $psm { param($v) $script:PolicyConfigKeyAllowList = $v } `
            ($savedAllow + @('extensions\.worktreeconfig'))
        Assert-Throws -Label 'scope scan denies even when the extension is permitted' -Action {
            Assert-PolicyInertLocalConfig -Workspace $wtLinked
        }
    }
    finally {
        & $psm { param($v) $script:PolicyConfigKeyAllowList = $v } $savedAllow
    }

    # The scan must assert that ambient scopes are GONE, not merely read values.
    $moduleSource = [IO.File]::ReadAllText($modulePath)
    Assert-True -Condition ($moduleSource.Contains('--show-scope')) -Label 'scan reads every configuration scope'
    Assert-True -Condition ($moduleSource.Contains('PolicyForbiddenConfigScopes')) -Label 'ambient scopes are asserted absent'
    Assert-True -Condition ($moduleSource.Contains('command-scope configuration is not exactly')) -Label 'command scope is asserted exact'
    Assert-True -Condition (-not ($moduleSource -cmatch "config', '--local', '--list'")) -Label 'no single-scope listing remains'

    # Each scope guard is exercised on its own against a synthetic listing, so a
    # kill is attributable to that guard rather than to a neighbour. A source
    # string check would not notice a guard whose body had been neutered.
    $originalInvokePolicyGit = & $psm { ${function:Invoke-PolicyGit} }
    try {
        & $psm {
            $script:StubConfigListing = ''
            Set-Item -Path function:Invoke-PolicyGit -Value {
                param($WorkingDirectory, $GitArguments, $TimeoutMilliseconds)
                return $script:StubConfigListing
            }
        }
        $forcedRecords = @()
        foreach ($setting in (& $psm { $script:PolicyForcedConfig })) {
            $parts = $setting.Split('=', 2)
            $forcedRecords += @('command', ($parts[0] + "`n" + $parts[1]))
        }
        function Invoke-ScopedScan {
            param([string[]] $Records)
            & $psm { param($v) $script:StubConfigListing = $v } (($Records -join [char]0) + [char]0)
            Assert-PolicyInertLocalConfig -Workspace 'C:\stub'
        }

        # Positive control: the synthetic shape itself must be admitted, or every
        # negative below would pass for the wrong reason.
        Invoke-ScopedScan -Records (@('local', "core.bare`nfalse") + $forcedRecords)
        Assert-True -Condition $true -Label 'synthetic pristine listing is admitted'

        foreach ($scope in @('system', 'global')) {
            Assert-Throws -Label "ambient $scope scope is asserted absent" `
                -Match 'failed to suppress ambient configuration' -Action {
                Invoke-ScopedScan -Records (@('local', "core.bare`nfalse", $scope, "core.pager`ncmd.exe") + $forcedRecords)
            }
        }
        Assert-Throws -Label 'unmodelled scope is denied' `
            -Match 'unmodelled configuration scope' -Action {
            Invoke-ScopedScan -Records (@('local', "core.bare`nfalse", 'submodule', "core.pager`ncmd.exe") + $forcedRecords)
        }
        Assert-Throws -Label 'extra command-scope key is denied' `
            -Match 'not exactly the policy forced settings' -Action {
            Invoke-ScopedScan -Records (@('local', "core.bare`nfalse") + $forcedRecords + @('command', "filter.evil.clean`ncmd.exe"))
        }
        Assert-Throws -Label 'missing forced command-scope key is denied' `
            -Match 'not exactly the policy forced settings' -Action {
            Invoke-ScopedScan -Records (@('local', "core.bare`nfalse") + $forcedRecords[0..($forcedRecords.Count - 3)])
        }
        Assert-Throws -Label 'unpaired record stream is denied' `
            -Match 'unpaired record stream' -Action {
            Invoke-ScopedScan -Records @('local', "core.bare`nfalse", 'local')
        }
        # A worktree-scope key still meets the key allow-list, so this proves the
        # scan reaches that scope at all rather than only the local one.
        Assert-Throws -Label 'per-checkout scope is reached by the scan' `
            -Match 'unmodelled git configuration key' -Action {
            Invoke-ScopedScan -Records (@('worktree', "filter.evil.clean`ncmd.exe") + $forcedRecords)
        }
    }
    finally {
        & $psm { param($sb) Set-Item -Path function:Invoke-PolicyGit -Value $sb } $originalInvokePolicyGit
    }
    # Prove the real function came back, not the stub.
    Assert-True -Condition ((& $psm { ${function:Invoke-PolicyGit} }).ToString().Contains('ReadToEndAsync')) -Label 'production git invoker restored'

    # --- H-5: both pipes must be drained so the timeout is always reachable ---
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    # Flood stderr well past the 64 KiB pipe buffer while writing nothing to
    # stdout. Reading stdout to EOF first would block here forever.
    [void] $psi.ArgumentList.Add('/c')
    [void] $psi.ArgumentList.Add('for /L %i in (1,1,20000) do @echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1>&2')
    $flood = [Diagnostics.Process]::Start($psi)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $outTask = $flood.StandardOutput.ReadToEndAsync()
    $errTask = $flood.StandardError.ReadToEndAsync()
    $exited = $flood.WaitForExit(20000)
    $watch.Stop()
    [void] [Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), 5000)
    if (-not $exited) { try { $flood.Kill($true) } catch { } }
    $flood.Dispose()
    Assert-True -Condition $exited -Label 'concurrent draining does not deadlock on a stderr flood'
    Assert-True -Condition ($watch.Elapsed.TotalSeconds -lt 20) -Label 'stderr flood completes well within the timeout'

    $moduleText = [IO.File]::ReadAllText($modulePath)
    Assert-True -Condition ($moduleText.Contains('ReadToEndAsync')) -Label 'stdout and stderr are drained concurrently'
    Assert-True -Condition (-not ($moduleText -cmatch 'StandardOutput\.ReadToEnd\(\)')) -Label 'no blocking stdout read before WaitForExit'
    Assert-True -Condition ($moduleText.Contains('$process.Kill($true)')) -Label 'timeout kills the child'
    Assert-True -Condition ($moduleText.Contains('Assert-PolicyInertLocalConfig')) -Label 'config scan exists'
    Assert-True -Condition (-not $moduleText.Contains('New-Item')) -Label 'no New-Item in module'
    Assert-True -Condition (-not $moduleText.Contains('Set-PolicyPrivateAcl')) -Label 'racy create-then-protect fallback removed'
    Assert-True -Condition (-not ($moduleText -cmatch 'Set-Acl\s+-Path')) -Label 'Set-Acl uses -LiteralPath'
    Assert-True -Condition (-not ($moduleText -cmatch 'Get-Acl\s+-Path')) -Label 'Get-Acl uses -LiteralPath'
    Assert-True -Condition (-not ($moduleText -cmatch 'Get-ChildItem\s+-Path')) -Label 'Get-ChildItem uses -LiteralPath'
    Assert-True -Condition ($moduleText.Contains('ProcessStartInfo')) -Label 'git runs via ProcessStartInfo'
    Assert-True -Condition ($moduleText.Contains('EnvironmentVariables.Clear()')) -Label 'child git environment is cleared'
    Assert-True -Condition ($moduleText.Contains('[IO.Directory]::Move')) -Label 'exclusive publication uses a rename'
    Assert-True -Condition ($moduleText.Contains('refusing to create the private root')) -Label 'reflection inability fails closed'
    Assert-True -Condition (-not $moduleText.Contains('POLICY_GIT_EXECUTABLE')) -Label 'no git executable override in module'
}
finally {
    if ([IO.Directory]::Exists($testRoot)) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
    }
}

Write-Output "Private-root assertions passed: $script:assertions"

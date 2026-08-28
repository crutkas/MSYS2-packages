[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
        [string] $Label
    )

    $script:assertions++
    $threw = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $threw = $true
    }
    if (-not $threw) {
        throw "Expected rejection: $Label"
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
    $realHead = Invoke-PolicyGit -WorkingDirectory $repoRoot -Arguments @('rev-parse', '--verify', 'HEAD')
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
        $hostileHead = Invoke-PolicyGit -WorkingDirectory $repoRoot -Arguments @('rev-parse', '--verify', 'HEAD')
        Assert-True -Condition ($hostileHead -ceq $realHead) -Label 'hostile Git environment does not reach the child'
    }
    finally {
        $env:GIT_DIR = $savedDir
        $env:GIT_WORK_TREE = $savedWork
        $env:GIT_CONFIG_COUNT = $savedCount
        Remove-Item Env:GIT_CONFIG_KEY_0, Env:GIT_CONFIG_VALUE_0, Env:GIT_SSH_COMMAND -ErrorAction SilentlyContinue
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

    # Source-level guarantees.
    $moduleText = [IO.File]::ReadAllText($modulePath)
    Assert-True -Condition (-not $moduleText.Contains('New-Item')) -Label 'no New-Item in module'
    Assert-True -Condition (-not $moduleText.Contains('Set-PolicyPrivateAcl')) -Label 'racy create-then-protect fallback removed'
    Assert-True -Condition (-not ($moduleText -cmatch '&\s+git\b')) -Label 'no bare & git invocation'
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

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
    Assert-PolicyPrivateAcl -Path $created

    # The ACL is applied by the create call itself, so the directory is never
    # observable with inherited permissions.
    $atomicRoot = Join-Path $testRoot 'atomic-root'
    $wasAtomic = New-PolicyPrivateDirectory -Path $atomicRoot
    Assert-True -Condition ([IO.Directory]::Exists($atomicRoot)) -Label 'atomic directory created'
    Assert-True -Condition ([bool] $wasAtomic) -Label 'atomic ACL-at-create path was taken'
    Assert-PolicyPrivateAcl -Path $atomicRoot
    $atomicAcl = Get-Acl -LiteralPath $atomicRoot
    Assert-True -Condition ($atomicAcl.AreAccessRulesProtected) -Label 'atomic ACL is protected'

    # A permissive directory must be rejected by the reverification helper.
    $loose = Join-Path $testRoot 'loose-root'
    [void] [IO.Directory]::CreateDirectory($loose)
    Assert-Throws -Label 'inherited ACL is rejected' -Action {
        Assert-PolicyPrivateAcl -Path $loose
    }

    # Literal directory APIs only: no wildcard-interpreting provider cmdlet may
    # be used to create or protect the private root.
    $moduleText = [IO.File]::ReadAllText($modulePath)
    Assert-True -Condition (-not $moduleText.Contains('New-Item')) -Label 'no New-Item in module'
    Assert-True -Condition (-not ($moduleText -cmatch 'Set-Acl\s+-Path')) -Label 'Set-Acl uses -LiteralPath'
    Assert-True -Condition (-not ($moduleText -cmatch 'Get-Acl\s+-Path')) -Label 'Get-Acl uses -LiteralPath'
    Assert-True -Condition (-not ($moduleText -cmatch 'Get-ChildItem\s+-Path')) -Label 'Get-ChildItem uses -LiteralPath'
    Assert-True -Condition ($moduleText.Contains('FileSystemAclExtensions')) -Label 'atomic create API is used'
}
finally {
    if ([IO.Directory]::Exists($testRoot)) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
    }
}

Write-Output "Private-root assertions passed: $script:assertions"

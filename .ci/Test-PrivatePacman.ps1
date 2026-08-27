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
$fakePacman = Join-Path $testRoot 'fake-pacman.cmd'
$packageRoot = Join-Path $testRoot 'packages'

try {
    New-Item -ItemType Directory -Path (Join-Path $sharedRoot 'var\log') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $sharedRoot 'var\lib\pacman\local\base-1') -Force | Out-Null
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sharedRoot 'var\log\pacman.log') -Value 'baseline'
    Set-Content -LiteralPath (Join-Path $sharedRoot 'var\lib\pacman\local\base-1\desc') -Value 'base'
    Set-Content -LiteralPath (Join-Path $packageRoot 'sample.pkg.tar.zst') -Value 'not a real package'

    @'
@echo off
:record
if "%~1"=="" goto mutate
>>"%PACMAN_ARG_RECORD%" echo(%~1
shift
goto record
:mutate
if defined PACMAN_DRIFT_LOG >>"%PACMAN_DRIFT_LOG%" echo(drift
exit /b %PACMAN_EXIT_CODE%
'@ | Set-Content -LiteralPath $fakePacman -Encoding ascii

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
        return New-PrivatePacmanContext @parameters
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
        Assert-Throws -Pattern 'shared MSYS2 root' -Action {
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

    Invoke-Test 'device namespace path is rejected' {
        $deviceRoot = '\\?\' + $sharedRoot + '\private'
        Assert-Throws -Pattern 'device namespace paths' -Action {
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
    }

    Invoke-Test 'ambiguous later help token remains mutating' {
        $kind = Get-PacmanOperationKind -ArgumentList @('-S', '--logfile', '--help', 'example')
        Assert-True ($kind.ToString() -eq 'Mutating') 'A later option value bypassed mutating classification.'
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

    Invoke-Test 'dash-prefixed package target cannot bypass PackagePath' {
        $context = New-TestContext -Name 'dash-package'
        Assert-Throws -Pattern "helper owns option termination|only through PackagePath" -Action {
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

    Invoke-Test 'nested junction escape is rejected before mutation' {
        $context = New-TestContext -Name 'nested-junction'
        $sharedTarget = Join-Path $sharedRoot 'usr'
        New-Item -ItemType Directory -Path $sharedTarget -Force | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $context.Root 'usr') -Target $sharedTarget | Out-Null
        $env:PACMAN_ARG_RECORD = Join-Path $testRoot 'nested-junction.args'
        $env:PACMAN_EXIT_CODE = '0'
        Assert-Throws -Pattern 'escapes private root' -Action {
            Invoke-PrivatePacman -Context $context -ArgumentList @('-S', 'example')
        }
        Assert-True (-not (Test-Path -LiteralPath $env:PACMAN_ARG_RECORD)) `
            'Fake pacman was invoked with an escaping root junction.'
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
}
finally {
    Remove-Item Env:PACMAN_ARG_RECORD -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_EXIT_CODE -ErrorAction SilentlyContinue
    Remove-Item Env:PACMAN_DRIFT_LOG -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "$script:Passed passed; $script:Failed failed"
if ($script:Failed -ne 0) {
    exit 1
}

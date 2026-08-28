[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'PrivateRoot.psm1'
Import-Module $modulePath -Force -ErrorAction Stop

$workspace = Join-Path $env:GITHUB_WORKSPACE 'protected-base'
$baseTree = Assert-PolicyBaseCheckout `
    -Workspace $workspace `
    -Repository $env:POLICY_REPOSITORY `
    -ExpectedCommit $env:POLICY_BASE_SHA

$privateRoot = New-PolicyPrivateRoot `
    -RunnerTemp $env:RUNNER_TEMP `
    -RepositoryId $env:POLICY_REPOSITORY_ID `
    -RunId $env:POLICY_RUN_ID `
    -RunAttempt $env:POLICY_RUN_ATTEMPT `
    -JobName $env:POLICY_JOB `
    -MatrixDiscriminator $env:POLICY_MATRIX

@(
    "POLICY_PRIVATE_ROOT=$privateRoot"
    "POLICY_BASE_TREE=$baseTree"
    "POLICY_REPOSITORY_ID=$env:POLICY_REPOSITORY_ID"
    "POLICY_RUN_ID=$env:POLICY_RUN_ID"
    "POLICY_RUN_ATTEMPT=$env:POLICY_RUN_ATTEMPT"
    "POLICY_JOB=$env:POLICY_JOB"
) | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8NoBOM -Append

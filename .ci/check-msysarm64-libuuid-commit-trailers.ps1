[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$BaseSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHeadSha,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$actualHead = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -ne $ExpectedHeadSha) {
    throw "Trailer check head mismatch: expected=$ExpectedHeadSha actual=$actualHead"
}
$baseType = (git cat-file -t $BaseSha).Trim()
if ($LASTEXITCODE -ne 0 -or $baseType -ne 'commit') {
    throw "Trailer check base is not a commit: $BaseSha"
}
$commits = @(git rev-list --reverse "$BaseSha..$ExpectedHeadSha")
if ($LASTEXITCODE -ne 0 -or $commits.Count -eq 0) {
    throw 'Trailer check found no owned commits'
}

$coauthor = 'Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>'
$session = 'Copilot-Session: 9fd53235-1dfb-47b4-82bb-4e84b9c141e6'
$records = [Collections.Generic.List[object]]::new()
foreach ($commit in $commits) {
    $body = (git show -s --format=%B $commit) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot read commit message: $commit"
    }
    $escapedCoauthor = [regex]::Escape($coauthor)
    $escapedSession = [regex]::Escape($session)
    if ($body -notmatch
        "(?s)\n\n$escapedCoauthor\n$escapedSession\s*$") {
        throw "Required contiguous trailer block is absent: $commit"
    }
    $parsed = @($body | git interpret-trailers --parse)
    if (@($parsed | Where-Object { $_ -eq $coauthor }).Count -ne 1 -or
        @($parsed | Where-Object { $_ -eq $session }).Count -ne 1) {
        throw "Required trailers are not uniquely parseable: $commit"
    }
    $records.Add([ordered]@{
        sha = $commit
        subject = (git show -s --format=%s $commit).Trim()
        trailer_block_sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes("$coauthor`n$session`n"))
        ).ToLowerInvariant()
    })
}

if (Test-Path -LiteralPath $EvidenceDirectory) {
    Remove-Item -LiteralPath $EvidenceDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$reportPath = Join-Path $EvidenceDirectory 'commit-trailers.json'
[IO.File]::WriteAllText(
    $reportPath,
    ([ordered]@{
        schema = 1
        base_sha = $BaseSha
        head_sha = $ExpectedHeadSha
        commit_count = $records.Count
        commits = @($records)
    } | ConvertTo-Json -Depth 5),
    [Text.UTF8Encoding]::new($false))
$reportHash = (Get-FileHash -Algorithm SHA256 $reportPath).
    Hash.ToLowerInvariant()
$manifestPath = Join-Path $EvidenceDirectory 'evidence-manifest.sha256'
[IO.File]::WriteAllText(
    $manifestPath,
    "$reportHash  commit-trailers.json`n",
    [Text.UTF8Encoding]::new($false))
$manifestHash = (Get-FileHash -Algorithm SHA256 $manifestPath).
    Hash.ToLowerInvariant()
[IO.File]::WriteAllText(
    (Join-Path $EvidenceDirectory 'evidence.seal'),
    "$manifestHash  evidence-manifest.sha256`n",
    [Text.UTF8Encoding]::new($false))

$records

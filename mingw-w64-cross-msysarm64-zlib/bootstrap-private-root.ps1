[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RootParent,

    [Parameter(Mandatory = $true)]
    [string] $InputRoot,

    [Parameter(Mandatory = $true)]
    [string] $EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$utf8 = [Text.UTF8Encoding]::new($false)
$base = @{
    AssetId = 532401203
    Name = 'msys2-base-x86_64-latest.tar.xz'
    Url = 'https://api.github.com/repos/msys2/msys2-installer/releases/assets/532401203'
    Size = 42820476L
    Sha256 = '3a56d2f156002c41de8c7e1e73ed6753e64c5e02389210c6d8a38b6d01349783'
}
$hostPackages = [ordered]@{
    'diffutils-3.12-1-x86_64.pkg.tar.zst' = @{
        Url = 'https://repo.msys2.org/msys/x86_64/diffutils-3.12-1-x86_64.pkg.tar.zst'
        Size = 394515L
        Sha256 = '7902c8ce3d4dd69a0f5e98dc9d5c83c17b23314ba486169db57ef6e2835ce3b6'
    }
    'isl-0.27-1-x86_64.pkg.tar.zst' = @{
        Url = 'https://repo.msys2.org/msys/x86_64/isl-0.27-1-x86_64.pkg.tar.zst'
        Size = 768472L
        Sha256 = 'cdd0a4ce0bf0d9e3f3eff2b770b8143e09e126a614de8b55bb5d30fc596b92d1'
    }
    'make-4.4.1-3-x86_64.pkg.tar.zst' = @{
        Url = 'https://repo.msys2.org/msys/x86_64/make-4.4.1-3-x86_64.pkg.tar.zst'
        Size = 514683L
        Sha256 = 'af0bdba17f06fe037f0194069adaa31a8fe45f1a11381501896aea1fae37bd5d'
    }
    'mpc-1.4.1-1-x86_64.pkg.tar.zst' = @{
        Url = 'https://repo.msys2.org/msys/x86_64/mpc-1.4.1-1-x86_64.pkg.tar.zst'
        Size = 87944L
        Sha256 = '0f5073ec2e8be265854ee3c7cb1079b5e8e02264d53e659d8414988c6c182f16'
    }
    'patch-2.7.6-3-x86_64.pkg.tar.zst' = @{
        Url = 'https://repo.msys2.org/msys/x86_64/patch-2.7.6-3-x86_64.pkg.tar.zst'
        Size = 98395L
        Sha256 = 'dd75ca0f715dd9c71a43af6a0ff3d068faeee1d768e02282d319671201cd5d45'
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Assert-File {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $Size,
        [Parameter(Mandatory = $true)][string] $Sha256
    )

    $item = Get-Item -LiteralPath $Path
    $hash = Get-Sha256 -Path $Path
    if ($item.Length -ne $Size -or $hash -ne $Sha256) {
        throw "Immutable input mismatch: $($item.Name)"
    }
}

function Download-Twice {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Url,
        [Parameter(Mandatory = $true)][long] $Size,
        [Parameter(Mandatory = $true)][string] $Sha256,
        [hashtable] $Headers = @{}
    )

    $primary = Join-Path $InputRoot "primary\$Name"
    $secondary = Join-Path $InputRoot "independent-redownload\$Name"
    Invoke-WebRequest -Uri $Url -Headers $Headers -OutFile $primary
    $client = [Net.Http.HttpClient]::new()
    try {
        $request = [Net.Http.HttpRequestMessage]::new(
            [Net.Http.HttpMethod]::Get,
            [Uri] $Url
        )
        foreach ($entry in $Headers.GetEnumerator()) {
            [void] $request.Headers.TryAddWithoutValidation(
                $entry.Key,
                [string] $entry.Value
            )
        }
        $response = $client.Send($request)
        [void] $response.EnsureSuccessStatusCode()
        $bytes = $response.Content.ReadAsByteArrayAsync().
            GetAwaiter().GetResult()
        [IO.File]::WriteAllBytes($secondary, $bytes)
    }
    finally {
        $client.Dispose()
    }
    Assert-File -Path $primary -Size $Size -Sha256 $Sha256
    Assert-File -Path $secondary -Size $Size -Sha256 $Sha256
    if ((Get-Sha256 -Path $primary) -ne (Get-Sha256 -Path $secondary)) {
        throw "Independent download mismatch: $Name"
    }
}

foreach ($path in @($RootParent, $InputRoot, $EvidenceRoot)) {
    if (Test-Path -LiteralPath $path) {
        throw "Private bootstrap path must be fresh: $path"
    }
    New-Item -ItemType Directory -Path $path | Out-Null
}
New-Item -ItemType Directory -Path `
    (Join-Path $InputRoot 'primary'), `
    (Join-Path $InputRoot 'independent-redownload') | Out-Null

$baseHeaders = @{
    Accept = 'application/octet-stream'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'msysarm64-zlib-private-bootstrap'
}
if (-not $env:GITHUB_TOKEN) {
    throw 'GITHUB_TOKEN is required for the immutable base asset'
}
$baseHeaders.Authorization = "Bearer $($env:GITHUB_TOKEN)"
Download-Twice `
    -Name $base.Name `
    -Url $base.Url `
    -Size $base.Size `
    -Sha256 $base.Sha256 `
    -Headers $baseHeaders
foreach ($entry in $hostPackages.GetEnumerator()) {
    Download-Twice `
        -Name $entry.Key `
        -Url $entry.Value.Url `
        -Size $entry.Value.Size `
        -Sha256 $entry.Value.Sha256
}

$tar = 'C:\Windows\System32\tar.exe'
if (-not (Test-Path -LiteralPath $tar -PathType Leaf)) {
    throw "Windows tar is missing: $tar"
}
$baseArchive = Join-Path $InputRoot "primary\$($base.Name)"
& $tar -xf $baseArchive -C $RootParent
if ($LASTEXITCODE -ne 0) {
    throw "Immutable base extraction failed: $LASTEXITCODE"
}

$msysRoot = Join-Path $RootParent 'msys64'
foreach ($relative in @(
    'usr\bin\bash.exe',
    'usr\bin\bsdtar.exe',
    'usr\bin\makepkg',
    'usr\bin\msys-2.0.dll',
    'usr\bin\pacman.exe'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $msysRoot $relative))) {
        throw "Immutable base is missing $relative"
    }
}

$hostManifest = @("source`tmethods`tasset`tbytes`tsha256")
$hostManifest += @(
    "github-asset:$($base.AssetId)`tInvoke-WebRequest+HttpClient`t" +
    "$($base.Name)`t$($base.Size)`t$($base.Sha256)"
)
foreach ($entry in $hostPackages.GetEnumerator()) {
    $hostManifest += @(
        "$($entry.Value.Url)`tInvoke-WebRequest+HttpClient`t$($entry.Key)`t" +
        "$($entry.Value.Size)`t$($entry.Value.Sha256)"
    )
}
[IO.File]::WriteAllText(
    (Join-Path $EvidenceRoot 'private-base-host-inputs.tsv'),
    (($hostManifest -join "`n") + "`n"),
    $utf8
)

$additionalPackages = @(
    foreach ($name in $hostPackages.Keys) {
        Join-Path $InputRoot "primary\$name"
    }
)
& (Join-Path $PSScriptRoot 'bootstrap-toolchain.ps1') `
    -Destination (Join-Path $InputRoot 'toolchain') `
    -MsysRoot $msysRoot `
    -AdditionalPackages $additionalPackages `
    -Install
if ($LASTEXITCODE -ne 0) {
    throw "Private toolchain bootstrap failed: $LASTEXITCODE"
}

Copy-Item `
    -LiteralPath (Join-Path $InputRoot 'toolchain\toolchain-inputs.tsv') `
    -Destination $EvidenceRoot
Copy-Item `
    -LiteralPath (Join-Path $InputRoot 'toolchain\installed-toolchain.tsv') `
    -Destination $EvidenceRoot
Copy-Item `
    -LiteralPath (Join-Path $InputRoot 'toolchain\private-tools.tsv') `
    -Destination $EvidenceRoot

$bootstrapTools = @(
    [ordered]@{
        role = 'windows-tar'
        path = $tar
        bytes = (Get-Item -LiteralPath $tar).Length
        sha256 = Get-Sha256 -Path $tar
    }
    [ordered]@{
        role = 'private-msys-runtime'
        path = 'usr/bin/msys-2.0.dll'
        bytes = (Get-Item (Join-Path $msysRoot 'usr\bin\msys-2.0.dll')).Length
        sha256 = Get-Sha256 -Path (
            Join-Path $msysRoot 'usr\bin\msys-2.0.dll'
        )
    }
)
[IO.File]::WriteAllText(
    (Join-Path $EvidenceRoot 'bootstrap-tools.json'),
    (($bootstrapTools | ConvertTo-Json -Depth 8) + "`n"),
    $utf8
)

$privateIdentity = [ordered]@{
    schema = 'msysarm64-zlib-private-root/v1'
    root = $msysRoot
    hosted_shared_root_forbidden = 'C:\msys64'
    bash = [ordered]@{
        path = Join-Path $msysRoot 'usr\bin\bash.exe'
        sha256 = Get-Sha256 -Path (
            Join-Path $msysRoot 'usr\bin\bash.exe'
        )
    }
    runtime = [ordered]@{
        path = Join-Path $msysRoot 'usr\bin\msys-2.0.dll'
        sha256 = Get-Sha256 -Path (
            Join-Path $msysRoot 'usr\bin\msys-2.0.dll'
        )
    }
    pacman = [ordered]@{
        path = Join-Path $msysRoot 'usr\bin\pacman.exe'
        sha256 = Get-Sha256 -Path (
            Join-Path $msysRoot 'usr\bin\pacman.exe'
        )
        arguments = @(
            '--root', '/',
            '--dbpath', '/var/lib/pacman',
            '--cachedir', '/var/cache/pacman/pkg',
            '--logfile', '/var/log/zlib-private-pacman.log',
            '--config', 'private-pacman.conf',
            '--hookdir', '/etc/pacman.d/hooks',
            '--gpgdir', '/etc/pacman.d/gnupg'
        )
    }
}
[IO.File]::WriteAllText(
    (Join-Path $EvidenceRoot 'private-root-identity.json'),
    (($privateIdentity | ConvertTo-Json -Depth 8) + "`n"),
    $utf8
)

& (Join-Path $PSScriptRoot 'snapshot-shared-state.ps1') `
    -Label before `
    -OutputDirectory $EvidenceRoot `
    -SharedRoot $msysRoot

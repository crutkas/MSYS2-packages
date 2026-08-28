[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [Parameter(Mandatory = $true)]
    [string]$Workspace,

    [string]$SharedRoot = 'C:\msys64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = 'crutkas/MSYS2-packages'
$recipe = Join-Path $Workspace 'mingw-w64-cross-msysarm64-gmp'
$lockPath = Join-Path $recipe 'dependency-lock.json'
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw "dependency lock is missing: $lockPath"
}
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($lock.PSObject.Properties.Name -contains 'coordinator_admission') {
    throw 'source must not contain coordinator admission'
}
if ($lock.canonical_runtime_admitted -ne $true -or
    $lock.canonical_runtime.admitted -ne $true -or
    $lock.canonical_runtime.independent_redownload_verified -ne $true -or
    [string]::IsNullOrWhiteSpace(
        $lock.canonical_runtime.coordinator_admission_reference)) {
    throw 'blocked: no corrected runtime identity is independently admitted'
}
$runtimeRequiredFields = @(
    'package',
    'version',
    'pkgrel',
    'required_version',
    'release_tag',
    'asset_name',
    'size',
    'sha256'
)
foreach ($field in $runtimeRequiredFields) {
    if ($null -eq $lock.canonical_runtime.$field -or
        [string]::IsNullOrWhiteSpace(
            [string]$lock.canonical_runtime.$field)) {
        throw "canonical runtime field is unresolved: $field"
    }
}
if ($lock.canonical_runtime.size -le 0 -or
    $lock.canonical_runtime.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'canonical runtime asset seal is invalid'
}
$runtimeVersion = "$($lock.canonical_runtime.version)-" +
    "$($lock.canonical_runtime.pkgrel)"
if ($lock.canonical_runtime.required_version -cne $runtimeVersion) {
    throw 'canonical runtime required_version is inconsistent'
}
if ($lock.build_classification.status -cne
        'canonical-runtime-admitted-build-enabled') {
    throw 'canonical runtime admission did not enable the build'
}
foreach ($denied in $lock.deny_tests) {
    if ($lock.canonical_runtime.version -ceq $denied.version -or
        $lock.canonical_runtime.release_tag -ceq $denied.release_tag) {
        throw 'canonical runtime matches an explicit deny test'
    }
}
foreach ($candidate in $lock.package_candidates.records) {
    if ($candidate.admitted -ne $false -or
        $candidate.eligible_for_admission -ne $false -or
        $candidate.independent_redownload_verified -ne $false -or
        $null -ne $candidate.coordinator_admission_reference -or
        $null -ne $candidate.asset_name -or
        $null -ne $candidate.size -or
        $null -ne $candidate.sha256) {
        throw "candidate build contract is not ready: $($candidate.package)"
    }
}

$destinationFull = [IO.Path]::GetFullPath($Destination)
$sharedFull = [IO.Path]::GetFullPath($SharedRoot)
if ($destinationFull.StartsWith(
        $sharedFull.TrimEnd('\') + '\',
        [StringComparison]::OrdinalIgnoreCase) -or
    $destinationFull -eq $sharedFull) {
    throw "private root cannot be inside shared MSYS2: $destinationFull"
}
if (Test-Path -LiteralPath $Destination) {
    throw "bootstrap destination already exists: $Destination"
}
New-Item -ItemType Directory -Path $Destination | Out-Null

$primary = Join-Path $Destination 'downloads\primary'
$independent = Join-Path $Destination 'downloads\independent-redownload'
$hostPrimary = Join-Path $Destination 'host\primary'
$hostIndependent = Join-Path $Destination 'host\independent-redownload'
$sourcePrimary = Join-Path $Destination 'sources\primary'
$sourceIndependent = Join-Path $Destination 'sources\independent-redownload'
$keys = Join-Path $Destination 'keys'
$keyIndependent = Join-Path $keys 'independent-redownload'
foreach ($directory in @(
        $primary,
        $independent,
        $hostPrimary,
        $hostIndependent,
        $sourcePrimary,
        $sourceIndependent,
        $keys,
        $keyIndependent)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

function Assert-File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Size) {
        throw "size mismatch for $Path`: expected $Size, got $($item.Length)"
    }
    $actual = (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actual -cne $Sha256) {
        throw "SHA-256 mismatch for $Path`: expected $Sha256, got $actual"
    }
}

function Download-HttpPair {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$PrimaryDirectory,
        [Parameter(Mandatory = $true)][string]$IndependentDirectory
    )

    $first = Join-Path $PrimaryDirectory $Name
    $second = Join-Path $IndependentDirectory $Name
    & curl.exe --fail --location --retry 3 --silent --show-error `
        --output $first $Url
    if ($LASTEXITCODE -ne 0) {
        throw "primary curl download failed: $Url"
    }
    Invoke-WebRequest -Uri $Url -OutFile $second
    Assert-File -Path $first -Size $Size -Sha256 $Sha256
    Assert-File -Path $second -Size $Size -Sha256 $Sha256
}

$base = $lock.private_msys2_base
$baseName = [IO.Path]::GetFileName([Uri]$base.archive.url)
$baseSigName = [IO.Path]::GetFileName([Uri]$base.signature.url)
Download-HttpPair `
    -Url $base.archive.url `
    -Name $baseName `
    -Size $base.archive.size `
    -Sha256 $base.archive.sha256 `
    -PrimaryDirectory $sourcePrimary `
    -IndependentDirectory $sourceIndependent
Download-HttpPair `
    -Url $base.signature.url `
    -Name $baseSigName `
    -Size $base.signature.size `
    -Sha256 $base.signature.sha256 `
    -PrimaryDirectory $sourcePrimary `
    -IndependentDirectory $sourceIndependent

$gmpSource = $lock.source
$gmpSourceName = [IO.Path]::GetFileName([Uri]$gmpSource.archive.url)
$gmpSignatureName = [IO.Path]::GetFileName([Uri]$gmpSource.signature.url)
Download-HttpPair `
    -Url $gmpSource.archive.url `
    -Name $gmpSourceName `
    -Size $gmpSource.archive.size `
    -Sha256 $gmpSource.archive.sha256 `
    -PrimaryDirectory $sourcePrimary `
    -IndependentDirectory $sourceIndependent
Download-HttpPair `
    -Url $gmpSource.signature.url `
    -Name $gmpSignatureName `
    -Size $gmpSource.signature.size `
    -Sha256 $gmpSource.signature.sha256 `
    -PrimaryDirectory $sourcePrimary `
    -IndependentDirectory $sourceIndependent
$pseudoRelocationScanner = $lock.pseudo_relocation_scanner
$pseudoRelocationScannerName = [IO.Path]::GetFileName(
    [Uri]$pseudoRelocationScanner.url)
Download-HttpPair `
    -Url $pseudoRelocationScanner.url `
    -Name $pseudoRelocationScannerName `
    -Size $pseudoRelocationScanner.size `
    -Sha256 $pseudoRelocationScanner.sha256 `
    -PrimaryDirectory $sourcePrimary `
    -IndependentDirectory $sourceIndependent

if ($lock.host_assets.Count -ne 15) {
    throw 'immutable host package closure is incomplete'
}
foreach ($asset in $lock.host_assets) {
    Download-HttpPair `
        -Url $asset.url `
        -Name $asset.name `
        -Size $asset.size `
        -Sha256 $asset.sha256 `
        -PrimaryDirectory $hostPrimary `
        -IndependentDirectory $hostIndependent
}

if ($lock.canonical_prerequisite_assets.Count -lt 1) {
    throw 'immutable prerequisite package closure is incomplete'
}
$canonicalAssets = @($lock.canonical_prerequisite_assets) +
    @($lock.canonical_runtime)
foreach ($asset in $canonicalAssets) {
    if ($asset.admitted -ne $true) {
        throw "unadmitted canonical prerequisite: $($asset.asset_name)"
    }
    foreach ($field in @(
            'package',
            'required_version',
            'release_tag',
            'asset_name',
            'size',
            'sha256')) {
        if ($null -eq $asset.$field -or
            [string]::IsNullOrWhiteSpace([string]$asset.$field)) {
            throw "canonical prerequisite field is unresolved: $field"
        }
    }
    if ($asset.size -le 0 -or
        $asset.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "canonical prerequisite asset seal is invalid: $($asset.asset_name)"
    }
    $release = gh api `
        "repos/$repository/releases/tags/$($asset.release_tag)" |
        ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "release lookup failed: $($asset.release_tag)"
    }
    $published = @(
        $release.assets |
            Where-Object Name -CEQ $asset.asset_name
    )
    if ($published.Count -ne 1) {
        throw "expected one release asset: $($asset.asset_name)"
    }
    if ($published[0].size -ne $asset.size -or
        $published[0].digest -cne "sha256:$($asset.sha256)") {
        throw "published release metadata mismatch: $($asset.asset_name)"
    }

    gh release download $asset.release_tag `
        --repo $repository `
        --pattern $asset.asset_name `
        --dir $primary
    if ($LASTEXITCODE -ne 0) {
        throw "gh release download failed: $($asset.asset_name)"
    }
    $encodedName = [Uri]::EscapeDataString($asset.asset_name)
    $url = "https://github.com/$repository/releases/download/" +
        "$($asset.release_tag)/$encodedName"
    $redownload = Join-Path $independent $asset.asset_name
    & curl.exe --fail --location --retry 3 --silent --show-error `
        --output $redownload $url
    if ($LASTEXITCODE -ne 0) {
        throw "independent release download failed: $($asset.asset_name)"
    }
    Assert-File `
        -Path (Join-Path $primary $asset.asset_name) `
        -Size $asset.size `
        -Sha256 $asset.sha256
    Assert-File `
        -Path $redownload `
        -Size $asset.size `
        -Sha256 $asset.sha256
}

$root = Join-Path $Destination 'root'
New-Item -ItemType Directory -Path $root | Out-Null
& tar.exe -xf (Join-Path $sourcePrimary $baseName) `
    -C $root --strip-components 1
if ($LASTEXITCODE -ne 0) {
    throw 'private base extraction failed'
}
$bash = Join-Path $root 'usr\bin\bash.exe'
$cygpath = Join-Path $root 'usr\bin\cygpath.exe'
if (-not (Test-Path -LiteralPath $bash -PathType Leaf) -or
    -not (Test-Path -LiteralPath $cygpath -PathType Leaf)) {
    throw 'private base omitted bash or cygpath'
}

$signingKeys = @(
    $base.signing_key,
    $gmpSource.signing_key
)
foreach ($key in $signingKeys) {
    $keyName = "$($key.fingerprint).asc"
    Download-HttpPair `
        -Url $key.url `
        -Name $keyName `
        -Size $key.size `
        -Sha256 $key.sha256 `
        -PrimaryDirectory $keys `
        -IndependentDirectory $keyIndependent
}

function Convert-PrivatePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $converted = & $cygpath -u ([IO.Path]::GetFullPath($Path))
    if ($LASTEXITCODE -ne 0) {
        throw "private cygpath failed: $Path"
    }
    return $converted
}

$keyPaths = @($signingKeys | ForEach-Object {
    Convert-PrivatePath (Join-Path $keys "$($_.fingerprint).asc")
})
$gpgScript = @'
set -euo pipefail
export PATH=/usr/bin:/bin
export GNUPGHOME=/var/lib/gmp-build-gnupg
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
shift
for key in "$@"; do
    gpg --batch --no-autostart --import "$key"
done
'@
& $bash --noprofile --norc -c $gpgScript -- import @keyPaths
if ($LASTEXITCODE -ne 0) {
    throw 'private signing key import failed'
}

function Confirm-Signature {
    param(
        [Parameter(Mandatory = $true)][string]$Signature,
        [Parameter(Mandatory = $true)][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Fingerprint,
        [Parameter(Mandatory = $true)][string]$PrimaryFingerprint
    )

    $signaturePath = Convert-PrivatePath $Signature
    $payloadPath = Convert-PrivatePath $Payload
    $script = @'
set -euo pipefail
export PATH=/usr/bin:/bin
export GNUPGHOME=/var/lib/gmp-build-gnupg
status="$(gpg --batch --no-autostart --status-fd 1 --verify "$1" "$2" 2>&1)"
printf '%s\n' "$status"
grep -Eq "^\[GNUPG:\] VALIDSIG $3 .* $4$" <<< "$status"
'@
    & $bash --noprofile --norc -c $script -- `
        $signaturePath $payloadPath $Fingerprint $PrimaryFingerprint
    if ($LASTEXITCODE -ne 0) {
        throw "signature verification failed: $Payload"
    }
}

Confirm-Signature `
    -Signature (Join-Path $sourcePrimary $baseSigName) `
    -Payload (Join-Path $sourcePrimary $baseName) `
    -Fingerprint $base.signature.signer `
    -PrimaryFingerprint $base.signature.primary_key
Confirm-Signature `
    -Signature (Join-Path $sourcePrimary $gmpSignatureName) `
    -Payload (Join-Path $sourcePrimary $gmpSourceName) `
    -Fingerprint $gmpSource.signature.signer `
    -PrimaryFingerprint $gmpSource.signing_key.fingerprint

$privateSetup = @'
set -euo pipefail
export PATH=/usr/bin:/bin
export MSYS=winsymlinks:sys
install -d \
  /etc/pacman.d/hooks \
  /etc/pacman.d/gnupg \
  /var/lib/pacman \
  /var/cache/pacman/pkg \
  /var/log
cat > /etc/gmp-build-pacman.conf <<'PACMAN_EOF'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
PACMAN_EOF
cp /etc/gmp-build-pacman.conf /etc/pacman.conf
pacman_args=(
  --root /
  --dbpath /var/lib/pacman
  --cachedir /var/cache/pacman/pkg
  --logfile /var/log/gmp-build-pacman.log
  --config /etc/gmp-build-pacman.conf
  --hookdir /etc/pacman.d/hooks
  --gpgdir /etc/pacman.d/gnupg
)
mapfile -t packages < <(
  find "$1" -maxdepth 1 -type f -name '*.pkg.tar.zst' | LC_ALL=C sort
)
test "${#packages[@]}" -eq 15
pacman "${pacman_args[@]}" --noconfirm -U "${packages[@]}"
test "$(pacman "${pacman_args[@]}" -Q gcc)" = "gcc 15.2.0-1"
test "$(pacman "${pacman_args[@]}" -Q binutils)" = "binutils 2.45-1"
test "$(pacman "${pacman_args[@]}" -Q make)" = "make 4.4.1-3"
test "$(pacman "${pacman_args[@]}" -Q m4)" = "m4 1.4.21-1"
test "$(pacman "${pacman_args[@]}" -Q autoconf2.73)" = "autoconf2.73 2.73-1"
test "$(pacman "${pacman_args[@]}" -Q automake1.18)" = "automake1.18 1.18.1-1"
test "$(pacman "${pacman_args[@]}" -Q libtool)" = "libtool 2.5.4-4"
(
  cd "$1"
  find . -maxdepth 1 -type f -name '*.pkg.tar.zst' -print0 |
    LC_ALL=C sort -z | xargs -0 sha256sum
) > /var/log/gmp-host-assets.sha256
'@
$hostPath = Convert-PrivatePath $hostPrimary
& $bash --noprofile --norc -c $privateSetup -- $hostPath
if ($LASTEXITCODE -ne 0) {
    throw 'private host dependency installation failed'
}

$releasePath = Convert-PrivatePath $primary
$assetManifest = Join-Path $Destination 'canonical-assets.tsv'
@($canonicalAssets | ForEach-Object {
    "$($_.package)`t$($_.required_version)"
}) | Set-Content -LiteralPath $assetManifest -Encoding utf8NoBOM
$assetManifestPath = Convert-PrivatePath $assetManifest
$installAssets = @'
set -euo pipefail
export PATH=/opt/bin:/usr/bin:/bin
export MSYS=winsymlinks:sys
pacman_args=(
  --root /
  --dbpath /var/lib/pacman
  --cachedir /var/cache/pacman/pkg
  --logfile /var/log/gmp-build-pacman.log
  --config /etc/gmp-build-pacman.conf
  --hookdir /etc/pacman.d/hooks
  --gpgdir /etc/pacman.d/gnupg
)
mapfile -t packages < <(
  find "$1" -maxdepth 1 -type f -name '*.pkg.tar.zst' | LC_ALL=C sort
)
test "${#packages[@]}" -eq "$2"
pacman "${pacman_args[@]}" --noconfirm -U "${packages[@]}"
while IFS=$'\t' read -r package version; do
  test -n "${package}"
  test -n "${version}"
  test "$(pacman "${pacman_args[@]}" -Q "${package}")" = \
    "${package} ${version}"
done < "$3"
test "$(sha256sum /opt/bin/aarch64-pc-cygwin-ld.exe | cut -d ' ' -f 1)" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
test "$(aarch64-pc-msys-gcc -dumpmachine)" = aarch64-pc-msys
test "$(aarch64-pc-msys-gcc -print-sysroot)" = /opt/aarch64-pc-msys
test "$(aarch64-pc-msys-g++ -dumpmachine)" = aarch64-pc-msys
test "$(aarch64-pc-msys-g++ -print-sysroot)" = /opt/aarch64-pc-msys
pacman "${pacman_args[@]}" -Q | LC_ALL=C sort > /var/log/gmp-host-packages.txt
'@
& $bash --noprofile --norc -c $installAssets -- `
    $releasePath `
    $canonicalAssets.Count `
    $assetManifestPath
if ($LASTEXITCODE -ne 0) {
    throw 'private target toolchain installation failed'
}

$summary = [ordered]@{
    schema = 1
    root = 'private'
    sources = 'independently-redownloaded-and-verified'
    host_assets = 'independently-redownloaded-and-verified'
    prerequisite_assets = 'independently-redownloaded-and-verified'
    classification = 'canonical-runtime-admitted-build-enabled'
    admissible = $false
    runtime_package = $lock.canonical_runtime.package
    runtime_version = $runtimeVersion
    runtime_release_tag = $lock.canonical_runtime.release_tag
    base_sha256 = $base.archive.sha256
    target = 'aarch64-pc-msys'
    linker_sha256 =
        '075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f'
    scanner_sha256 =
        '888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9'
}
$summary | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $Destination 'bootstrap.json') `
        -Encoding utf8NoBOM

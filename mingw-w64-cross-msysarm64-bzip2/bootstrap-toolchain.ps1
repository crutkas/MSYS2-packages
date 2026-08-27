param(
    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [switch]$Install,

    [switch]$RuntimeOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = 'crutkas/MSYS2-packages'
$baseName = 'msys2-base-x86_64-20260611.tar.xz'
$baseUrl = "https://repo.msys2.org/distrib/x86_64/$baseName"
$baseSize = 53555380L
$baseSha256 = 'a2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221'
$baseSignatureUrl = "$baseUrl.sig"
$baseSignatureSize = 566L
$baseSignatureSha256 = '076f5623b702d5016cf0253e1d14a6bd4870a90243243e96409b227f0d5bf70f'
$baseSigner = 'E0AA0F031DBD80FFBA57B06D5A62D0CAB6264964'
$baseSigningKeyFingerprint = '0EBF782C5D53F7E5FB02A66746BD761F7A49B0EC'
$baseSigningKeyName = "msys2-installer-$baseSigningKeyFingerprint.asc"
$baseSigningKeyUrl = 'https://keyserver.ubuntu.com/pks/lookup'
$hostPackageBaseUrl = 'https://repo.msys2.org/msys/x86_64'
$hostPackageSigner = '5F944B027F7FE2091985AA2EFA11531AA0AA7F57'
$hostPackages = [ordered]@{
    'make-4.4.1-3-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Size = 514683L
        Sha256 = 'af0bdba17f06fe037f0194069adaa31a8fe45f1a11381501896aea1fae37bd5d'
        SignatureSize = 566L
        SignatureSha256 = '7f53c96aeb1a29d9917e2b00e9f709fbdc5b0458e6535e88b1fed69365191265'
    }
    'patch-2.7.6-3-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Size = 98395L
        Sha256 = 'dd75ca0f715dd9c71a43af6a0ff3d068faeee1d768e02282d319671201cd5d45'
        SignatureSize = 566L
        SignatureSha256 = 'b05a72f972973df0b5aea64fa0531b12832f2a6c79af2bf93c481e00b7f2a674'
    }
    'isl-0.27-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Size = 768472L
        Sha256 = 'cdd0a4ce0bf0d9e3f3eff2b770b8143e09e126a614de8b55bb5d30fc596b92d1'
        SignatureSize = 566L
        SignatureSha256 = '3b750274ab3cb639270008c5ec9d8899ff3853cc8fdcd68a3659027d510497b8'
    }
    'mpc-1.4.1-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Size = 87944L
        Sha256 = '0f5073ec2e8be265854ee3c7cb1079b5e8e02264d53e659d8414988c6c182f16'
        SignatureSize = 566L
        SignatureSha256 = 'da7938e3020fad92d4acf2144206c8d9e4f8147fc1de62bca8011a2d6aee5e86'
    }
}

function Assert-PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Size) {
        throw "size mismatch for $($item.Name): expected $Size, got $($item.Length)"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) {
        throw "SHA-256 mismatch for $($item.Name): expected $Sha256, got $actual"
    }
}

function New-PrivateMsysRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RootDirectory,
        [switch]$InstallBuildTools
    )

    $downloadDirectory = Join-Path $Destination 'base-download'
    $redownloadDirectory = Join-Path $Destination 'base-independent-redownload'
    $hostDirectory = Join-Path $Destination 'host-packages'
    $hostRedownloadDirectory = Join-Path $Destination 'host-packages-independent-redownload'
    $extractDirectory = Join-Path $Destination 'base-extract'
    New-Item -ItemType Directory `
        -Path $downloadDirectory, $redownloadDirectory, $hostDirectory, `
              $hostRedownloadDirectory, $extractDirectory |
        Out-Null
    $archive = Join-Path $downloadDirectory $baseName
    $signature = "$archive.sig"
    $signingKey = Join-Path $downloadDirectory $baseSigningKeyName
    $redownloadArchive = Join-Path $redownloadDirectory $baseName
    $redownloadSignature = "$redownloadArchive.sig"
    $redownloadSigningKey = Join-Path $redownloadDirectory $baseSigningKeyName
    & curl.exe --fail --location --retry 3 --silent --show-error `
        --output $archive $baseUrl
    if ($LASTEXITCODE -ne 0) {
        throw 'private MSYS2 base download failed'
    }
    & curl.exe --fail --location --retry 3 --silent --show-error `
        --output $signature $baseSignatureUrl
    if ($LASTEXITCODE -ne 0) {
        throw 'private MSYS2 base signature download failed'
    }
    & curl.exe --fail --location --retry 3 --silent --show-error --get `
        --data-urlencode 'op=get' `
        --data-urlencode "search=0x$baseSigner" `
        --output $signingKey $baseSigningKeyUrl
    if ($LASTEXITCODE -ne 0) {
        throw 'private MSYS2 base signing key download failed'
    }
    Invoke-WebRequest -UseBasicParsing -Uri $baseUrl `
        -OutFile $redownloadArchive
    Invoke-WebRequest -UseBasicParsing -Uri $baseSignatureUrl `
        -OutFile $redownloadSignature
    & curl.exe --fail --location --retry 3 --silent --show-error --get `
        --data-urlencode 'op=get' `
        --data-urlencode "search=0x$baseSigner" `
        --output $redownloadSigningKey $baseSigningKeyUrl
    if ($LASTEXITCODE -ne 0) {
        throw 'independent private MSYS2 base signing key download failed'
    }
    Assert-PinnedFile -Path $archive -Size $baseSize -Sha256 $baseSha256
    Assert-PinnedFile -Path $signature -Size $baseSignatureSize `
        -Sha256 $baseSignatureSha256
    Assert-PinnedFile -Path $redownloadArchive -Size $baseSize `
        -Sha256 $baseSha256
    Assert-PinnedFile -Path $redownloadSignature -Size $baseSignatureSize `
        -Sha256 $baseSignatureSha256
    foreach ($keyFile in $signingKey, $redownloadSigningKey) {
        if ((Get-Item -LiteralPath $keyFile).Length -eq 0) {
            throw 'private MSYS2 base signing key download is empty'
        }
    }
    if ($InstallBuildTools) {
        foreach ($entry in $hostPackages.GetEnumerator()) {
            $packageUrl = "$hostPackageBaseUrl/$($entry.Key)"
            $package = Join-Path $hostDirectory $entry.Key
            $packageSignature = "$package.sig"
            $redownloadPackage = Join-Path $hostRedownloadDirectory $entry.Key
            $redownloadPackageSignature = "$redownloadPackage.sig"
            & curl.exe --fail --location --retry 3 --silent --show-error `
                --output $package $packageUrl
            if ($LASTEXITCODE -ne 0) {
                throw "private host package download failed: $($entry.Key)"
            }
            & curl.exe --fail --location --retry 3 --silent --show-error `
                --output $packageSignature "$packageUrl.sig"
            if ($LASTEXITCODE -ne 0) {
                throw "private host package signature download failed: $($entry.Key)"
            }
            Invoke-WebRequest -UseBasicParsing -Uri $packageUrl `
                -OutFile $redownloadPackage
            Invoke-WebRequest -UseBasicParsing -Uri "$packageUrl.sig" `
                -OutFile $redownloadPackageSignature
            Assert-PinnedFile -Path $package -Size $entry.Value.Size `
                -Sha256 $entry.Value.Sha256
            Assert-PinnedFile -Path $packageSignature `
                -Size $entry.Value.SignatureSize `
                -Sha256 $entry.Value.SignatureSha256
            Assert-PinnedFile -Path $redownloadPackage -Size $entry.Value.Size `
                -Sha256 $entry.Value.Sha256
            Assert-PinnedFile -Path $redownloadPackageSignature `
                -Size $entry.Value.SignatureSize `
                -Sha256 $entry.Value.SignatureSha256
        }
    }

    $archivePreflight = @'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
with tarfile.open(archive, mode="r:xz") as handle:
    members = handle.getmembers()
    if not members:
        raise SystemExit("private base archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or path.parts[0] != "msys64":
            raise SystemExit(f"unsafe or unexpected archive path: {member.name}")
        if ".." in path.parts:
            raise SystemExit(f"archive traversal path: {member.name}")
        if member.issym() or member.islnk():
            target = pathlib.PurePosixPath(member.linkname)
            if target.is_absolute():
                raise SystemExit(f"absolute archive link: {member.name}")
            resolved = pathlib.PurePosixPath(*path.parent.parts, *target.parts)
            depth = 0
            for part in resolved.parts:
                if part == "..":
                    depth -= 1
                elif part not in ("", "."):
                    depth += 1
                if depth < 0:
                    raise SystemExit(f"archive link traversal: {member.name}")
'@
    & python -c $archivePreflight $archive
    if ($LASTEXITCODE -ne 0) {
        throw 'private MSYS2 base archive preflight failed'
    }

    & tar.exe -xf $archive -C $extractDirectory
    if ($LASTEXITCODE -ne 0) {
        throw 'private MSYS2 base extraction failed'
    }
    $extractedRoot = Join-Path $extractDirectory 'msys64'
    if (-not (Test-Path -LiteralPath $extractedRoot -PathType Container)) {
        throw 'private MSYS2 base did not contain msys64'
    }
    Move-Item -LiteralPath $extractedRoot -Destination $RootDirectory
    Remove-Item -LiteralPath $extractDirectory -Force

    $bash = Join-Path $RootDirectory 'usr\bin\bash.exe'
    $pacman = Join-Path $RootDirectory 'usr\bin\pacman.exe'
    $cygpath = Join-Path $RootDirectory 'usr\bin\cygpath.exe'
    foreach ($tool in $bash, $pacman, $cygpath) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
            throw "private MSYS2 tool is missing: $tool"
        }
    }

    $env:MSYS = 'winsymlinks:sys'
    $env:PATH = "$(Join-Path $RootDirectory 'usr\bin');$env:PATH"
    $verificationGpgDirectory = Join-Path $RootDirectory 'etc\bootstrap-gnupg'
    New-Item -ItemType Directory -Path $verificationGpgDirectory | Out-Null
    $archivePosix = & $cygpath -u $archive
    $signaturePosix = & $cygpath -u $signature
    $signingKeyPosix = & $cygpath -u $signingKey
    $redownloadSigningKeyPosix = & $cygpath -u $redownloadSigningKey
    foreach ($keyPath in $signingKeyPosix, $redownloadSigningKeyPosix) {
        $keyListing = & $bash --noprofile --norc -c @'
set -e
/usr/bin/gpg --homedir /etc/bootstrap-gnupg --batch --no-autostart \
  --with-colons --import-options show-only --import "$1"
'@ -- $keyPath 2>&1
        $keyListingLines = @(
            $keyListing |
                ForEach-Object { $_.ToString() }
        )
        if ($LASTEXITCODE -ne 0 -or
            -not ($keyListingLines -match
                "^fpr:::::::::$baseSigningKeyFingerprint`:$") -or
            -not ($keyListingLines -match "^fpr:::::::::$baseSigner`:$")) {
            throw 'private MSYS2 base signing key fingerprint check failed'
        }
    }
    & $bash --noprofile --norc -c @'
set -e
/usr/bin/gpg --homedir /etc/bootstrap-gnupg --batch --no-autostart --import "$1"
'@ -- $signingKeyPosix
    if ($LASTEXITCODE -ne 0) {
        throw 'private MSYS2 base signing key import failed'
    }
    $signatureOutput = & $bash --noprofile --norc -c @'
set -e
/usr/bin/gpg --homedir /etc/bootstrap-gnupg --batch --no-autostart \
  --status-fd 1 --verify "$1" "$2"
'@ -- $signaturePosix $archivePosix 2>&1
    $signatureExitCode = $LASTEXITCODE
    $signatureStatus = @($signatureOutput) |
        ForEach-Object { $_.ToString() }
    $validSignatureLines = @(
        $signatureStatus |
            Where-Object {
                $_.StartsWith("[GNUPG:] VALIDSIG $baseSigner ") -and
                $_.EndsWith(" $baseSigningKeyFingerprint")
            }
    )
    if ($signatureExitCode -ne 0 -or
        $validSignatureLines.Count -ne 1) {
        throw 'private MSYS2 base detached signature verification failed'
    }

    & $bash --noprofile --norc -lc `
        '/usr/bin/pacman-key --gpgdir /etc/pacman.d/gnupg --init'
    if ($LASTEXITCODE -ne 0) {
        throw 'private pacman keyring initialization failed'
    }
    & $bash --noprofile --norc -lc `
        '/usr/bin/pacman-key --gpgdir /etc/pacman.d/gnupg --populate msys2'
    if ($LASTEXITCODE -ne 0) {
        throw 'private pacman keyring population failed'
    }

    @'
[options]
Architecture = auto
# This config has no repositories. Every local package is hash-pinned above, and
# official repository packages are additionally verified against their detached sigs.
SigLevel = Never
LocalFileSigLevel = Never
'@ | Set-Content `
        -LiteralPath (Join-Path $RootDirectory 'etc\pacman-local.conf') `
        -Encoding utf8NoBOM
    $pacmanArguments = @(
        '--root', '/'
        '--dbpath', '/var/lib/pacman'
        '--cachedir', '/var/cache/pacman/pkg'
        '--logfile', '/var/log/pacman.log'
        '--config', '/etc/pacman-local.conf'
        '--hookdir', '/etc/pacman.d/hooks'
        '--gpgdir', '/etc/pacman.d/gnupg'
    )
    New-Item -ItemType Directory -Force `
        -Path (Join-Path $RootDirectory 'var\cache\pacman\pkg'), `
              (Join-Path $RootDirectory 'var\log'), `
              (Join-Path $RootDirectory 'etc\pacman.d\hooks') | Out-Null

    if ($InstallBuildTools) {
        $hostPackagePaths = @(
            foreach ($name in $hostPackages.Keys) {
            $package = Join-Path $hostDirectory $name
            $packageSignature = "$package.sig"
            $packagePosix = (& $cygpath -u $package).Trim()
            $signaturePosix = (& $cygpath -u $packageSignature).Trim()
            $hostSignatureOutput = & $bash --noprofile --norc -c @'
set -e
/usr/bin/gpg --homedir /etc/pacman.d/gnupg --batch --no-autostart \
  --status-fd 1 --verify "$1" "$2"
'@ -- $signaturePosix $packagePosix 2>&1
            $hostSignatureExitCode = $LASTEXITCODE
            $hostSignatureLines = @(
                $hostSignatureOutput |
                    ForEach-Object { $_.ToString() }
            )
            $validHostSignatures = @(
                $hostSignatureLines |
                    Where-Object {
                        $_.StartsWith(
                            "[GNUPG:] VALIDSIG $hostPackageSigner "
                        )
                    }
            )
            if ($hostSignatureExitCode -ne 0 -or
                $validHostSignatures.Count -ne 1) {
                throw "private host package signature verification failed: $name"
            }
                $packagePosix
            }
        )
        & $pacman @pacmanArguments -U --noconfirm -- @hostPackagePaths
        if ($LASTEXITCODE -ne 0) {
            throw 'private MSYS2 build dependency transaction failed'
        }
        $installedHostPackages = @(
            & $pacman @pacmanArguments -Q make patch isl mpc
        ) | ForEach-Object { $_.ToString() }
        if ($LASTEXITCODE -ne 0 -or
            $installedHostPackages.Count -ne $hostPackages.Count -or
            $installedHostPackages -notcontains 'make 4.4.1-3' -or
            $installedHostPackages -notcontains 'patch 2.7.6-3' -or
            $installedHostPackages -notcontains 'isl 0.27-1' -or
            $installedHostPackages -notcontains 'mpc 1.4.1-1') {
            throw 'private MSYS2 build dependency identity check failed'
        }
    }

    @(
        "identity`tvalue"
        "base-url`t$baseUrl"
        "base-bytes`t$baseSize"
        "base-sha256`t$baseSha256"
        "signature-url`t$baseSignatureUrl"
        "signature-bytes`t$baseSignatureSize"
        "signature-sha256`t$baseSignatureSha256"
        "signature-signer`t$baseSigner"
        "signing-key-url`t$baseSigningKeyUrl"
        "signing-key-primary-fingerprint`t$baseSigningKeyFingerprint"
        "signing-key-primary-sha256`t$((Get-FileHash -LiteralPath $signingKey -Algorithm SHA256).Hash.ToLowerInvariant())"
        "signing-key-redownload-sha256`t$((Get-FileHash -LiteralPath $redownloadSigningKey -Algorithm SHA256).Hash.ToLowerInvariant())"
        "archive-preflight`tpass"
        "private-root`troot"
        "private-db`troot/var/lib/pacman"
        "private-cache`troot/var/cache/pacman/pkg"
        "private-log`troot/var/log/pacman.log"
        "private-config`troot/etc/pacman-local.conf"
        "private-hooks`troot/etc/pacman.d/hooks"
        "private-gpg`troot/etc/pacman.d/gnupg"
    ) | Set-Content -LiteralPath (Join-Path $Destination 'private-base.tsv') `
        -Encoding utf8NoBOM
    if ($InstallBuildTools) {
        @(
            "asset`tbytes`tsha256`tsignature-bytes`tsignature-sha256`tsigner"
            foreach ($entry in $hostPackages.GetEnumerator()) {
                "$($entry.Key)`t$($entry.Value.Size)`t$($entry.Value.Sha256)`t" +
                    "$($entry.Value.SignatureSize)`t$($entry.Value.SignatureSha256)`t" +
                    $hostPackageSigner
            }
        ) | Set-Content -LiteralPath (Join-Path $Destination 'host-inputs.tsv') `
            -Encoding utf8NoBOM
    }

    [pscustomobject]@{
        Root = $RootDirectory
        Bash = $bash
        Pacman = $pacman
        PacmanArguments = $pacmanArguments
        Cygpath = $cygpath
    }
}

$expected = [ordered]@{
    'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-binutils-pr21-3356eec-20260827'
        Size = 6545114L
        Sha256 = '3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b'
    }
    'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Size = 43966034L
        Sha256 = '063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e'
    }
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-gcc-static-runtime-20260815'
        Size = 357954L
        Sha256 = '17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c'
    }
    'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'cygwinarm64-libstdcxx-headers-pr7-20260815'
        Size = 2184212L
        Sha256 = '1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6'
    }
    'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 9319013L
        Sha256 = '263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21'
    }
    'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 4743L
        Sha256 = '33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f'
    }
    'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 86822L
        Sha256 = 'e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca'
    }
    'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Size = 2349635L
        Sha256 = '7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24'
    }
    'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 9893043L
        Sha256 = '158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e'
    }
    'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-runtime-pr10-a527-20260824'
        Size = 4426157L
        Sha256 = 'c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1'
    }
    'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-support-20260826'
        Size = 1520166L
        Sha256 = '9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08'
    }
    'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Size = 4963824L
        Sha256 = '990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438'
    }
    'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst' = [pscustomobject]@{
        Tag = 'msysarm64-gcc-pr13-20260826'
        Size = 83876291L
        Sha256 = 'a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22'
    }
}

$selectedInputs = [ordered]@{}
if ($RuntimeOnly) {
    $runtimeInputNames = @(
        'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
    )
    foreach ($name in $runtimeInputNames) {
        $selectedInputs[$name] = $expected[$name]
    }
}
else {
    foreach ($entry in $expected.GetEnumerator()) {
        $selectedInputs[$entry.Key] = $entry.Value
    }
}

function Download-InputSet {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)]
        [ValidateSet('gh', 'curl')]
        [string]$Method
    )

    if (Test-Path -LiteralPath $Directory) {
        throw "download destination already exists: $Directory"
    }
    New-Item -ItemType Directory -Path $Directory | Out-Null

    $releaseCache = @{}
    $hashes = [ordered]@{}
    foreach ($entry in $selectedInputs.GetEnumerator()) {
        $name = $entry.Key
        $asset = $entry.Value
        if (-not $releaseCache.ContainsKey($asset.Tag)) {
            $releaseJson = & gh api `
                "repos/$repository/releases/tags/$($asset.Tag)"
            if ($LASTEXITCODE -ne 0) {
                throw "release lookup failed: $($asset.Tag)"
            }
            $releaseCache[$asset.Tag] = $releaseJson | ConvertFrom-Json
        }

        $published = @(
            $releaseCache[$asset.Tag].assets |
                Where-Object Name -EQ $name
        )
        if ($published.Count -ne 1) {
            throw "expected one published release asset: $name"
        }
        if ($published[0].size -ne $asset.Size) {
            throw "published size mismatch for $name"
        }
        if ($published[0].digest -ne "sha256:$($asset.Sha256)") {
            throw "published digest mismatch for $name"
        }

        $path = Join-Path $Directory $name
        if ($Method -eq 'gh') {
            & gh release download $asset.Tag `
                --repo $repository `
                --pattern $name `
                --dir $Directory
            if ($LASTEXITCODE -ne 0) {
                throw "primary gh download failed: $name"
            }
        }
        else {
            $encodedName = [Uri]::EscapeDataString($name)
            $url = "https://github.com/$repository/releases/download/$($asset.Tag)/$encodedName"
            & curl.exe --fail --location --retry 3 `
                --silent --show-error `
                --output $path $url
            if ($LASTEXITCODE -ne 0) {
                throw "independent curl download failed: $name"
            }
        }

        $item = Get-Item -LiteralPath $path
        if ($item.Length -ne $asset.Size) {
            throw "downloaded size mismatch for $name"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $asset.Sha256) {
            throw "SHA-256 mismatch for $name`: expected $($asset.Sha256), got $hash"
        }
        $hashes[$name] = $hash
    }

    $actualNames = @(
        Get-ChildItem -LiteralPath $Directory -File -Filter '*.pkg.tar.zst' |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedNames = @($selectedInputs.Keys | Sort-Object)
    if (Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames) {
        throw 'downloaded package set does not exactly match the pinned input set'
    }

    return $hashes
}

if (-not $env:GH_TOKEN) {
    throw 'GH_TOKEN is required'
}
if ($Install -and $RuntimeOnly) {
    throw 'Install and RuntimeOnly are mutually exclusive'
}
if (Test-Path -LiteralPath $Destination) {
    throw "destination already exists: $Destination"
}
New-Item -ItemType Directory -Path $Destination | Out-Null
$privateRoot = Join-Path $Destination 'root'
$privateOutput = @(
    New-PrivateMsysRoot `
        -RootDirectory $privateRoot `
        -InstallBuildTools:(-not $RuntimeOnly)
)
$privateCandidates = @(
    $privateOutput |
        Where-Object {
            $_.PSObject.Properties.Name -contains 'Cygpath' -and
            $_.PSObject.Properties.Name -contains 'Pacman'
        }
)
if ($privateCandidates.Count -ne 1) {
    throw 'private MSYS2 root materialization did not return one root identity'
}
$private = $privateCandidates[0]

$primaryDirectory = Join-Path $Destination 'primary'
$redownloadDirectory = Join-Path $Destination 'independent-redownload'
$primaryHashes = Download-InputSet -Directory $primaryDirectory -Method gh
$redownloadHashes = Download-InputSet -Directory $redownloadDirectory -Method curl

foreach ($name in $selectedInputs.Keys) {
    if ($primaryHashes[$name] -ne $redownloadHashes[$name]) {
        throw "independent redownload mismatch for $name"
    }
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$hashReport = Join-Path $Destination 'release-inputs.tsv'
@(
    "source`tidentity`tasset`tsha256"
    foreach ($name in $selectedInputs.Keys) {
        $source = "release:$($selectedInputs[$name].Tag)"
        "$source`tgh+curl`t$name`t$($primaryHashes[$name])"
    }
) | Set-Content -LiteralPath $hashReport -Encoding utf8NoBOM

if (-not $Install -and -not $RuntimeOnly) {
    exit 0
}

$installOrder = if ($RuntimeOnly) {
    @($runtimeInputNames)
}
else {
    @(
        'mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst'
        'mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
        'mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst'
        'mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst'
        'mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst'
    )
}
$packagePaths = @(
    $installOrder |
        ForEach-Object {
            & $private.Cygpath -u (Join-Path $primaryDirectory $_)
        }
)
$pacman = $private.Pacman
$bash = $private.Bash
$pacmanArguments = $private.PacmanArguments

$env:MSYS = 'winsymlinks:sys'
& $pacman @pacmanArguments --noconfirm -U -- @packagePaths
if ($LASTEXITCODE -ne 0) {
    throw "atomic toolchain transaction failed with exit code $LASTEXITCODE"
}

if ($RuntimeOnly) {
    $runtimePreflight = @'
set -euo pipefail
test -f /opt/aarch64-pc-msys/bin/msys-2.0.dll
test -f /opt/aarch64-pc-msys/lib/libmsys-2.0.a
'@
    & $bash --noprofile --norc -c $runtimePreflight
    if ($LASTEXITCODE -ne 0) {
        throw "installed runtime preflight failed with exit code $LASTEXITCODE"
    }
    @(
        "package`tversion"
        foreach ($name in @(
            'mingw-w64-cross-msysarm64-headers'
            'mingw-w64-cross-msysarm64-windows-default-manifest'
            'mingw-w64-cross-msysarm64-sysroot'
            'mingw-w64-cross-msysarm64-runtime'
            'mingw-w64-cross-msysarm64-runtime-devel'
        )) {
            $query = & $pacman @pacmanArguments -Q $name
            if ($LASTEXITCODE -ne 0) {
                throw "installed runtime query failed: $name"
            }
            ($query -replace ' ', "`t")
        }
    ) | Set-Content `
        -LiteralPath (Join-Path $Destination 'installed-runtime.tsv') `
        -Encoding utf8NoBOM
    exit 0
}

$preflight = @'
set -euo pipefail
export PATH=/usr/bin:/opt/bin:/mingw64/bin:$PATH
test "$(aarch64-pc-msys-gcc -dumpmachine)" = aarch64-pc-msys
test "$(aarch64-pc-msys-gcc -dumpversion)" = 15.0.1
test "$(sha256sum /opt/bin/aarch64-pc-cygwin-ld.exe | cut -d" " -f1)" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
tools=(
  addr2line ar as c++filt dlltool dllwrap elfedit gprof ld ld.bfd
  nm objcopy objdump ranlib readelf size strings strip windmc windres
)
for tool in "${tools[@]}"; do
  alias="/opt/bin/aarch64-pc-msys-${tool}.exe"
  test -L "$alias"
  test "$(readlink "$alias")" = "aarch64-pc-cygwin-${tool}.exe"
done
test -L /opt/aarch64-pc-msys/bin/ar.exe
test "$(readlink /opt/aarch64-pc-msys/bin/ar.exe)" = ../../aarch64-pc-cygwin/bin/ar.exe
test -f /opt/aarch64-pc-msys/bin/msys-2.0.dll
test -f /opt/aarch64-pc-msys/lib/libmsys-2.0.a
test -f /opt/aarch64-pc-msys/usr/lib/libkernel32.a
'@
& $bash --noprofile --norc -c $preflight
if ($LASTEXITCODE -ne 0) {
    throw "installed compiler preflight failed with exit code $LASTEXITCODE"
}

$ownership = [ordered]@{
    '/opt/bin/aarch64-pc-msys-gcc.exe' =
        'mingw-w64-cross-msysarm64-gcc'
    '/opt/bin/aarch64-pc-cygwin-ar.exe' =
        'mingw-w64-cross-cygwinarm64-binutils'
    '/opt/bin/aarch64-pc-msys-ld.exe' =
        'mingw-w64-cross-cygwinarm64-binutils'
}
foreach ($entry in $ownership.GetEnumerator()) {
    $owner = & $pacman @pacmanArguments -Qoq $entry.Key
    if ($LASTEXITCODE -ne 0 -or $owner -ne $entry.Value) {
        throw "private package ownership mismatch for $($entry.Key)"
    }
}

$installedReport = Join-Path $Destination 'installed-toolchain.tsv'
$installedNames = @(
    'mingw-w64-cross-cygwinarm64-binutils'
    'mingw-w64-cross-cygwinarm64-gcc-stage1'
    'mingw-w64-cross-cygwinarm64-gcc-libs-stage1'
    'mingw-w64-cross-cygwinarm64-libstdc++-headers'
    'mingw-w64-cross-msysarm64-headers'
    'mingw-w64-cross-msysarm64-windows-default-manifest'
    'mingw-w64-cross-msysarm64-sysroot'
    'mingw-w64-cross-msysarm64-w32api-runtime'
    'mingw-w64-cross-msysarm64-runtime'
    'mingw-w64-cross-msysarm64-runtime-devel'
    'mingw-w64-cross-msysarm64-libstdc++-headers'
    'mingw-w64-cross-msysarm64-gcc-libs'
    'mingw-w64-cross-msysarm64-gcc'
)
@(
    "package`tversion"
    foreach ($name in $installedNames) {
        $query = & $pacman @pacmanArguments -Q $name
        if ($LASTEXITCODE -ne 0) {
            throw "installed package query failed: $name"
        }
        ($query -replace ' ', "`t")
    }
) | Set-Content -LiteralPath $installedReport -Encoding utf8NoBOM

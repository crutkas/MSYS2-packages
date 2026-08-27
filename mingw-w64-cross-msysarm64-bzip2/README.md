# AArch64 MSYS bzip2/libbz2

This fork-only recipe cross-builds bzip2 1.0.8 for the native
`aarch64-pc-msys` personality. It does not replace the repository's existing
i686/x86_64 `bzip2` recipe and must not be submitted upstream.

## Package boundary

- `mingw-w64-cross-msysarm64-libbz2` owns
  `/opt/aarch64-pc-msys/usr/bin/msys-bz2-1.dll`.
- `mingw-w64-cross-msysarm64-libbz2-devel` owns `bzlib.h`, `libbz2.a`,
  `libbz2.dll.a`, and relocatable `bzip2.pc` metadata below
  `/opt/aarch64-pc-msys/usr`.
- `mingw-w64-cross-msysarm64-bzip2` owns only target CLI programs, scripts,
  and manuals. The four target PEs are `bzip2.exe`, `bunzip2.exe`,
  `bzcat.exe`, and `bzip2recover.exe`.

No x86_64 build utility is shipped. The CLI package is not a build-host tools
package. GnuPG consumes only the exact `libbz2=1.0.8-4` and
`libbz2-devel=1.0.8-4` packages.

## Immutable inputs

The source archive, detached signature, and release key are pinned:

| Input | Bytes | SHA-256 / fingerprint |
| --- | ---: | --- |
| `bzip2-1.0.8.tar.gz` | 810029 | `ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269` |
| `bzip2-1.0.8.tar.gz.sig` | 310 | `c667e2db9a3cd17bde492584263cb7c30d8050538678ece3078ae58230e6e5e1` |
| release key | 5236 | `3a189df1faa883973d80f1fc6d7450affddbf35989427692a6bf90e48b7466ad` |
| release signer | - | `EC3CFE88F6CA0788774F5C1D1AA44BE649DE760A` |

The private build client is materialized only from:

| Identity | Value |
| --- | --- |
| Base | `https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260611.tar.xz` |
| Bytes / SHA-256 | `53555380` / `a2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221` |
| Signature bytes / SHA-256 | `566` / `076f5623b702d5016cf0253e1d14a6bd4870a90243243e96409b227f0d5bf70f` |
| Signature signer | `E0AA0F031DBD80FFBA57B06D5A62D0CAB6264964` |
| Signing-key primary fingerprint | `0EBF782C5D53F7E5FB02A66746BD761F7A49B0EC` |

The archive and signature are independently downloaded twice and traversal/link
preflighted before extraction. The installer key is retrieved by exact signing
subkey and both its primary and signing fingerprints are required in a dedicated
private verification keyring. Build roots add only byte-pinned, signed
`make-4.4.1-3`, `patch-2.7.6-3`, `isl-0.27-1`, and `mpc-1.4.1-1` archives; no
live repository synchronization or named package installation is allowed.
Native execution roots install only the pinned runtime closure. Bootstrap
transactions use a repository-free private pacman configuration, so an omitted
dependency fails rather than downloading. Every pacman transaction uses that
root's client and explicit root, database, cache, log, config, hooks, and GPG paths.
`C:\msys64\usr\bin\pacman.exe` is never invoked; the shared package database and
log are only hashed as before/after sentinels.

Target inputs are the a527 runtime/sysroot release, the complete GCC/support
releases, and fixed binutils `2.44.50-2`. The linker SHA-256 is
`075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`.
The reviewed scanner is kept byte-for-byte at
`.ci/check-aarch64-pseudo-relocs.ps1`, SHA-256
`888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`.

## Gates

The focused workflow builds twice in independent private roots and requires
byte-identical canonical package archives. Validation covers:

- AA64 PE/COFF identity for every DLL, executable, object, and archive member;
- deterministic target `ar`/`ranlib` indexes for static and import archives;
- exact exports/import symbols, MSYS runtime imports, and no Cygwin/MinGW/x64
  contamination;
- static and shared native consumers plus reviewed pseudo-reloc reports bound
  to input hashes;
- archive path/link preflight, package metadata, non-overlap, ownership,
  install/remove/reinstall restoration, corrupted-package rejection, and path
  leak checks;
- Windows 11 ARM CLI compression/decompression, stdin/pipeline and file modes,
  CRC/error behavior, large deterministic input, concurrent API consumers,
  process/native architecture, and loaded-module paths/machines.

Workflow artifacts are candidates only. No release is created, and downstream
consumption remains blocked until the coordinator admits one unique release
tag and its exact asset bytes, hashes, producer commit, metadata, owned paths,
DLL basename, and evidence identities.

# AArch64 MSYS SQLite layer

This fork-only package source-builds SQLite 3.53.4 for `aarch64-pc-msys`.
It is an independent layer on `crutkas-aarch64-gcc-layer` and does not consume
MinGW, Cygwin, x64 MSYS, or sibling native-library package outputs.

## Package split

- `mingw-w64-cross-msysarm64-libsqlite` owns `msys-sqlite3-0.dll`.
- `mingw-w64-cross-msysarm64-libsqlite-devel` owns the headers, static and
  import libraries, pkg-config metadata, validation report, and validator.
- `mingw-w64-cross-msysarm64-sqlite` owns the native `sqlite3.exe` shell.

All target payloads live below `/opt/aarch64-pc-msys`. Package archives use the
`x86_64` package architecture because they are installed into the x64 MSYS
cross-build host; every executable, DLL, object, and archive member inside the
target prefix is AArch64 PE/COFF.

## Pinned inputs

SQLite uses the current repository recipe version and feature flags where the
independent target sysroot can support them:

- source: `sqlite-amalgamation-3530400.zip`
- SHA-256: `1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d`
- runtime/sysroot release: `msysarm64-runtime-pr10-a527-20260824`
- runtime/sysroot version: `3.6.10.r0.ga527ace21-1`
- GCC release: `msysarm64-gcc-pr13-20260826`
- GCC version: `15.0.1dev-1`
- GCC support release: `msysarm64-gcc-pr13-support-20260826`
- w32api version: `14.0.0.r0.g9b3dd0125-1`
- binutils release: `cygwinarm64-binutils-pr21-3356eec-20260827`
- binutils package: `2.44.50-2`

The focused workflow independently downloads and hashes every exact asset. The
final w32api package SHA-256 is
`7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24`;
the configured libstdc++ header package SHA-256 is
`9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08`.
Both are immutable fork-support assets produced at GCC head
`42f1fb808363203a83c7f6f935ab7e4bdffbe127`.

The `a527` runtime/sysroot is the immutable final runtime input. The fixed
binutils package is 6,545,114 bytes with SHA-256
`3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b`.
Its canonical linker SHA-256 is
`075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`.

The fixed-binutils source is frozen at
`crutkas/binutils-woarm64@3f05fc4d3e0eeab265f2157e3257a7067b6e7223`
(tree `ecca625d45883e13128283a8c1750dac7997f729`). Its 66,204,943-byte
GitHub archive has SHA-256
`d11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e`;
the source handoff SHA-256 is
`2e49f41fe87318294a48369958880abd9457571ebbcb9393eef0f1261f8f0a3f`.
The canonical downstream scanner is pinned from package head
`3356eec1411983cc252b04afac32bca5f3b8d824` with SHA-256
`888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`.
Every final SQLite PE scan must exit zero with no 12, 21, legacy-v1, or unknown
records. The admitted producer's native run `33083775213` passed with only
flag 64, including a real C++ ASLR module delta greater than 4 GiB.

Readline and zlib integration are intentionally disabled. Neither dependency is
part of this independent GCC-base layer, and using the host copies would create
an x64 fallback. Core FTS3/4/5, RTree, Geopoly, session, pre-update hook,
DBSTAT/DBPAGE, math, metadata, STAT4, soundex, and secure-delete features remain
enabled. `SQLITE_ENABLE_UPDATE_DELETE_LIMIT` is intentionally omitted because
SQLite requires it while regenerating the parser; defining it only when
compiling the pre-generated amalgamation would falsely advertise unsupported
syntax.

## Validation boundary

The build and post-package validators:

- inspect every emitted PE, object, and archive member as AArch64 PE/COFF;
- verify static and import-library archive maps;
- enumerate every import and reject Cygwin, MinGW, x86, or unknown DLLs;
- verify the package-owned SQLite DLL and exact runtime DLL are AArch64;
- compile dynamic and static API/data-export consumers against the staged
  devel split;
- scan the DLL, CLI, and both API consumers for rejected pseudo-relocations;
- reject package file overlap and verify pacman ownership;
- install, remove, and reinstall all three SQLite packages atomically; and
- run commit/rollback, integrity, and compile-option SQL on a native GitHub
  Windows ARM64 runner.

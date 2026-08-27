# AArch64 MSYS gettext/libintl

This fork-only recipe prepares GNU gettext 0.22.5-1 for the exact
`aarch64-pc-msys` LP64/AAPCS64/SEH target. It must not be proposed to upstream
MSYS2 and it does not publish a release.

## Fail-closed state

The static contract is intentionally landable while the final build is
blocked. Native libiconv 1.18-1 is not admitted because the ARM64 MSYS
argv/fork runtime defect is still being fixed. Both libiconv split records in
`dependency-lock.json` therefore have null release, asset, size, and hash
fields. CI rejects any provisional/worktree package bytes and does not enter
the final build job until those records and the private base signature are
fully admitted.

The private x64 host base is pinned to
`https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260611.tar.xz`,
size `53555380`, SHA-256
`a2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221`.
Its 566-byte detached signature is pinned to SHA-256
`076f5623b702d5016cf0253e1d14a6bd4870a90243243e96409b227f0d5bf70f`
and signer `E0AA0F031DBD80FFBA57B06D5A62D0CAB6264964`.

No step invokes the shared `C:\msys64` pacman. An admitted build extracts a
fresh private root and uses its own executable, root, database, cache, log,
configuration, hook directory, GPG directory, and sentinel snapshots.

## Package split

| Package | Target-owned payload |
| --- | --- |
| `mingw-w64-cross-msysarm64-libintl` | `msys-intl-8.dll` runtime |
| `mingw-w64-cross-msysarm64-libintl-devel` | `libintl.h`, static library, import library, and libtool metadata |
| `mingw-w64-cross-msysarm64-gettext-libs` | `libgettextpo` and `libasprintf` runtime DLLs |
| `mingw-w64-cross-msysarm64-gettext-devel` | remaining target headers, libraries, macros, and development data |
| `mingw-w64-cross-msysarm64-gettext` | target ARM64 tools, helper executables, catalogs, manuals, and runtime data |

All target files live below `/opt/aarch64-pc-msys/usr`. Host x86_64 programs
are build dependencies only and cannot enter any package payload.

## Consumer contract

Coreutils consumes
`mingw-w64-cross-msysarm64-libintl=0.22.5-1` at runtime and must consume
`mingw-w64-cross-msysarm64-libintl-devel=0.22.5-1` while building. The stable
surface is:

- `/opt/aarch64-pc-msys/usr/bin/msys-intl-8.dll`
- `/opt/aarch64-pc-msys/usr/include/libintl.h`
- `/opt/aarch64-pc-msys/usr/lib/libintl.a`
- `/opt/aarch64-pc-msys/usr/lib/libintl.dll.a`
- `aarch64-pc-msys-libintl` and `aarch64-pc-msys-libintl-devel` provides

The lock records coreutils session `f861b5ca`, current PR #27 head
`a2be2108e203cfb24d58dbad32856ca751ee32cd`, libiconv session `47f325f1`,
and unpublished PR #22 head
`cfd0c4491b03089c1c7a17c48db570b99156957c`. Session IDs are coordination
identities, not artifact or commit hashes.

## Evidence gates

An admitted build verifies the pinned gettext source and detached signature,
a527 runtime/sysroot, GCC and support assets, fixed binutils 2.44.50-2,
linker, and scanner. It then audits AA64 PE files, objects, every archive
member and armap, runtime imports, MSYS personality, pseudo-relocations,
static/shared catalog consumers, UTF-8 output, locale/domain behavior,
threading, module loading, isolated install/remove/reinstall, two-build
reproducibility, provenance, and path leakage.

The native consumers take no arguments and do not fork. This preserves
locale/domain/thread/module coverage without treating the unresolved
Windows-to-MSYS argv or fork state-copy paths as evidence.

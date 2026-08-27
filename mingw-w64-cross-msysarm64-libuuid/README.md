# aarch64-pc-msys libuuid

This fork-only package builds util-linux 2.40.2 libuuid with the released
`aarch64-pc-msys` GCC and runtime stack. It produces only the runtime DLL and
the headers, import library, and pkg-config metadata needed by native target
consumers such as APR.

The split packages are:

- `mingw-w64-cross-msysarm64-libuuid`
- `mingw-w64-cross-msysarm64-libuuid-devel`

The configure host is intentionally `aarch64-pc-cygwin`, matching the MSYS
libtool convention used by the repository's native packages. Every compiler
and binutils command is nevertheless the package-owned
`aarch64-pc-msys-*` tool, and the compiler is required to report
`aarch64-pc-msys` while defining `__MSYS__`, `__CYGWIN__`, `__aarch64__`, and
`_WIN64`. The binutils aliases must be the 20 relative symlinks owned by
`mingw-w64-cross-cygwinarm64-binutils` 2.44.50-2; the linker is pinned by
SHA-256, and the three GCC-owned target bridges remain a separate ownership
boundary.

`validate-libuuid.sh` audits every packaged PE/COFF file and archive member as
ARM64, records every DLL import, rejects Cygwin or x64 contamination, verifies
the exported UUID API, and links ARM64 dynamic and static smoke executables.
Every emitted PE is also checked by the exact producer scanner pinned from
fixed-binutils commit `3356eec1411983cc252b04afac32bca5f3b8d824`.
Pseudo-reloc flags 12, 21, legacy v1, and unknown values fail closed. Fork CI
installs the full toolchain and both packages into an isolated root, removes
and reinstalls the libuuid pair, then runs both smoke executables natively on
a Windows 11 ARM runner.

The devel package intentionally does not ship util-linux's static
`libuuid.a`. The target w32api package already owns that path for its Windows
GUID archive. CI proves that archive remains w32api-owned and byte-identical
through the complete libuuid package lifecycle; dynamic `-luuid` links select
the package-owned `libuuid.dll.a`. A util-linux static archive is still built,
its target armap and every member are audited, and it is linked into the
non-installed static smoke fixture before being excluded from package
ownership.

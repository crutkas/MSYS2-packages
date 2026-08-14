# AArch64 Cygwin compile-time sysroot

This package set installs the source-derived newlib and Cygwin headers, a
vendored w32api header snapshot, a compile-only GCC specs fragment, and a
target-built default manifest under `/opt/aarch64-pc-cygwin`.

## Source pins

- runtime/newlib/winsup:
  `crutkas/msys2-runtime@ee50e02239f3a10f5a5d7321c2ef9a40a756f2e0`
- w32api headers: vendored `14.0.0.r0.g9b3dd0125` snapshot

The runtime SHA is the frozen first ARM64 configuration and register-context
base. It does not claim a linkable ARM64 runtime DLL.

## Install order

1. `mingw-w64-cross-cygwinarm64-binutils`
2. `mingw-w64-cross-cygwinarm64-headers`
3. `mingw-w64-cross-cygwinarm64-windows-default-manifest`
4. `mingw-w64-cross-cygwinarm64-gcc-stage0` when its sibling package is ready

The `mingw-w64-cross-cygwinarm64-sysroot` meta package installs steps 2 and 3.
The specs fragment is opt-in:

```sh
aarch64-pc-cygwin-gcc \
  --sysroot=/opt/aarch64-pc-cygwin \
  -specs=/opt/aarch64-pc-cygwin/lib/cygwin-compile-only.specs \
  -c source.c
```

## Deliberate runtime boundary

This is a compile-time bootstrap sysroot. It intentionally does not contain
`cygwin1.dll`, `msys-2.0.dll`, `libcygwin.a`, `libmsys-2.0.a`, `crt0.o`, or
the Cygwin convenience archives. None of those can be authoritative until the
first ARM64 MSYS runtime is linked.

The runtime build links `new-msys-2.0.dll` with entry point `dll_entry`, then
installs it as `${bindir}/msys-2.0.dll`. `_msys_dll_entry` is not the runtime
DLL entry point.

The first runtime link must supply:

- the generated MSYS linker script and export definition;
- the runtime `libdll.a` and version objects;
- `libcygserver.a`;
- the newly built newlib `libm.a` and `libc.a`;
- target `libgcc`;
- legitimate ARM64 `libkernel32.a` and `libntdll.a`.

That link produces the temporary linker import archive `msysdll.a`. The
runtime's `mkimport` step combines it with the runtime CRT objects to produce
`${exec_prefix}/aarch64-pc-cygwin/lib/libmsys-2.0.a`.

Normal target executable links then reserve:

- `${exec_prefix}/aarch64-pc-cygwin/lib/crt0.o`, which defines
  `mainCRTStartup` and calls `msys_crt0`;
- `${exec_prefix}/aarch64-pc-cygwin/lib/libmsys-2.0.a`.

MSYS-linked user DLLs use `_msys_dll_entry`, defined through
`DECLARE_CYGWIN_DLL`/`dll_entry.o` and supplied by `libmsys-2.0.a`.

The runtime-generated target library namespace also reserves `libc.a`,
`libm.a`, `libpthread.a`, `libdl.a`, `libutil.a`, `libresolv.a`, `librt.a`,
`libacl.a`, `libssp.a`, and `libaio.a`. These are later link-surface artifacts,
not prerequisites already proven by the frozen source SHA. No `libcygwin.a`
compatibility alias belongs in this bootstrap layer.

The remaining pre-runtime blocker is a fork-local, source-pinned w32api-runtime
build that can emit the ARM64 Windows import libraries. Header-only packaging
must not synthesize those libraries from symbol lists or another architecture.

`/usr/share/cygwinarm64-sysroot/sysroot-manifest.sha256` records every file
installed under `/opt/aarch64-pc-cygwin` by the headers and default-manifest
packages.

# AArch64 MSYS compile-time sysroot

This package set installs the source-derived newlib and MSYS headers, a
vendored w32api header snapshot, a compile-only GCC specs fragment, and a
target-built default manifest under `/opt/aarch64-pc-msys`.

## Install order

1. `mingw-w64-cross-cygwinarm64-binutils`
2. `mingw-w64-cross-msysarm64-headers`
3. `mingw-w64-cross-msysarm64-windows-default-manifest`
4. `mingw-w64-cross-cygwinarm64-gcc-stage1`

The `mingw-w64-cross-msysarm64-sysroot` meta package installs steps 2 and 3.
The specs fragment is opt-in:

```sh
aarch64-pc-msys-gcc \
  --sysroot=/opt/aarch64-pc-msys \
  -specs=/opt/aarch64-pc-msys/lib/cygwin-compile-only.specs \
  -c source.c
```

## Deliberate runtime boundary

This is a compile-time bootstrap sysroot. It intentionally does not contain
`cygwin1.dll`, `msys-2.0.dll`, `libcygwin.a`, `libmsys-2.0.a`, `crt0.o`, or
the MSYS convenience archives. None of those can be authoritative until the
first ARM64 MSYS runtime is linked.

The first runtime link must explicitly produce `msys-2.0.dll` with entry point
`_msys_dll_entry`. Its source build must supply:

- the generated MSYS linker script and export definition;
- the runtime `libdll.a` and version objects;
- `libcygserver.a`;
- the newly built newlib `libm.a` and `libc.a`;
- target `libgcc`;
- legitimate ARM64 `libkernel32.a` and `libntdll.a`.

That link produces the DLL-side import archive used by the runtime's
`mkimport` step. Only then may the runtime package install
`libmsys-2.0.a`, `crt0.o`, `gcrt0.o`, and its derived convenience archives.
No `libcygwin.a` compatibility alias belongs in this bootstrap layer.

The remaining pre-runtime blocker is a fork-local, source-pinned w32api-runtime
build that can emit the ARM64 Windows import libraries. Header-only packaging
must not synthesize those libraries from symbol lists or another architecture.

`/usr/share/msys-sysroot/sysroot-manifest.sha256` records every file
installed under `/opt/aarch64-pc-msys` by the headers and default-manifest
packages.

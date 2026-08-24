# AArch64 MSYS compile-time sysroot

This package set installs the source-derived newlib and MSYS headers, a
vendored w32api header snapshot, a compile-only GCC specs fragment, and a
target-built default manifest under `/opt/aarch64-pc-msys`.

The MSYS/newlib sources are pinned to
`crutkas/msys2-runtime@a527ace21c23b763bb96841745f0e2d8cd984f4a`
(archive SHA256
`153aa6ae82a6220176a0a0ce265e1f126e3ce8ee40d717a95dfe906e810a3472`).
All packages from this pkgbase use version `3.6.10.r0.ga527ace21-1`.

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

## Runtime boundary

The first source-built runtime layer now lives in
`mingw-w64-cross-msysarm64-runtime` and
`mingw-w64-cross-msysarm64-runtime-devel`.

It supplies the authoritative ARM64 MSYS DLL and startup/library layer:

- `msys-2.0.dll`
- `libmsys-2.0.a`
- newlib `libc.a` and `libm.a`
- `crt0.o` and `gcrt0.o`
- the subordinate runtime archives (`libpthread.a`, `libdl.a`, `libutil.a`,
  `libresolv.a`, `librt.a`, `libacl.a`, `libaio.a`, `libssp.a`)
- `libcygserver.a`

No `libcygwin.a` compatibility alias belongs in this bootstrap layer.

The remaining pre-runtime blocker is a fork-local, source-pinned w32api-runtime
build that can emit the ARM64 Windows import libraries. Header-only packaging
must not synthesize those libraries from symbol lists or another architecture.

`/usr/share/msys-sysroot/sysroot-manifest.sha256` records every file
installed under `/opt/aarch64-pc-msys` by the headers and default-manifest
packages.

# ARM64 MSYS runtime layer

This package split installs the first source-built MSYS runtime layer needed for
the final `aarch64-pc-msys` toolchain.

The runtime source is pinned to
`crutkas/msys2-runtime@a527ace21c23b763bb96841745f0e2d8cd984f4a`
(archive SHA256
`153aa6ae82a6220176a0a0ce265e1f126e3ce8ee40d717a95dfe906e810a3472`).
Both packages from this pkgbase use version `3.6.10.r0.ga527ace21-1`.

## Install order

1. `mingw-w64-cross-cygwinarm64-binutils`
2. `mingw-w64-cross-cygwinarm64-gcc-stage1`
3. `mingw-w64-cross-msysarm64-headers`
4. `mingw-w64-cross-msysarm64-windows-default-manifest`
5. `mingw-w64-cross-msysarm64-sysroot`
6. `mingw-w64-cross-msysarm64-w32api-runtime`
7. `mingw-w64-cross-msysarm64-runtime`
8. `mingw-w64-cross-msysarm64-runtime-devel`

`mingw-w64-cross-msysarm64-runtime` owns only the source-built
`msys-2.0.dll`.

`mingw-w64-cross-msysarm64-runtime-devel` owns the authoritative runtime and
newlib archives and startup objects:

- `libmsys-2.0.a`
- `libc.a`
- `libm.a`
- `crt0.o`
- `gcrt0.o`
- `libpthread.a`
- `libdl.a`
- `libutil.a`
- `libresolv.a`
- `librt.a`
- `libacl.a`
- `libaio.a`
- `libgmon.a`
- `libssp.a`
- `libcygserver.a`
- source-produced newlib `libg.a`

No `libcygwin.a` compatibility alias belongs in this bootstrap layer.

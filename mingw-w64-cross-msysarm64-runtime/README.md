# ARM64 MSYS runtime layer

This package split installs the first source-built MSYS runtime layer needed for
the final `aarch64-pc-msys` toolchain.

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
- `libssp.a`
- `libcygserver.a`
- `libg.a`

No `libcygwin.a` compatibility alias belongs in this bootstrap layer.

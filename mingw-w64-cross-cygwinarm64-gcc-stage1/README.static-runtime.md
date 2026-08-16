# AArch64 Cygwin static GCC runtime

This pkgbase is the first headers-enabled GCC layer for `aarch64-pc-cygwin`.
It is hosted by x86_64 MSYS and is pinned to
`crutkas/gcc-woarm64@e1a057af466f066d86b20270fb7864764951420d`
(source archive SHA-256
`8194893d7093f3cadedc2ec42375ffbbc02a22e30d943e5f1c1aefa273af8122`).
That commit contains the fork-local `_WIN64`, SEH, crtbegin, crtend, and
full-static-libgcc source chain. No recipe flag defines `_WIN64`.

The split follows the native MSYS2 GCC convention:

- `mingw-w64-cross-cygwinarm64-gcc-stage1` contains the C, C++, and LTO
  compiler, compiler-private host executables, and built-in target specs.
- `mingw-w64-cross-cygwinarm64-gcc-libs-stage1` contains only the target
  static GCC runtime archives, GCC startup/end objects, validation reports,
  and the GCC Runtime Library Exception.

The runtime package deliberately excludes shared libgcc DLLs and import
libraries, Cygwin/MSYS runtime import libraries, newlib libc/libm, libsupc++,
libstdc++, and runtime DLLs. The compiler split owns the generated `unwind.h`
and `gcov.h` interfaces, matching normal GCC package ownership. The compiler
can discover the packaged runtime files through its normal versioned GCC
search directory; no overlay specs are needed.

## Fork-local inputs

Install the following packages in order before building:

1. `mingw-w64-cross-cygwinarm64-binutils` `2.44.50-1`
2. `mingw-w64-cross-cygwinarm64-headers` `3.6.10.r0.gee50e0223-1`
3. `mingw-w64-cross-cygwinarm64-windows-default-manifest`
   `3.6.10.r0.gee50e0223-1`
4. `mingw-w64-cross-cygwinarm64-w32api-runtime`
   `14.0.0.r0.g9b3dd0125-1`
5. `mingw-w64-cross-cygwinarm64-sysroot` `3.6.10.r0.gee50e0223-1`
6. `mingw-w64-cross-cygwinarm64-gcc-stage1` `15.0.1dev-1`
7. `mingw-w64-cross-cygwinarm64-libstdc++-headers` `15.0.1dev-1`

Their package SHA-256 values are recorded in `source-identity.txt` and
`install-order.txt` in the runtime package.

## Validation and boundary

`validate-static-runtime.sh` audits every packaged archive member and startup
object as AArch64 PE/COFF, records exact member counts and SHA-256 values,
summarizes SEH and DWARF-CFI sections, checks crtbegin/crtend and
`__cxa_atexit` ordering inputs, performs an LTO plus section-GC link using only
static libgcc, validates natural `_WIN64`, compiler specs/search paths and
ownership isolation, and compiles the fork-local runtime's `cxx.o`,
`create_posix_thread.o`, and `autoload.o` without a recipe-level `_WIN64`
define.

An ordinary Cygwin program or shared link remains intentionally impossible.
The first legitimate `msys-2.0.dll` link still requires source-built
winsup/newlib runtime objects, newlib libc/libm archives, and the linker-created
runtime import library. This package does not synthesize any of those inputs.

# AArch64 MSYS GCC layer

This package split provides the production `aarch64-pc-msys` GCC toolchain
layer built from the fork-local `gcc-woarm64` source pin
`crutkas/gcc-woarm64@bd1d77ba35e2820df5387cca5213925adb07a0ee`.

## Package split

- `mingw-w64-cross-msysarm64-gcc`
- `mingw-w64-cross-msysarm64-gcc-libs`

The compiler package ships the frontends and driver bits. The `gcc-libs`
package owns the target runtime libraries, startup objects, and compiler
runtime archives under `/opt/aarch64-pc-msys/lib/gcc/15.0.1/`.

## Install order

1. `mingw-w64-cross-cygwinarm64-binutils`
2. `mingw-w64-cross-msysarm64-headers`
3. `mingw-w64-cross-msysarm64-windows-default-manifest`
4. `mingw-w64-cross-msysarm64-sysroot`
5. `mingw-w64-cross-cygwinarm64-gcc-stage1`
6. `mingw-w64-cross-msysarm64-w32api-runtime`
7. `mingw-w64-cross-msysarm64-runtime`
8. `mingw-w64-cross-msysarm64-runtime-devel`
9. `mingw-w64-cross-msysarm64-libstdc++-headers`
10. `mingw-w64-cross-msysarm64-gcc-libs`
11. `mingw-w64-cross-msysarm64-gcc`

## Boundary

The shipped compiler personality is `aarch64-pc-msys`, not the stage-0
`aarch64-pc-cygwin` bootstrap personality used by earlier layers. The final
compiler links `msys-2.0.dll`/`libmsys-2.0.a`, defines `__MSYS__`, preserves
LP64, and consumes the real runtime/newlib/w32api sysroot from the previous
stack.

The compiler package does not ship target C++ headers. Those remain in the
separate `mingw-w64-cross-msysarm64-libstdc++-headers` package so the compiler
layer stays reproducible and the install boundary remains explicit.

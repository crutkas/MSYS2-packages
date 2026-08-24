# AArch64 MSYS target libstdc++ headers

This package installs the GCC 15 target C++ standard-library header tree for
`aarch64-pc-msys`. It is configured and installed from
`crutkas/gcc-woarm64@e1a057af466f066d86b20270fb7864764951420d`; no host,
MinGW, or pre-generated C++ configuration headers are copied into the target.

## Why a transient compiler configuration is required

The frozen compiler-only stage reports `Thread model: single`. GCC's
libstdc++ configure logic reads that value to select `gthr-default.h` and
`_GLIBCXX_HAS_GTHREADS`. Installing headers from that configuration would
incorrectly disable MSYS POSIX threading.

The package therefore builds, but does not install, the GCC driver and its
host-side prerequisites from the exact same source pin with
`--enable-threads=posix`. Target compilation is delegated to the installed
same-source stage-0 backend. The normal `gthr-default.h -> gthr-posix.h`
libgcc configure result is staged before libstdc++ configure. Only the
upstream `install-headers` target is run. The package rejects any target
archive, object, executable, or DLL.

The frozen compiler also omits the required Windows ARM64 `_WIN64` target
macro. Configuration and the recorded runtime continuation supply `-D_WIN64`
explicitly. This does not alter a libstdc++ feature result; it preserves the
Windows LP64 data model while the compiler macro fix remains a separate
stage-0 blocker.

The assembler contract starts at the package-owned
`/opt/bin/aarch64-pc-cygwin-as`. GCC configures its build-tree `gcc/as`
wrapper with that exact original path, and each probe supplies the same scoped
`original` value. Validation requires the verbose compiler trace to select the
wrapper and verifies that the resulting object is AArch64 PE/COFF.

## Install order

1. `mingw-w64-cross-cygwinarm64-binutils`
2. `mingw-w64-cross-msysarm64-sysroot`
3. `mingw-w64-cross-cygwinarm64-gcc-stage1`
4. `mingw-w64-cross-msysarm64-w32api-runtime`
5. `mingw-w64-cross-msysarm64-libstdc++-headers`

The complete installed header list and per-file hashes are stored in
`/opt/aarch64-pc-msys/share/msys-sysroot/libstdcxx-headers/`.

## Deliberate boundary

This package provides declarations and correctly configured target headers,
including `bits/c++config.h`, MSYS/newlib OS headers, AArch64 CPU headers,
and POSIX gthread headers. It does not provide:

- `libstdc++.a`, `libstdc++.dll.a`, or a libstdc++ DLL;
- `libsupc++.a`;
- target `libgcc`, `libgcc_eh`, or `libgcc_s`;
- newlib `libc.a` or `libm.a`;
- MSYS/MSYS startup objects, import library, or runtime DLL.

Objects may contain unresolved C++ ABI, unwind, allocation, pthread, atomic,
or libc symbols. Linking remains invalid until those source-built target
libraries and the runtime import surface exist.

`_GLIBCXX_HAS_GTHREADS` is enabled because the real target pthread headers
compile against GCC's POSIX gthread interface. `_GLIBCXX_HAVE_TLS` remains
disabled: GCC's cross configure test requires a target link, and neither
target libgcc nor newlib libraries are present. The compiler emits the MSYS
emulated TLS model, but this header layer does not claim the missing runtime
support.

The C++17 allocation/time and quick-exit feature results are not inferred from
host libraries. A narrow source patch enables them only for MSYS/MSYS, after
the package verifies matching declarations and implementations in the pinned
newlib/winsup source. Installed dependency provenance is recorded as hashes of
the actual pacman-owned file manifests, not as unverified package filenames.

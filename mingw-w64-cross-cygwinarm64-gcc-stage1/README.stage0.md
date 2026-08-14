# AArch64 Cygwin stage-0 GCC

This package is the no-headers compiler stage for `aarch64-pc-cygwin`. It is
hosted by x86_64 MSYS, pinned to
`crutkas/gcc-woarm64@bd1d77ba35e2820df5387cca5213925adb07a0ee`, and requires the
fork-local `mingw-w64-cross-cygwinarm64-binutils` package.

The target uses the Cygwin LP64 data model, AAPCS64 calling convention, PE
SEH unwind metadata, Cygwin TLS model, and reserves `x18` for the Windows TEB.
The later `aarch64-pc-msys` compiler may share backend code, but it has a
different target triple, preprocessor identity, sysroot, and runtime specs.

Only C, C++, and LTO compiler components that do not require a target sysroot
are installed. This package cannot link executables: it deliberately contains
no Cygwin headers, startup objects, import libraries, or target runtime
libraries. The validation script confirms that an ordinary link cannot fall
through to host libraries.

Target `libgcc` is not packaged. With LP64 w32api headers present, this pinned
GCC source reaches `libgcc/unwind-seh.c` but passes an `ULONG64 *` image base
to the pointer-sized `RtlLookupFunctionEntry` parameter requiring
`PULONG_PTR`. The next compiler input is a reviewed `crutkas/gcc-woarm64`
commit that makes the SEH image-base type pointer-sized for Cygwin LP64. A
later runtime stage will additionally require `libcygwin.a` and the AArch64
w32api import libraries. No generated or fake headers are used to bypass
either dependency.

`stage0-report.json` and `gcc.specs` record the installed compiler identity,
sysroot, multilib, predefined macros, ABI checks, object format, LTO plugin,
link refusal, and ownership namespace. Run `validate-stage0.sh /opt
<report-directory>` to reproduce the isolated no-headers checks after
installation.

The expected `mingw-w64-cross-cygwinarm64-sysroot` contract places newlib,
winsup, and w32api headers under `/opt/aarch64-pc-cygwin/include`, the default
manifest under `lib`, and opt-in compile-only specs at
`lib/cygwin-compile-only.specs`. Once a stable fork-local sysroot package is
available, run
`validate-sysroot.sh /opt <report-directory>` for header-aware C/C++ object
tests. The current specs add the root newlib/winsup include directory for C
but not C++, so the integration validator supplies that same real sysroot
directory explicitly to `g++` and records the gap. It never links.

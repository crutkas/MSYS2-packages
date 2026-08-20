# AArch64 MSYS ncurses layer

This package split source-builds ncurses for `aarch64-pc-msys` from the fork-local
snapshot pinned in this branch. It does not reuse MinGW, Cygwin, or x64 MSYS
artifacts.

## Install order

1. `mingw-w64-cross-cygwinarm64-binutils`
2. `mingw-w64-cross-cygwinarm64-gcc-stage1`
3. `mingw-w64-cross-msysarm64-sysroot`
4. `mingw-w64-cross-msysarm64-runtime`
5. `mingw-w64-cross-msysarm64-ncurses`
6. `mingw-w64-cross-msysarm64-ncurses-devel`

## Package split

- `mingw-w64-cross-msysarm64-ncurses` owns the ARM64 DLLs, tools, terminfo data,
  manpages, and license.
- `mingw-w64-cross-msysarm64-ncurses-devel` owns headers, static/import libs,
  `*-config` scripts, and pkg-config files.

## Build boundary

The package uses a native x86_64 helper `tic` only to compile the terminfo
database during packaging. The packaged binaries, archives, and import libs are
all AArch64 PE objects built against the real `aarch64-pc-msys` sysroot and
runtime layer.

The CI runner can verify compile/link/package artifacts, but it cannot execute
the target ARM64 binaries as a native Windows 11 ARM smoke here. When that
runtime is available, run a curses init/teardown and wide-character smoke
against the installed `/opt/aarch64-pc-msys` tree.

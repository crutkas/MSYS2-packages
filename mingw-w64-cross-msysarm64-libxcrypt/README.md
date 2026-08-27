# aarch64-pc-msys libxcrypt

This fork-only recipe cross-builds libxcrypt 4.5.2 with the native
`aarch64-pc-msys-gcc` 15.0.1dev toolchain. It produces separate runtime and
development packages; no x86-64 target binary or Cygwin runtime fallback is
accepted by the validator.

## Pinned inputs

- Source: `libxcrypt-4.5.2.tar.xz`,
  SHA-256 `71513a31c01a428bccd5367a32fd95f115d6dac50fb5b60c779d5c7942aec071`
- Runtime/sysroot: `msysarm64-runtime-pr10-a527-20260824`,
  version `3.6.10.r0.ga527ace21-1`
- Full GCC: `msysarm64-gcc-pr13-20260826`, version `15.0.1dev-1`
- GCC support packages: `msysarm64-gcc-pr13-support-20260826`
- w32api: `14.0.0.r0.g9b3dd0125-1`

The focused workflow verifies each GitHub release digest, downloads every
asset independently with both `gh` and `curl`, compares both SHA-256 values,
and installs the complete bootstrap set in one pacman transaction under
`MSYS=winsymlinks:sys`.

## Package boundary

The runtime package owns only `msys-crypt-2.dll` and its license. The devel
package owns `crypt.h`, the static and import libraries, pkg-config metadata,
manuals, validation tooling, and its license. CI installs, audits, removes,
and reinstalls the pair to verify transactions, ownership, and preserved
system symlinks.

Cross checks cover AA64 PE/COFF identity, imports, exported symbols, import
archive members, static archive members, headers, pkg-config metadata, and
dynamic/static link probes. A `windows-11-arm` job runs the known DES vector
`crypt("password", "ab") == "abJnggxhB/yWI"` natively.

This package and its releases are for `crutkas/MSYS2-packages` only. They must
not be proposed to or consumed by upstream MSYS2 until the ARM64 runtime and
toolchain are upstream-supported.

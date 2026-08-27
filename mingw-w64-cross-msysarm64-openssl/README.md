# aarch64-pc-msys OpenSSL

This fork-only package cross-builds OpenSSL 3.5.1 for the native MSYS POSIX
ABI. It does not use MinGW CRT libraries, Win32 OpenSSL targets, x64 payloads,
or `cygwin1.dll`.

## Source and target

- OpenSSL: `3.5.1`
- Source SHA-256:
  `529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f`
- Configure target: `Cygwin-aarch64`
- Target triplet: `aarch64-pc-msys`
- ABI: LP64, POSIX threads, MSYS `dlfcn`
- Assembly: disabled until GNU AArch64 PE/COFF perlasm output is proven
- Fixed-binutils producer: PR 21 head
  `3356eec1411983cc252b04afac32bca5f3b8d824`, run `33044771291`
- Fixed linker SHA-256:
  `075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`
- Reviewed pseudo-reloc scanner SHA-256:
  `888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`

The target inherits `Cygwin-common`; therefore it retains the POSIX thread,
terminal, dynamic-loading, and shared-library behavior used by the current
MSYS2 OpenSSL package. The existing MSYS2 patches retain `/usr/ssl`, `msys-` DLL names, the
provider/engine layout, and Cygwin thread-detach handling. A target-specific
patch also prevents OpenSSL from treating the GCC-defined `_WIN64` macro as
the Microsoft LLP64 ABI; SHA, AES, BN, modes, Whirlpool, and service lookup
instead retain Cygwin/MSYS LP64 types and layouts.

## Exact toolchain inputs

| Release | Asset | SHA-256 |
|---|---|---|
| `cygwinarm64-binutils-pr21-3356eec-20260827` | `mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst` | `3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b` |
| `msysarm64-runtime-pr10-a527-20260824` | `mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21` |
| `msysarm64-runtime-pr10-a527-20260824` | `mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f` |
| `msysarm64-runtime-pr10-a527-20260824` | `mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca` |
| `msysarm64-runtime-pr10-a527-20260824` | `mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e` |
| `msysarm64-runtime-pr10-a527-20260824` | `mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1` |
| `msysarm64-gcc-pr13-support-20260826` | `mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst` | `7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24` |
| `msysarm64-gcc-pr13-support-20260826` | `mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst` | `9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08` |
| `msysarm64-gcc-pr13-20260826` | `mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst` | `990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438` |
| `msysarm64-gcc-pr13-20260826` | `mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst` | `a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22` |

CI verifies every archive before one `MSYS=winsymlinks:sys pacman -U`
transaction installs the final runtime, sysroot, w32api, GCC headers, GCC
libraries, and GCC driver.

## Package ownership

- `mingw-w64-cross-msysarm64-libopenssl`: crypto/TLS DLLs, providers, engines
- `mingw-w64-cross-msysarm64-openssl`: CLI, `c_rehash`, `/usr/ssl`, CLI manuals
- `mingw-w64-cross-msysarm64-openssl-devel`: headers, static/import libraries,
  pkg-config metadata, validation evidence
- `mingw-w64-cross-msysarm64-openssl-docs`: API manuals and HTML documentation

The validator checks every EXE, DLL, engine, and provider for AA64 PE identity,
MSYS imports, foreign-ABI imports, and pseudo-relocation flags using the exact
reviewed scanner from fixed-binutils PR 21. It rejects flags 12, 21, unknown
flags, and legacy tables. It also compiles and links dynamic and static
`aarch64-pc-msys` EVP/TLS consumers, validates archive maps, and records a
complete payload manifest.
The fork CI atomically installs, removes, and reinstalls all four packages and
checks pacman ownership for each boundary.

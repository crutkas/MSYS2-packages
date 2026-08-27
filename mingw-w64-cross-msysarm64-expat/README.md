# aarch64-pc-msys Expat

This fork-only recipe cross-builds Expat 2.7.1 for native ARM64 MSYS. The
package archives have an `x86_64` package architecture because they are
installed on the cross-build host; every library, DLL, and executable payload
under `/opt/aarch64-pc-msys` is AA64.

## Outputs

- `mingw-w64-cross-msysarm64-expat`: `xmlwf.exe` and its man page.
- `mingw-w64-cross-msysarm64-libexpat`: `msys-expat-1.dll`.
- `mingw-w64-cross-msysarm64-libexpat-devel`: headers, static and import
  libraries, pkg-config/CMake metadata, reports, and reusable validators.

## Pinned inputs

Source:

- `expat-2.7.1.tar.xz`
- SHA-256
  `354552544b8f99012e5062f7d570ec77f14b412a3ff5c7d8d0dae62c0d217c30`
- OpenPGP release key `3176EF7DB2367F1FCA4F306B1F9B0E909AF37285`
- A target-only patch includes the POSIX `<unistd.h>` declarations that MSYS
  needs even though its compiler also defines the Windows ABI macros.

Fixed-binutils release `cygwinarm64-binutils-pr21-3356eec-20260827`:

| Input | Identity |
|---|---|
| Package | `mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst` |
| Package SHA-256 | `3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b` |
| Extracted `.PKGINFO` SHA-256 | `c49d9b366e4c5e5a564511cce75042a51629d2ef5887aa5a9256c5974eea3826` |
| Linker SHA-256 | `075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f` |
| Source commit | `3f05fc4d3e0eeab265f2157e3257a7067b6e7223` |
| Source tree | `ecca625d45883e13128283a8c1750dac7997f729` |
| Source archive SHA-256 | `d11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e` |
| Producer commit | `3356eec1411983cc252b04afac32bca5f3b8d824` |
| Canonical scanner SHA-256 | `888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9` |

Runtime/sysroot release `msysarm64-runtime-pr10-a527-20260824`:

| Asset | SHA-256 |
|---|---|
| `mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21` |
| `mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f` |
| `mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca` |
| `mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e` |
| `mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1` |

GCC release `msysarm64-gcc-pr13-20260826`:

| Asset | SHA-256 |
|---|---|
| `mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst` | `990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438` |
| `mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst` | `a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22` |

GCC support release `msysarm64-gcc-pr13-support-20260826`:

| Asset | SHA-256 |
|---|---|
| `mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst` | `9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08` |
| `mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst` | `7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24` |

CI verifies every downloaded byte before installing the full dependency
closure and both GCC packages in one pacman transaction with
`MSYS=winsymlinks:sys`.

## Validation

The build runs the upstream Expat test suite with the build-host compiler,
then cross-compiles and links an XML parser smoke program with the final
`aarch64-pc-msys` GCC. The validators audit every target DLL, executable, and
archive member for AA64, reject Cygwin/x64 contamination, record imports,
validate pkg-config/CMake paths and dependency metadata, and exercise atomic
install/remove/reinstall transactions in a fresh isolated libalpm root. The
validator preserves and compares shared package-database snapshots before and
after the isolated transactions. Every DLL, executable, and XML smoke binary
must also have an empty runtime pseudo-relocation list, ruling out ambiguous
21-bit and 12-bit records.

The XML smoke executable runs when the validation host reports ARM64. The
Windows x64 CI runner records an explicit native-execution skip after the AA64
compile, link, and import checks.

# AArch64 MSYS zlib

This split cross-builds zlib 1.3.1 for the native `aarch64-pc-msys`
personality. It never substitutes an x86 or MinGW target:
`/opt/bin/aarch64-pc-msys-gcc.exe -dumpmachine` must return
`aarch64-pc-msys`, and every packaged PE/COFF payload is audited as AA64.

## Package split

- `mingw-w64-cross-msysarm64-zlib` owns `/usr/bin/msys-z.dll`.
- `mingw-w64-cross-msysarm64-zlib-devel` owns the headers, static library,
  import library, pkg-config metadata, and manual.
- `mingw-w64-cross-msysarm64-zlib-minigzip` owns the dynamically linked
  `minigzip.exe` compression smoke utility.

All target paths are rooted below `/opt/aarch64-pc-msys/usr` in the cross
package. On a native ARM64 MSYS installation that prefix becomes `/usr`.

## Immutable compiler inputs

The focused fork CI never installs into the hosted `C:\msys64` root. It
downloads the 42,820,476-byte MSYS2 base asset `532401203` twice and requires
SHA-256 `3a56d2f156002c41de8c7e1e73ed6753e64c5e02389210c6d8a38b6d01349783`.
The private root receives only these additional host packages:

| Asset | SHA-256 |
| --- | --- |
| `diffutils-3.12-1-x86_64.pkg.tar.zst` | `7902c8ce3d4dd69a0f5e98dc9d5c83c17b23314ba486169db57ef6e2835ce3b6` |
| `isl-0.27-1-x86_64.pkg.tar.zst` | `cdd0a4ce0bf0d9e3f3eff2b770b8143e09e126a614de8b55bb5d30fc596b92d1` |
| `make-4.4.1-3-x86_64.pkg.tar.zst` | `af0bdba17f06fe037f0194069adaa31a8fe45f1a11381501896aea1fae37bd5d` |
| `mpc-1.4.1-1-x86_64.pkg.tar.zst` | `0f5073ec2e8be265854ee3c7cb1079b5e8e02264d53e659d8414988c6c182f16` |
| `patch-2.7.6-3-x86_64.pkg.tar.zst` | `dd75ca0f715dd9c71a43af6a0ff3d068faeee1d768e02282d319671201cd5d45` |

Every base, host, and toolchain asset is downloaded independently with
`Invoke-WebRequest` and `HttpClient`, then checked against an exact byte count
and SHA-256 before one private `pacman` transaction. Root, database, cache,
log, config, hooks, and GPG paths are all explicit. The source signature is
verified by private `gpgv` against the committed Mark Adler key.

Runtime/sysroot release `msysarm64-runtime-pr10-a527-20260824`:

| Asset | SHA-256 |
| --- | --- |
| `mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21` |
| `mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f` |
| `mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca` |
| `mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e` |
| `mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1` |

Full GCC release `msysarm64-gcc-pr13-20260826`:

| Asset | SHA-256 |
| --- | --- |
| `mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst` | `990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438` |
| `mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst` | `a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22` |

GCC support release `msysarm64-gcc-pr13-support-20260826`:

| Asset | SHA-256 |
| --- | --- |
| `mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst` | `7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24` |
| `mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst` | `9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08` |

Stage1 dependency closure:

| Release | Asset | SHA-256 |
| --- | --- | --- |
| `cygwinarm64-gcc-static-runtime-20260815` | `mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst` | `063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e` |
| `cygwinarm64-gcc-static-runtime-20260815` | `mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst` | `17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c` |
| `cygwinarm64-libstdcxx-headers-pr7-20260815` | `mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst` | `1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6` |

Fixed binutils release `cygwinarm64-binutils-pr21-3356eec-20260827`:

| Identity | Value |
| --- | --- |
| Package | `mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst` |
| Package bytes / SHA-256 | `6545114` / `3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b` |
| Linker SHA-256 | `075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f` |
| Producer PR/head/run/artifact | `21` / `3356eec1411983cc252b04afac32bca5f3b8d824` / `33044771291` / `9635492584` |
| Source commit/tree | `3f05fc4d3e0eeab265f2157e3257a7067b6e7223` / `ecca625d45883e13128283a8c1750dac7997f729` |
| Source archive bytes / SHA-256 | `66204943` / `d11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e` |
| Native run/job | `33083775213` / `98557748328` |

The package-owned shared pseudo-reloc scanner is vendored from producer head
`3356eec1411983cc252b04afac32bca5f3b8d824` at
`.ci/check-aarch64-pseudo-relocs.ps1`, SHA-256
`888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`.

## Validation

The target build reuses zlib's example and minigzip programs in static and
dynamic forms. Target validation checks PE machine `0xAA64`, all static/import
archive members and armaps, every emitted object and PE, DLL imports, public
and import symbols, dynamic and static consumer links, pkg-config paths,
pseudo-reloc v2 records, and a deterministic payload manifest. Pseudo-reloc
widths 12 and 21 are rejected as ambiguous; only the runtime-supported 8, 16,
32, and 64-bit forms are accepted.
Focused CI also installs and removes all three split packages atomically in a
fresh isolated libalpm root, and requires the shared package database snapshots
from before and after that proof to match. The ARM runner executes the packaged
dynamic minigzip round trip with the released native `msys-2.0.dll`.

Each pseudo-reloc report binds the exact retained input SHA-256 and the
scanner, objdump, and nm hashes. Evidence text is validated as UTF-8 without a
BOM. Native evidence records OS and process architecture, `IsWow64Process2`
results, and every loaded module's AA64 machine and SHA-256.

All external actions are pinned to full commits:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`
- `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093`

Release `msysarm64-zlib-pr32-20260827` is a frozen noncanonical predecessor
and must not be consumed or modified. A replacement is published only under a
new annotated prerelease tag after independent push/PR equality and durable
evidence sealing.

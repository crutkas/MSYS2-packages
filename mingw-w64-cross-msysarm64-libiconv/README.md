# AArch64 MSYS libiconv

This fork-only package source-builds GNU libiconv 1.19-1 from current MSYS2
recipe commit `84dfd072fc4338cce775628ffc0a053da7e57d80` for
`aarch64-pc-msys`. It is stacked on `crutkas-aarch64-gcc-layer`; it does not
use MinGW, x64 MSYS, or an x64 target-library fallback.

## Package split

- `mingw-w64-cross-msysarm64-libiconv` owns the target ARM64 DLLs.
- `mingw-w64-cross-msysarm64-iconv` owns `iconv.exe`, manuals, and conversion
  data.
- `mingw-w64-cross-msysarm64-libiconv-devel` owns headers, static libraries,
  import libraries, and target-correct pkg-config metadata.

Target files are rooted below `/opt/aarch64-pc-msys/usr`. Licenses remain in
the host package database below `/usr/share/licenses`.

## Frozen ownership

The exact source of truth is `crutkas/build-extra` PR 12 at commit
`3ef6d935092dc6ab2e376bcd0ffc74fa52dac39d`. Its 36,191-byte ownership TSV
has SHA-256
`045104e4e84dbbc788382c1d7ed64220f4956b913714d1f287a69263caa26805`;
the 311,663-byte backlog JSON has SHA-256
`fd6d4e4f01db476e8b97271f35e349973791d1c7719c095b068a9508942414e4`.
The two exact TSV rows are 154 bytes with SHA-256
`c43f18ca170ac8de0bf53e2faa3816641daa1f56d886798ee5c33323edc420e4`.
This recipe closes both residuals:

| Frozen residual | Baseline owner | Replacement owner |
| --- | --- | --- |
| `usr/bin/msys-iconv-2.dll` | `libiconv=1.19-1` | `mingw-w64-cross-msysarm64-libiconv=1.19-1` |
| `usr/bin/iconv.exe` | `iconv=1.19-1` | `mingw-w64-cross-msysarm64-iconv=1.19-1` |

`ownership-manifest.json` records the immutable mapping and remains
`admitted: false` until corrected-runtime clean A/B and native gates pass.

The compiler driver and sysroot remain exactly `aarch64-pc-msys`. Configure
uses `aarch64-pc-cygwin` only as libtool's compatibility host spelling because
MSYS shares Cygwin's PE/DLL mechanics and upstream libtool has no `msys` host
case. The installed MSYS libtool macros emit `msys-*.dll` names.

## Pinned prerequisite releases

Bootstrap releases:

| Release | Asset | SHA-256 |
| --- | --- | --- |
| `cygwinarm64-binutils-pr21-3356eec-20260827` | `mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst` | `3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b` |
| `cygwinarm64-sysroot-pr3-20260813` | `mingw-w64-cross-cygwinarm64-headers-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst` | `5266346cc10b142f871704ce4277699b1a5daa3121dc869990b4bedce69c0611` |
| `cygwinarm64-sysroot-pr3-20260813` | `mingw-w64-cross-cygwinarm64-windows-default-manifest-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst` | `cc089511fede6042a25f83fcb5903fddeede89ddd9655360741513ee9015e3dc` |
| `cygwinarm64-sysroot-pr3-20260813` | `mingw-w64-cross-cygwinarm64-sysroot-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst` | `4ed8a30f592317bf7e4def6f3c773139f2565b0f8afaedd820f7ee46d33cad20` |
| `cygwinarm64-w32api-20260813` | `mingw-w64-cross-cygwinarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst` | `53478f9a60e2fdad7d3b4357fa4fb937a1afab16af16a55e5a25ae9fac308fa7` |
| `cygwinarm64-gcc-static-runtime-20260815` | `mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst` | `063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e` |
| `cygwinarm64-gcc-static-runtime-20260815` | `mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst` | `17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c` |
| `cygwinarm64-libstdcxx-headers-pr7-20260815` | `mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst` | `1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6` |

Runtime and sysroot release `msysarm64-runtime-pr10-a527-20260824`:

| Asset | SHA-256 |
| --- | --- |
| `mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21` |
| `mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f` |
| `mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca` |
| `mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e` |
| `mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst` | `c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1` |

Compiler release `msysarm64-gcc-pr13-20260826`:

| Asset | SHA-256 |
| --- | --- |
| `mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst` | `a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22` |
| `mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst` | `990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438` |

Compiler support release `msysarm64-gcc-pr13-support-20260826`:

| Asset | SHA-256 |
| --- | --- |
| `mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst` | `9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08` |
| `mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst` | `7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24` |

CI downloads every asset by exact name, verifies SHA-256, and installs the
compiler closure in one `pacman -U` transaction with
`MSYS=winsymlinks:sys`.

## Validation

The fixed binutils package is built from source commit
`3f05fc4d3e0eeab265f2157e3257a7067b6e7223` (source archive SHA-256
`d11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e`);
its source tree is `ecca625d45883e13128283a8c1750dac7997f729`.
Producer PR 21 at head `3356eec1411983cc252b04afac32bca5f3b8d824`
created artifact `9635492584` in successful run `33044771291`. The extracted
`.PKGINFO` is 950 bytes with SHA-256
`c49d9b366e4c5e5a564511cce75042a51629d2ef5887aa5a9256c5974eea3826`;
its linker SHA-256 is
`075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`.
Native run `33083775213` (job `98557748328`) passed with a real ASLR
`std::cout` relocation delta of `0x37cbe0000`, no ambiguous records, and
successful rollback.

The x64 cross-build audits every installed target PE and every object and
symbol map in each static/import archive as AArch64, rejects
Cygwin/x64/MinGW runtime imports, links dynamic and static iconv conversion
smokes, and checks every unstripped PE pseudo-reloc
v2 record with the sealed parser whose SHA-256 is
`888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`.
Malformed tables and bit widths 12 or 21 are hard failures. CI then checks
package metadata and ownership and performs install-remove-reinstall with
private root, database, cache, log, config, and hook paths while sealing the
host package database and log before and after.
A separate `windows-11-arm` job executes dynamic and static library smokes
that convert ISO-8859-1 bytes `63 61 66 e9` to UTF-8. With the corrected
runtime, it must also preserve the CLI encoding list, byte-exact stdin/stdout
conversion, and nonzero stderr behavior for an invalid encoding.

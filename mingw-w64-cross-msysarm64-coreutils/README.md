# Native AArch64 MSYS coreutils lane

This fork-only lane builds GNU coreutils 8.32 for the exact
`aarch64-pc-msys` LP64/AAPCS64/SEH target. It does not publish releases,
contact upstream, use MinGW LLP64 output, consume provisional worktree
packages, or mutate the shared `C:\msys64` package database.

## Payload contract

`path-manifest.json` is the authoritative machine-readable integration table.
Its ordered arrays contain every exact path; consumers must not infer paths
from utility names or package contents.

The 108-path table was reconciled byte-for-byte against ownership commit
`7a77c0c5ff81d1c979302c9cc49a62f26f68d17c`. The immutable fork-only artifact
source is `crutkas/build-extra#12` commit
`3ef6d935092dc6ab2e376bcd0ffc74fa52dac39d`. Its 433-line ownership TSV has
SHA-256 `045104e4e84dbbc788382c1d7ed64220f4956b913714d1f287a69263caa26805`.
The committed-LF backlog JSON SHA-256 is
`fd6d4e4f01db476e8b97271f35e349973791d1c7719c095b068a9508942414e4`;
the generator-produced CRLF provenance SHA-256 remains
`b8fa19d43c8db1b36fa29f98e2d2e221eec2fa14da21d1bf94efada04b03b773`.

| Table | Exact count | Integration action |
| --- | ---: | --- |
| `baseline.paths` | 108 | Remove the legacy x64 coreutils PE at each path |
| `busybox.paths` | 59 | Historical inventory; apply only from a fresh admitted layer |
| `busybox.paths ∩ baseline.paths` | 54 | Do not package a duplicate coreutils executable |
| `busybox.cross_package_claims` | 5 | Remove the named non-coreutils owner transitively |
| `busybox_semantic_proof.paths` | 24 | Historical inventory for the fresh clean A/B semantic lane |
| `native_coreutils.paths` | 30 | Apply this package's native GNU coreutils file |
| `dependency_removals` | 0 | Reject any attempted removal |
| `required_unowned_paths` | 0 | Fail if this ever becomes non-empty |

The five cross-package BusyBox claims are exact:

| Path | Legacy owner |
| --- | --- |
| `usr/bin/cmp.exe` | `diffutils` |
| `usr/bin/diff.exe` | `diffutils` |
| `usr/bin/find.exe` | `findutils` |
| `usr/bin/unzip.exe` | `unzip` |
| `usr/bin/xargs.exe` | `findutils` |

The complete residual is partitioned as `54 + 24 + 30 + 0 = 108`. The
24-path semantic A/B lane is the coreutils intersection of
`arm64-busybox/experimental-replacements.txt` from `crutkas/build-extra#4`
commit `50de8f12409d8cc8e16aef190629073db1a8606d`; the source list has 25 paths
because `usr/bin/awk.exe` is owned by `gawk`, not coreutils. The 443-byte
source list has SHA-256
`d7885e0b6c34e9cba7d245135946e38fa2cac64c0fc50e2b59ab1ee2e9f1498b`.
PR #4 and its PR #8 descendant are permanently denied lineage. These fields
preserve historical inventory bytes only and provide zero admission or
semantic credit. Both BusyBox sets must be rebound to fresh, independently
admitted clean-layer assets before final A/B or native execution.

The package-owned native paths are exactly:

```text
usr/bin/b2sum.exe
usr/bin/basenc.exe
usr/bin/chcon.exe
usr/bin/chgrp.exe
usr/bin/chown.exe
usr/bin/chroot.exe
usr/bin/csplit.exe
usr/bin/dir.exe
usr/bin/dircolors.exe
usr/bin/fmt.exe
usr/bin/gkill.exe
usr/bin/hostid.exe
usr/bin/hostname.exe
usr/bin/mkfifo.exe
usr/bin/mknod.exe
usr/bin/nice.exe
usr/bin/nohup.exe
usr/bin/numfmt.exe
usr/bin/pathchk.exe
usr/bin/pinky.exe
usr/bin/pr.exe
usr/bin/ptx.exe
usr/bin/runcon.exe
usr/bin/sha224sum.exe
usr/bin/stdbuf.exe
usr/bin/tty.exe
usr/bin/users.exe
usr/bin/vdir.exe
usr/bin/who.exe
usr/lib/coreutils/libstdbuf.dll
```

`usr/lib/coreutils/libstdbuf.dll` is package-owned because the pinned MSYS
`stdbuf.exe` patch hardcodes that preload filename. The recipe audits the DLL
as AA64/MSYS, requires its exact two constructor-support exports, and scans
its pseudo-relocations. Lifecycle tests prove package ownership. Native tests
prove `stdbuf` loads exactly this private DLL, exercise buffering behavior,
and reject missing or corrupt DLLs. Dependency removal is forbidden.

The historical ownership inventory uses `crutkas/build-extra#12` commit
`3ef6d935092dc6ab2e376bcd0ffc74fa52dac39d`. Its BusyBox and semantic source
is denied PR #4 commit `50de8f12409d8cc8e16aef190629073db1a8606d`;
denied descendant PR #8 commit
`be0217cb572704f27ea04c9abde8bb992b8ef0c0` is not a successor. Integration
must:

1. Verify the manifest counts and set equations.
2. Reject any overlap between the BusyBox and native output sets.
3. Remove the five cross-package legacy owners listed above.
4. Source both BusyBox sets only from fresh independently admitted clean assets.
5. Strip the package prefix `opt/aarch64-pc-msys/` when applying 30 native files.
6. Reject removal of `usr/lib/coreutils/libstdbuf.dll`.
7. Fail if the three baseline dispositions overlap or do not cover all 108 paths.

This models the coreutils-owned x64 gap from 108 to zero: 54 direct BusyBox
paths, 24 clean-layer semantic-proof paths, 30 native coreutils package paths,
and no dependency removals. BusyBox's full cross-package delta remains 59.

## Build and audit

The recipe pins the coreutils source, detached signature, four existing MSYS2
patches, signing key, and the exact pseudo-relocation scanner from fixed
binutils commit `3356eec1411983cc252b04afac32bca5f3b8d824`. The scanner SHA-256
is `888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`.
The fixed linker SHA-256 is
`075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`.

The build routes includes and libraries only through
`/opt/aarch64-pc-msys`, audits all 108 staged PE files as AA64, packages only
the exact 30-path residual, requires
`msys-2.0.dll`, rejects Cygwin/MinGW/x64 imports, checks every shipped object
and archive member plus archive armaps with target-owned tools, and scans
every PE pseudo-relocation table. Empty tables and scalar 8/16/32/64 records
are accepted; 12, 21, unknown, malformed, and out-of-bounds data fail.
An ABI executable plus dynamic and static GMP consumers are cross-linked,
audited, uploaded, and executed by the native ARM64 job.

Package lifecycle validation uses a fresh root and always supplies
`--root`, `--dbpath`, `--cachedir`, `--logfile`, `--config`, and `--hookdir`.
It sets `MSYS=winsymlinks:sys`, verifies metadata and ownership, performs
install/remove/reinstall, and proves the shared package database and log are
byte-for-byte unchanged. The coordinator's pre-work shared observation was
1178 database files with canonical-manifest SHA-256
`93a39fb4e4105489b733275fa94e8cc718f25c239f0064cd64c4a68832a68c34`
and a 155150-byte log with SHA-256
`925ce045782b49e6454956eae9ee0a5b700b17c805843d18329509f4e2a492c8`.
Every run captures its own before/after values; it does not assume those
observation values remain current.

## Admission status

`dependency-lock.json` distinguishes admitted fixed binutils from diagnostic
a527-derived runtime/compiler/support packages. Final package and native CI
are intentionally fail-closed until every diagnostic input is replaced by a
corrected admitted identity and these additional inputs are admitted:

| Input | Required identity |
| --- | --- |
| Native GMP | `mingw-w64-cross-msysarm64-gmp 6.3.0-2` |
| Native GMP development files | `mingw-w64-cross-msysarm64-gmp-devel 6.3.0-2` |
| Native libiconv | `mingw-w64-cross-msysarm64-libiconv 1.18-1` |
| Native libiconv development files | `mingw-w64-cross-msysarm64-libiconv-devel 1.18-1` |
| Native libintl | `mingw-w64-cross-msysarm64-libintl 0.22.5-1` |
| Native libintl development files | `mingw-w64-cross-msysarm64-libintl-devel 0.22.5-1` |
| Immutable x64 host root | Complete host build closure, exact archive identity pending |
| ARM64 Git payload | Exact artifact identity for hook/build-script probes pending |
| Clean BusyBox payload | Fresh independently admitted 59-path artifact pending |
| Clean BusyBox semantic proof payload | Fresh independently admitted 24-path A/B artifact pending |

Static recipe, manifest, malformed-scanner, architecture/import/personality,
armap, private-root, overlap/unowned, and native-evidence completeness tests
remain runnable while blocked. No package hash is reported until every input
is admitted and the clean private-root build and native Windows 11 ARM matrix
both pass.

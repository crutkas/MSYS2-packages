# Native ARM64 MSYS GMP infrastructure

This fork-only lane defines GMP `6.3.0-2` for `aarch64-pc-msys`. It cannot
build packages or run native tests until `dependency-lock.json` contains a
complete, independently admitted corrected-runtime record and complete admitted
prerequisite asset records. Revoked inputs exist only under `deny_tests` so the
contract tests can prove they cannot become active dependencies.

The package contract is:

- `mingw-w64-cross-msysarm64-gmp=6.3.0-2` provides
  `aarch64-pc-msys-gmp=6.3.0`, depends exactly on the admitted runtime, and owns
  `/opt/aarch64-pc-msys/usr/bin/msys-gmp-10.dll`.
- `mingw-w64-cross-msysarm64-gmp-devel=6.3.0-2` provides
  `aarch64-pc-msys-gmp-devel=6.3.0`, depends exactly on the runtime package and
  admitted runtime-devel package, and owns `gmp.h`, `libgmp.a`,
  `libgmp.dll.a`, and any truthful generated development metadata below
  `/opt/aarch64-pc-msys/usr`.

The frozen build-extra PR 12 ownership binding at head `3ef6d935` maps source
package `gmp` version `6.3.0-2` and source commit
`7a77c0c5ff81d1c979302c9cc49a62f26f68d17c` to exactly one product residual:
`usr/bin/msys-gmp-10.dll`. Headers, import/static libraries, tools, tests, and
evidence are infrastructure, not product-delta paths.

The target contract is LP64, AAPCS64, and SEH. Upstream GMP AArch64 assembly is
disabled because it is not a proven PE/COFF ARM64 SEH implementation. The
generic C implementation is built by the final `aarch64-pc-msys` GCC and must
use 64-bit limbs. Assembly may be enabled only after every non-leaf object has
valid PE unwind metadata and native exception coverage.

All future builds start from the pinned private MSYS2 base archive. Pacman root,
database, cache, log, configuration, hooks, and GnuPG directories are explicit
and private; the shared `C:\msys64` tree is sealed before and after. Sources,
signatures, signing fingerprints, release tags, asset names, sizes, and hashes
are immutable and fail closed. Package builds use a stable neutral source path
so `.BUILDINFO`, `gmp.h`, debug data, logs, and evidence cannot disclose a
worktree path.

Validation definitions cover:

- deterministic A/B package and inner-tree comparison with `ranlib -D`;
- every PE, archive member, real armap, import, export, pseudo-relocation table,
  unwind section, and AA64 machine identity;
- dynamic and static C and C++ arithmetic, thread, fork, and exception-unwind
  consumers;
- binary-safe ASCII, UTF-16LE, UTF-16BE, NUL-rich, slash, case, and
  JSON-escaped private-path scans, with unreadable or skipped inputs fatal;
- exact `.PKGINFO`, `.MTREE`, file ownership, and one-DLL product mapping;
- private install/remove/reinstall plus deliberate corruption, `pacman -Qkk`
  detection, and byte-exact restoration;
- genuine Windows ARM64 held-process module closure with zero x64 modules.

The pull-request workflow currently runs only static contract, parser, and
adversarial fixture tests at the exact same-repository event head. Package and
native jobs are structurally disabled and upload no package artifacts. Enabling
them requires a separate change after corrected-runtime admission; newly built
bytes remain unadmitted candidates until independent redownload, reproducibility,
native, and audit evidence is accepted.

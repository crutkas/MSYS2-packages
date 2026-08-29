# Private pacman v2 contract

`PrivatePacman.psm1` runs one local `pacman -U` transaction in a fresh,
session-owned root without repository access. It is intended for CI source
that must not mutate an existing MSYS2 installation, especially
`C:\msys64`.

This helper is not package or native admission. It does not download,
install, build, publish, or approve packages by itself. A caller must provide
an independently prepared private seed, a complete local package root, and
separately pinned signed ownership evidence.

## Safety boundary

The helper:

- accepts only canonical DOS paths on a local fixed drive;
- rejects UNC, device, provider, mapped, substituted, and share paths;
- rejects traversal, reserved names, alternate data streams, junctions,
  symbolic links, other reparse ancestors, and filesystem aliases;
- requires the workspace, seed, and package root to use the same fixed drive;
- copies a reparse-free seed into a random sibling staging directory, verifies
  the source and copied byte manifests, then atomically renames the staging
  directory to the final root;
- creates an external, exclusively locked owner sentinel before publishing
  the private root;
- requires a canonical, versioned manifest that binds one owner and session to
  every package path, nonnegative Int64 length, lowercase SHA-256, and
  deterministic package-set SHA-256;
- frames the package set with a version header, decimal count, canonical
  base64 UTF-8 paths, actual tab separators, decimal Int64 lengths, lowercase
  SHA-256 values, and LF record terminators;
- requires the raw manifest SHA-256 and public-key SHA-256 to be supplied
  independently, accepts exactly one canonical subject-public-key-info
  `PUBLIC KEY` PEM object, and requires curve OID
  `1.2.840.10045.3.1.7` (NIST P-256/secp256r1);
- accepts exactly one canonical RFC 4648 base64 DER signature line terminated
  by one LF and verifies it over the exact UTF-8 manifest bytes;
- rejects missing, extra, non-package, aliased, or reparse entries anywhere
  in the package root before creating session state;
- constructs the complete native argument list internally and accepts no
  caller-provided pacman options;
- permits only local `-U`, with package files locked against writes, renames,
  and deletion for the entire transaction;
- writes a repository-free config and requires both configured and
  root-local hook directories to be empty;
- closes native standard input and constructs the child environment from an
  empty block containing only canonical private paths, OS-derived Windows
  paths, fixed locale/MSYS values, and no inherited proxy, Git, shell startup,
  loader, or package-manager injection variables;
- holds the private config, executable, owner marker, and package inputs
  against replacement while pacman runs;
- snapshots every protected tree by hashing each regular file's bytes; the
  exported snapshot command and every internal evidence path reject every
  nested reparse entry with no lenient production mode;
- binds each root and entry's owner SID, group/DACL security descriptor SDDL,
  complete Windows attribute mask, file identity, and filesystem change time
  into the canonical digest and evidence;
- watches security and attribute changes in addition to names, writes, and
  sizes, so restored metadata changes remain fatal even when final digests
  match;
- enumerates named streams on every admitted root, directory, and file and
  fails closed if any alternate data stream is present; rejecting reparse
  entries prevents stream enumeration from following an external link target;
- always includes canonical `C:\msys64` in the protected set, but records an
  absent root as `NotCovered`, never as successful literal-root coverage;
- keeps that logical production path distinct from the filesystem observation
  path so the private contract harness can substitute an isolated populated
  tree without creating or mutating `C:\msys64`; production has no substitution
  surface and observes the real path;
- requires a complete preflight snapshot and a separate disposable watcher to
  observe a quiet interval before authoritative monitoring starts; only
  pre-monitor noise is discarded;
- starts authoritative protected-root watchers before the complete byte and
  metadata before snapshot, requires it to match the preflight digest, never
  clears authoritative events, keeps the watchers active through private-root
  cleanup, and fails on any change event, watcher error, or before/after digest
  difference;
- removes reparse entries as leaves during cleanup and never follows their
  targets; and
- preserves evidence outside the disposable private root on success and
  failure.

The process receives exactly one value for each isolation switch:

```text
--root
--dbpath
--cachedir
--logfile
--config
--hookdir
--gpgdir
```

It also receives `--noconfirm`, `--noscriptlet`, one `-U`, one helper-owned
`--`, and only canonical package paths after that separator. The generated
config has an `[options]` section and no repository, `Server`, or `Include`
directive.

The config deliberately retains `LocalFileSigLevel = Optional`. The ownership
manifest authenticates an inventory for this diagnostic contract; it is not a
native pacman package-signature admission policy. Independently admitted
package bytes and a separately trusted native package-signature policy remain
external blockers.

## Threat model

The module fails closed against accidental shared-root use, ambiguous paths,
normal concurrent changes, input replacement, child failure, timeout, and
cleanup errors. It is not a security sandbox against a malicious process
running as the same Windows user. Such a process can attack the helper,
pacman, or evidence storage with the caller's authority.

`FileSystemWatcher` events supplement, but do not replace, full byte
snapshots. A normal completed invocation requires both mechanisms to remain
clean. The canonical digest also binds filesystem change time, which ordinary
content, ACL, attribute, and named-stream mutate/restore operations cannot
restore; this remains fail-closed if watcher callback delivery is delayed. A
private test barrier separately proves that a mutate/restore operation paused
inside baseline capture is retained by the authoritative watcher. If the
owning PowerShell process crashes, watcher continuity is lost; recovery can
remove only roots with matching internal and external ownership records and
records the outcome as failed, never successful.

The canonical security evidence contains owner, group, and DACL state readable
with `READ_CONTROL`. Audit SACL access requires `SeSecurityPrivilege` and is
not claimed as an admission signal. Security watcher events still invalidate a
transaction while monitoring is active.

## Usage

All private inputs must be on the same fixed drive. `SeedRoot` must contain
the private executable at `usr\bin\pacman.exe` and must not overlap a
protected root. Ownership manifest, signature, and public-key files must be
distinct, canonical, outside the package root, and locked for the transaction.

The canonical ownership manifest schema is
`private-pacman-package-ownership/v3`. Its ordered fields are `Schema`,
`Owner`, `SessionId`, `SignatureAlgorithm`, `PackageSetCanonicalization`,
`PackageSetSha256`, and `Packages`. Package entries are sorted by ordinal path
and contain only `Path`, `Length`, and `Sha256`; their JSON types are strictly
string, Int64, and string.

`PackageSetCanonicalization` is `private-pacman-package-set/v1`. Its exact
UTF-8 framing is an LF-terminated version line, an LF-terminated invariant
decimal package count, then one LF-terminated record per package. Each record
is canonical base64 of the UTF-8 relative path, an actual U+0009 tab, the
nonnegative invariant decimal Int64 length, another actual tab, and the
lowercase 64-hex SHA-256. Base64, decimal, and hash alphabets exclude the
separators; field validation rejects control characters, non-Int64 values,
uppercase hashes, duplicates, and non-ordinal order. The version header and
manifest schema prevent the former literal-backtick framing digest from being
confused with this encoding.

The detached signature file is exactly one canonical RFC 4648 base64 DER
ECDSA signature followed by one LF. The public-key file is exactly the
LF-internal, no-trailing-newline output of subject-public-key-info
`PUBLIC KEY` PEM encoding. Private-key labels or material, extra PEM objects,
other labels, malformed base64, CRLF, and trailing payload are rejected before
verification. Import is followed by an exact named-curve OID check for NIST
P-256; a different 256-bit curve such as brainpoolP256r1 is rejected. The
caller must obtain expected manifest and public-key hashes from a trusted
control plane rather than from adjacent files.

ECDSA does not provide a unique signature byte string, and this contract does
not claim signature uniqueness. Evidence retains the SHA-256 of the exact raw
signature file, while the independently pinned manifest hash binds the signed
content.

`New-PrivatePacmanOwnershipManifest` can create the unsigned canonical
manifest from an isolated package root. Signature creation and trusted hash
distribution intentionally remain outside this module.

```powershell
Import-Module "$repository\.ci\PrivatePacman.psm1" -Force

$layout = New-PrivatePacmanLayout `
    -WorkspaceRoot 'D:\runner-temp\private-pacman' `
    -SessionId "arm64-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"

try {
    $result = Invoke-PrivatePacmanUpgrade `
        -Layout $layout `
        -SeedRoot 'D:\private-msys2-seed' `
        -PackageRoot 'D:\local-packages' `
        -OwnershipManifestPath 'D:\ownership\packages.ownership.json' `
        -OwnershipSignaturePath 'D:\ownership\packages.ownership.sig' `
        -OwnershipPublicKeyPath 'D:\ownership\packages.ownership.pem' `
        -ExpectedManifestSha256 $trustedManifestSha256 `
        -ExpectedPublicKeySha256 $trustedPublicKeySha256 `
        -ExpectedOwner 'arm64-campaign:run-123' `
        -ProtectedRoot @('D:\other-shared-package-state')
}
catch {
    # The terminating error includes the external result.json path when
    # initialization advanced far enough to create evidence.
    throw
}
```

The layout explicitly names:

- `Root`
- `DatabasePath`
- `CachePath`
- `LogPath`
- `ConfigPath`
- `HookPath`
- `GpgPath`
- `PacmanPath`
- `StateDirectory`
- `EvidenceDirectory`

The module rederives and verifies every layout property before touching the
filesystem, so a serialized or modified layout cannot redirect a managed
path.

The process environment evidence uses
`private-pacman-child-environment/v1`. `ProcessStartInfo.Environment` is
cleared before these exact production entries are added in ordinal-name
evidence order:

```text
COMSPEC
GNUPGHOME
HOME
LANG
LC_ALL
MSYS
MSYSTEM
MSYSTEM_PREFIX
PATH
SystemRoot
TEMP
TMP
TMPDIR
WINDIR
```

`SystemRoot`, `WINDIR`, `System32`, and `COMSPEC` are derived from Windows APIs
and resolved through the same canonical final-path checks rather than copied
from the parent environment. `PATH` contains only the private `usr\bin`,
canonical `System32`, and canonical Windows root. `HOME`, `GNUPGHOME`, and all
temporary variables are inside the disposable private root. Locale values are
`C.UTF-8`, `MSYSTEM` is `MSYS`, `MSYSTEM_PREFIX` is `/usr`, and `MSYS` is
`winsymlinks:nativestrict`. The test harness can add an exact, non-exported
recorder-control set through private module state; production has no caller
environment override surface.

Windows may synthesize `PROCESSOR_ARCHITECTURE` when it creates the native
process. The contract compares every declared entry exactly, permits only that
documented OS-added name with the value implied by the recorder's attested
process architecture (`ARM64`, `AMD64`, or `x86`), and rejects every other
undeclared name. The canonical environment digest continues to bind only the
explicit launch block.

The harness publishes the recorder as a RID-matched, framework-dependent,
single-file executable with the installed .NET 10 SDK. It records the SDK
version, target RID, builder and PE architectures, executable SHA-256, and
runtime recorder attestation. The harness, `dotnet` host, recorder PE, and
running recorder must all match the operating-system architecture; emulated
recorders fail the contract.

## Evidence and cleanup

The external state directory contains:

- `owner.json`: session ID, nonce, exact root paths, owning process,
  protected roots, phase, and final result digest;
- `evidence/invocation.json`: executable, exact argv, locked package hashes,
  signed ownership identity, seed-copy digest, managed-config digest, and
  complete sorted declared child environment with canonical schema and
  SHA-256;
- `evidence/protected-*-before.json` and
  `evidence/protected-*-after.json`: full byte, owner/group/DACL, attribute,
  entry count, strict reparse-rejection, and named-stream-policy manifests;
- `evidence/result.json`: process output and exit status, before/after
  protected digests and counts, `Covered`/`NotCovered`/`CaptureFailed` status,
  watcher events/errors, cleanup status, and failures.

All module JSON evidence and the suite report are UTF-8 without BOM, LF-only,
and terminated by exactly one LF.

Protected-root summaries retain the logical `Path` and the actual
`FileSystemPath` used for snapshots and watchers. They are identical in
production. Only private harness state can map logical `C:\msys64` to a
session-owned physical tree, making canonical transaction coverage countable
without touching a machine installation. The report publishes both the direct
literal-root snapshot and transaction-boundary evidence even when a test fails.

`private-pacman-tree-snapshot/v3` records `ReparsePointPolicy = reject`.
Covered before/after evidence must have nonnegative equal entry counts and
equal canonical digests. Missing `C:\msys64` snapshots retain deterministic
missing digests and count zero for observation, but coverage is `NotCovered`.
A snapshot error produces `CaptureFailed` records and a failed transaction;
it cannot become a skip. No expected count or digest is imposed on an
arbitrary future installation.

The private root is removed on success, child crash, timeout, protected-state
drift, and other handled failures. Evidence remains external.

If the owning PowerShell process itself terminates before `finally` runs,
the root and sentinel intentionally remain. After confirming the child
process is gone, recover only that exact session:

```powershell
Remove-PrivatePacmanSession -Layout $layout -Confirm:$false
```

Recovery takes an exclusive sentinel lock, requires matching internal and
external nonces and canonical paths, removes only the recorded root or
staging root, and writes `evidence/recovery.json`. Recovery always records
`WatcherContinuity = false` and `Result = cleaned-fail-closed`.

## Diagnostic workflow boundary

`private-pacman-contract.yml` runs for every pull request. A fork pull request
gets a visible failing job rather than a skipped result. A same-repository run
checks out and verifies the exact PR head and uploads only its JSON diagnostic
report. Upload uses an unconditional step, so the canonical and literal-root
records remain available on both passing and failing runs.

This workflow is defined by candidate-controlled source and is not an
authoritative admission gate. Production use requires protected default-branch
governance that the candidate cannot alter or self-certify.

The report labels itself `self-reported-diagnostic-only` and
`AdmissionReady = false`. Passed, failed, and skipped totals are separate and
must add to the total. The workflow validates those fields, rejects
`CaptureFailed`, requires equal nonnegative counts for `Covered`, and requires
at least one skip when literal coverage is `NotCovered`. Synthetic populated
evidence is separately typed and can never satisfy literal-root coverage.

There is no production caller in this change. Before one can be admitted, a
separate trusted integration must pin raw manifest and public-key source URLs
or commits, bind expected repository and host identities across redirects,
allowlist signer keys and ownership names, and establish trusted time and
revocation policy. Those gates are intentionally unresolved here.

## Contract tests

Run the source-only contract with the .NET 10 SDK available:

```powershell
pwsh -NoLogo -NoProfile -NonInteractive `
    -File .ci\Test-PrivatePacman.ps1 `
    -ReportPath "$env:TEMP\private-pacman-contract.json"
```

The test script publishes a small native argv recorder from generated C# source
with the .NET 10 SDK. It never invokes pacman or consumes a campaign candidate
artifact; package-shaped test files contain only synthetic fixture text in a
temporary directory. The suite covers native process provenance, canonical
manifest determinism, raw hash and key pinning, signature tampering,
owner/session binding, complete package enumeration, signed traversal,
argv completeness, repository absence, path aliases, drive mismatch,
UNC/device/share paths, junctions, file symlinks, seed reparse points, atomic
collisions, concurrent sentinel ownership, package/config/root locks,
permanent and restored ACL/attribute drift, permanent and transient alternate
data streams, transient protected-state races, a deterministic private
snapshot barrier that injects mutation during baseline capture, child crashes,
timeouts, parent-process crash recovery, and reparse-safe cleanup.

The JSON report and logs expose coverage status, `ExistedBefore`,
`ExistedAfter`, entry counts, and pre/post content and canonical digests for
the literal and deterministic synthetic roots. One native-boundary transaction
protects literal canonical `C:\msys64`; its transaction evidence and separate
suite-level pre/post snapshot are reported. If that root is absent, both
literal checks are `NotCovered` and their dedicated test records are skipped,
not passed. Capture errors are `CaptureFailed` failures with complete error
text, so an unreadable entry or forbidden stream cannot suppress diagnostic
JSON or shape success.

The suite also covers exact P-256 OID binding, brainpool rejection, canonical
SPKI-only PEM input, strict signature text framing, noncanonical base64,
versioned injective package framing and its fixed digest vector, hostile
inherited environment removal, exact effective-environment recording,
case-sensitive package extensions, `CONIN$`/`CONOUT$`, and strict ordinary,
junction, file-symlink, and directory-symlink snapshots. Unavailable optional
symlink capabilities are skipped rather than passed.

The suite resolves its temporary base through the native final path before
applying the same canonicality checks as production. Remaining adversarial
transactions substitute a small populated fixed-drive root and one test uses a
deterministic snapshot barrier by changing private module state only inside the
test harness; the production command surface exposes neither override. This
avoids repeatedly walking a hosted multi-gigabyte installation without
weakening production behavior. An absent hosted-run root remains an explicit
non-admission gate rather than evidence for a populated installation.

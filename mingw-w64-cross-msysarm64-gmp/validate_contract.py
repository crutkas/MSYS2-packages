#!/usr/bin/env python3
"""Fail-closed static contract checks for the blocked MSYS ARM64 GMP lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


DENIED_RUNTIME = {
    "kind": "revoked-runtime",
    "package": "mingw-w64-cross-msysarm64-runtime",
    "version": "3.6.10.r0.ga527ace21-1",
    "release_tag": "msysarm64-runtime-pr10-a527-20260824",
    "reason": "proven unload trampoline defect",
}
PACKAGE_RECORDS = {
    "mingw-w64-cross-msysarm64-gmp": "6.3.0-2",
    "mingw-w64-cross-msysarm64-gmp-devel": "6.3.0-2",
}
HOST_ASSETS_SHA256 = (
    "d02e92ea70cd59bb42dd5166e4c6f03cc5b1a6143646a9febca6644c11a83ff0"
)
LOCAL_SOURCE_INDEXES = {
    "gmp-consumer.c": 3,
    "gmp-consumer.cpp": 4,
    "scan-forbidden-paths.py": 5,
    "validate-gmp.sh": 6,
    "README.md": 7,
    "dependency-lock.json": 8,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_text(path: Path) -> str:
    data = path.read_bytes()
    require(b"\r" not in data, f"{path.name} is not LF-normalized")
    return data.decode("utf-8")


def walk_values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child)
    elif isinstance(value, str):
        yield value


def shell_array(text: str, name: str) -> list[str]:
    match = re.search(
        rf"(?ms)^{re.escape(name)}=\(\s*(.*?)^\)",
        text,
    )
    require(match is not None, f"PKGBUILD omits {name}")
    return re.findall(r"['\"]([0-9a-f]{64})['\"]", match.group(1))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def workflow_job(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\s*\n(.*?)(?=^  [a-z][a-z0-9-]+:\s*$|\Z)",
        workflow,
    )
    require(match is not None, f"workflow job is missing: {name}")
    return match.group(1)


def validate(repo_root: Path) -> None:
    lane = repo_root / "mingw-w64-cross-msysarm64-gmp"
    workflow_path = repo_root / ".github/workflows/msysarm64-gmp.yml"
    required_files = [
        "PKGBUILD",
        "dependency-lock.json",
        "bootstrap-private-root.ps1",
        "build-canonical.ps1",
        "compare-reproducibility.ps1",
        "shared-sentinel.ps1",
        "validate-gmp.sh",
        "validate-package-lifecycle.sh",
        "scan-forbidden-paths.py",
        "test_scan_forbidden_paths.py",
        "gmp-consumer.c",
        "gmp-consumer.cpp",
        "native-smoke.ps1",
        "test-native-smoke-contract.ps1",
        "README.md",
        "validate_contract.py",
        "test_validate_contract.py",
        ".gitignore",
    ]
    texts = {name: read_text(lane / name) for name in required_files}
    workflow = read_text(workflow_path)
    lock = json.loads(texts["dependency-lock.json"])

    require(lock.get("schema") == 2, "dependency lock schema must be 2")
    require(lock.get("package") == "mingw-w64-cross-msysarm64-gmp",
            "dependency lock package changed")
    require(lock.get("version") == "6.3.0-2",
            "dependency lock version changed")
    require(lock.get("canonical_runtime_admitted") is False,
            "canonical runtime admission must remain blocked")

    denied = lock.get("deny_tests")
    require(denied == [DENIED_RUNTIME], "revoked runtime deny record changed")
    active_lock = {key: value for key, value in lock.items()
                   if key != "deny_tests"}
    active_values = set(walk_values(active_lock))
    for denied_value in (
        DENIED_RUNTIME["version"],
        DENIED_RUNTIME["release_tag"],
        DENIED_RUNTIME["reason"],
    ):
        require(denied_value not in active_values,
                f"revoked runtime escaped deny_tests: {denied_value}")

    canonical = lock.get("canonical_runtime", {})
    require(canonical == {
        "package": "mingw-w64-cross-msysarm64-runtime",
        "version": None,
        "pkgrel": None,
        "required_version": None,
        "release_tag": None,
        "asset_name": None,
        "size": None,
        "sha256": None,
        "coordinator_admission_reference": None,
        "independent_redownload_verified": False,
        "admitted": False,
    }, "canonical runtime must remain unresolved and unadmitted")
    require(lock.get("canonical_prerequisite_assets") == [],
            "canonical prerequisite assets must remain unresolved")

    build = lock.get("build_classification", {})
    require(build == {
        "status": "blocked-missing-corrected-runtime",
        "admissible": False,
        "publishable": False,
        "consumable": False,
    }, "build classification must remain fail-closed")

    records = lock.get("package_candidates", {}).get("records")
    require(isinstance(records, list) and len(records) == 2,
            "package candidate records changed")
    require(
        {record.get("package") for record in records} == set(PACKAGE_RECORDS),
        "package candidate set changed",
    )
    for record in records:
        package = record.get("package")
        require(package in PACKAGE_RECORDS, "unknown package candidate")
        require(record == {
            "package": package,
            "required_version": PACKAGE_RECORDS[package],
            "release_tag": None,
            "asset_name": None,
            "size": None,
            "sha256": None,
            "coordinator_admission_reference": None,
            "independent_redownload_verified": False,
            "admitted": False,
            "eligible_for_admission": False,
        }, f"{package} candidate must remain unresolved and unadmitted")

    ownership = lock.get("product_ownership")
    require(ownership == {
        "repository": "build-extra",
        "pull_request": 12,
        "frozen_head": "3ef6d935",
        "source_package": "gmp",
        "source_version": "6.3.0-2",
        "source_commit": "7a77c0c5ff81d1c979302c9cc49a62f26f68d17c",
        "product_residual_paths": ["usr/bin/msys-gmp-10.dll"],
        "non_product_categories": [
            "headers",
            "import-libraries",
            "static-libraries",
            "tools",
            "tests",
            "evidence",
        ],
    }, "frozen PR12 one-DLL ownership binding changed")

    source = lock.get("source", {})
    require(source.get("archive") == {
        "url": "https://ftpmirror.gnu.org/gmp/gmp-6.3.0.tar.xz",
        "size": 2094196,
        "sha256": "a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898",
    }, "GMP source archive lock changed")
    require(source.get("signature") == {
        "url": "https://ftpmirror.gnu.org/gmp/gmp-6.3.0.tar.xz.sig",
        "size": 374,
        "sha256": "94def8c1a731854de684689126046ec93589147abd4cd0025f12d741d323aa82",
        "signer": "343C2FF0FBEE5EC2EDBEF399F3599FF828C67298",
    }, "GMP source signature lock changed")
    require(source.get("signing_key") == {
        "url": "https://raw.githubusercontent.com/mozilla-firefox/firefox/56036ccaf45df86c0155e9b9cf3d9f240888db0b/build/unix/build-gcc/343C2FF0FBEE5EC2EDBEF399F3599FF828C67298.key",
        "size": 2050,
        "sha256": "c492d99c6407bb32d793ec3540b650adc8b8bf9829634fbce3d8709cc63db0a0",
        "fingerprint": "343C2FF0FBEE5EC2EDBEF399F3599FF828C67298",
    }, "GMP signing key lock changed")
    require(lock.get("pseudo_relocation_scanner", {}).get("sha256") ==
            "888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9",
            "pseudo-relocation scanner lock changed")
    base = lock.get("private_msys2_base", {})
    require(base.get("archive", {}).get("size") == 53555380,
            "private base size changed")
    require(base.get("archive", {}).get("sha256") ==
            "a2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221",
            "private base hash changed")
    require(base.get("signature", {}).get("size") == 566,
            "private base signature size changed")
    require(base.get("signature", {}).get("sha256") ==
            "076f5623b702d5016cf0253e1d14a6bd4870a90243243e96409b227f0d5bf70f",
            "private base signature hash changed")
    require(base.get("signature", {}).get("signer") ==
            "E0AA0F031DBD80FFBA57B06D5A62D0CAB6264964",
            "private base signature signer changed")
    require(base.get("signature", {}).get("primary_key") ==
            "0EBF782C5D53F7E5FB02A66746BD761F7A49B0EC",
            "private base primary key changed")
    require(base.get("signing_key") == {
        "url": "https://raw.githubusercontent.com/sous-chefs/cinc-omnibus/74d12b9b38bc37874a8771ca41c42a91a8133016/files/default/msys2-signing-key.asc",
        "size": 39649,
        "sha256": "a8ad613c9f662e3e76260e02c69b0afd7b13a33043e546eebdf195650b33d0ba",
        "fingerprint": "0EBF782C5D53F7E5FB02A66746BD761F7A49B0EC",
    }, "private base signing key lock changed")
    host_assets = lock.get("host_assets")
    require(isinstance(host_assets, list) and len(host_assets) == 15,
            "host asset closure count changed")
    host_asset_seal = hashlib.sha256(json.dumps(
        host_assets,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()).hexdigest()
    require(host_asset_seal == HOST_ASSETS_SHA256,
            "immutable host asset closure changed")

    pkgbuild = texts["PKGBUILD"]
    for denied_value in (
        DENIED_RUNTIME["version"],
        DENIED_RUNTIME["release_tag"],
    ):
        require(denied_value not in pkgbuild,
                "PKGBUILD contains a revoked runtime default")
    for snippet in (
        "MSYSARM64_CANONICAL_RUNTIME_ADMITTED:-false",
        "'autoconf'",
        "'automake'",
        "'libtool'",
        "_runtime_version=${MSYSARM64_CANONICAL_RUNTIME_VERSION:?}",
        "_runtime_pkgrel=${MSYSARM64_CANONICAL_RUNTIME_PKGREL:?}",
        '"${RANLIB}" -D "${dest_dir}/usr/lib/libgmp.a"',
        '"${RANLIB}" -D "${dest_dir}/usr/lib/libgmp.dll.a"',
        '"mingw-w64-cross-msysarm64-runtime=${_runtime_version}-${_runtime_pkgrel}"',
        '"mingw-w64-cross-msysarm64-gmp=${pkgver}-${pkgrel}"',
        '"mingw-w64-cross-msysarm64-runtime-devel=${_runtime_version}-${_runtime_pkgrel}"',
        "aarch64-pc-msys-gmp=${pkgver}",
        "aarch64-pc-msys-gmp-devel=${pkgver}",
        "msys-gmp-10.dll",
        '${_target}-g++" -dumpmachine',
        "libstdc++.a",
    ):
        require(snippet in pkgbuild, f"PKGBUILD contract missing: {snippet}")
    require("'autotools'" not in pkgbuild,
            "PKGBUILD declares an unavailable autotools dependency")

    sums = shell_array(pkgbuild, "sha256sums")
    require(len(sums) == 9, "PKGBUILD source checksum count changed")
    require(sums[0] == source["archive"]["sha256"],
            "PKGBUILD GMP source checksum diverged from lock")
    require(sums[1] == source["signature"]["sha256"],
            "PKGBUILD GMP signature checksum diverged from lock")
    require(sums[2] == lock["pseudo_relocation_scanner"]["sha256"],
            "PKGBUILD scanner checksum diverged from lock")
    for filename, index in LOCAL_SOURCE_INDEXES.items():
        require(sums[index] == sha256(lane / filename),
                f"PKGBUILD local source checksum is stale: {filename}")

    bootstrap = texts["bootstrap-private-root.ps1"]
    for denied_value in (
        DENIED_RUNTIME["version"],
        DENIED_RUNTIME["release_tag"],
    ):
        require(denied_value not in bootstrap,
                "bootstrap contains a revoked runtime input")
    for snippet in (
        "$lock.canonical_runtime_admitted -ne $true",
        "$lock.canonical_prerequisite_assets.Count -lt 1",
        "$asset.admitted -ne $true",
        "$candidate.admitted -ne $false",
        "--root",
        "--dbpath",
        "--cachedir",
        "--logfile",
        "--config",
        "--hookdir",
        "--gpgdir",
        "canonical-runtime-admitted-build-enabled",
        "GNUPGHOME=/var/lib/gmp-build-gnupg",
    ):
        require(snippet in bootstrap,
                f"bootstrap fail-closed contract missing: {snippet}")
    require("a527" not in bootstrap.lower(),
            "bootstrap mentions the denied runtime family")

    canonical_build = texts["build-canonical.ps1"]
    for snippet in (
        "canonical_runtime_admitted",
        "independent_redownload_verified",
        "canonical-runtime-admitted-build-enabled",
        "foreach ($label in @('A', 'B'))",
        "private-$label",
        "New-Item -ItemType Directory -Path $neutralRecipe",
        "makepkg --noconfirm --cleanbuild --clean --force",
        "compare-reproducibility.ps1",
        "-Action Capture",
        "-Action Compare",
    ):
        require(snippet in canonical_build,
                f"canonical A/B build harness missing: {snippet}")
    require("Copy-Item -LiteralPath $recipe" not in canonical_build,
            "canonical build can copy unclean workspace outputs")

    reproducibility = texts["compare-reproducibility.ps1"]
    for snippet in (
        "archive bytes differ between builds",
        "inner trees differ between builds",
        "Get-FileHash",
        "Get-InnerSeal",
        "eligible_for_admission -ne $false",
        "classification=canonical-build-candidate",
        "admissible=false",
    ):
        require(snippet in reproducibility,
                f"reproducibility harness missing: {snippet}")

    lifecycle = texts["validate-package-lifecycle.sh"]
    for denied_value in (
        DENIED_RUNTIME["version"],
        DENIED_RUNTIME["release_tag"],
    ):
        require(denied_value not in lifecycle,
                "lifecycle contains a revoked runtime input")
    for snippet in (
        "canonical_prerequisite_assets",
        'runtime["admitted"] is not True',
        'asset["admitted"] is not True',
        "pacman_args=(",
        "-Qkk",
        "corruption-restored-payload.sha256",
        "reinstalled-payload.sha256",
        ".PKGINFO",
        ".MTREE",
        "runtime_target_entries",
        "canonical_runtime_admitted",
        "independent_redownload_verified",
        "coordinator_admission_reference",
        "stat -c '%s'",
        "assert_pkginfo_set",
        "target_dll_entries",
        "check_package_integrity",
        "-Qkk",
        "forbidden_status",
        "shared-before.sentinel",
        "shared-after.sentinel",
        "unreadable_or_skipped",
    ):
        require(snippet in lifecycle,
                f"lifecycle contract missing: {snippet}")
    require("diagnostic" not in lifecycle.lower(),
            "lifecycle still classifies canonical candidates as diagnostics")

    native = texts["native-smoke.ps1"]
    for snippet in (
        "canonical_runtime_admitted",
        "independently admitted GMP package records",
        "independent_redownload_verified",
        "coordinator_admission_reference",
        "native admission package set is not exact",
        "Get-FileHash",
        "OSArchitecture -ne 'Arm64'",
        "$machine -eq 0x8664",
        "process.Modules",
        "gmp-cxx-dynamic-smoke.exe",
        "gmp-cxx-static-smoke.exe",
        "MSYS2_PATH_TYPE = 'strict'",
        '"x64-modules`t0"',
    ):
        require(snippet in native, f"native contract missing: {snippet}")

    scanner = texts["scan-forbidden-paths.py"]
    for snippet in (
        "utf-16le",
        "utf-16be",
        "nul-rich",
        "json.dumps",
        "JSON_STRING",
        "gzip",
        "bz2",
        "lzma",
        "unreadable_or_skipped",
        "scan_ar",
        "_extract_package",
        "_decompress_package",
        "_decompress_limited",
        "_scan_tar_stream",
        "scan_blob",
        "MAX_NESTING",
        "subprocess.Popen",
        "--zstd",
        ".pkg.tar.zst",
    ):
        require(snippet in scanner, f"binary scanner missing: {snippet}")

    workflow_jobs = re.findall(r"(?m)^  ([a-z][a-z0-9-]+):\s*$", workflow)
    require(workflow_jobs == [
        "static-contract",
        "canonical-package",
        "canonical-native",
    ], "workflow job set changed")
    for job_name in ("canonical-package", "canonical-native"):
        job = workflow_job(workflow, job_name)
        require(
            re.search(r"(?m)^    if: \$\{\{ false \}\}\s*$", job) is not None,
            f"{job_name} is not blocked at job scope",
        )
    for forbidden in (
        "bootstrap-private-root.ps1",
        "build-canonical.ps1",
        "native-smoke.ps1",
        "makepkg",
        "upload-artifact",
        "download-artifact",
    ):
        require(forbidden not in workflow,
                f"blocked workflow contains executable path: {forbidden}")
    require(
        "github.event.pull_request.head.repo.full_name == github.repository"
        in workflow,
        "workflow lacks same-repository pull-request binding",
    )
    require("github.event.pull_request.head.sha || github.sha" in workflow,
            "workflow lacks exact event-head checkout")
    uses = re.findall(r"(?m)^\s*uses:\s*([^@\s]+)@([^\s]+)\s*$", workflow)
    require(uses, "workflow contains no pinned action")
    for action, revision in uses:
        require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
                f"action is not SHA-pinned: {action}@{revision}")
    require("foreach ($script in @" in workflow and
            "& $bash -n $script" in workflow,
            "workflow does not syntax-check each Bash script separately")
    require("[Management.Automation.Language.Parser]::ParseFile(" in workflow,
            "workflow does not parse every PowerShell script")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    args = parser.parse_args()
    try:
        validate(args.repo_root.resolve())
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"contract validation failed: {error}")
        return 1
    print("contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

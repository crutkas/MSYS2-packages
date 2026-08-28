#!/usr/bin/env python3

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_SOURCE_HASHES = {
    "coreutils-8.32.tar.xz":
        "4458d8de7849df44ccab15e16b1548b285224dbba5f08fac070c1c0e0bcc4cfa",
    "check-aarch64-pseudo-relocs.ps1":
        "888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9",
    "001-coreutils-8.30.patch":
        "467bde24da0ccea48260f58d3c94a84de4e027ab598a926003642f791da47ca2",
    "002-coreutils-8.32-enable-stdbuf.patch":
        "e3be62b9aceb3231f09f05bc3bd8b18f6aaa495f5063781cdd261d560a7e80d0",
    "003-coreutils-8.32-fix-test-cases.patch":
        "ad9e0582373500c0668e38483401169f48d6a2f8ad8d28ef8e7b06e4a3e08a74",
    "004-msystem-osname-cygwin.patch":
        "3922afd54b2323772f5cbd0638d0887ef858199bbaf4076a1db318173021c3dc",
}
EXPECTED_SIGNATURE_HASH = (
    "71b944375b322ba77c9c56b687b48df885c676d4fd7c465b3706713a9b62ce0a"
)

REQUIRED_PACMAN_OPTIONS = (
    "--root", "--dbpath", "--cachedir", "--logfile", "--config", "--hookdir"
)

REQUIRED_NATIVE_CASES = {
    "filesystem-metadata", "permissions", "hardlinks", "symlinks",
    "sparse-files", "stat-realpath-readlink", "install-cp-mv-rm",
    "text-encoding", "path-spaces-globs", "pipes-signals-exit-codes",
    "git-hook", "build-script",
    "busybox-text-delegation",
    "linked-consumers",
    "stdbuf-loader-closure",
    "stdbuf-missing-dll-negative",
    "stdbuf-corrupt-dll-negative",
}

EXPECTED_SEMANTIC_PATHS = {
    "usr/bin/chmod.exe", "usr/bin/date.exe", "usr/bin/dd.exe",
    "usr/bin/df.exe", "usr/bin/du.exe", "usr/bin/factor.exe",
    "usr/bin/groups.exe", "usr/bin/id.exe", "usr/bin/install.exe",
    "usr/bin/link.exe", "usr/bin/logname.exe", "usr/bin/ls.exe",
    "usr/bin/printenv.exe", "usr/bin/pwd.exe", "usr/bin/readlink.exe",
    "usr/bin/realpath.exe", "usr/bin/shred.exe", "usr/bin/shuf.exe",
    "usr/bin/sleep.exe", "usr/bin/stat.exe", "usr/bin/stty.exe",
    "usr/bin/sync.exe", "usr/bin/timeout.exe", "usr/bin/whoami.exe",
}


class ContractError(ValueError):
    pass


def _unique(name, values):
    if len(values) != len(set(values)):
        raise ContractError(f"{name} contains duplicate paths")


def validate_path_manifest(data):
    if data.get("schema_version") != 1:
        raise ContractError("path manifest schema mismatch")
    if data.get("target") != "aarch64-pc-msys":
        raise ContractError("path manifest target mismatch")

    baseline = data["baseline"]["paths"]
    busybox = data["busybox"]["paths"]
    semantic = data["busybox_semantic_proof"]["paths"]
    native = data["native_coreutils"]["paths"]
    dependency_removals = data["dependency_removals"]
    cross = data["busybox"]["cross_package_claims"]
    transitive = data["transitive_removals"]
    unowned = data["required_unowned_paths"]
    baseline_set = set(baseline)
    busybox_set = set(busybox)
    semantic_set = set(semantic)
    native_set = set(native)
    removal_set = set(dependency_removals)
    cross_set = {entry["path"] for entry in cross}

    _unique("baseline", baseline)
    _unique("BusyBox claims", busybox)
    _unique("BusyBox semantic proof", semantic)
    _unique("native coreutils", native)
    _unique("dependency removals", dependency_removals)
    _unique("BusyBox cross-package claims", list(cross_set))

    provenance = data["baseline"]
    if provenance.get("version") != "8.32-5":
        raise ContractError("baseline coreutils version mismatch")
    if provenance.get("ownership_commit") != (
        "7a77c0c5ff81d1c979302c9cc49a62f26f68d17c"
    ):
        raise ContractError("baseline ownership commit mismatch")
    if provenance.get("artifact_repository") != "crutkas/build-extra":
        raise ContractError("baseline artifact repository mismatch")
    if provenance.get("artifact_pull_request") != 12:
        raise ContractError("baseline artifact pull request mismatch")
    if provenance.get("artifact_commit") != (
        "3ef6d935092dc6ab2e376bcd0ffc74fa52dac39d"
    ):
        raise ContractError("baseline artifact commit mismatch")
    if provenance.get("ownership_manifest_sha256") != (
        "045104e4e84dbbc788382c1d7ed64220f4956b913714d1f287a69263caa26805"
    ):
        raise ContractError("baseline ownership manifest hash mismatch")
    if provenance.get("backlog_model_sha256") != (
        "fd6d4e4f01db476e8b97271f35e349973791d1c7719c095b068a9508942414e4"
    ):
        raise ContractError("baseline committed backlog model hash mismatch")
    if provenance.get("backlog_model_generator_crlf_sha256") != (
        "b8fa19d43c8db1b36fa29f98e2d2e221eec2fa14da21d1bf94efada04b03b773"
    ):
        raise ContractError("baseline generator backlog model hash mismatch")

    if len(baseline) != 108 or data["baseline"]["pe_path_count"] != 108:
        raise ContractError("baseline coreutils path count must be 108")
    if len(busybox) != 59 or data["busybox"]["claimed_path_count"] != 59:
        raise ContractError("BusyBox claim count must be 59")
    busybox_contract = data["busybox"]
    if busybox_contract.get("identity_status") != "historical-inventory-only":
        raise ContractError("BusyBox historical identity status mismatch")
    if busybox_contract.get("admission_credit") is not False:
        raise ContractError("BusyBox historical identity received admission credit")
    if busybox_contract.get("repository") != "crutkas/build-extra":
        raise ContractError("BusyBox repository mismatch")
    if busybox_contract.get("pull_request") != 4:
        raise ContractError("BusyBox pull request mismatch")
    if busybox_contract.get("commit") != (
        "50de8f12409d8cc8e16aef190629073db1a8606d"
    ):
        raise ContractError("BusyBox commit mismatch")
    if busybox_contract.get("workflow_run") != 31771293786:
        raise ContractError("BusyBox workflow mismatch")
    semantic_contract = data["busybox_semantic_proof"]
    if semantic_contract.get("identity_status") != "historical-inventory-only":
        raise ContractError("semantic proof historical identity status mismatch")
    if semantic_contract.get("admission_credit") is not False:
        raise ContractError("semantic proof historical identity received admission credit")
    if semantic_contract.get("repository") != "crutkas/build-extra":
        raise ContractError("semantic proof repository mismatch")
    if semantic_contract.get("pull_request") != 4:
        raise ContractError("semantic proof pull request mismatch")
    if semantic_contract.get("commit") != (
        "50de8f12409d8cc8e16aef190629073db1a8606d"
    ):
        raise ContractError("semantic proof commit mismatch")
    if semantic_contract.get("source_manifest") != (
        "arm64-busybox/experimental-replacements.txt"
    ):
        raise ContractError("semantic proof source mismatch")
    if semantic_contract.get("source_manifest_size") != 443:
        raise ContractError("semantic proof source size mismatch")
    if semantic_contract.get("source_manifest_sha256") != (
        "d7885e0b6c34e9cba7d245135946e38fa2cac64c0fc50e2b59ab1ee2e9f1498b"
    ):
        raise ContractError("semantic proof source hash mismatch")
    if semantic_contract.get("source_path_count") != 25:
        raise ContractError("semantic proof source count mismatch")
    if semantic_contract.get("non_coreutils_paths") != ["usr/bin/awk.exe"]:
        raise ContractError("semantic proof non-coreutils set mismatch")
    if len(semantic) != 24 or semantic_contract.get("path_count") != 24:
        raise ContractError("BusyBox semantic proof path count must be 24")
    if semantic_set != EXPECTED_SEMANTIC_PATHS:
        raise ContractError("BusyBox semantic proof path set mismatch")
    if len(native) != 30 or data["native_coreutils"]["path_count"] != 30:
        raise ContractError("native coreutils path count must be 30")
    if "usr/lib/coreutils/libstdbuf.dll" not in native_set:
        raise ContractError("native coreutils must own libstdbuf.dll")
    if dependency_removals:
        raise ContractError("coreutils dependency removals are forbidden")
    claimed_sets = {
        "BusyBox": busybox_set & baseline_set,
        "semantic proof": semantic_set,
        "native coreutils": native_set,
        "dependency removal": removal_set,
    }
    names = list(claimed_sets)
    for index, name in enumerate(names):
        for other in names[index + 1:]:
            overlap = claimed_sets[name] & claimed_sets[other]
            if overlap:
                raise ContractError(
                    f"{name} overlaps {other}: {sorted(overlap)}"
                )
    if cross_set != busybox_set - baseline_set:
        raise ContractError("cross-package claims do not match BusyBox minus coreutils")
    if len(busybox_set & baseline_set) != 54:
        raise ContractError("BusyBox must directly replace 54 coreutils paths")
    if semantic_set - baseline_set:
        raise ContractError("semantic proof contains non-coreutils baseline paths")
    if native_set != baseline_set - busybox_set - semantic_set:
        raise ContractError("native coreutils is not the exact 30-path residual set")
    if set().union(*claimed_sets.values()) != baseline_set:
        raise ContractError("coreutils baseline partition is incomplete")
    if unowned:
        raise ContractError(f"required paths are unowned: {unowned}")

    transitive_set = {entry["path"] for entry in transitive}
    if transitive_set != cross_set:
        raise ContractError("transitive removal table does not match cross-package claims")
    for entry in cross + transitive:
        if not entry.get("baseline_owner"):
            raise ContractError(f"missing baseline owner for {entry.get('path')}")

    integration = data["integration"]
    if not integration.get("fail_on_overlap"):
        raise ContractError("integration must fail on overlap")
    if not integration.get("fail_on_unowned_required_path"):
        raise ContractError("integration must fail on unowned paths")
    if integration.get("net_coreutils_x64_gap_after_apply") != 0:
        raise ContractError("coreutils x64 gap after apply must be zero")
    expected_counts = {
        "busybox_direct_coreutils_replacements": 54,
        "busybox_semantic_proof_paths": 24,
        "native_coreutils_arm64_replacements": 30,
        "coreutils_dependency_removals": 0,
    }
    for field, expected_count in expected_counts.items():
        if integration.get(field) != expected_count:
            raise ContractError(f"integration count mismatch: {field}")
    handoff = integration.get("clean_busybox_handoff", {})
    if handoff.get("status") != "unresolved" or handoff.get("required") is not True:
        raise ContractError("clean BusyBox handoff status mismatch")
    if handoff.get("admitted_identity") is not None:
        raise ContractError("unadmitted clean BusyBox handoff has an identity")
    if handoff.get("denied_historical_commits") != [
        "50de8f12409d8cc8e16aef190629073db1a8606d",
        "be0217cb572704f27ea04c9abde8bb992b8ef0c0",
    ]:
        raise ContractError("denied BusyBox lineage mismatch")


def validate_dependency_lock(data):
    if data.get("schema_version") != 1:
        raise ContractError("dependency lock schema mismatch")
    if data.get("target") != "aarch64-pc-msys":
        raise ContractError("dependency target mismatch")
    if data.get("personality") != "MSYS":
        raise ContractError("dependency personality mismatch")
    if data.get("abi") != {
        "data_model": "LP64",
        "calling_convention": "AAPCS64",
        "exception_model": "SEH",
    }:
        raise ContractError("dependency ABI mismatch")

    sources = {entry["name"]: entry for entry in data["sources"]}
    if set(sources) != set(EXPECTED_SOURCE_HASHES):
        raise ContractError("source lock membership mismatch")
    for name, expected in EXPECTED_SOURCE_HASHES.items():
        if sources[name].get("sha256") != expected:
            raise ContractError(f"source hash mismatch for {name}")
        if not sources[name].get("url", "").startswith("https://"):
            raise ContractError(f"source URL is not HTTPS for {name}")
        if not isinstance(sources[name].get("size"), int):
            raise ContractError(f"source size missing for {name}")
    source = sources["coreutils-8.32.tar.xz"]
    if source.get("signature_sha256") != EXPECTED_SIGNATURE_HASH:
        raise ContractError("source signature hash mismatch")
    if source.get("signature_size") != 833:
        raise ContractError("source signature size mismatch")
    if source.get("signing_key") != "6C37DC12121A5006BC1DB804DF6FD971306037D9":
        raise ContractError("source signing key mismatch")

    assets = data["toolchain_assets"]
    if len(assets) != 10:
        raise ContractError("admitted toolchain closure must contain 10 assets")
    for asset in assets:
        if not re.fullmatch(r"[0-9a-f]{64}", asset.get("sha256", "")):
            raise ContractError(f"invalid admitted asset hash: {asset.get('name')}")
        if not isinstance(asset.get("size"), int) or asset["size"] <= 0:
            raise ContractError(f"invalid admitted asset size: {asset.get('name')}")
        if not isinstance(asset.get("admitted"), bool):
            raise ContractError(f"toolchain admission flag missing: {asset.get('name')}")
        if not isinstance(asset.get("diagnostic_only"), bool):
            raise ContractError(f"toolchain diagnostic flag missing: {asset.get('name')}")
        if asset["diagnostic_only"] and asset["admitted"]:
            raise ContractError(f"diagnostic toolchain asset admitted: {asset.get('name')}")
    if not assets[0]["admitted"] or assets[0]["diagnostic_only"]:
        raise ContractError("fixed binutils admission mismatch")
    if any(
        asset["admitted"] or not asset["diagnostic_only"]
        for asset in assets[1:]
    ):
        raise ContractError("a527-derived toolchain assets must remain diagnostic")

    unresolved = data["target_dependency_assets"]
    expected = {
        "mingw-w64-cross-msysarm64-gmp",
        "mingw-w64-cross-msysarm64-gmp-devel",
        "mingw-w64-cross-msysarm64-libiconv",
        "mingw-w64-cross-msysarm64-libiconv-devel",
        "mingw-w64-cross-msysarm64-libintl",
        "mingw-w64-cross-msysarm64-libintl-devel",
    }
    if {entry["package"] for entry in unresolved} != expected:
        raise ContractError("unresolved target dependency set mismatch")
    execution_inputs = data["execution_inputs"]
    if {entry["name"] for entry in execution_inputs} != {
        "immutable-host-root",
        "arm64-git-payload",
        "clean-busybox-payload",
        "clean-busybox-semantic-proof-payload",
    }:
        raise ContractError("unresolved execution input set mismatch")
    denied_commits = {
        "50de8f12409d8cc8e16aef190629073db1a8606d",
        "be0217cb572704f27ea04c9abde8bb992b8ef0c0",
    }
    clean_busybox = [
        entry for entry in execution_inputs
        if entry["name"].startswith("clean-busybox-")
    ]
    for entry in clean_busybox:
        if entry.get("admitted"):
            for field in (
                "repository", "commit", "workflow_run", "release_tag",
                "asset_name", "url", "size", "sha256",
            ):
                if not entry.get(field):
                    raise ContractError(
                        f"admitted clean BusyBox input lacks {field}: "
                        f"{entry['name']}"
                    )
            if entry["commit"] in denied_commits:
                raise ContractError("denied BusyBox lineage was admitted")
    all_inputs = assets + unresolved + execution_inputs
    admitted = data.get("final_build_admitted")
    inputs_admitted = all(entry.get("admitted") for entry in all_inputs)
    if admitted and not inputs_admitted:
        raise ContractError("final build admitted with unresolved inputs")
    if not admitted and inputs_admitted:
        raise ContractError("final build remains blocked after all inputs were admitted")
    for entry in all_inputs:
        if entry.get("admitted"):
            for field in ("size", "sha256"):
                if not entry.get(field):
                    raise ContractError(
                        f"admitted input lacks {field}: "
                        f"{entry.get('package', entry.get('name'))}"
                    )


def validate_pe_audit(file_output, imports, personality="MSYS"):
    if personality != "MSYS":
        raise ContractError("wrong target personality")
    lowered = file_output.lower()
    if "architecture: aarch64" not in lowered:
        raise ContractError("wrong PE architecture")
    if not re.search(r"file format pei?-aarch64-little", lowered):
        raise ContractError("wrong PE format")
    import_text = "\n".join(imports).lower()
    if "msys-2.0.dll" not in import_text:
        raise ContractError("MSYS runtime import missing")
    rejected = (
        "cygwin1.dll", "x86_64", "i686", "msvcrt", "ucrtbase",
        "libwinpthread", "libgcc_s_seh-1.dll",
    )
    if any(value in import_text for value in rejected):
        raise ContractError("foreign target import detected")


def validate_archive_audit(armap_output, member_outputs):
    if "Archive index:" not in armap_output:
        raise ContractError("archive armap is missing")
    if not member_outputs:
        raise ContractError("archive has no members")
    for output in member_outputs:
        lowered = output.lower()
        if "architecture: aarch64" not in lowered:
            raise ContractError("archive member has wrong architecture")
        if "file format pe-aarch64-little" not in lowered:
            raise ContractError("archive member has wrong object format")


def validate_native_evidence(data):
    cases = set(data.get("cases", []))
    missing = REQUIRED_NATIVE_CASES - cases
    if missing:
        raise ContractError(f"native evidence is incomplete: {sorted(missing)}")
    if data.get("host_architecture") != "Arm64":
        raise ContractError("native host is not Arm64")
    if data.get("x64_process_or_module_count") != 0:
        raise ContractError("native evidence contains x64 process or module")
    if data.get("busybox_audited_path_count") != 59:
        raise ContractError("native evidence did not audit all BusyBox paths")
    if data.get("semantic_proof_audited_path_count") != 24:
        raise ContractError("native evidence did not audit all semantic proof paths")
    if data.get("native_path_count") != 30:
        raise ContractError("native evidence did not audit all package paths")
    if data.get("result") != "pass":
        raise ContractError("native evidence did not pass")


def validate_text_contract(package_dir):
    recipe = (package_dir / "PKGBUILD").read_text(encoding="utf-8")
    workflow = (
        package_dir.parent / ".github" / "workflows" / "arm64-coreutils.yml"
    ).read_text(encoding="utf-8")
    lifecycle = (
        package_dir / "validate-package-lifecycle.sh"
    ).read_text(encoding="utf-8")

    recipe_markers = (
        "pkgname=mingw-w64-cross-msysarm64-coreutils",
        "_target=aarch64-pc-msys",
        "--host=\"${_target}\"",
        "-specs=${_target_root}/lib/cygwin-compile-only.specs",
        "path-manifest.json",
        "check-aarch64-pseudo-relocs.ps1",
        "mingw-w64-cross-msysarm64-gmp=${_gmp_version}",
        "mingw-w64-cross-msysarm64-gmp-devel=${_gmp_version}",
        "mingw-w64-cross-msysarm64-libiconv=${_libiconv_version}",
        "mingw-w64-cross-msysarm64-libiconv-devel=${_libiconv_version}",
        "mingw-w64-cross-msysarm64-libintl=${_libintl_version}",
        "mingw-w64-cross-msysarm64-libintl-devel=${_libintl_version}",
        "libstdbuf-export-count=2",
    )
    for marker in recipe_markers:
        if marker not in recipe:
            raise ContractError(f"recipe metadata mismatch: {marker}")
    depends_match = re.search(
        r"(?ms)^depends=\(\n(?P<body>.*?)^\)\n", recipe
    )
    makedepends_match = re.search(
        r"(?ms)^makedepends=\(\n(?P<body>.*?)^\)\n", recipe
    )
    if not depends_match or not makedepends_match:
        raise ContractError("recipe dependency arrays are malformed")
    depends_body = depends_match.group("body")
    makedepends_body = makedepends_match.group("body")
    for package in ("gmp", "libiconv", "libintl"):
        runtime = f"mingw-w64-cross-msysarm64-{package}=${{_"
        devel = f"mingw-w64-cross-msysarm64-{package}-devel=${{_"
        if runtime not in depends_body or devel in depends_body:
            raise ContractError(f"runtime dependency split mismatch: {package}")
        if devel not in makedepends_body or runtime in makedepends_body:
            raise ContractError(f"build dependency split mismatch: {package}")

    for option in REQUIRED_PACMAN_OPTIONS:
        if option not in lifecycle:
            raise ContractError(f"private-root argument omitted: {option}")
    if "winsymlinks:sys" not in lifecycle:
        raise ContractError("lifecycle does not preserve MSYS symlinks")
    if "shared-before" not in lifecycle or "shared-after" not in lifecycle:
        raise ContractError("shared state sealing is missing")

    workflow_markers = (
        "github.repository == 'crutkas/MSYS2-packages'",
        "windows-11-arm",
        "dependency-lock.json",
        "final_build_admitted",
        "validate_contract.py",
        "x64_process_or_module_count",
        "clean-busybox-payload",
        "clean-busybox-semantic-proof-payload",
        "makepkg --cleanbuild --noconfirm --check",
        "PACMAN=/opt/private-bin/pacman",
        "--root /",
        "--dbpath /var/lib/pacman",
        "--cachedir /var/cache/pacman/pkg",
        "--logfile /var/log/pacman.log",
        "--config /etc/pacman.conf",
        "--hookdir /etc/pacman.d/hooks",
    )
    for marker in workflow_markers:
        if marker not in workflow:
            raise ContractError(f"workflow contract missing: {marker}")
    if "./.ci/ci-build.sh" in workflow:
        raise ContractError("workflow bypasses PKGBUILD check()")
    actions = re.findall(r"(?m)^\s*-\s+uses:\s+([^@\s]+)@([^\s]+)", workflow)
    if not actions:
        raise ContractError("workflow contains no actions")
    for action, revision in actions:
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ContractError(
                f"workflow action is not SHA-pinned: {action}@{revision}"
            )


def validate_all(package_dir):
    with (package_dir / "path-manifest.json").open(encoding="utf-8") as handle:
        validate_path_manifest(json.load(handle))
    with (package_dir / "dependency-lock.json").open(encoding="utf-8") as handle:
        validate_dependency_lock(json.load(handle))
    validate_text_contract(package_dir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "package_dir", nargs="?", type=Path,
        default=Path(__file__).resolve().parent,
    )
    args = parser.parse_args()
    try:
        validate_all(args.package_dir.resolve())
    except (ContractError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("coreutils ARM64 contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
LOCK = ROOT / "dependency-lock.json"
HOST_LOCK = ROOT / "host-build-lock.json"
PKGBUILD = ROOT / "PKGBUILD"
LIFECYCLE = ROOT / "validate-package-lifecycle.sh"
NATIVE_SMOKE = ROOT / "native-smoke.ps1"
WORKFLOW = ROOT.parent / ".github" / "workflows" / "arm64-gettext.yml"
MAIN_WORKFLOW = ROOT.parent / ".github" / "workflows" / "main.yml"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACTION_USES = re.compile(r"uses:\s+([^@\s]+)@([^\s#]+)")

LIBICONV_CONTRACT = {
    "mingw-w64-cross-msysarm64-libiconv": {
        "required_version": "1.18-1",
        "expected_asset_name": "mingw-w64-cross-msysarm64-libiconv-1.18-1-x86_64.pkg.tar.zst",
        "provides": ["aarch64-pc-msys-libiconv=1.18"],
        "owned_paths": [
            "/opt/aarch64-pc-msys/usr/bin/msys-charset-1.dll",
            "/opt/aarch64-pc-msys/usr/bin/msys-iconv-2.dll",
        ],
    },
    "mingw-w64-cross-msysarm64-libiconv-devel": {
        "required_version": "1.18-1",
        "expected_asset_name": "mingw-w64-cross-msysarm64-libiconv-devel-1.18-1-x86_64.pkg.tar.zst",
        "provides": ["aarch64-pc-msys-libiconv-devel=1.18"],
        "owned_paths": [
            "/opt/aarch64-pc-msys/usr/include/libcharset.h",
            "/opt/aarch64-pc-msys/usr/include/localcharset.h",
            "/opt/aarch64-pc-msys/usr/include/iconv.h",
            "/opt/aarch64-pc-msys/usr/lib/libcharset.a",
            "/opt/aarch64-pc-msys/usr/lib/libcharset.dll.a",
            "/opt/aarch64-pc-msys/usr/lib/libcharset.la",
            "/opt/aarch64-pc-msys/usr/lib/libiconv.a",
            "/opt/aarch64-pc-msys/usr/lib/libiconv.dll.a",
            "/opt/aarch64-pc-msys/usr/lib/libiconv.la",
            "/opt/aarch64-pc-msys/usr/lib/pkgconfig/libiconv.pc",
        ],
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_lock(path: pathlib.Path = LOCK) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def require_bool(value: object, name: str) -> None:
    require(type(value) is bool, f"{name} must be a JSON boolean")


def libiconv_contract_payload(dependencies: list[dict]) -> list[dict]:
    keys = ("package", "required_version", "expected_asset_name", "provides", "owned_paths")
    return [
        {key: dependency[key] for key in keys}
        for dependency in sorted(dependencies, key=lambda item: item["package"])
    ]


def libiconv_record_digest(dependency: dict) -> str:
    payload = {key: value for key, value in dependency.items() if key != "record_sha256"}
    return canonical_digest(payload)


def libiconv_admission_hash(lock: dict) -> str:
    dependencies = sorted(
        lock["target_dependency_assets"], key=lambda dependency: dependency["package"]
    )
    require(
        all(dependency["admitted"] is True for dependency in dependencies),
        "libiconv is not fully admitted",
    )
    return canonical_digest(
        {
            "canonical_release_tag": lock["libiconv_admission"]["canonical_release_tag"],
            "records": dependencies,
        }
    )


def validate_host_lock(host_lock: dict) -> None:
    require(host_lock["schema_version"] == 1, "unexpected host lock schema")
    require(
        host_lock["repository"] == "https://repo.msys2.org/msys/x86_64/",
        "host repository drift",
    )
    database = host_lock["database"]
    require(database["size"] == 485002, "host database size drift")
    require(database["signature_size"] == 566, "host database signature size drift")
    for name in ("sha256", "signature_sha256"):
        require(SHA256.fullmatch(database[name]) is not None, f"bad host database {name}")
    require(
        database["signing_key"] == "5F944B027F7FE2091985AA2EFA11531AA0AA7F57",
        "host database signer drift",
    )
    require(
        host_lock["direct_packages"]
        == [
            "autotools",
            "base-devel",
            "gcc",
            "gettext-devel",
            "groff",
            "libiconv-devel",
            "python",
        ],
        "host direct package drift",
    )
    assets = host_lock["assets"]
    require(len(assets) == 131, "host closure count drift")
    require(
        canonical_digest(assets) == host_lock["closure_sha256"],
        "host closure digest mismatch",
    )
    names = set()
    filenames = set()
    for asset in assets:
        require(asset["package"] not in names, f"duplicate host package {asset['package']}")
        require(asset["filename"] not in filenames, f"duplicate host asset {asset['filename']}")
        names.add(asset["package"])
        filenames.add(asset["filename"])
        require(asset["version"], f"missing host version for {asset['package']}")
        require(
            asset["url"] == host_lock["repository"] + asset["filename"],
            f"host URL drift for {asset['package']}",
        )
        require(
            type(asset["size"]) is int and asset["size"] > 0,
            f"bad host size for {asset['package']}",
        )
        require(
            SHA256.fullmatch(asset["sha256"]) is not None,
            f"bad host hash for {asset['package']}",
        )
    require(
        {
            "autoconf-wrapper",
            "automake-wrapper",
            "base-devel",
            "gcc",
            "gettext-devel",
            "groff",
            "libtool",
            "m4",
            "make",
            "patch",
            "pkgconf",
            "python",
        }
        <= names,
        "host build tools missing from closure",
    )


def validate_lock(lock: dict) -> None:
    require(lock["schema_version"] == 1, "unexpected lock schema")
    require(lock["target"] == "aarch64-pc-msys", "wrong target")
    require(lock["personality"] == "MSYS", "wrong personality")
    require(
        lock["abi"]
        == {
            "data_model": "LP64",
            "calling_convention": "AAPCS64",
            "exception_model": "SEH",
        },
        "wrong ABI contract",
    )

    coordination = lock["coordination"]
    require(coordination["coreutils_session_id"] == "f861b5ca", "coreutils session drift")
    require(coordination["libiconv_session_id"] == "47f325f1", "libiconv session drift")
    for name in ("coreutils_pr_head", "libiconv_pr_head"):
        require(COMMIT.fullmatch(coordination[name]) is not None, f"invalid {name}")
    require(
        coordination["coreutils_runtime_requirement"]
        == "mingw-w64-cross-msysarm64-libintl=0.22.5-1",
        "coreutils runtime contract drift",
    )
    require(
        coordination["coreutils_devel_requirement"]
        == "mingw-w64-cross-msysarm64-libintl-devel=0.22.5-1",
        "coreutils devel contract drift",
    )

    toolchain = lock["toolchain"]
    require(COMMIT.fullmatch(toolchain["binutils_commit"]) is not None, "bad binutils commit")
    for name in ("linker_sha256", "pseudo_reloc_scanner_sha256"):
        require(SHA256.fullmatch(toolchain[name]) is not None, f"bad {name}")
    require(toolchain["pseudo_reloc_scanner_size"] == 10569, "scanner size drift")

    source = lock["sources"][0]
    require(source["name"] == "gettext-0.22.5.tar.gz", "wrong source")
    require(source["size"] == 26861674, "source size drift")
    require(source["signature_size"] == 833, "signature size drift")
    for name in ("sha256", "signature_sha256"):
        require(SHA256.fullmatch(source[name]) is not None, f"bad source {name}")
    require(
        source["signing_key"] == "9001B85AF9E1B83DF1BDA942F5BE8B267C6A406D",
        "source signer drift",
    )

    base = lock["private_host_base"]
    require_bool(base["admitted"], "private_host_base.admitted")
    require(
        base["name"] == "msys2-base-x86_64-20260611.tar.xz",
        "private base name drift",
    )
    require(
        base["url"]
        == "https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260611.tar.xz",
        "private base URL drift",
    )
    require(base["size"] == 53555380, "private base size drift")
    require(SHA256.fullmatch(base["sha256"]) is not None, "private base hash invalid")
    require(
        base["signature_url"]
        == "https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260611.tar.xz.sig",
        "private base signature URL drift",
    )
    require(base["signature_size"] == 566, "private base signature size drift")
    require(
        base["signing_key"] == "E0AA0F031DBD80FFBA57B06D5A62D0CAB6264964",
        "private base signer drift",
    )
    if base["admitted"]:
        require(SHA256.fullmatch(base["signature_sha256"] or "") is not None, "base signature not pinned")
    else:
        require(base["signature_sha256"] is None, "unadmitted base has signature bytes")

    assets = lock["admitted_assets"]
    require(len(assets) == 10, "unexpected admitted asset count")
    names = set()
    for asset in assets:
        require(asset["name"] not in names, f"duplicate asset {asset['name']}")
        names.add(asset["name"])
        require(asset["size"] > 0, f"missing size for {asset['name']}")
        require(SHA256.fullmatch(asset["sha256"]) is not None, f"bad hash for {asset['name']}")
    require(
        "mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst"
        in names,
        "fixed binutils package absent",
    )

    target_dependencies = lock["target_dependency_assets"]
    require(len(target_dependencies) == 2, "libiconv split contract drift")
    require(
        canonical_digest(libiconv_contract_payload(target_dependencies))
        == lock["libiconv_admission"]["contract_sha256"],
        "libiconv static contract digest mismatch",
    )
    require(
        {dependency["package"] for dependency in target_dependencies}
        == set(LIBICONV_CONTRACT),
        "libiconv package identities drift",
    )
    for dependency in target_dependencies:
        package = dependency["package"]
        contract = LIBICONV_CONTRACT[package]
        for name, expected in contract.items():
            require(dependency[name] == expected, f"{package} {name} drift")
        require_bool(dependency["admitted"], f"{package}.admitted")
        if dependency["admitted"] is True:
            require(
                dependency["release_tag"]
                == lock["libiconv_admission"]["canonical_release_tag"],
                f"{package} release tag is not canonical",
            )
            require(
                dependency["asset_name"] == dependency["expected_asset_name"],
                f"{package} asset name drift",
            )
            require(
                type(dependency["size"]) is int and dependency["size"] > 0,
                f"{package} size invalid",
            )
            require(SHA256.fullmatch(dependency["sha256"]) is not None, "bad dependency hash")
            require(
                dependency["record_sha256"] == libiconv_record_digest(dependency),
                f"{package} full record digest mismatch",
            )
        else:
            for name in ("release_tag", "asset_name", "size", "sha256", "record_sha256"):
                require(dependency[name] is None, f"provisional dependency has {name}")

    admission_states = {dependency["admitted"] for dependency in target_dependencies}
    require(len(admission_states) == 1, "libiconv splits must be admitted atomically")
    canonical_release = lock["libiconv_admission"]["canonical_release_tag"]
    if admission_states == {True}:
        expected_release = re.compile(
            "^msysarm64-libiconv-pr22-"
            + re.escape(coordination["libiconv_pr_head"][:8])
            + r"-[0-9]{8}$"
        )
        require(
            isinstance(canonical_release, str)
            and expected_release.fullmatch(canonical_release) is not None,
            "canonical libiconv release tag invalid",
        )
    else:
        require(canonical_release is None, "unadmitted libiconv has a release tag")

    require_bool(lock["final_build_admitted"], "final_build_admitted")
    fully_admitted = base["admitted"] is True and all(
        dependency["admitted"] is True for dependency in target_dependencies
    )
    require(
        lock["final_build_admitted"] is fully_admitted,
        "final admission does not match immutable inputs",
    )


def validate_text_contracts() -> None:
    pkgbuild = PKGBUILD.read_text(encoding="utf-8")
    lifecycle = LIFECYCLE.read_text(encoding="utf-8")
    smoke = NATIVE_SMOKE.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    main_workflow = MAIN_WORKFLOW.read_text(encoding="utf-8")
    host_lock = load_lock(HOST_LOCK)
    validate_host_lock(host_lock)

    for package in (
        "mingw-w64-cross-msysarm64-libintl",
        "mingw-w64-cross-msysarm64-libintl-devel",
        "mingw-w64-cross-msysarm64-gettext-libs",
        "mingw-w64-cross-msysarm64-gettext-devel",
        "mingw-w64-cross-msysarm64-gettext",
    ):
        require(package in pkgbuild, f"missing split {package}")
        require(package in lifecycle, f"lifecycle omits {package}")

    for contract in (
        "msys-intl-8.dll",
        "include/libintl.h",
        "lib/libintl.a",
        "lib/libintl.dll.a",
        "aarch64-pc-msys-libintl",
        "aarch64-pc-msys-libintl-devel",
        "bin/autopoint",
        "bin/gettextize",
        "bin/gettext.sh",
        "msys-gettextlib-0-22-5.dll",
        "msys-gettextsrc-0-22-5.dll",
    ):
        require(contract in pkgbuild, f"package contract omits {contract}")

    for gate in (
        "architecture: aarch64",
        "pei?-aarch64-little",
        "--print-armap",
        "Archive index:",
        "msys-2.0.dll",
        "cygwin1",
        "x86_64",
        "check-aarch64-pseudo-relocs.ps1",
        "GETTEXT_FINAL_BUILD_ADMITTED",
        "LIBICONV_ADMISSION_SHA256",
    ):
        require(gate in pkgbuild, f"PKGBUILD omits gate {gate}")

    for private_flag in (
        "--root",
        "--dbpath",
        "--cachedir",
        "--logfile",
        "--config",
        "--hookdir",
        "--gpgdir",
    ):
        require(private_flag in lifecycle, f"lifecycle omits {private_flag}")
        require(private_flag in workflow, f"workflow omits {private_flag}")

    require("C:\\\\msys64\\\\usr\\\\bin\\\\pacman.exe" not in workflow, "shared pacman referenced")
    require("final_build_admitted" in workflow, "workflow lacks admission output")
    require("needs.contract.outputs.final_build_admitted == 'true'" in workflow, "build not gated")
    require("private_host_base.url" in workflow, "private base URL lock absent")
    require("private_host_base.signature_url" in workflow, "private signature URL lock absent")
    require("host-build-lock.json" in workflow, "host build closure is not consumed")
    require("--nodeps" not in workflow, "makepkg dependency checks are bypassed")
    require("GETTEXT_SOURCE_GNUPGHOME" in workflow, "final source signer keyring absent")
    require("Compare-Object $expectedProvides $actualProvides" in workflow, "provides are not exact")
    require(
        "Compare-Object $expectedTargetPaths $actualTargetPaths" in workflow,
        "target ownership is not exact",
    )
    require(
        "github.event.pull_request.head.repo.full_name == github.repository" in workflow,
        "custom workflow does not enforce same-repository PR heads",
    )
    require(
        "crutkas-arm64-gettext-libintl" in main_workflow,
        "generic shared-root CI does not exclude this fork-only lane",
    )
    require(
        "github.event.pull_request.head.repo.full_name == github.repository" in main_workflow,
        "generic CI skip trusts an external fork branch name",
    )
    require("reproduc" in workflow.lower(), "reproducibility gate absent")
    require("path-leak" in workflow, "path leak gate absent")
    require("release" not in "\n".join(
        line.lower() for line in workflow.splitlines() if line.lstrip().startswith("uses:")
    ), "release action forbidden")
    expected_actions = {
        "al-cheb/configure-pagefile-action": "a3b6ebd6b634da88790d9c58d4b37a7f4a7b8708",
        "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
        "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "jeremyd2019/package-grokker/grok-artifacts": "3028d539ec65a74cabafb2b7deff1f91f273af72",
        "msys2/setup-msys2": "66cd2cce69caa17b53920067426061ca1de3a884",
    }
    for workflow_name, workflow_text in (
        ("custom", workflow),
        ("generic", main_workflow),
    ):
        action_uses = ACTION_USES.findall(workflow_text)
        require(action_uses, f"{workflow_name} workflow has no actions")
        for action, revision in action_uses:
            require(action in expected_actions, f"unexpected action {action}")
            require(
                revision == expected_actions[action],
                f"{workflow_name} workflow {action} is not SHA pinned",
            )

    for smoke_gate in (
        "static-consumer.exe",
        "dynamic-consumer.exe",
        "msys-intl-8.dll",
        "native locale/domain/thread/module smoke",
        "Fork/argv-dependent CLI execution is intentionally blocked",
    ):
        require(smoke_gate in smoke, f"native smoke omits {smoke_gate}")


def main() -> int:
    if sys.argv[1:] == ["--print-libiconv-admission"]:
        try:
            print(libiconv_admission_hash(load_lock()))
        except (AssertionError, KeyError, TypeError, ValueError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        return 0
    if sys.argv[1:]:
        print("ERROR: unsupported arguments", file=sys.stderr)
        return 2
    try:
        validate_lock(load_lock())
        validate_host_lock(load_lock(HOST_LOCK))
        validate_text_contracts()
    except (AssertionError, KeyError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    digest = hashlib.sha256(LOCK.read_bytes()).hexdigest()
    print(f"contract=valid lock_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

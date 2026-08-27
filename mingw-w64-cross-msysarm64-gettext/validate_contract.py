#!/usr/bin/env python3

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
LOCK = ROOT / "dependency-lock.json"
PKGBUILD = ROOT / "PKGBUILD"
LIFECYCLE = ROOT / "validate-package-lifecycle.sh"
NATIVE_SMOKE = ROOT / "native-smoke.ps1"
WORKFLOW = ROOT.parent / ".github" / "workflows" / "arm64-gettext.yml"
MAIN_WORKFLOW = ROOT.parent / ".github" / "workflows" / "main.yml"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_lock(path: pathlib.Path = LOCK) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def libiconv_admission_hash(lock: dict) -> str:
    dependencies = sorted(
        lock["target_dependency_assets"], key=lambda dependency: dependency["package"]
    )
    require(
        all(dependency["admitted"] for dependency in dependencies),
        "libiconv is not fully admitted",
    )
    digest_input = "\n".join(dependency["sha256"] for dependency in dependencies)
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()


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
    for dependency in target_dependencies:
        require(dependency["required_version"] == "1.18-1", "libiconv version drift")
        if dependency["admitted"]:
            for name in ("release_tag", "asset_name", "size", "sha256"):
                require(dependency[name], f"admitted dependency lacks {name}")
            require(SHA256.fullmatch(dependency["sha256"]) is not None, "bad dependency hash")
        else:
            for name in ("release_tag", "asset_name", "size", "sha256"):
                require(dependency[name] is None, f"provisional dependency has {name}")

    fully_admitted = base["admitted"] and all(
        dependency["admitted"] for dependency in target_dependencies
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
    require(
        "crutkas-arm64-gettext-libintl" in main_workflow,
        "generic shared-root CI does not exclude this fork-only lane",
    )
    require("reproduc" in workflow.lower(), "reproducibility gate absent")
    require("path-leak" in workflow, "path leak gate absent")
    require("release" not in "\n".join(
        line.lower() for line in workflow.splitlines() if line.lstrip().startswith("uses:")
    ), "release action forbidden")

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
        validate_text_contracts()
    except (AssertionError, KeyError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    digest = hashlib.sha256(LOCK.read_bytes()).hexdigest()
    print(f"contract=valid lock_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

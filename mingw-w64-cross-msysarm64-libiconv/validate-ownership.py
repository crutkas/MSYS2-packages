#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


EXPECTED_PROVENANCE = {
    "repository": "crutkas/build-extra",
    "pull_request": 12,
    "commit": "3ef6d935092dc6ab2e376bcd0ffc74fa52dac39d",
    "inventory_commit": "7a77c0c5ff81d1c979302c9cc49a62f26f68d17c",
    "ownership_manifest": "arm64-x64-ownership-v2.55.0.4.tsv",
    "ownership_manifest_blob": "b533787b2fc714fb6055b01cd816760d62431a31",
    "ownership_manifest_size": 36191,
    "ownership_manifest_sha256":
        "045104e4e84dbbc788382c1d7ed64220f4956b913714d1f287a69263caa26805",
    "backlog_model": "arm64-x64-backlog-v2.55.0.4.json",
    "backlog_model_blob": "61a0b93fa1dd7dea0b357047a92b261b201b527f",
    "backlog_model_size": 311663,
    "backlog_model_sha256":
        "fd6d4e4f01db476e8b97271f35e349973791d1c7719c095b068a9508942414e4",
    "residual_rows_size": 154,
    "residual_rows_sha256":
        "c43f18ca170ac8de0bf53e2faa3816641daa1f56d886798ee5c33323edc420e4",
}

EXPECTED_RESIDUALS = {
    "usr/bin/iconv.exe": {
        "baseline_owner": "iconv",
        "baseline_version": "1.19-1",
        "installed_path": "opt/aarch64-pc-msys/usr/bin/iconv.exe",
        "replacement_package": "mingw-w64-cross-msysarm64-iconv",
        "replacement_version": "1.19-1",
        "role": "cli",
    },
    "usr/bin/msys-iconv-2.dll": {
        "baseline_owner": "libiconv",
        "baseline_version": "1.19-1",
        "installed_path": "opt/aarch64-pc-msys/usr/bin/msys-iconv-2.dll",
        "replacement_package": "mingw-w64-cross-msysarm64-libiconv",
        "replacement_version": "1.19-1",
        "role": "runtime-library",
    },
}

EXPECTED_SUPPORT_PATHS = [
    {
        "source_staged_path": "usr/bin/msys-charset-1.dll",
        "installed_path":
            "opt/aarch64-pc-msys/usr/bin/msys-charset-1.dll",
        "replacement_package": "mingw-w64-cross-msysarm64-libiconv",
    },
]


class ContractError(ValueError):
    pass


def validate(manifest, staged_root):
    if manifest.get("schema_version") != 1:
        raise ContractError("ownership schema mismatch")
    if manifest.get("target") != "aarch64-pc-msys":
        raise ContractError("ownership target mismatch")
    if manifest.get("package_prefix") != "opt/aarch64-pc-msys":
        raise ContractError("ownership package prefix mismatch")
    if manifest.get("source_recipe") != {
        "name": "libiconv",
        "version": "1.19-1",
        "recipe_repository": "msys2/MSYS2-packages",
        "recipe_commit": "84dfd072fc4338cce775628ffc0a053da7e57d80",
        "source_sha256":
            "88dd96a8c0464eca144fc791ae60cd31cd8ee78321e67397e25fc095c4a19aa6",
    }:
        raise ContractError("source recipe identity mismatch")
    if manifest.get("frozen_ownership") != EXPECTED_PROVENANCE:
        raise ContractError("frozen ownership provenance mismatch")

    residuals = manifest.get("residuals", [])
    if manifest.get("residual_path_count") != 2 or len(residuals) != 2:
        raise ContractError("exactly two residual paths are required")
    by_path = {entry.get("baseline_path"): entry for entry in residuals}
    if set(by_path) != set(EXPECTED_RESIDUALS):
        raise ContractError("residual path membership mismatch")
    for path, expected in EXPECTED_RESIDUALS.items():
        entry = by_path[path]
        for key, value in expected.items():
            if entry.get(key) != value:
                raise ContractError(f"{path}: {key} mismatch")
        if entry.get("source_staged_path") != path:
            raise ContractError(f"{path}: staged path mismatch")
        if not (staged_root / path).is_file():
            raise ContractError(f"{path}: missing staged source file")
    support_paths = manifest.get("support_paths")
    if support_paths != EXPECTED_SUPPORT_PATHS:
        raise ContractError("support path ownership mismatch")
    installed_paths = [
        entry["installed_path"] for entry in residuals + support_paths
    ]
    if len(installed_paths) != len(set(installed_paths)):
        raise ContractError("replacement package paths overlap")
    for entry in support_paths:
        if not (staged_root / entry["source_staged_path"]).is_file():
            raise ContractError(
                f"{entry['source_staged_path']}: missing staged support file")

    cli = by_path["usr/bin/iconv.exe"]
    if cli.get("required_semantics") != [
        "encoding-name-resolution",
        "invalid-encoding-nonzero-stderr",
        "binary-stdin-stdout-streams",
    ]:
        raise ContractError("iconv CLI semantics contract mismatch")
    library = by_path["usr/bin/msys-iconv-2.dll"]
    if library.get("required_abi") != {
        "dll_basename": "msys-iconv-2.dll",
        "exported_symbols": [
            "_libiconv_version",
            "libiconv_open",
            "libiconv",
            "libiconv_close",
            "locale_charset",
        ],
        "public_api": ["iconv_open", "iconv", "iconv_close"],
        "runtime_import": "msys-2.0.dll",
    }:
        raise ContractError("libiconv ABI contract mismatch")
    if manifest.get("admission") != {
        "admitted": False,
        "blocked_on": "corrected-runtime-clean-ab-native",
        "a527_evidence": "diagnostic-only",
        "corrected_runtime": None,
    }:
        raise ContractError("ownership admission gate mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("staged_root", type=Path)
    args = parser.parse_args()
    with args.manifest.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    try:
        validate(manifest, args.staged_root)
    except ContractError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

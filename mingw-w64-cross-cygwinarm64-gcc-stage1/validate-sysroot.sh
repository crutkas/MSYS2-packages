#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "usage: $0 <prefix-root> <report-directory>" >&2
  exit 2
fi

prefix_root=$(cd "$1" && pwd)
report_dir=$2
target=aarch64-pc-cygwin
fixtures=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/cygwinarm64-sysroot.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)

cc="${prefix_root}/bin/${target}-gcc"
cxx="${prefix_root}/bin/${target}-g++"
objdump=/opt/bin/${target}-objdump
specs="/opt/${target}/lib/cygwin-compile-only.specs"
manifest="/opt/${target}/lib/default-manifest.o"
compile_tool=("-B/opt/${target}/bin/" "-specs=${specs}")
cxx_compile_tool=(
  "${compile_tool[@]}"
  -isystem "/opt/${target}/include"
  -idirafter "/opt/${target}/include/w32api"
)

test -x "$cc"
test -x "$cxx"
test -x "$objdump"
test -f "$specs"
test -f "$manifest"

"$cc" "${compile_tool[@]}" -E -P "$fixtures/sysroot-fragment.c" \
  -o "$work/sysroot-fragment.i"
"$cc" "${compile_tool[@]}" -O2 -fexceptions -funwind-tables \
  -c "$fixtures/sysroot-fragment.c" -o "$work/sysroot-fragment.o"
"$cxx" "${cxx_compile_tool[@]}" -E -P "$fixtures/sysroot-fragment.cc" \
  -o "$work/sysroot-fragment.ii"
"$cxx" "${cxx_compile_tool[@]}" -O2 -fno-exceptions -fno-rtti \
  -c "$fixtures/sysroot-fragment.cc" -o "$work/sysroot-fragment-cxx.o"

for object in \
  "$work/sysroot-fragment.o" \
  "$work/sysroot-fragment-cxx.o" \
  "$manifest"
do
  test "$(od -An -tx2 -N2 "$object" | tr -d '[:space:]')" = aa64
  "$objdump" -f "$object" | grep -F 'file format pe-aarch64-little'
done

"$objdump" -h "$work/sysroot-fragment.o" > "$work/sections.txt"
grep -Eq '[[:space:]]\.pdata[[:space:]]' "$work/sections.txt"
grep -Eq '[[:space:]]\.xdata[[:space:]]' "$work/sections.txt"

pacman -Q \
  mingw-w64-cross-cygwinarm64-headers \
  mingw-w64-cross-cygwinarm64-windows-default-manifest \
  mingw-w64-cross-cygwinarm64-sysroot \
  > "$work/packages.txt"

python - "$work" "$report_dir/sysroot-compile-report.json" "$specs" <<'PY'
import hashlib
import json
import pathlib
import sys

work = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
specs_path = pathlib.Path(sys.argv[3])

report = {
    "schema_version": 1,
    "target": "aarch64-pc-cygwin",
    "link_attempted": False,
    "specs": {
        "path": "/opt/aarch64-pc-cygwin/lib/cygwin-compile-only.specs",
        "sha256": hashlib.sha256(specs_path.read_bytes()).hexdigest(),
    },
    "packages": (work / "packages.txt").read_text().splitlines(),
    "validation": {
        "c_preprocessed": True,
        "c_object": True,
        "cxx_preprocessed": True,
        "cxx_object": True,
        "c_specs_add_root_include": True,
        "cxx_specs_add_root_include": False,
        "cxx_root_include_supplied_explicitly": True,
        "newlib_headers": True,
        "winsup_headers": True,
        "w32api_headers": True,
        "lp64": True,
        "seh_sections": [".pdata", ".xdata"],
        "coff_machine": "0xAA64",
        "default_manifest_machine": "0xAA64",
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY

python -m json.tool "$report_dir/sysroot-compile-report.json" > /dev/null
echo "sysroot compile validation passed: ${report_dir}/sysroot-compile-report.json"

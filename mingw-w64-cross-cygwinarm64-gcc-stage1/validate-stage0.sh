#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "usage: $0 <prefix-root> <report-directory>" >&2
  exit 2
fi

prefix_root=$(cd "$1" && pwd)
report_dir=$2
target=aarch64-pc-cygwin
package=mingw-w64-cross-cygwinarm64-gcc-stage1
source_commit=bd1d77ba35e2820df5387cca5213925adb07a0ee
fixtures=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/cygwinarm64-gcc-stage0.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
mkdir -p "$work/empty-sysroot"

export PATH="${prefix_root}/bin:/opt/bin:${PATH}"
cc="${prefix_root}/bin/${target}-gcc"
cxx="${prefix_root}/bin/${target}-g++"
objdump=/opt/bin/${target}-objdump
gcc_nm="${prefix_root}/bin/${target}-gcc-nm"
tool_path=/opt/${target}/bin
compile_tool=("-B${tool_path}/" "--sysroot=${work}/empty-sysroot" -nostdinc)

test -x "$cc"
test -x "$cxx"
test -x "$objdump"
test -x "$gcc_nm"
test "$("$cc" -dumpmachine)" = "$target"
test "$("$cxx" -dumpmachine)" = "$target"
test "$("$cc" -print-sysroot)" = "/opt/${target}"
"$cc" -print-multi-lib > "$work/multilib.txt"
grep -Fx '.;' "$work/multilib.txt"

"$cc" "${compile_tool[@]}" -dM -E -x c /dev/null > "$work/macros.txt"
"$cxx" "${compile_tool[@]}" -dM -E -x c++ /dev/null > "$work/cxx-macros.txt"
grep -Eq '^#define __CYGWIN__ (1|)$' "$work/macros.txt"
grep -Eq '^#define __LP64__ (1|)$' "$work/macros.txt"
grep -Fx '#define __SIZEOF_LONG__ 8' "$work/macros.txt"
grep -Fx '#define __SIZEOF_POINTER__ 8' "$work/macros.txt"
grep -Fx '#define __SIZEOF_LONG_DOUBLE__ 8' "$work/macros.txt"
grep -Eq '^#define __SEH__ (1|)$' "$work/macros.txt"
if grep -q '^#define __MSYS__' "$work/macros.txt"; then
  echo "Cygwin target unexpectedly defines __MSYS__" >&2
  exit 1
fi

"$cc" "${compile_tool[@]}" -O2 -c "$fixtures/abi.c" -o "$work/abi.o"
"$cc" "${compile_tool[@]}" -O2 -c "$fixtures/newlib-fragment.c" \
  -o "$work/newlib-fragment.o"
"$cxx" "${compile_tool[@]}" -E -P "$fixtures/winsup-fragment.cc" \
  -o "$work/winsup-fragment.ii"
"$cxx" "${compile_tool[@]}" -O2 -fno-exceptions -fno-rtti \
  -c "$fixtures/winsup-fragment.cc" -o "$work/winsup-fragment.o"
"$cc" "${compile_tool[@]}" -O2 -c "$fixtures/tls.c" -o "$work/tls.o"
"$cc" "${compile_tool[@]}" -O2 -fexceptions -funwind-tables \
  -c "$fixtures/unwind.c" -o "$work/unwind.o"
"$cc" "${compile_tool[@]}" -O2 -c "$fixtures/register-pressure.c" \
  -o "$work/register-pressure.o"

machine=$(od -An -tx2 -N2 "$work/abi.o" | tr -d '[:space:]')
test "$machine" = aa64
"$objdump" -f "$work/abi.o" > "$work/object-format.txt"
grep -F 'file format pe-aarch64-little' "$work/object-format.txt"
grep -F 'architecture: aarch64' "$work/object-format.txt"

"$objdump" -h "$work/unwind.o" > "$work/unwind-sections.txt"
grep -Eq '[[:space:]]\.pdata[[:space:]]' "$work/unwind-sections.txt"
grep -Eq '[[:space:]]\.xdata[[:space:]]' "$work/unwind-sections.txt"
"$objdump" -r "$work/tls.o" > "$work/tls-relocations.txt"
/opt/bin/${target}-nm "$work/tls.o" > "$work/tls-symbols.txt"
grep -F '__emutls_get_address' "$work/tls-relocations.txt"
grep -F '__emutls_v.cygtls_slot' "$work/tls-symbols.txt"

"$objdump" -d "$work/register-pressure.o" > "$work/register-pressure.txt"
if grep -Eq '(^|[^[:alnum:]_])x18([^[:alnum:]_]|$)' \
    "$work/register-pressure.txt"; then
  echo "reserved x18 was allocated under register pressure" >&2
  exit 1
fi

"$cc" "${compile_tool[@]}" -O2 -flto -c "$fixtures/abi.c" \
  -o "$work/abi-lto.o"
"$gcc_nm" "$work/abi-lto.o" > "$work/lto-nm.txt"
grep -F 'abi_probe' "$work/lto-nm.txt"
plugin=$(find "${prefix_root}/libexec/gcc/${target}" \
  -type f -name '*lto_plugin.dll' -print -quit)
test -n "$plugin"

if "$cc" "${compile_tool[@]}" "$fixtures/abi.c" \
    -o "$work/ordinary.exe" > "$work/link.log" 2>&1; then
  echo "stage-0 unexpectedly linked an executable without a sysroot" >&2
  exit 1
fi
test ! -e "$work/ordinary.exe"
grep -Eiq 'crt|cannot find|cygwin' "$work/link.log"

"$cc" -dumpspecs > "$report_dir/gcc.specs"
grep -F -- '-lcygwin' "$report_dir/gcc.specs" > /dev/null
if grep -Eq -- '-lmsys-2\.0|_msys_dll_entry|--dll-search-prefix=msys-' \
    "$report_dir/gcc.specs"; then
  echo "Cygwin stage-0 contains stale MSYS target specs" >&2
  exit 1
fi
if grep -Eiq '/usr/lib|cygwin1\.dll|msys-2\.0' "$work/link.log"; then
  echo "stage-0 attempted to use a host or MSYS runtime" >&2
  exit 1
fi
"$cc" -print-search-dirs > "$work/search-dirs.txt"
"$cc" "${compile_tool[@]}" -E -Wp,-v -x c /dev/null \
  > /dev/null 2> "$work/include-search.txt"

if [[ "$prefix_root" = /opt ]] && pacman -Q "$package" > /dev/null 2>&1; then
  pacman -Qlq "$package" |
    grep '^/opt/' |
    grep -v '/$' |
    LC_ALL=C sort -u > "$work/ownership.txt"
else
  find "$prefix_root" \( -type f -o -type l \) -print |
    sed "s#^${prefix_root}#/opt#" |
    LC_ALL=C sort > "$work/ownership.txt"
fi
while IFS= read -r owned_path; do
  case "$owned_path" in
    "/opt/bin/${target}-"* | \
    "/opt/${target}/"* | \
    "/opt/lib/gcc/${target}/"* | \
    "/opt/libexec/gcc/${target}/"* | \
    "/opt/share/doc/${package}/"* | \
    "/opt/share/licenses/${package}/"*)
      ;;
    *)
      echo "unexpected non-target-owned path: ${owned_path}" >&2
      exit 1
      ;;
  esac
done < "$work/ownership.txt"

python - "$work" "$report_dir/stage0-report.json" "$plugin" \
  "$prefix_root" "$fixtures" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

work = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
plugin_path = pathlib.Path(sys.argv[3])
prefix_root = sys.argv[4]
fixtures = sys.argv[5]

def text(name):
    return (work / name).read_text(encoding="utf-8", errors="replace")

def macro(name):
    match = re.search(rf"^#define {re.escape(name)}(?:\s+(.*))?$",
                      text("macros.txt"), re.MULTILINE)
    return None if match is None else (match.group(1) or "")

def scrub(value):
    return value.replace(prefix_root, "/opt").replace(
        str(work), "<work>").replace(fixtures, "<fixtures>")

def scrub_lines(name):
    return scrub(text(name)).splitlines()

specs_path = report_path.parent / "gcc.specs"
specs_hash = hashlib.sha256(specs_path.read_bytes()).hexdigest()
owned_files = text("ownership.txt").splitlines()
canonical_plugin = "/opt" + str(plugin_path).replace("\\", "/").split("/opt", 1)[-1]

report = {
    "schema_version": 1,
    "package": "mingw-w64-cross-cygwinarm64-gcc-stage1",
    "source": {
        "repository": "https://github.com/crutkas/gcc-woarm64",
        "commit": "bd1d77ba35e2820df5387cca5213925adb07a0ee",
        "version": "15.0.1 experimental",
    },
    "configuration": {
        "build": "x86_64-pc-msys",
        "host": "x86_64-pc-msys",
        "target": "aarch64-pc-cygwin",
        "sysroot": "/opt/aarch64-pc-cygwin",
        "validation_sysroot": "isolated empty directory",
        "native_system_header_dir": "/usr/include",
        "without_headers": True,
        "with_newlib": True,
        "languages": ["c", "c++", "lto"],
        "abi": "lp64",
        "multilib": text("multilib.txt").splitlines(),
    },
    "predefined_macros": {
        "__CYGWIN__": macro("__CYGWIN__"),
        "__MSYS__": macro("__MSYS__"),
        "__LP64__": macro("__LP64__"),
        "__SEH__": macro("__SEH__"),
        "__SIZEOF_LONG__": macro("__SIZEOF_LONG__"),
        "__SIZEOF_POINTER__": macro("__SIZEOF_POINTER__"),
        "__SIZEOF_LONG_DOUBLE__": macro("__SIZEOF_LONG_DOUBLE__"),
    },
    "abi_validation": {
        "long_bytes": 8,
        "pointer_bytes": 8,
        "long_double_bytes": 8,
        "va_list_bytes": 32,
        "va_list_alignment": 8,
        "x18_reserved": True,
        "x18_validation": "not allocated in register-pressure object",
        "seh": True,
        "tls_object_compiled": True,
        "tls_model": "emutls",
        "tls_runtime_symbol": "__emutls_get_address",
    },
    "object_validation": {
        "coff_machine": "0xAA64",
        "format": "pe-aarch64-little",
        "unwind_sections": [".pdata", ".xdata"],
    },
    "lto": {
        "plugin": canonical_plugin,
        "plugin_sha256": hashlib.sha256(plugin_path.read_bytes()).hexdigest(),
        "plugin_loaded_by_gcc_nm": True,
    },
    "link_policy": {
        "ordinary_link_succeeded": False,
        "host_library_fallback": False,
        "host_cygwin_dll_used": False,
        "cygwin_target_specs_present": True,
        "msys_target_specs_present": False,
        "diagnostic": scrub_lines("link.log"),
    },
    "target_libgcc": {
        "packaged": False,
        "probe": {
            "failure_source": "libgcc/unwind-seh.c:152",
            "failure": "ULONG64 * is incompatible with LP64 w32api PULONG_PTR",
        },
        "next_inputs": [
            "reviewed crutkas/gcc-woarm64 SEH image-base LP64 type fix",
            "/opt/aarch64-pc-cygwin/usr/lib/libcygwin.a for a later runtime stage",
            "/opt/aarch64-pc-cygwin/usr/lib AArch64 w32api import libraries for a later runtime stage",
        ],
    },
    "search": {
        "programs_and_libraries": scrub_lines("search-dirs.txt"),
        "includes": scrub_lines("include-search.txt"),
    },
    "specs": {
        "path": "/opt/share/doc/mingw-w64-cross-cygwinarm64-gcc-stage1/gcc.specs",
        "sha256": specs_hash,
    },
    "ownership": {
        "files": owned_files,
        "collision_counts": {
            "host_gcc": sum(path.startswith("/usr/") for path in owned_files),
            "aarch64_w64_mingw32": sum("aarch64-w64-mingw32" in path
                                      for path in owned_files),
            "aarch64_pc_msys": sum("aarch64-pc-msys" in path
                                   for path in owned_files),
        },
    },
    "fixtures": {
        "newlib_fragment_compiled": True,
        "winsup_fragment_preprocessed": True,
        "winsup_fragment_compiled": True,
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
PY

python -m json.tool "$report_dir/stage0-report.json" > /dev/null
echo "stage-0 validation passed: ${report_dir}/stage0-report.json"

#!/usr/bin/env bash

set -euo pipefail

if (( $# != 5 )); then
  echo "usage: $0 <stage-prefix> <report-dir> <runtime-source> <runtime-build> <fixtures>" >&2
  exit 2
fi

prefix_root=$(cd "$1" && pwd)
report_dir=$2
runtime_source=$(cd "$3" && pwd)
runtime_build=$4
fixtures=$(cd "$5" && pwd)
target=aarch64-pc-msys
gcc_version=15.0.1
package=mingw-w64-cross-msysarm64-libstdc++-headers

mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
work="$report_dir/work"
rm -rf "$work"
mkdir -p "$work"
rm -rf "$runtime_build"
mark() {
  printf '%s\n' "$1" >> "$report_dir/validation-progress.txt"
}
fail() {
  {
    printf 'step\t%s\n' "${current_step:-unknown}"
    printf 'line\t%s\n' "$1"
    printf 'command\t%s\n' "$2"
  } > "$report_dir/validation-failure.txt"
}
trap 'fail "$LINENO" "$BASH_COMMAND"' ERR
mark "start"

copy_failure_logs() {
  local name="$1"
  for ext in err txt log; do
    if [[ -f "$work/${name}.${ext}" ]]; then
      cp -f "$work/${name}.${ext}" "$report_dir/${name}.${ext}"
    fi
  done
}

cxx=${LIBSTDCXX_VALIDATE_CXX:-/opt/bin/${target}-g++}
stage0_cxx=/opt/bin/aarch64-pc-cygwin-g++
objdump=/opt/bin/${target}-objdump
nm=/opt/bin/${target}-nm
generic_include="${prefix_root}/${target}/include/c++/${gcc_version}"
target_include="${generic_include}/${target}"
backward_include="${generic_include}/backward"
sysroot=/opt/${target}
specs="${sysroot}/lib/cygwin-compile-only.specs"

validate_include_paths() {
  python - "$1" <<'PY'
import pathlib
import re
import shlex
import sys

paths = []
for line in pathlib.Path(sys.argv[1]).read_text(
    encoding="utf-8", errors="replace"
).splitlines():
    stripped = line.strip()
    if line.startswith(" ") and stripped.startswith(("/", "\\")):
        paths.append(stripped)
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        continue
    for index, token in enumerate(tokens):
        if token in ("-I", "-isystem", "-idirafter") and index + 1 < len(tokens):
            paths.append(tokens[index + 1])
        elif token.startswith("-I") and len(token) > 2:
            paths.append(token[2:])

for path in paths:
    normalized = path.replace("\\", "/").lower()
    if (
        "aarch64-w64-mingw32" in normalized
        or re.search(r"(^|/)usr/include/c\+\+(/|$)", normalized)
        or re.search(r"(^|/)usr/lib/gcc/x86_64[^/]*/", normalized)
        or re.search(
            r"(^|/)(mingw32|mingw64|ucrt64|clang32|clang64|clangarm64)/",
            normalized,
        )
    ):
        raise SystemExit(f"foreign C++ include path: {path}")
PY
}

compile_tool=(
  "-B${sysroot}/bin/"
  "--sysroot=${sysroot}"
  "-specs=${specs}"
)
cxx_headers=(
  -D_WIN64
  -nostdinc++
  -isystem "$generic_include"
  -isystem "$target_include"
  -isystem "$backward_include"
  -isystem "${sysroot}/include"
  -idirafter "${sysroot}/include/w32api"
)

current_step="cxx-executable"
test -x "$cxx"
current_step="stage0-cxx-executable"
test -x "$stage0_cxx"
current_step="objdump-executable"
test -x "$objdump"
current_step="nm-executable"
test -x "$nm"
mark "executables-ok"
current_step="spec-file"
test -f "$specs"
current_step="c++config"
test -f "${target_include}/bits/c++config.h"
current_step="gthr-default"
test -f "${target_include}/bits/gthr-default.h"
current_step="gthr-posix"
test -f "${target_include}/bits/gthr-posix.h"
mark "header-files-ok"
current_step="dumpmachine"
test "$("$cxx" -dumpmachine)" = "$target"
mark "dumpmachine-ok"
current_step="thread-model"
grep -Fx 'Thread model: posix' <("$cxx" -v 2>&1)
mark "thread-model-ok"
mark "initial-checks-ok"

"$cxx" "${compile_tool[@]}" \
  -dM -E -x c++ /dev/null \
  > "$work/compiler-macros.txt"
"$stage0_cxx" -dM -E -x c++ /dev/null \
  > "$work/stage0-compiler-macros.txt"
test "$("$stage0_cxx" -dumpmachine)" = aarch64-pc-cygwin
for macro_file in \
  "$work/compiler-macros.txt" \
  "$work/stage0-compiler-macros.txt"
do
  grep -Fx '#define _WIN64 1' "$macro_file"
  grep -Eq '^#define __CYGWIN__( 1)?$' "$macro_file"
  grep -Eq '^#define __SEH__( 1)?$' "$macro_file"
  grep -Fx '#define __LP64__ 1' "$macro_file"
  grep -Fx '#define __SIZEOF_LONG__ 8' "$macro_file"
  grep -Fx '#define __SIZEOF_POINTER__ 8' "$macro_file"
  grep -Fx '#define __SIZEOF_LONG_DOUBLE__ 8' "$macro_file"
done
grep -Eq '^#define __MSYS__( 1)?$' "$work/compiler-macros.txt"
if grep -Eq '^#define __MSYS__( 1)?$' "$work/stage0-compiler-macros.txt"; then
  echo "Cygwin stage-0 unexpectedly defines __MSYS__" >&2
  exit 1
fi
mark "compiler-macros-ok"

if ! "$cxx" "${compile_tool[@]}" "${cxx_headers[@]}" \
  -std=gnu++17 -dM -E "$fixtures/header-features.cc" \
  > "$work/header-macros.txt" 2> "$work/header-features.err"; then
  copy_failure_logs header-features
  echo "header-features preprocessor failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
for macro in \
  _GLIBCXX_HAS_GTHREADS \
  _GLIBCXX_USE_WCHAR_T \
  _GLIBCXX_ATOMIC_BUILTINS \
  _GLIBCXX_HAVE_ALIGNED_ALLOC \
  _GLIBCXX_HAVE_AT_QUICK_EXIT \
  _GLIBCXX_HAVE_MEMALIGN \
  _GLIBCXX_HAVE_POSIX_MEMALIGN \
  _GLIBCXX_HAVE_QUICK_EXIT \
  _GLIBCXX_HAVE_TIMESPEC_GET \
  __GTHREADS \
  __GTHREADS_CXX0X
do
  grep -Eq "^#define ${macro}( 1)?$" "$work/header-macros.txt"
done
grep -Fx '#define _GLIBCXX_GTHREAD_USE_WEAK 0' "$work/header-macros.txt"
grep -Fx '#define __LP64__ 1' "$work/header-macros.txt"
grep -Fx '#define __SIZEOF_LONG__ 8' "$work/header-macros.txt"
grep -Fx '#define __SIZEOF_POINTER__ 8' "$work/header-macros.txt"
grep -Fx '#define __SIZEOF_WCHAR_T__ 2' "$work/header-macros.txt"
grep -Fx '#define __SIZEOF_LONG_DOUBLE__ 8' "$work/header-macros.txt"
grep -Fx '#define __cpp_aligned_new 201606L' "$work/header-macros.txt"
grep -Fx '#define __cpp_sized_deallocation 201309L' "$work/header-macros.txt"
grep -Fx '#define _WIN64 1' "$work/header-macros.txt"
if grep -q '^#define _GLIBCXX_HAVE_TLS' "$work/header-macros.txt"; then
  echo "header stage unexpectedly claims TLS before target link libraries exist" >&2
  exit 1
fi
mark "header-macros-ok"

cmp "${target_include}/bits/gthr-default.h" \
  "${target_include}/bits/gthr-posix.h"
grep -F '__CYGWIN__' "${target_include}/bits/os_defines.h"
if grep -Eiq 'mingw|aarch64-w64-mingw32|x86_64' \
    "${target_include}/bits/c++config.h" \
    "${target_include}/bits/os_defines.h" \
    "${target_include}/bits/cpu_defines.h"; then
  echo "foreign target identity found in configured headers" >&2
  exit 1
fi
mark "header-identity-ok"

if ! "$cxx" "${compile_tool[@]}" "${cxx_headers[@]}" \
  -std=gnu++17 -E -Wp,-v "$fixtures/header-features.cc" \
  > /dev/null 2> "$work/include-search.txt"; then
  copy_failure_logs include-search
  echo "include-search preprocessor failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! validate_include_paths "$work/include-search.txt"; then
  copy_failure_logs include-search
  echo "include-search validation failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
mark "include-search-ok"

if ! "$cxx" "${compile_tool[@]}" "${cxx_headers[@]}" \
  -std=gnu++17 -O2 -fexceptions -funwind-tables \
  -c "$fixtures/header-features.cc" -o "$work/header-features.o" \
  2> "$work/header-features.err"; then
  copy_failure_logs header-features
  echo "header-features compile failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! "$cxx" "${compile_tool[@]}" "${cxx_headers[@]}" \
  -std=gnu++17 -O2 -fexceptions -funwind-tables \
  -c "$fixtures/exceptions.cc" -o "$work/exceptions.o" \
  2> "$work/exceptions.err"; then
  copy_failure_logs exceptions
  echo "exceptions compile failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! "$cxx" "${compile_tool[@]}" "${cxx_headers[@]}" \
  -std=gnu++17 -O2 \
  -c "$fixtures/atomic.cc" -o "$work/atomic.o" \
  2> "$work/atomic.err"; then
  copy_failure_logs atomic
  echo "atomic compile failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
mark "object-compiles-ok"

for object in header-features exceptions atomic; do
  object_path="$work/${object}.o"
  if ! test -f "$object_path"; then
    echo "${object} object missing" > "$report_dir/validation-failure.txt"
    exit 1
  fi
  if ! test "$(od -An -tx2 -N2 "$object_path" | tr -d '[:space:]')" = aa64; then
    echo "${object} object has unexpected magic" > "$report_dir/validation-failure.txt"
    exit 1
  fi
  if ! "$objdump" -f "$object_path" \
    > "$report_dir/${object}-file.txt" 2> "$work/${object}-objdump.err"; then
    copy_failure_logs "${object}-objdump"
    echo "${object} objdump failed" > "$report_dir/validation-failure.txt"
    exit 1
  fi
  if ! grep -F 'file format pe-aarch64-little' \
    "$report_dir/${object}-file.txt"; then
    echo "${object} object has unexpected file format" > "$report_dir/validation-failure.txt"
    exit 1
  fi
done

if ! "$objdump" -h "$work/exceptions.o" \
  > "$report_dir/exceptions-sections.txt" 2> "$work/exceptions-sections.err"; then
  copy_failure_logs exceptions-sections
  echo "exceptions section dump failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! "$nm" -u "$work/exceptions.o" \
  > "$report_dir/exceptions-undefined.txt" 2> "$work/exceptions-nm.err"; then
  copy_failure_logs exceptions-nm
  echo "exceptions undefined-symbol dump failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! grep -Eq '[[:space:]]\.pdata[[:space:]]' \
  "$report_dir/exceptions-sections.txt"; then
  echo "exceptions sections missing .pdata" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! grep -Eq '[[:space:]]\.xdata[[:space:]]' \
  "$report_dir/exceptions-sections.txt"; then
  echo "exceptions sections missing .xdata" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! grep -F '__cxa_throw' "$report_dir/exceptions-undefined.txt"; then
  echo "exceptions object missing __cxa_throw" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! grep -E '__gxx_personality|_Unwind_Resume' \
  "$report_dir/exceptions-undefined.txt"; then
  echo "exceptions object missing unwind support" > "$report_dir/validation-failure.txt"
  exit 1
fi

if ! "$nm" -u "$work/header-features.o" \
  > "$report_dir/header-features-undefined.txt" 2> "$work/header-features-nm.err"; then
  copy_failure_logs header-features-nm
  echo "header-features undefined-symbol dump failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! grep -F 'operator new' <("$nm" -u -C "$work/header-features.o"); then
  echo "header-features object missing operator new" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! grep -F 'operator delete' <("$nm" -u -C "$work/header-features.o"); then
  echo "header-features object missing operator delete" > "$report_dir/validation-failure.txt"
  exit 1
fi
if ! "$nm" -u "$work/atomic.o" \
  > "$report_dir/atomic-undefined.txt" 2> "$work/atomic-nm.err"; then
  copy_failure_logs atomic-nm
  echo "atomic undefined-symbol dump failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
if grep -E '__atomic_|__sync_' "$report_dir/atomic-undefined.txt"; then
  echo "lock-free atomic probe unexpectedly requires an atomic runtime" > "$report_dir/validation-failure.txt"
  exit 1
fi

if ! (cd "${runtime_source}/winsup" && ./autogen.sh \
  > "$work/runtime-autogen.log" 2> "$work/runtime-autogen.err"); then
  copy_failure_logs runtime-autogen
  echo "runtime autogen failed" > "$report_dir/validation-failure.txt"
  exit 1
fi
mark "runtime-autogen-ok"
mkdir -p "$runtime_build"
(
  cd "$runtime_build"
  PATH="/opt/bin:${PATH}" \
  CC="${cxx}" \
  CXX="${cxx}" \
  CPP="${cxx} -E -x c" \
  CXXCPP="${cxx} -E -x c++" \
  CPPFLAGS="-D_WIN64 -I${sysroot}/include -isystem ${generic_include} -isystem ${target_include} -isystem ${backward_include} -idirafter ${sysroot}/include/w32api" \
  CFLAGS='-D_WIN64' \
  CXXFLAGS="-D_WIN64 -I${sysroot}/include -nostdinc++ -isystem ${generic_include} -isystem ${target_include} -isystem ${backward_include} -Wno-error=register -Wno-error=sign-compare -Wno-error=c++20-compat -Wno-error=comment -Wno-error" \
  LDFLAGS="-L${sysroot}/usr/lib" \
  ac_cv_lib_sframe_sframe_decode=no \
  ac_cv_lib_zstd_ZSTD_isError=no \
    "${runtime_source}/winsup/configure" \
      --host="${target}" \
      --target="${target}" \
      --disable-doc \
      --disable-dumper \
      --with-cross-bootstrap \
      > "$report_dir/runtime-configure.log" 2>&1
)
mark "runtime-configure-ok"

runtime_cygwin="${runtime_build}/cygwin"
make -C "$runtime_cygwin" V=1 globals.h \
  > "$report_dir/runtime-generated-headers.log" 2>&1
make -C "$runtime_cygwin" V=1 \
  cxx.o create_posix_thread.o autoload.o \
  > "$report_dir/runtime-objects.log" 2>&1

for object in cxx create_posix_thread autoload; do
  object_path="${runtime_cygwin}/${object}.o"
  test -f "$object_path"
  test "$(od -An -tx2 -N2 "$object_path" | tr -d '[:space:]')" = aa64
  "$objdump" -f "$object_path" \
    > "$report_dir/runtime-${object}-file.txt"
  "$objdump" -h "$object_path" \
    > "$report_dir/runtime-${object}-sections.txt"
  "$nm" -a "$object_path" \
    > "$report_dir/runtime-${object}-symbols.txt"
  grep -F 'file format pe-aarch64-little' \
    "$report_dir/runtime-${object}-file.txt"
  grep -Eq '[[:space:]]\.pdata[[:space:]]' \
    "$report_dir/runtime-${object}-sections.txt"
  grep -Eq '[[:space:]]\.xdata[[:space:]]' \
    "$report_dir/runtime-${object}-sections.txt"
done
"$nm" -C "$runtime_cygwin/cxx.o" \
  > "$report_dir/runtime-cxx-demangled.txt"
grep -F 'operator new(unsigned long)' \
  "$report_dir/runtime-cxx-demangled.txt"
grep -F '__cxa_pure_virtual' \
  "$report_dir/runtime-cxx-symbols.txt"
grep -F "$generic_include" "$report_dir/runtime-objects.log"
validate_include_paths "$report_dir/runtime-objects.log"
mark "runtime-objects-ok"

pacman -Q \
  mingw-w64-cross-cygwinarm64-binutils \
  mingw-w64-cross-cygwinarm64-gcc-stage1 \
  mingw-w64-cross-msysarm64-headers \
  mingw-w64-cross-msysarm64-sysroot \
  mingw-w64-cross-msysarm64-w32api-runtime \
  mingw-w64-cross-msysarm64-windows-default-manifest \
  > "$report_dir/packages.txt"

input_packages=(
  mingw-w64-cross-cygwinarm64-binutils
  mingw-w64-cross-msysarm64-headers
  mingw-w64-cross-msysarm64-windows-default-manifest
  mingw-w64-cross-msysarm64-sysroot
  mingw-w64-cross-cygwinarm64-gcc-stage1
  mingw-w64-cross-msysarm64-w32api-runtime
)
: > "$report_dir/input-packages.txt"
for index in "${!input_packages[@]}"; do
  input_package=${input_packages[$index]}
  input_manifest="$work/${input_package}.sha256"
  while IFS= read -r input_file; do
    if [[ -f "$input_file" || -L "$input_file" ]]; then
      sha256sum "$input_file"
    fi
  done < <(pacman -Qlq "$input_package" | LC_ALL=C sort -u) \
    > "$input_manifest"
  input_hash=$(sha256sum "$input_manifest" | cut -d' ' -f1)
  input_count=$(wc -l < "$input_manifest")
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$((index + 1))" \
    "$input_package" \
    "$(pacman -Q "$input_package" | cut -d' ' -f2)" \
    "$input_count" \
    "$input_hash" \
    >> "$report_dir/input-packages.txt"
done

find "${prefix_root}/${target}/include/c++/${gcc_version}" \
  -type f -print \
  | sed "s#^${prefix_root}#/opt#" \
  | LC_ALL=C sort \
  > "$report_dir/owned-headers.txt"
header_count=$(wc -l < "$report_dir/owned-headers.txt")

pacman -Ql \
  mingw-w64-cross-cygwinarm64-binutils \
  mingw-w64-cross-cygwinarm64-gcc-stage1 \
  mingw-w64-cross-msysarm64-headers \
  mingw-w64-cross-msysarm64-sysroot \
  mingw-w64-cross-msysarm64-w32api-runtime \
  | sed -n 's/^[^ ]* //p' \
  | grep -v '/$' \
  | LC_ALL=C sort -u \
  > "$work/input-owned-files.txt"
python - "$report_dir/owned-headers.txt" "$work/input-owned-files.txt" "$report_dir/collisions.txt" <<'PY'
from pathlib import Path
import sys

owned = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines()
inputs = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").splitlines()
collisions = sorted(set(owned) & set(inputs))
Path(sys.argv[3]).write_text(
    "\n".join(collisions) + ("\n" if collisions else ""),
    encoding="utf-8",
)
PY
test ! -s "$report_dir/collisions.txt"
{
  printf 'owned-headers\t%s\n' "$header_count"
  printf 'input-package-collisions\t0\n'
  printf 'allowed-prefix\t/opt/%s/include/c++/%s\n' \
    "$target" "$gcc_version"
} > "$report_dir/ownership-report.txt"
mark "ownership-ok"

cp \
    "$work/compiler-macros.txt" \
    "$work/stage0-compiler-macros.txt" \
    "$work/header-macros.txt" \
    "$work/include-search.txt" \
    "$report_dir/"
for report_file in "$report_dir"/*; do
    [[ -f "$report_file" ]] || continue
    sed -i \
      -e "s#${prefix_root}#/opt#g" \
      -e "s#${runtime_source}#<runtime-source>#g" \
      -e "s#${runtime_build}#<runtime-build>#g" \
      -e "s#${fixtures}#<fixtures>#g" \
      -e "s#${report_dir}#<report>#g" \
      -e "s#${work}#<work>#g" \
      "$report_file"
done

python - "$report_dir" "$work" "$header_count" <<'PY'
import json
import pathlib
import re
import sys

report_dir = pathlib.Path(sys.argv[1])
work = pathlib.Path(sys.argv[2])
header_count = int(sys.argv[3])

macros_text = (work / "header-macros.txt").read_text()

def macro(name):
    match = re.search(
        rf"^#define {re.escape(name)}(?:\s+(.*))?$",
        macros_text,
        re.MULTILINE,
    )
    return None if match is None else (match.group(1) or "")

report = {
    "schema_version": 1,
    "package": "mingw-w64-cross-msysarm64-libstdc++-headers",
    "target": "aarch64-pc-msys",
    "gcc_source_commit": "e1a057af466f066d86b20270fb7864764951420d",
    "runtime_validation_commit": "c7932d64f13d51deacdcbfdab8df79bcb35ebd92",
    "header_count": header_count,
    "installed_target_libraries": 0,
    "configuration": {
        "abi": "lp64",
        "os": "msys/newlib",
        "cpu": "aarch64",
        "thread_model": "posix",
        "stage0_reported_thread_model": "posix",
        "stage0_predefines_win64": True,
        "stage0_predefines_msys": False,
        "validation_compiler_predefines_win64": True,
        "validation_compiler_predefines_msys": True,
        "controlled_win64_define": True,
        "libstdcxx_tls": False,
        "libstdcxx_tls_reason": "target link probe cannot succeed before target libgcc and newlib libraries exist",
        "link_tests_run": False,
    },
    "macros": {
        name: macro(name)
        for name in (
            "_GLIBCXX_HAS_GTHREADS",
            "_GLIBCXX_USE_WCHAR_T",
            "_GLIBCXX_HAVE_TLS",
            "_GLIBCXX_ATOMIC_BUILTINS",
            "_GLIBCXX_HAVE_ALIGNED_ALLOC",
            "_GLIBCXX_HAVE_AT_QUICK_EXIT",
            "_GLIBCXX_HAVE_MEMALIGN",
            "_GLIBCXX_HAVE_POSIX_MEMALIGN",
            "_GLIBCXX_HAVE_QUICK_EXIT",
            "_GLIBCXX_HAVE_TIMESPEC_GET",
            "_GLIBCXX_GTHREAD_USE_WEAK",
            "__GTHREADS",
            "__GTHREADS_CXX0X",
            "__LP64__",
            "__SIZEOF_LONG__",
            "__SIZEOF_POINTER__",
            "__SIZEOF_WCHAR_T__",
            "__SIZEOF_LONG_DOUBLE__",
            "__cpp_aligned_new",
            "__cpp_sized_deallocation",
            "_WIN64",
        )
    },
    "object_validation": {
        "format": "pe-aarch64-little",
        "coff_machine": "0xAA64",
        "header_features": True,
        "atomic_lock_free_without_libatomic": True,
        "exceptions": True,
        "seh_sections": [".pdata", ".xdata"],
        "runtime_objects": ["cxx.o", "create_posix_thread.o", "autoload.o"],
    },
    "leakage": {
        "host_cxx_headers": False,
        "mingw_headers": False,
        "x86_64_headers": False,
        "target_libraries_installed": False,
    },
    "ownership": {
        "allowed_prefix": "/opt/aarch64-pc-msys/include/c++/15.0.1",
        "input_package_collisions": 0,
    },
    "packages": (report_dir / "packages.txt").read_text().splitlines(),
    "boundary": {
        "target_libgcc": "absent",
        "target_newlib_libraries": "absent",
        "target_libstdcxx_libraries": "absent",
        "runtime_dll_and_import_library": "absent",
    },
}

(report_dir / "validation-report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
PY

python -m json.tool "$report_dir/validation-report.json" > /dev/null
echo "libstdc++ header validation passed: ${report_dir}/validation-report.json"
mark "report-generated"

#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "usage: $0 PREFIX_ROOT REPORT_DIR" >&2
  exit 2
fi

prefix_root=$(cd "$1" && pwd)
report_dir=$2
mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
workdir="$report_dir/work"
rm -rf "$workdir"
mkdir -p "$workdir"
export PATH="${prefix_root}/bin:${PATH}"

target=${TARGET:-aarch64-pc-msys}
cc=${CC:-aarch64-pc-msys-gcc}
cxx=${CXX:-aarch64-pc-msys-g++}
binutils_prefix=${BINUTILS_PREFIX:-aarch64-pc-cygwin}
ar=${AR:-${binutils_prefix}-ar}
nm=${NM:-${binutils_prefix}-nm}
objdump=${OBJDUMP:-${binutils_prefix}-objdump}
windres=${WINDRES:-${binutils_prefix}-windres}
gcc_version=$("$cxx" -dumpversion)
sysroot=/opt/${target}
generic_include="${sysroot}/include/c++/${gcc_version}"
target_include="${generic_include}/${target}"
backward_include="${generic_include}/backward"
sysroot_include="${sysroot}/include"
sysroot_w32api="${sysroot}/include/w32api"
specs="${sysroot}/lib/cygwin-compile-only.specs"

for tool in "$cc" "$cxx" "$ar" "$nm" "$objdump" "$windres"; do
  command -v "$tool" >/dev/null
done

compile_tool=(
  "-B${prefix_root}/bin/"
  "-B${prefix_root}/libexec/gcc/${target}/${gcc_version}/"
  "-B${prefix_root}/lib/gcc/${target}/${gcc_version}/"
  "--sysroot=${sysroot}"
  "-specs=${specs}"
)

link_tool=(
  "-B${prefix_root}/bin/"
  "-B${prefix_root}/libexec/gcc/${target}/${gcc_version}/"
  "-B${prefix_root}/lib/gcc/${target}/${gcc_version}/"
  "--sysroot=${sysroot}"
)

audit_file() {
  local file=$1
  case "$file" in
    *.a)
      local archive_dir="${workdir}/$(basename "$file" .a)"
      mkdir -p "$archive_dir"
      "$ar" t "$file" > "${archive_dir}/members.txt"
      test -s "${archive_dir}/members.txt"
      if sort "${archive_dir}/members.txt" | uniq -d | grep -q .; then
        echo "duplicate archive member names in $file" >&2
        exit 1
      fi
      (
        cd "$archive_dir"
        "$ar" x "$file"
      )
      while IFS= read -r member; do
        member_path="${archive_dir}/${member}"
        test "$(od -An -tx2 -N2 "$member_path" | tr -d '[:space:]')" = aa64
        "$objdump" -f "$member_path" | grep -F 'file format pe-aarch64-little' >/dev/null
      done < "${archive_dir}/members.txt"
      ;;
    *.dll|*.exe|*.o)
      "$objdump" -f "$file" | grep -Eq 'file format pei?-aarch64-little'
      if [[ "$file" == *.o ]]; then
        test "$(od -An -tx2 -N2 "$file" | tr -d '[:space:]')" = aa64
      fi
      ;;
  esac
}

"$cxx" "${compile_tool[@]}" -dM -E -x c++ /dev/null > "$workdir/compiler-macros.txt"
test "$("$cxx" -dumpmachine)" = "$target"
grep -Fx 'Thread model: posix' <("$cxx" -v 2>&1)
grep -Eq '^#define __MSYS__( 1)?$' "$workdir/compiler-macros.txt"
grep -Eq '^#define __CYGWIN__( 1)?$' "$workdir/compiler-macros.txt"
grep -Eq '^#define __SEH__( 1)?$' "$workdir/compiler-macros.txt"
grep -Fx '#define _WIN64 1' "$workdir/compiler-macros.txt"
grep -Fx '#define __LP64__ 1' "$workdir/compiler-macros.txt"
grep -Fx '#define __SIZEOF_LONG__ 8' "$workdir/compiler-macros.txt"
grep -Fx '#define __SIZEOF_POINTER__ 8' "$workdir/compiler-macros.txt"
grep -Fx '#define __SIZEOF_LONG_DOUBLE__ 8' "$workdir/compiler-macros.txt"

"$cxx" "${compile_tool[@]}" -E -Wp,-v -x c++ /dev/null > /dev/null 2> "$workdir/include-search.txt"

python - "$workdir/include-search.txt" "$generic_include" "$target_include" "$backward_include" "$sysroot_include" "$sysroot_w32api" <<'PY'
import pathlib
import re
import shlex
import sys

paths = []
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
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

allowed = tuple(
    value.replace("\\", "/").lower().rstrip("/")
    for value in sys.argv[2:]
)
for path in paths:
    normalized = path.replace("\\", "/").lower()
    if not normalized.startswith(allowed):
        raise SystemExit(f"foreign include path: {path}")
    if (
        "aarch64-w64-mingw32" in normalized
        or "x86_64" in normalized
        or re.search(r"(^|/)usr/include/c\+\+(/|$)", normalized)
        or re.search(r"(^|/)(mingw32|mingw64|ucrt64|clang32|clang64|clangarm64)/", normalized)
    ):
        raise SystemExit(f"foreign include path: {path}")
PY

if grep -q -- '-D_WIN64' "$workdir/include-search.txt"; then
  echo "compiler unexpectedly injects a recipe-level _WIN64 define" >&2
  exit 1
fi

cat > "$workdir/hello.c" <<'EOF'
#include <windows.h>
int main(void) {
  HANDLE h = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (h == NULL)
    return 1;
  CloseHandle(h);
  return 0;
}
EOF
cat > "$workdir/hello.cc" <<'EOF'
#include <string>
int main() {
  std::string s = "msys";
  return s.size() == 4 ? 0 : 1;
}
EOF

"$cc" "${link_tool[@]}" -O2 "$workdir/hello.c" -o "$workdir/hello-c.exe"
"$cxx" "${link_tool[@]}" -O2 -std=gnu++17 "$workdir/hello.cc" -o "$workdir/hello-cxx.exe"

for file in "$workdir/hello-c.exe" "$workdir/hello-cxx.exe"; do
  "$objdump" -f "$file" | grep -F 'file format pei-aarch64-little'
  "$objdump" -p "$file" | sed -n 's/^[[:space:]]*DLL Name: //p' > "${file}.imports"
  grep -F 'msys-2.0.dll' "${file}.imports"
  grep -F 'KERNEL32.dll' "${file}.imports"
  ! grep -Ei '^cygwin1\.dll$' "${file}.imports"
done

! grep -Ei 'cygwin1\.dll|libcygwin\.a|x86_64' "$workdir/include-search.txt"

find "$prefix_root" -type f \( -name '*.a' -o -name '*.dll' -o -name '*.dll.a' -o -name '*.exe' -o -name '*.o' \) \
  | LC_ALL=C sort > "$report_dir/file-list.txt"
while IFS= read -r file; do
  audit_file "$file"
done < "$report_dir/file-list.txt"

(
  cd "$prefix_root"
  find opt -type f -print0 | sort -z | xargs -0 sha256sum
) > "$report_dir/package-manifest.sha256"

{
  printf 'package\tmingw-w64-cross-msysarm64-gcc\n'
  printf 'target\t%s\n' "$target"
  printf 'dumpmachine\t%s\n' "$("$cxx" -dumpmachine)"
  printf 'thread-model\tposix\n'
  printf 'msys-macro\t%s\n' "$(grep -Eq '^#define __MSYS__( 1)?$' "$workdir/compiler-macros.txt" && echo yes)"
  printf 'win64-macro\t%s\n' "$(grep -Fx '#define _WIN64 1' "$workdir/compiler-macros.txt" && echo yes)"
  printf 'lp64-macro\t%s\n' "$(grep -Fx '#define __LP64__ 1' "$workdir/compiler-macros.txt" && echo yes)"
  printf 'package-manifest\t%s\n' "$report_dir/package-manifest.sha256"
} > "$report_dir/summary.txt"

cat > "$report_dir/source-identity.txt" <<EOF
package-version	${pkgver:-15.0.1dev}-1
gcc-repository	https://github.com/crutkas/gcc-woarm64
gcc-commit	bd1d77ba35e2820df5387cca5213925adb07a0ee
gcc-archive-sha256	3ab5b2a037d027ab4e69b5597f2a82e77e87bca79ee764381a717b2e8328d060
runtime-version	3.6.10.r0.g6922c388b-1
sysroot-version	3.6.10.r0.g6922c388b-1
w32api-version	14.0.0.r0.g9b3dd0125-1
target	aarch64-pc-msys
abi	lp64
thread-model	posix
link-default	msys-2.0.dll
EOF

python - "$report_dir/source-identity.txt" "$report_dir/validation-report.json" <<'PY'
import json
import pathlib
import sys

data = {}
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    key, value = line.split("\t", 1)
    data[key] = value
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(data, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

printf 'validated\t%s\n' "$("$cxx" -dumpmachine)" > "$report_dir/validated.txt"

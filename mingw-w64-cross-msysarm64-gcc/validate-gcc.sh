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
ld=${LD:-${binutils_prefix}-ld}
windres=${WINDRES:-${binutils_prefix}-windres}
gcc_version=$("$cxx" -dumpversion)
sysroot=/opt/${target}
generic_include="${sysroot}/include/c++/${gcc_version}"
target_include="${generic_include}/${target}"
backward_include="${generic_include}/backward"
sysroot_include="${sysroot}/include"
sysroot_w32api="${sysroot}/include/w32api"
specs="${sysroot}/lib/cygwin-compile-only.specs"
libgcc_dir="${prefix_root}/lib/gcc/${target}/${gcc_version}"

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

cat > "$workdir/ctor-order.c" <<'EOF'
volatile int ctor_order_state;

void
user_ctor(void)
{
  ctor_order_state |= 1;
}

void
user_dtor(void)
{
  ctor_order_state |= 2;
}

static void user_ctor_entry(void) __attribute__((constructor));
static void user_dtor_entry(void) __attribute__((destructor));

static void
user_ctor_entry(void)
{
  user_ctor();
}

static void
user_dtor_entry(void)
{
  user_dtor();
}
EOF
cat > "$workdir/cxa-order.cc" <<'EOF'
struct lifetime_probe
{
  lifetime_probe();
  ~lifetime_probe();
};

volatile int lifetime_state;

lifetime_probe::lifetime_probe()
{
  ++lifetime_state;
}

lifetime_probe::~lifetime_probe()
{
  --lifetime_state;
}

lifetime_probe global_lifetime_probe;
EOF
cat > "$workdir/unwind.c" <<'EOF'
extern void consume_frame(const void *);

__attribute__((noinline)) int
seh_frame(int value)
{
  volatile unsigned char frame[96];

  frame[0] = (unsigned char) value;
  frame[95] = (unsigned char) (value >> 1);
  consume_frame((const void *) frame);
  return frame[0] + frame[95];
}
EOF

"$cc" "${compile_tool[@]}" -O2 -fexceptions -funwind-tables \
  -c "$workdir/unwind.c" -o "$workdir/unwind.o"
"$objdump" -h "$workdir/unwind.o" > "$workdir/unwind-sections.txt"
grep -Eq '[[:space:]]\.pdata[[:space:]]' "$workdir/unwind-sections.txt"
grep -Eq '[[:space:]]\.xdata[[:space:]]' "$workdir/unwind-sections.txt"

"$cc" "${compile_tool[@]}" -O2 -c "$workdir/ctor-order.c" -o "$workdir/ctor-order.o"
"$cxx" "${compile_tool[@]}" -O2 -c "$workdir/cxa-order.cc" -o "$workdir/cxa-order.o"
"$objdump" -h "$workdir/ctor-order.o" > "$workdir/ctor-order-sections.txt"
"$objdump" -r "${libgcc_dir}/crtbegin.o" > "$workdir/crtbegin.relocations.txt"
"$nm" -u "$workdir/cxa-order.o" > "$workdir/cxa-order.undefined.txt"
"$nm" -a "${libgcc_dir}/crtend.o" > "$workdir/crtend.symbols.txt"
grep -Eq '[[:space:]]\.ctors[[:space:]]' "$workdir/ctor-order-sections.txt"
grep -Eq '[[:space:]]\.dtors[[:space:]]' "$workdir/ctor-order-sections.txt"
grep -F '__cxa_atexit' "$workdir/cxa-order.undefined.txt"
grep -F '__cxa_atexit' "$workdir/crtbegin.relocations.txt"
grep -F 'register_frame_ctor' "$workdir/crtend.symbols.txt"

"$ld" -r \
  -Map="$workdir/ctor-order.map" \
  -o "$workdir/ctor-order-linked.o" \
  "${libgcc_dir}/crtbegin.o" \
  "$workdir/ctor-order.o" \
  "$workdir/cxa-order.o" \
  "${libgcc_dir}/crtend.o"
python - "$workdir/ctor-order.map" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
begin = text.find("crtbegin.o")
user = text.find("ctor-order.o")
end = text.find("crtend.o")
if min(begin, user, end) < 0 or not begin < user < end:
    raise SystemExit("crtbegin/user/crtend load order is not preserved")

ctors = re.search(r"\.ctors(?P<body>.*?)(?:\n\.[A-Za-z]|\Z)", text, re.S)
if not ctors:
    raise SystemExit("linked map has no .ctors output section")
body = ctors.group("body")
if body.find("ctor-order.o") < 0 or body.find("crtend.o") < 0:
    raise SystemExit("linked map lacks user or crtend .ctors contribution")
if body.find("ctor-order.o") > body.find("crtend.o"):
    raise SystemExit("crtend .ctors contribution does not follow user constructors")
PY

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

"$cc" "${link_tool[@]}" -dumpspecs > "$workdir/gcc.specs"
grep -F -- '-lmsys-2.0' "$workdir/gcc.specs"
! grep -F -- '-lcygwin' "$workdir/gcc.specs"

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
gcc-commit	e1a057af466f066d86b20270fb7864764951420d
gcc-archive-sha256	8194893d7093f3cadedc2ec42375ffbbc02a22e30d943e5f1c1aefa273af8122
gcc-source-chain	9b0c288d8f337d685017621b2e9d84579f8aa391,3053d5071151031574f9ea272031d1dcba053f62,626c500b14b8eac6754b80b3a175acc305426c06,e1a057af466f066d86b20270fb7864764951420d
runtime-version	3.6.10.r0.gc7932d64f-1
sysroot-version	3.6.10.r0.gc7932d64f-1
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

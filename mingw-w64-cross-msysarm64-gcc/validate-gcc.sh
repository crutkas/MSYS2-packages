#!/usr/bin/env bash

set -euo pipefail

if (( $# != 2 )); then
  echo "usage: $0 PREFIX_ROOT REPORT_DIR" >&2
  exit 2
fi

prefix_root=$(cd "$1" && pwd)
package_root=$(dirname "$prefix_root")
if [[ $(basename "$prefix_root") != opt ]]; then
  echo "PREFIX_ROOT must name the package's opt prefix: $prefix_root" >&2
  exit 1
fi
report_dir=$2
mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
workdir="$report_dir/work"
rm -rf "$workdir"
mkdir -p "$workdir"
export PATH="${prefix_root}/bin:${PATH}"

target=${TARGET:-aarch64-pc-msys}
cc=${TARGET_CC:-"${prefix_root}/bin/${target}-gcc.exe"}
cxx=${TARGET_CXX:-"${prefix_root}/bin/${target}-g++.exe"}
binutils_prefix=${BINUTILS_PREFIX:-aarch64-pc-cygwin}
ar=${AR:-${binutils_prefix}-ar}
nm=${NM:-${binutils_prefix}-nm}
objdump=${OBJDUMP:-${binutils_prefix}-objdump}
ld=${LD:-${binutils_prefix}-ld}
windres=${WINDRES:-${binutils_prefix}-windres}
host_ar=/usr/bin/ar
host_objdump=/usr/bin/objdump
sysroot="/opt/${target}"

record_driver_path() {
  local role=$1
  local tool=$2
  local expected=$3
  local resolved
  local hash

  if [[ "$tool" != /* ]]; then
    echo "$role compiler path must be absolute: $tool" >&2
    return 1
  fi
  resolved=$(realpath -m "$tool")
  if [[ ! -f "$resolved" || ! -x "$resolved" ]]; then
    echo "$role compiler is missing or not executable: $resolved" >&2
    return 1
  fi
  hash=$(sha256sum --binary "$resolved" | cut -d' ' -f1)
  printf '%s\t%s\t%s\t%s\n' "$role" "$tool" "$resolved" "$hash" \
    >> "$report_dir/compiler-tools.tsv"
  printf '%s\n' "$resolved"
}

query_driver() {
  local role=$1
  local tool=$2
  local option=$3
  local result_name=$4
  local stderr_file="$report_dir/${role}-${option#-}.stderr.txt"
  local output
  local rc
  local bytes

  set +e
  output=$("$tool" "$option" 2> "$stderr_file")
  rc=$?
  set -e
  bytes=$(printf '%s' "$output" | od -An -tx1 | tr -d '[:space:]')
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$role" "$tool" "$option" "$rc" "$output" "$bytes" \
    >> "$report_dir/compiler-queries.tsv"
  if (( rc != 0 )); then
    echo "$role compiler query failed: tool=$tool option=$option rc=$rc stderr=$stderr_file" >&2
    return 1
  fi
  printf -v "$result_name" '%s' "$output"
}

: > "$report_dir/compiler-tools.tsv"
: > "$report_dir/compiler-queries.tsv"
expected_cc=$(realpath -m "${prefix_root}/bin/${target}-gcc.exe")
expected_cxx=$(realpath -m "${prefix_root}/bin/${target}-g++.exe")
cc_resolved=$(record_driver_path CC "$cc" "$expected_cc")
cxx_resolved=$(record_driver_path CXX "$cxx" "$expected_cxx")
query_driver CC "$cc_resolved" -dumpmachine cc_machine
query_driver CC "$cc_resolved" -dumpversion cc_version
query_driver CXX "$cxx_resolved" -dumpmachine cxx_machine
query_driver CXX "$cxx_resolved" -dumpversion cxx_version
if [[ "$cc_machine" != "$target" ]]; then
  echo "CC dumpmachine mismatch: tool=$cc_resolved expected=$target actual=$cc_machine" >&2
  exit 1
fi
if [[ "$cxx_machine" != "$target" ]]; then
  echo "CXX dumpmachine mismatch: tool=$cxx_resolved expected=$target actual=$cxx_machine" >&2
  exit 1
fi
if [[ -z "$cc_version" || -z "$cxx_version" || "$cc_version" != "$cxx_version" ]]; then
  echo "compiler version mismatch: CC=$cc_version CXX=$cxx_version" >&2
  exit 1
fi
if [[ "$cc_resolved" != "$expected_cc" ]]; then
  echo "CC compiler path mismatch: expected=$expected_cc actual=$cc_resolved" >&2
  exit 1
fi
if [[ "$cxx_resolved" != "$expected_cxx" ]]; then
  echo "CXX compiler path mismatch: expected=$expected_cxx actual=$cxx_resolved" >&2
  exit 1
fi
gcc_version=$cxx_version
set +e
"$cxx_resolved" -v \
  > "$report_dir/CXX-version.stdout.txt" \
  2> "$report_dir/CXX-version.stderr.txt"
cxx_version_rc=$?
set -e
if (( cxx_version_rc != 0 )); then
  echo "CXX version probe failed: tool=$cxx_resolved rc=$cxx_version_rc" >&2
  exit 1
fi
thread_model=$(sed -n 's/^Thread model: //p' "$report_dir/CXX-version.stderr.txt")
if [[ "$thread_model" != posix ]]; then
  echo "CXX thread model mismatch: tool=$cxx_resolved expected=posix actual=${thread_model:-<missing>}" >&2
  exit 1
fi
printf 'target\t%s\nversion\t%s\nthread-model\t%s\n' \
  "$target" "$gcc_version" "$thread_model" \
  > "$report_dir/compiler-identity.tsv"

generic_include="${sysroot}/include/c++/${gcc_version}"
target_include="${generic_include}/${target}"
backward_include="${generic_include}/backward"
sysroot_include="${sysroot}/include"
sysroot_w32api="${sysroot}/include/w32api"
specs="${sysroot}/lib/cygwin-compile-only.specs"
target_gcc_root="${prefix_root}/lib/gcc/${target}"
libgcc_dir="${prefix_root}/lib/gcc/${target}/${gcc_version}"
compiler_include="${libgcc_dir}/include"
compiler_fixed_include="${libgcc_dir}/include-fixed"

for tool in "$ar" "$nm" "$objdump" "$windres" \
  "$host_ar" "$host_objdump"; do
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

payload_arch() {
  local file=$1
  case "$file" in
    "${target_gcc_root}/"*liblto_plugin*.a)
      printf 'host\n'
      ;;
    "${prefix_root}/${target}/bin/ar.exe"|\
    "${prefix_root}/${target}/bin/nm.exe"|\
    "${prefix_root}/${target}/bin/ranlib.exe")
      printf 'host\n'
      ;;
    "${prefix_root}/bin/"*.exe|\
    "${prefix_root}/libexec/"*|\
    "${prefix_root}/lib/bfd-plugins/"*)
      printf 'host\n'
      ;;
    "${prefix_root}/bin/msys-"*.dll|\
    "${prefix_root}/bin/"*.dll.a|\
    "${target_gcc_root}/"*)
      printf 'target\n'
      ;;
    *)
      echo "unclassified PE/COFF payload: $file" >&2
      return 1
      ;;
  esac
}

reject_match() {
  local pattern=$1
  local file=$2
  local description=$3
  local rc

  if grep -Ei -- "$pattern" "$file"; then
    echo "$description" >&2
    return 1
  else
    rc=$?
    if (( rc != 1 )); then
      echo "failed to inspect $file: grep exited $rc" >&2
      return "$rc"
    fi
  fi
}

audit_file() {
  local file=$1
  local arch
  local archive_dir
  local archive_tool
  local actual_format
  local actual_machine
  local duplicates
  local image_format
  local inspect_tool
  local machine
  local member
  local member_path
  local members_file
  local object_format
  local signature

  arch=$(payload_arch "$file")
  if [[ "$arch" == target ]]; then
    machine=aa64
    object_format=pe-aarch64-little
    image_format=pei-aarch64-little
    archive_tool=$ar
    inspect_tool=$objdump
  else
    machine=8664
    object_format=pe-x86-64
    image_format=pei-x86-64
    archive_tool=$host_ar
    inspect_tool=$host_objdump
  fi

  case "$file" in
    *.a)
      archive_dir=$(mktemp -d "${workdir}/archive.XXXXXX")
      members_file="${archive_dir}/members.txt"
      if ! "$archive_tool" t "$file" > "$members_file"; then
        echo "malformed archive: $file" >&2
        rm -rf "$archive_dir"
        return 1
      fi
      if [[ ! -s "$members_file" ]]; then
        echo "empty archive: $file" >&2
        rm -rf "$archive_dir"
        return 1
      fi
      duplicates=$(awk 'seen[$0]++ { print }' "$members_file")
      if [[ -n "$duplicates" ]]; then
        echo "duplicate archive member names in $file" >&2
        rm -rf "$archive_dir"
        return 1
      fi
      if ! (
        cd "$archive_dir"
        "$archive_tool" x "$file"
      ); then
        echo "failed to extract archive: $file" >&2
        rm -rf "$archive_dir"
        return 1
      fi
      while IFS= read -r member; do
        member_path="${archive_dir}/${member}"
        if [[ ! -f "$member_path" ]]; then
          echo "missing extracted archive member: $file($member)" >&2
          rm -rf "$archive_dir"
          return 1
        fi
        signature=$(od -An -tx1 -N4 "$member_path" | tr -d '[:space:]')
        if [[ "$signature" == 0000ffff ]]; then
          actual_machine=$(
            od -An -tx2 -j6 -N2 "$member_path" | tr -d '[:space:]'
          )
          actual_format="short-import:${signature}"
        else
          actual_machine=$(od -An -tx2 -N2 "$member_path" | tr -d '[:space:]')
          actual_format=$(
            "$inspect_tool" -f "$member_path" \
              | sed -n 's/^.*file format //p'
          )
        fi
        if [[ "$actual_machine" != "$machine" ]]; then
          echo "wrong COFF machine in $file($member): ${actual_machine:-unknown}" >&2
          rm -rf "$archive_dir"
          return 1
        fi
        if [[ "$signature" != 0000ffff && \
            "$actual_format" != "$object_format" ]]; then
          echo "wrong object format in $file($member): ${actual_format:-unknown}" >&2
          rm -rf "$archive_dir"
          return 1
        fi
        printf '%s(%s)\t%s\t%s\t%s\t%s\n' \
          "${file#"$package_root"/}" "$member" "$arch" "$object_format" \
          "$actual_format" "$actual_machine" \
          >> "$report_dir/payload-audit.tsv"
      done < "$members_file"
      rm -rf "$archive_dir"
      ;;
    *.dll|*.exe)
      actual_format=$(
        "$inspect_tool" -f "$file" \
          | sed -n 's/^.*file format //p'
      )
      if [[ "$actual_format" != "$image_format" ]]; then
        echo "wrong image format for $file: ${actual_format:-unknown}" >&2
        return 1
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "${file#"$package_root"/}" "$arch" "$image_format" "$actual_format" \
        "$machine" \
        >> "$report_dir/payload-audit.tsv"
      ;;
    *.o)
      actual_machine=$(od -An -tx2 -N2 "$file" | tr -d '[:space:]')
      actual_format=$(
        "$inspect_tool" -f "$file" \
          | sed -n 's/^.*file format //p'
      )
      if [[ "$actual_machine" != "$machine" || \
          "$actual_format" != "$object_format" ]]; then
        echo "wrong COFF object for $file: machine=${actual_machine:-unknown} format=${actual_format:-unknown}" >&2
        return 1
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "${file#"$package_root"/}" "$arch" "$object_format" "$actual_format" \
        "$actual_machine" \
        >> "$report_dir/payload-audit.tsv"
      ;;
    *)
      echo "unsupported payload type: $file" >&2
      return 1
      ;;
  esac
}

write_package_manifest() {
  (
    cd "$package_root"
    find opt -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum --binary \
      | sed -E 's/^([0-9a-f]{64}) \*/\1  /'
  )
}

validate_binutils_bridges() {
  local actual_target
  local bridge
  local expected_target
  local owned_target
  local owner
  local tool

  for tool in ar nm ranlib; do
    bridge="${prefix_root}/${target}/bin/${tool}.exe"
    expected_target="../../${binutils_prefix}/bin/${tool}.exe"
    if [[ ! -L "$bridge" ]]; then
      echo "Missing internal binutils bridge: $bridge" >&2
      return 1
    fi
    actual_target=$(readlink "$bridge")
    if [[ "$actual_target" != "$expected_target" ]]; then
      echo "Unexpected internal binutils bridge target: $bridge -> $actual_target" >&2
      return 1
    fi
    owned_target="/opt/${binutils_prefix}/bin/${tool}.exe"
    if [[ ! -x "$owned_target" ]]; then
      echo "Missing binutils-owned bridge target: $owned_target" >&2
      return 1
    fi
    owner=$(pacman -Qoq "$owned_target")
    if [[ "$owner" != mingw-w64-cross-cygwinarm64-binutils ]]; then
      echo "Unexpected bridge target owner: $owned_target -> $owner" >&2
      return 1
    fi
    if [[ -e "${prefix_root}/bin/${target}-${tool}.exe" || \
        -L "${prefix_root}/bin/${target}-${tool}.exe" ]]; then
      echo "Forbidden public target-binutils alias in GCC payload: ${target}-${tool}.exe" >&2
      return 1
    fi
    printf '%s\thost-tool-bridge\trelative-symlink\t%s\t%s\n' \
      "${bridge#"$package_root"/}" "$actual_target" "$owner" \
      >> "$report_dir/payload-audit.tsv"
  done
}

validate_required_payloads() {
  local required_host
  local required_plugin
  local required_target_name
  local -a plugin_roots
  local -a required_plugins
  local -a required_targets

  validate_binutils_bridges

  for required_host in \
    "${prefix_root}/bin/${target}-gcc.exe" \
    "${prefix_root}/bin/${target}-g++.exe" \
    "${prefix_root}/libexec/gcc/${target}/${gcc_version}/cc1.exe" \
    "${prefix_root}/libexec/gcc/${target}/${gcc_version}/cc1plus.exe" \
    "${prefix_root}/libexec/gcc/${target}/${gcc_version}/lto1.exe" \
    "${prefix_root}/libexec/gcc/${target}/${gcc_version}/lto-wrapper.exe" \
    "${prefix_root}/libexec/gcc/${target}/${gcc_version}/collect2.exe"
  do
    if [[ ! -e "$required_host" ]]; then
      echo "Missing required host tool: $required_host" >&2
      return 1
    fi
    if [[ $(payload_arch "$required_host") != host ]]; then
      echo "Required host tool is in the wrong payload role: $required_host" >&2
      return 1
    fi
    audit_file "$required_host"
  done

  plugin_roots=("${prefix_root}/libexec")
  if [[ -d "${prefix_root}/lib/bfd-plugins" ]]; then
    plugin_roots+=("${prefix_root}/lib/bfd-plugins")
  fi
  mapfile -t required_plugins < <(
    find -L "${plugin_roots[@]}" -type f -name '*lto_plugin*.dll' \
      | LC_ALL=C sort -u
  )
  if (( ${#required_plugins[@]} < 1 )); then
    echo "Missing required host LTO plugin" >&2
    return 1
  fi
  for required_plugin in "${required_plugins[@]}"; do
    if [[ $(payload_arch "$required_plugin") != host ]]; then
      echo "Required host LTO plugin is in the wrong payload role: $required_plugin" >&2
      return 1
    fi
    audit_file "$required_plugin"
  done

  for required_target_name in \
    libgcc.a \
    crtbegin.o \
    msys-gcc_s-seh-1.dll \
    libstdc++.a \
    msys-stdc++-6.dll
  do
    mapfile -t required_targets < <(
      find -L "$target_gcc_root" -type f -name "$required_target_name"
    )
    if (( ${#required_targets[@]} != 1 )); then
      echo "Expected one $required_target_name target artifact; found ${#required_targets[@]}" >&2
      return 1
    fi
    if [[ $(payload_arch "${required_targets[0]}") != target ]]; then
      echo "Required target artifact is in the wrong payload role: ${required_targets[0]}" >&2
      return 1
    fi
    audit_file "${required_targets[0]}"
  done
}

if [[ ${VALIDATE_GCC_FUNCTIONS_ONLY:-0} == 1 ]]; then
  return 0 2>/dev/null || exit 0
fi

"$cxx" "${compile_tool[@]}" -dM -E -x c++ /dev/null > "$workdir/compiler-macros.txt"
grep -Fx 'Thread model: posix' "$report_dir/CXX-version.stderr.txt"
grep -Eq '^#define __MSYS__( 1)?$' "$workdir/compiler-macros.txt"
grep -Eq '^#define __CYGWIN__( 1)?$' "$workdir/compiler-macros.txt"
grep -Eq '^#define __SEH__( 1)?$' "$workdir/compiler-macros.txt"
grep -Fx '#define _WIN64 1' "$workdir/compiler-macros.txt"
grep -Fx '#define __LP64__ 1' "$workdir/compiler-macros.txt"
grep -Fx '#define __SIZEOF_LONG__ 8' "$workdir/compiler-macros.txt"
grep -Fx '#define __SIZEOF_POINTER__ 8' "$workdir/compiler-macros.txt"
grep -Fx '#define __SIZEOF_LONG_DOUBLE__ 8' "$workdir/compiler-macros.txt"
cp "$workdir/compiler-macros.txt" "$report_dir/compiler-macros.txt"

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

python - "$workdir/include-search.txt" \
  "$compiler_include" "$compiler_fixed_include" \
  "$generic_include" "$target_include" "$backward_include" \
  "$sysroot_include" "$sysroot_w32api" <<'PY'
import pathlib
import posixpath
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

def normalize(value):
    return posixpath.normpath(value.replace("\\", "/").lower()).rstrip("/")

allowed = tuple(normalize(value) for value in sys.argv[2:])
for path in paths:
    normalized = normalize(path)
    if not any(
        normalized == root or normalized.startswith(root + "/")
        for root in allowed
    ):
        raise SystemExit(f"foreign include path: {path}")
    if (
        "aarch64-w64-mingw32" in normalized
        or "x86_64" in normalized
        or re.search(r"(^|/)usr/include/c\+\+(/|$)", normalized)
        or re.search(r"(^|/)(mingw32|mingw64|ucrt64|clang32|clang64|clangarm64)/", normalized)
    ):
        raise SystemExit(f"foreign include path: {path}")
PY

reject_match '-D_WIN64' "$workdir/include-search.txt" \
  'compiler unexpectedly injects a recipe-level _WIN64 define'

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
  reject_match '^cygwin1\.dll$' "${file}.imports" \
    "unexpected cygwin1.dll dependency in $file"
done

"$cc" "${link_tool[@]}" -dumpspecs > "$workdir/gcc.specs"
grep -F -- '-lmsys-2.0' "$workdir/gcc.specs"
reject_match '(^|[[:space:]])-lcygwin([[:space:]]|$)' "$workdir/gcc.specs" \
  'compiler specs reference -lcygwin'

reject_match 'cygwin1\.dll|libcygwin\.a|x86_64' "$workdir/include-search.txt" \
  'foreign include/runtime path detected'

printf 'path\trole\texpected-format\tactual-format\tmachine\n' \
  > "$report_dir/payload-audit.tsv"
validate_required_payloads

(
  cd "$package_root"
  find -L opt -type f \( -name '*.a' -o -name '*.dll' -o \
    -name '*.dll.a' -o -name '*.exe' -o -name '*.o' \) \
    | LC_ALL=C sort
) > "$report_dir/file-list.txt"
while IFS= read -r relative_file; do
  audit_file "${package_root}/${relative_file}"
done < "$report_dir/file-list.txt"

write_package_manifest > "$report_dir/package-manifest.sha256"

{
  printf 'package\tmingw-w64-cross-msysarm64-gcc\n'
  printf 'target\t%s\n' "$target"
  printf 'dumpmachine\t%s\n' "$cxx_machine"
  printf 'thread-model\tposix\n'
  printf 'msys-macro\t%s\n' "$(grep -Eq '^#define __MSYS__( 1)?$' "$workdir/compiler-macros.txt" && echo yes)"
  printf 'win64-macro\t%s\n' "$(grep -Fx '#define _WIN64 1' "$workdir/compiler-macros.txt" && echo yes)"
  printf 'lp64-macro\t%s\n' "$(grep -Fx '#define __LP64__ 1' "$workdir/compiler-macros.txt" && echo yes)"
  printf 'package-manifest\t%s\n' "$report_dir/package-manifest.sha256"
} > "$report_dir/summary.txt"

cat > "$report_dir/source-identity.txt" <<EOF
package-version	${pkgver:-15.0.1dev}-1
gcc-repository	https://github.com/crutkas/gcc-woarm64
gcc-commit	50bcb1fbfb31a4a51b6cf0a517ecf3c668d00506
gcc-archive-sha256	b6d0494f22b70e9cb8cadda260a299aaba109fc20e4342542b9443f9cb4597a9
gcc-source-chain	9b0c288d8f337d685017621b2e9d84579f8aa391,3053d5071151031574f9ea272031d1dcba053f62,626c500b14b8eac6754b80b3a175acc305426c06,e1a057af466f066d86b20270fb7864764951420d,50bcb1fbfb31a4a51b6cf0a517ecf3c668d00506
runtime-version	3.6.10.r0.ga527ace21-1
sysroot-version	3.6.10.r0.ga527ace21-1
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

printf 'validated\t%s\n' "$cxx_machine" > "$report_dir/validated.txt"
rm -rf "$workdir"

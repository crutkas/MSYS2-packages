#!/usr/bin/env bash

set -euo pipefail
export TZ=UTC

if (( $# != 2 )); then
  echo "usage: $0 PREFIX REPORT_DIR" >&2
  exit 2
fi

prefix=$(cd "$1" && pwd)
report_dir=$2
mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
workdir="${report_dir}/work"
rm -rf "$workdir"
mkdir -p "$workdir"

target=${TARGET:-aarch64-pc-msys}
cc=${TARGET_CC:-"/opt/bin/${target}-gcc.exe"}
cxx=${TARGET_CXX:-"/opt/bin/${target}-g++.exe"}
ar=${TARGET_AR:-/opt/bin/aarch64-pc-cygwin-ar.exe}
nm=${TARGET_NM:-/opt/bin/aarch64-pc-cygwin-nm.exe}
objdump=${TARGET_OBJDUMP:-/opt/bin/aarch64-pc-cygwin-objdump.exe}
binutils_root=${TARGET_BINUTILS_ROOT:-/opt/bin}
build_dir=${TARGET_BUILD_DIR:-}
scanner=${PSEUDO_RELOC_SCANNER:-}
powershell=${PSEUDO_RELOC_PWSH:-pwsh}
scanner_sha256=888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9
linker="${binutils_root}/aarch64-pc-cygwin-ld.exe"
linker_sha256=075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
opt_root=$(dirname "$binutils_root")
sysroot="/opt/${target}"
specs="${sysroot}/lib/cygwin-compile-only.specs"
dll="${prefix}/bin/msys-z.dll"
minigzip="${prefix}/bin/minigzip.exe"
static_lib="${prefix}/lib/libz.a"
import_lib="${prefix}/lib/libz.dll.a"
pc_file="${prefix}/lib/pkgconfig/zlib.pc"

for tool in "$cc" "$cxx" "$ar" "$nm" "$objdump" "$linker" python "$powershell"; do
  command -v "$tool" >/dev/null
done
test -f "$scanner"
for file in \
  "$dll" \
  "$minigzip" \
  "$static_lib" \
  "$import_lib" \
  "$pc_file" \
  "${prefix}/include/zlib.h" \
  "${prefix}/include/zconf.h"
do
  test -f "$file"
done

test "$("$cc" -dumpmachine)" = "$target"
test "$("$cc" -dumpversion)" = 15.0.1
test "$("$cxx" -dumpmachine)" = "$target"
test "$("$cxx" -dumpversion)" = 15.0.1
test "$(pacman -Qoq "$cc")" = mingw-w64-cross-msysarm64-gcc
test "$(pacman -Qoq "$cxx")" = mingw-w64-cross-msysarm64-gcc
compiler_identity=$(pacman -Q mingw-w64-cross-msysarm64-gcc)
test "$(sha256sum "$linker" | cut -d' ' -f1)" = "$linker_sha256"
test "$(sha256sum "$scanner" | cut -d' ' -f1)" = "$scanner_sha256"
binutils_identity=$(pacman -Q mingw-w64-cross-cygwinarm64-binutils)
test "$binutils_identity" = \
  'mingw-w64-cross-cygwinarm64-binutils 2.44.50-2'
test "$(pacman -Qoq "$ar")" = \
  mingw-w64-cross-cygwinarm64-binutils

gcc_search=(
  "-B${binutils_root}/"
  "-B${opt_root}/libexec/gcc/${target}/15.0.1/"
  "-B${opt_root}/lib/gcc/${target}/15.0.1/"
)
cxx_include="${sysroot}/include/c++/15.0.1"
cxx_header_search=(
  -nostdinc++
  -isystem "$cxx_include"
  -isystem "${cxx_include}/${target}"
  -isystem "${cxx_include}/backward"
)

python - "$dll" "$minigzip" <<'PY'
import pathlib
import struct
import sys

for name in sys.argv[1:]:
    data = pathlib.Path(name).read_bytes()
    if data[:2] != b"MZ":
        raise SystemExit(f"{name}: missing DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise SystemExit(f"{name}: missing PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    if machine != 0xAA64:
        raise SystemExit(f"{name}: expected AA64, got 0x{machine:04X}")
PY

audit_pe() {
  local file=$1
  local stem=$2

  (
    cd "$(dirname "$file")"
    "$objdump" -f -p "$(basename "$file")"
  ) > "${report_dir}/${stem}.objdump.txt"
  grep -E 'file format pei?-aarch64-little' \
    "${report_dir}/${stem}.objdump.txt"
  sed -n 's/^[[:space:]]*DLL Name: //p' \
    "${report_dir}/${stem}.objdump.txt" \
    > "${report_dir}/${stem}.imports.txt"
  if grep -Ei 'cygwin1\.dll|x86_64|mingw(32|64)|ucrtbase\.dll' \
      "${report_dir}/${stem}.objdump.txt"; then
    echo "$file contains a foreign target or import" >&2
    return 1
  fi
}

: > "${report_dir}/pseudo-relocs.tsv"
audit_pseudo_relocs() {
  local file=$1
  local stem=$2
  local output="${report_dir}/${stem}.pseudo-relocs.json"
  local file_win output_win scanner_win objdump_win nm_win

  file_win=$(cygpath -w "$file")
  output_win=$(cygpath -w "$output")
  scanner_win=$(cygpath -w "$scanner")
  objdump_win=$(cygpath -w "$objdump")
  nm_win=$(cygpath -w "$nm")
  MSYS2_ARG_CONV_EXCL='*' \
    "$powershell" -NoLogo -NoProfile -NonInteractive \
      -File "$scanner_win" \
      -PePath "$file_win" \
      -OutputPath "$output_win" \
      -Objdump "$objdump_win" \
      -Nm "$nm_win"

  python - "$output" "$stem" \
    "${report_dir}/pseudo-relocs.tsv" <<'PY'
import json
import pathlib
import sys

output_path, stem, report_path = map(pathlib.Path, sys.argv[1:])
data = json.loads(output_path.read_text(encoding="utf-8-sig"))
if data.get("result") != "pass":
    raise SystemExit(f"{stem}: shared pseudo-reloc scanner did not pass")
violations = data.get("policy_violations", [])
flags = data.get("flags", [])
if violations or any(flag not in (8, 16, 32, 64) for flag in flags):
    raise SystemExit(f"{stem}: rejected pseudo-reloc policy: {violations!r}")
if any(flag in (12, 21) for flag in flags):
    raise SystemExit(f"{stem}: ambiguous pseudo-reloc flags: {flags!r}")
data["input_path"] = stem
output_path.write_text(
    json.dumps(data, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
flag_text = ",".join(str(flag) for flag in flags) or "none"
with pathlib.Path(report_path).open("a", encoding="utf-8", newline="\n") as report:
    report.write(
        f"{stem}\t{data.get('table_format')}\t"
        f"{data.get('record_count')}\t{flag_text}\tpass\n"
    )
PY
}

audit_pe "$dll" zlib-dll
audit_pe "$minigzip" minigzip
audit_pseudo_relocs "$dll" zlib-dll
audit_pseudo_relocs "$minigzip" minigzip
grep -Fix 'msys-2.0.dll' "${report_dir}/zlib-dll.imports.txt"
grep -Fix 'msys-2.0.dll' "${report_dir}/minigzip.imports.txt"
grep -Fix 'msys-z.dll' "${report_dir}/minigzip.imports.txt"

sed -n '/Ordinal\/Name Pointer/,/^$/p' \
  "${report_dir}/zlib-dll.objdump.txt" \
  > "${report_dir}/zlib-dll.exports.txt"
"$nm" -g "$import_lib" > "${report_dir}/zlib-import.symbols.txt"
for symbol in \
  adler32 \
  compress \
  compress2 \
  crc32 \
  deflate \
  deflateInit_ \
  inflate \
  inflateInit_ \
  uncompress \
  zlibVersion
do
  grep -Eq "[[:space:]]${symbol}$" "${report_dir}/zlib-dll.exports.txt"
  grep -Eq "[[:space:]]__imp_${symbol}$" \
    "${report_dir}/zlib-import.symbols.txt"
done

audit_archive() {
  local archive=$1
  local stem=$2
  local count=0
  local member

  "$ar" t "$archive" > "${report_dir}/${stem}.members.txt"
  "$nm" -s "$archive" > "${report_dir}/${stem}.armap.txt"
  grep -F 'Archive index:' "${report_dir}/${stem}.armap.txt"
  while IFS= read -r member; do
    test -n "$member"
    "$ar" p "$archive" "$member" > "${workdir}/archive-member.o"
    test -s "${workdir}/archive-member.o"
    "$objdump" -f "${workdir}/archive-member.o" \
      > "${workdir}/archive-member.objdump.txt"
    grep -F 'architecture: aarch64' \
      "${workdir}/archive-member.objdump.txt" >/dev/null
    grep -F 'file format pe-aarch64-little' \
      "${workdir}/archive-member.objdump.txt" >/dev/null
    count=$((count + 1))
  done < "${report_dir}/${stem}.members.txt"
  test "$count" -gt 0
  printf '%s\t%s\n' "$stem" "$count" \
    >> "${report_dir}/archive-member-counts.tsv"
}

: > "${report_dir}/archive-member-counts.tsv"
audit_archive "$static_lib" zlib-static
audit_archive "$import_lib" zlib-import

grep -Fx 'prefix=/usr' "$pc_file"
grep -Fx 'exec_prefix=/usr' "$pc_file"
grep -Fx 'libdir=/usr/lib' "$pc_file"
grep -Fx 'sharedlibdir=/usr/lib' "$pc_file"
grep -Fx 'includedir=/usr/include' "$pc_file"
grep -Fx 'Version: 1.3.1' "$pc_file"
if grep -Ei '/opt/|aarch64-pc-cygwin|x86_64|mingw(32|64)' "$pc_file"; then
  echo "$pc_file contains a build-host or cross-prefix leak" >&2
  exit 1
fi

cat > "${workdir}/compression-smoke.c" <<'EOF'
#include <string.h>
#include <zlib.h>

int
main(void)
{
  static const unsigned char input[] = "aarch64-pc-msys zlib smoke";
  unsigned char compressed[128];
  unsigned char output[128];
  uLongf compressed_size = sizeof(compressed);
  uLongf output_size = sizeof(output);

  if (compress2(compressed, &compressed_size, input, sizeof(input), 9) != Z_OK)
    return 1;
  if (uncompress(output, &output_size, compressed, compressed_size) != Z_OK)
    return 2;
  if (output_size != sizeof(input) || memcmp(input, output, sizeof(input)) != 0)
    return 3;
  return zlibVersion()[0] == '1' ? 0 : 4;
}
EOF

"$cc" \
  "${gcc_search[@]}" \
  "--sysroot=${sysroot}" \
  "-specs=${specs}" \
  -I"${prefix}/include" \
  "${workdir}/compression-smoke.c" \
  -L"${prefix}/lib" \
  -Wl,--no-insert-timestamp \
  -lz \
  -o "${workdir}/compression-smoke-dynamic.exe"
audit_pe "${workdir}/compression-smoke-dynamic.exe" compression-smoke-dynamic
audit_pseudo_relocs \
  "${workdir}/compression-smoke-dynamic.exe" \
  compression-smoke-dynamic
grep -Fix 'msys-2.0.dll' \
  "${report_dir}/compression-smoke-dynamic.imports.txt"
grep -Fix 'msys-z.dll' \
  "${report_dir}/compression-smoke-dynamic.imports.txt"

"$cc" \
  "${gcc_search[@]}" \
  "--sysroot=${sysroot}" \
  "-specs=${specs}" \
  -I"${prefix}/include" \
  "${workdir}/compression-smoke.c" \
  "$static_lib" \
  -Wl,--no-insert-timestamp \
  -o "${workdir}/compression-smoke-static.exe"
audit_pe "${workdir}/compression-smoke-static.exe" compression-smoke-static
audit_pseudo_relocs \
  "${workdir}/compression-smoke-static.exe" \
  compression-smoke-static
grep -Fix 'msys-2.0.dll' \
  "${report_dir}/compression-smoke-static.imports.txt"
if grep -Fix 'msys-z.dll' \
    "${report_dir}/compression-smoke-static.imports.txt"; then
  echo "static zlib smoke unexpectedly imports msys-z.dll" >&2
  exit 1
fi

cat > "${workdir}/pseudo-reloc-cxx.cc" <<'EOF'
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
int startup_state = 0;

struct Startup {
  Startup() { startup_state = 41; }
};

Startup startup;
}

int
main()
{
  if (startup_state != 41)
    return 1;

  try {
    throw std::runtime_error("arm64-msys");
  } catch (const std::exception& error) {
    if (std::string(error.what()) != "arm64-msys")
      return 2;
  }

  std::cout << "cxx-runtime-ok" << std::endl;
  return 0;
}
EOF

"$cxx" \
  "${gcc_search[@]}" \
  "--sysroot=${sysroot}" \
  "-specs=${specs}" \
  "${cxx_header_search[@]}" \
  -O2 \
  -std=gnu++20 \
  -Wl,--no-insert-timestamp \
  "${workdir}/pseudo-reloc-cxx.cc" \
  -o "${workdir}/pseudo-reloc-cxx.exe"
audit_pe "${workdir}/pseudo-reloc-cxx.exe" pseudo-reloc-cxx
audit_pseudo_relocs "${workdir}/pseudo-reloc-cxx.exe" pseudo-reloc-cxx
grep -Fix 'msys-2.0.dll' \
  "${report_dir}/pseudo-reloc-cxx.imports.txt"
grep -Fix 'msys-gcc_s-seh-1.dll' \
  "${report_dir}/pseudo-reloc-cxx.imports.txt"
grep -Fix 'msys-stdc++-6.dll' \
  "${report_dir}/pseudo-reloc-cxx.imports.txt"
install -m755 "${workdir}/pseudo-reloc-cxx.exe" \
  "${report_dir}/pseudo-reloc-cxx.exe"

if [[ -n "$build_dir" ]]; then
  test -d "$build_dir"
  : > "${report_dir}/build-object-audit.tsv"
  while IFS= read -r -d '' file; do
    name=$(basename "$file")
    "$objdump" -f "$file" > "${workdir}/${name}.objdump.txt"
    grep -F 'architecture: aarch64' \
      "${workdir}/${name}.objdump.txt" >/dev/null
    grep -F 'file format pe-aarch64-little' \
      "${workdir}/${name}.objdump.txt" >/dev/null
    printf '%s\t%s\n' "$name" \
      "$(sha256sum "$file" | cut -d' ' -f1)" \
      >> "${report_dir}/build-object-audit.tsv"
  done < <(find "$build_dir" -maxdepth 1 -type f -name '*.o' -print0)
  test -s "${report_dir}/build-object-audit.tsv"

  while IFS= read -r -d '' file; do
    name=$(basename "$file")
    stem="build-${name%.*}"
    audit_pe "$file" "$stem"
    audit_pseudo_relocs "$file" "$stem"
  done < <(
    find "$build_dir" -maxdepth 1 -type f \
      \( -name '*.exe' -o -name '*.dll' \) -print0
  )
fi

{
  printf 'compiler\t%s\n' "$cc"
  printf 'compiler-identity\t%s\n' "$compiler_identity"
  printf 'compiler-target\t%s\n' "$("$cc" -dumpmachine)"
  printf 'compiler-version\t%s\n' "$("$cc" -dumpversion)"
  printf 'cxx-compiler\t%s\n' "$cxx"
  printf 'cxx-compiler-target\t%s\n' "$("$cxx" -dumpmachine)"
  printf 'cxx-compiler-version\t%s\n' "$("$cxx" -dumpversion)"
  printf 'archive-tool\t%s\n' "$ar"
  printf 'binutils-identity\t%s\n' "$binutils_identity"
  printf 'binutils-root\t%s\n' "$binutils_root"
  printf 'linker\t%s\n' "$linker"
  printf 'linker-sha256\t%s\n' "$linker_sha256"
  printf 'pseudo-reloc-scanner\t%s\n' \
    '.ci/check-aarch64-pseudo-relocs.ps1'
  printf 'pseudo-reloc-scanner-sha256\t%s\n' "$scanner_sha256"
} > "${report_dir}/compiler-identity.tsv"

(
  cd "$prefix"
  find . -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum --binary \
    | sed -E 's/^([0-9a-f]{64}) \*/\1  /'
) > "${report_dir}/payload-manifest.sha256"

rm -rf "$workdir"
printf 'target\t%s\n' "$target" > "${report_dir}/validated.txt"
printf 'machine\t0xAA64\n' >> "${report_dir}/validated.txt"
printf 'zlib-version\t1.3.1\n' >> "${report_dir}/validated.txt"

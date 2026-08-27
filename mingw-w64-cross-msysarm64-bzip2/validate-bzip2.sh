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
ar=${TARGET_AR:-/opt/bin/aarch64-pc-cygwin-ar.exe}
nm=${TARGET_NM:-/opt/bin/aarch64-pc-cygwin-nm.exe}
objdump=${TARGET_OBJDUMP:-/opt/bin/aarch64-pc-cygwin-objdump.exe}
strip=${TARGET_STRIP:-/opt/bin/aarch64-pc-cygwin-strip.exe}
binutils_root=${TARGET_BINUTILS_ROOT:-/opt/bin}
strings=${TARGET_STRINGS:-"${binutils_root}/aarch64-pc-cygwin-strings.exe"}
build_dir=${TARGET_BUILD_DIR:-}
consumer_source=${NATIVE_CONSUMER_SOURCE:-}
scanner=${PSEUDO_RELOC_SCANNER:-}
powershell=${PSEUDO_RELOC_PWSH:-pwsh}
python=${VALIDATION_PYTHON:-python}
scanner_sha256=888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9
linker="${binutils_root}/aarch64-pc-cygwin-ld.exe"
linker_sha256=075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
sysroot="/opt/${target}"
specs="${sysroot}/lib/cygwin-compile-only.specs"
dll="${prefix}/bin/msys-bz2-1.dll"
static_lib="${prefix}/lib/libbz2.a"
import_lib="${prefix}/lib/libbz2.dll.a"
pc_file="${prefix}/lib/pkgconfig/bzip2.pc"
header="${prefix}/include/bzlib.h"
cli_names=(bzip2 bunzip2 bzcat bzip2recover)

for tool in \
  "$cc" "$ar" "$nm" "$objdump" "$strip" "$strings" "$linker" \
  "$python" "$powershell"; do
  command -v "$tool" >/dev/null
done
for file in "$scanner" "$consumer_source" "$dll" "$static_lib" \
  "$import_lib" "$pc_file" "$header"; do
  test -f "$file"
done
for cli in "${cli_names[@]}"; do
  test -f "${prefix}/bin/${cli}.exe"
done

test "$("$cc" -dumpmachine)" = "$target"
test "$("$cc" -dumpversion)" = 15.0.1
compiler_identity=$("$cc" --version | head -n 1)
test "$(sha256sum "$linker" | cut -d' ' -f1)" = "$linker_sha256"
test "$(sha256sum "$scanner" | cut -d' ' -f1)" = "$scanner_sha256"
binutils_identity=$("$ar" --version | head -n 1)

gcc_search=(
  "-B${binutils_root}/"
  "-B$(dirname "$binutils_root")/libexec/gcc/${target}/15.0.1/"
  "-B$(dirname "$binutils_root")/lib/gcc/${target}/15.0.1/"
)

assert_aa64() {
  "$python" - "$1" <<'PY'
import pathlib
import struct
import sys

name = pathlib.Path(sys.argv[1])
data = name.read_bytes()
if data[:2] != b"MZ":
    raise SystemExit(f"{name}: missing DOS header")
pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe_offset:pe_offset + 4] != b"PE\0\0":
    raise SystemExit(f"{name}: missing PE signature")
machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
if machine != 0xAA64:
    raise SystemExit(f"{name}: expected AA64, got 0x{machine:04X}")
PY
}

audit_pe() {
  local file=$1
  local stem=$2

  assert_aa64 "$file"
  (
    cd "$(dirname "$file")"
    "$objdump" -f -p "$(basename "$file")"
  ) > "${report_dir}/${stem}.objdump.txt"
  grep -E 'file format pei?-aarch64-little' \
    "${report_dir}/${stem}.objdump.txt"
  grep -F 'architecture: aarch64' "${report_dir}/${stem}.objdump.txt"
  sed -n 's/^[[:space:]]*DLL Name: //p' \
    "${report_dir}/${stem}.objdump.txt" \
    > "${report_dir}/${stem}.imports.txt"
  if grep -Ei 'cygwin1\.dll|x86_64|mingw(32|64)|ucrtbase\.dll|msvcrt\.dll' \
      "${report_dir}/${stem}.objdump.txt"; then
    echo "$file contains a foreign target or import" >&2
    return 1
  fi
  grep -Fix 'msys-2.0.dll' "${report_dir}/${stem}.imports.txt"
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

  "$python" - "$output" "$file" "$stem" \
    "${report_dir}/pseudo-relocs.tsv" "$scanner_sha256" <<'PY'
import hashlib
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
input_path = pathlib.Path(sys.argv[2])
stem = sys.argv[3]
report_path = pathlib.Path(sys.argv[4])
scanner_sha256 = sys.argv[5]
data = json.loads(output_path.read_text(encoding="utf-8-sig"))
if data.get("result") != "pass":
    raise SystemExit(f"{stem}: shared pseudo-reloc scanner did not pass")
violations = data.get("policy_violations", [])
flags = data.get("flags", [])
if violations or any(flag not in (8, 16, 32, 64) for flag in flags):
    raise SystemExit(f"{stem}: rejected pseudo-reloc policy: {violations!r}")
if any(flag in (12, 21) for flag in flags):
    raise SystemExit(f"{stem}: ambiguous pseudo-reloc flags: {flags!r}")
input_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
data["input_path"] = stem
data["input_sha256"] = input_sha256
data["scanner_sha256"] = scanner_sha256
output_path.write_text(
    json.dumps(data, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
flag_text = ",".join(str(flag) for flag in flags) or "none"
with report_path.open("a", encoding="utf-8", newline="\n") as report:
    report.write(
        f"{stem}\t{input_sha256}\t{data.get('table_format')}\t"
        f"{data.get('record_count')}\t{flag_text}\tpass\n"
    )
PY
}

audit_pe "$dll" libbz2-dll
audit_pseudo_relocs "$dll" libbz2-dll

for cli in "${cli_names[@]}"; do
  audit_pe "${prefix}/bin/${cli}.exe" "$cli"
  audit_pseudo_relocs "${prefix}/bin/${cli}.exe" "$cli"
done
for cli in bzip2 bunzip2 bzcat; do
  grep -Fix 'msys-bz2-1.dll' "${report_dir}/${cli}.imports.txt"
done
if grep -Fix 'msys-bz2-1.dll' "${report_dir}/bzip2recover.imports.txt"; then
  echo "bzip2recover unexpectedly imports libbz2" >&2
  exit 1
fi

sed -n '/Ordinal\/Name Pointer/,/^$/p' \
  "${report_dir}/libbz2-dll.objdump.txt" \
  > "${report_dir}/libbz2-dll.exports.txt"
"$nm" -g "$import_lib" > "${report_dir}/libbz2-import.symbols.txt"
symbols=(
  BZ2_bzBuffToBuffCompress
  BZ2_bzBuffToBuffDecompress
  BZ2_bzCompress
  BZ2_bzCompressEnd
  BZ2_bzCompressInit
  BZ2_bzDecompress
  BZ2_bzDecompressEnd
  BZ2_bzDecompressInit
  BZ2_bzRead
  BZ2_bzWrite
  BZ2_bzlibVersion
)
for symbol in "${symbols[@]}"; do
  grep -Eq "[[:space:]]${symbol}$" "${report_dir}/libbz2-dll.exports.txt"
  grep -Eq "[[:space:]]__imp_${symbol}$" \
    "${report_dir}/libbz2-import.symbols.txt"
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
audit_archive "$static_lib" libbz2-static
audit_archive "$import_lib" libbz2-import

grep -Fx 'prefix=/usr' "$pc_file"
grep -Fx 'exec_prefix=${prefix}' "$pc_file"
grep -Fx 'libdir=${exec_prefix}/lib' "$pc_file"
grep -Fx 'includedir=${prefix}/include' "$pc_file"
grep -Fx 'Version: 1.0.8' "$pc_file"
grep -Fx 'Libs: -L${libdir} -lbz2' "$pc_file"
if grep -Ei '/opt/|aarch64-pc-cygwin|x86_64|mingw(32|64)|[A-Z]:\\' \
    "$pc_file"; then
  echo "$pc_file contains a build-host or cross-prefix leak" >&2
  exit 1
fi

for mode in dynamic static; do
  library=$import_lib
  if [[ "$mode" == static ]]; then
    library=$static_lib
  fi
  "$cc" \
    "${gcc_search[@]}" \
    "--sysroot=${sysroot}" \
    "-specs=${specs}" \
    -O2 \
    -I"${prefix}/include" \
    "$consumer_source" \
    "$library" \
    -Wl,--no-insert-timestamp \
    -o "${workdir}/${mode}-consumer.exe"
  "$strip" --strip-debug "${workdir}/${mode}-consumer.exe"
  audit_pe "${workdir}/${mode}-consumer.exe" "${mode}-consumer"
  audit_pseudo_relocs \
    "${workdir}/${mode}-consumer.exe" \
    "${mode}-consumer"
  install -m755 "${workdir}/${mode}-consumer.exe" \
    "${report_dir}/${mode}-consumer.exe"
done
grep -Fix 'msys-bz2-1.dll' "${report_dir}/dynamic-consumer.imports.txt"
if grep -Fix 'msys-bz2-1.dll' "${report_dir}/static-consumer.imports.txt"; then
  echo "static consumer unexpectedly imports msys-bz2-1.dll" >&2
  exit 1
fi

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
fi

cp "${report_dir}/dynamic-consumer.exe" "${workdir}/negative-machine.exe"
"$python" - "${workdir}/negative-machine.exe" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())
pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
struct.pack_into("<H", data, pe_offset + 4, 0x8664)
path.write_bytes(data)
PY
if audit_pe "${workdir}/negative-machine.exe" negative-machine; then
  echo "foreign-machine negative fixture unexpectedly passed" >&2
  exit 1
fi
printf 'foreign-machine\trejected\n' > "${report_dir}/negative-gates.tsv"

negative_json="${workdir}/negative-machine.json"
if MSYS2_ARG_CONV_EXCL='*' \
    "$powershell" -NoLogo -NoProfile -NonInteractive \
      -File "$(cygpath -w "$scanner")" \
      -PePath "$(cygpath -w "${workdir}/negative-machine.exe")" \
      -OutputPath "$(cygpath -w "$negative_json")" \
      -Objdump "$(cygpath -w "$objdump")" \
      -Nm "$(cygpath -w "$nm")"; then
  echo "scanner accepted a foreign-machine negative fixture" >&2
  exit 1
fi
printf 'scanner-foreign-machine\trejected\n' \
  >> "${report_dir}/negative-gates.tsv"

for file in "$dll" "$static_lib" "$import_lib" \
  "${prefix}/bin/"*.exe "${report_dir}/dynamic-consumer.exe" \
  "${report_dir}/static-consumer.exe"; do
  "$objdump" -h "$file" >/dev/null 2>&1 || true
  if "$strings" "$file" | grep -Eiq \
      '([A-Z]:\\|/home/runner|/build/|crutkas-redesigned-guacamole|x86_64-pc-msys)'; then
    echo "$file contains a build-host path or personality leak" >&2
    exit 1
  fi
done

{
  printf 'compiler\t%s\n' "$cc"
  printf 'compiler-identity\t%s\n' "$compiler_identity"
  printf 'compiler-target\t%s\n' "$("$cc" -dumpmachine)"
  printf 'compiler-version\t%s\n' "$("$cc" -dumpversion)"
  printf 'archive-tool\t%s\n' "$ar"
  printf 'binutils-identity\t%s\n' "$binutils_identity"
  printf 'linker-sha256\t%s\n' "$linker_sha256"
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
{
  printf 'target\t%s\n' "$target"
  printf 'machine\t0xAA64\n'
  printf 'bzip2-version\t1.0.8\n'
  printf 'shared-consumer\tpass\n'
  printf 'static-consumer\tpass\n'
} > "${report_dir}/validated.txt"

#!/usr/bin/bash

set -euo pipefail
export PATH="/opt/bin:/usr/bin:/bin"

if [[ "$#" -ne 5 ]]; then
  echo "usage: $0 PKGROOT BUILD_DIR REPORT_DIR C_SOURCE CXX_SOURCE" >&2
  exit 2
fi

pkgroot=$1
build_dir=$2
report=$3
consumer=$4
cxx_consumer=$5
target=${TARGET:?}
target_root=${TARGET_ROOT:?}
cc=${TARGET_CC:?}
cxx=${TARGET_CXX:?}
ar=${TARGET_AR:?}
nm=${TARGET_NM:?}
objdump=${TARGET_OBJDUMP:?}
build_source_root=${BUILD_SOURCE_ROOT:?}
windows_build_source="$(cygpath -w "${build_source_root}")"
scanner=${PSEUDO_RELOC_SCANNER:?}
binary_scanner=${BINARY_PATH_SCANNER:?}
pwsh_command=${PWSH:?}
python_command=${PYTHON:?}
specs="${target_root}/lib/cygwin-compile-only.specs"
scanner_objdump="$(basename "$(readlink -f "${objdump}")")"
scanner_nm="$(basename "$(readlink -f "${nm}")")"

test -d "${pkgroot}"
test -d "${build_dir}"
test -f "${consumer}"
test -f "${cxx_consumer}"
test -f "${scanner}"
test -f "${binary_scanner}"
test -f "${pwsh_command}"
rm -rf "${report}"
mkdir -p "${report}/pseudo-relocs"

test -f "${pkgroot}/bin/msys-gmp-10.dll"
test -f "${pkgroot}/include/gmp.h"
test -f "${pkgroot}/lib/libgmp.a"
test -f "${pkgroot}/lib/libgmp.dll.a"
grep -Eq '^#define (GMP_LIMB_BITS|__GMP_BITS_PER_MP_LIMB)[[:space:]]+64$' \
  "${pkgroot}/include/gmp.h"

common_flags=(
  -O2
  -pipe
  -D__MSYS__
  -B/opt/bin/
  "--sysroot=${target_root}"
  "-specs=${specs}"
  -static-libgcc
  -Wl,--no-insert-timestamp
  "-I${pkgroot}/include"
)
"${cc}" "${common_flags[@]}" "${consumer}" \
  "-L${pkgroot}/lib" -lgmp -pthread \
  -o "${report}/gmp-dynamic-smoke.exe"
"${cc}" "${common_flags[@]}" "${consumer}" \
  -DGMP_STATIC "${pkgroot}/lib/libgmp.a" -pthread \
  -o "${report}/gmp-static-smoke.exe"
"${cxx}" "${common_flags[@]}" -std=gnu++17 -static-libstdc++ \
  "${cxx_consumer}" "-L${pkgroot}/lib" -lgmp -pthread \
  -o "${report}/gmp-cxx-dynamic-smoke.exe"
"${cxx}" "${common_flags[@]}" -std=gnu++17 -static-libstdc++ \
  -DGMP_STATIC "${cxx_consumer}" "${pkgroot}/lib/libgmp.a" -pthread \
  -o "${report}/gmp-cxx-static-smoke.exe"

mapfile -d '' -t pe_files < <(
  {
    find "${pkgroot}" -type f \( -name '*.dll' -o -name '*.exe' \) -print0
    find "${report}" -maxdepth 1 -type f -name '*.exe' -print0
  } | sort -z
)
test "${#pe_files[@]}" -eq 5
: > "${report}/pe-audit.txt"
: > "${report}/imports.txt"
: > "${report}/unwind.txt"
for file in "${pe_files[@]}"; do
  relative=${file#"${pkgroot}/"}
  [[ "${relative}" != "${file}" ]] || relative=${file#"${report}/"}
  file_info="$(
    cd "$(dirname "${file}")"
    "${objdump}" -f "./$(basename "${file}")"
  )"
  printf '%s\n%s\n' "${relative}" "${file_info}" >> "${report}/pe-audit.txt"
  grep -Fq 'architecture: aarch64' <<< "${file_info}"
  grep -Eq 'file format pei?-aarch64-little' <<< "${file_info}"

  section_info="$(
    cd "$(dirname "${file}")"
    "${objdump}" -h "./$(basename "${file}")"
  )"
  printf '%s\n%s\n' "${relative}" "${section_info}" >> "${report}/unwind.txt"
  grep -Eq '[[:space:]]+\.pdata[[:space:]]+' <<< "${section_info}"
  grep -Eq '[[:space:]]+\.xdata[[:space:]]+' <<< "${section_info}"

  imports="$(
    cd "$(dirname "${file}")"
    "${objdump}" -p "./$(basename "${file}")" |
      sed -n 's/^[[:space:]]*DLL Name: //p'
  )"
  printf '%s\n%s\n' "${relative}" "${imports}" >> "${report}/imports.txt"
  grep -Fqi 'msys-2.0.dll' <<< "${imports}"
  ! grep -Eiq \
    'cygwin1\.dll|libgcc_s|libwinpthread|msvcrt|ucrtbase|mingw|x86_64|i[3-6]86' \
    <<< "${imports}"

  scan_name="$(tr '/\\' '__' <<< "${relative}")"
  "${pwsh_command}" -NoLogo -NoProfile -NonInteractive \
    -File "${scanner}" \
    -PePath "${file}" \
    -Objdump "${scanner_objdump}" \
    -Nm "${scanner_nm}" \
    -OutputPath "${report}/pseudo-relocs/${scan_name}.json"
  MSYS2_ARG_CONV_EXCL='*' "${python_command}" -c '
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
for raw in sys.argv[2:]:
    variants = (raw, raw.replace("\\", "/"), raw.replace("\\", "\\\\"))
    for variant in variants:
        data = data.replace(
            variant.encode("utf-8"), b"<BUILD_SOURCE_ROOT>")
path.write_bytes(data)
' \
    "$(cygpath -w "${report}/pseudo-relocs/${scan_name}.json")" \
    "${build_source_root}" \
    "${windows_build_source}"
  grep -Fq '"result": "pass"' \
    "${report}/pseudo-relocs/${scan_name}.json"
done

dynamic_imports="$("${objdump}" -p "${report}/gmp-dynamic-smoke.exe" |
  sed -n 's/^[[:space:]]*DLL Name: //p')"
grep -Eiq '^msys-gmp-[0-9]+\.dll$' <<< "${dynamic_imports}"
static_imports="$("${objdump}" -p "${report}/gmp-static-smoke.exe" |
  sed -n 's/^[[:space:]]*DLL Name: //p')"
! grep -Eiq '^msys-gmp-[0-9]+\.dll$' <<< "${static_imports}"
cxx_dynamic_imports="$(
  "${objdump}" -p "${report}/gmp-cxx-dynamic-smoke.exe" |
    sed -n 's/^[[:space:]]*DLL Name: //p'
)"
grep -Eiq '^msys-gmp-[0-9]+\.dll$' <<< "${cxx_dynamic_imports}"
cxx_static_imports="$(
  "${objdump}" -p "${report}/gmp-cxx-static-smoke.exe" |
    sed -n 's/^[[:space:]]*DLL Name: //p'
)"
! grep -Eiq '^msys-gmp-[0-9]+\.dll$' <<< "${cxx_static_imports}"

dll_exports="$(
  cd "${pkgroot}/bin"
  "${objdump}" -p ./msys-gmp-10.dll
)"
printf '%s\n' "${dll_exports}" > "${report}/exports.txt"
for symbol in __gmpz_init_set_ui __gmpz_mul __gmpz_cmp; do
  grep -Fq "${symbol}" <<< "${dll_exports}"
done

mapfile -d '' -t archives < <(
  find "${pkgroot}/lib" -type f \( -name '*.a' -o -name '*.dll.a' \) \
    -print0 | sort -z
)
test "${#archives[@]}" -eq 2
: > "${report}/archive-audit.txt"
: > "${report}/archive-armaps.txt"
member_index=0
for archive in "${archives[@]}"; do
  map_info="$("${nm}" --print-armap "${archive}")"
  printf '%s\n%s\n' "${archive#${pkgroot}/}" "${map_info}" \
    >> "${report}/archive-armaps.txt"
  grep -Fq 'Archive index:' <<< "${map_info}"
  mapfile -t members < <("${ar}" t "${archive}")
  member_count=${#members[@]}
  test "${member_count}" -gt 0
  archive_info="$(
    cd "$(dirname "${archive}")"
    "${objdump}" -f "./$(basename "${archive}")"
  )"
  printf '%s\n' "${archive#${pkgroot}/}" >> "${report}/archive-audit.txt"
  printf 'member\t%s\n' "${members[@]}" >> "${report}/archive-audit.txt"
  printf '%s\n' "${archive_info}" >> "${report}/archive-audit.txt"
  architecture_count="$(
    grep -Fc 'architecture: aarch64' <<< "${archive_info}"
  )"
  format_count="$(
    grep -Ec 'file format pei?-aarch64-little' <<< "${archive_info}"
  )"
  test "${architecture_count}" -eq "${member_count}"
  test "${format_count}" -eq "${member_count}"
  member_index=$((member_index + member_count))
done

if [[ -f "${pkgroot}/lib/libgmp.la" ]]; then
  grep -Fxq "libdir='${target_root}/usr/lib'" \
    "${pkgroot}/lib/libgmp.la"
  ! grep -Eiq 'x86_64|i[3-6]86|cygwin1\.dll|mingw' \
    "${pkgroot}/lib/libgmp.la"
fi
! grep -RIEq 'x86_64|i[3-6]86|cygwin1\.dll|mingw' \
  "${pkgroot}/include"
(
  cd "${pkgroot}"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${report}/payload.sha256"
{
  printf 'package\tmingw-w64-cross-msysarm64-gmp\n'
  printf 'version\t6.3.0-2\n'
  printf 'target\t%s\n' "${target}"
  printf 'abi\tLP64/AAPCS64/SEH\n'
  printf 'assembly\tdisabled-until-pe-coff-seh-unwind-is-proven\n'
  printf 'runtime-dll\tmsys-gmp-10.dll\n'
  printf 'pe-count\t%s\n' "${#pe_files[@]}"
  printf 'archive-count\t%s\n' "${#archives[@]}"
  printf 'archive-member-count\t%s\n' "${member_index}"
  printf 'consumer-count\t4\n'
  printf 'classification\tcanonical-build-candidate\n'
  printf 'admissible\tfalse\n'
  printf 'runtime-status\tindependently-admitted-input-required\n'
  printf 'native-execution\tpending-independent-admission\n'
  printf 'scanner-sha256\t%s\n' \
    "$(sha256sum "${scanner}" | cut -d ' ' -f 1)"
} > "${report}/identity.tsv"
scan_report="${report}.forbidden-path-scan.json"
rm -f "${scan_report}"
MSYS2_ARG_CONV_EXCL='*' "${python_command}" \
  "$(cygpath -w "${binary_scanner}")" \
  --forbid "${build_source_root}" \
  --forbid "${windows_build_source}" \
  --report "$(cygpath -w "${scan_report}")" \
  "$(cygpath -w "${pkgroot}")" \
  "$(cygpath -w "${report}")" \
  "$(cygpath -w "${consumer}")" \
  "$(cygpath -w "${cxx_consumer}")" \
  "$(cygpath -w "${scanner}")" \
  "$(cygpath -w "${binary_scanner}")" \
  "$(cygpath -w "$0")"
grep -Fq '"status": "pass"' "${scan_report}"
grep -Fq '"unreadable_or_skipped": 0' "${scan_report}"
mv "${scan_report}" "${report}/forbidden-path-scan.json"

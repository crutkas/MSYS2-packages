#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: validate-libuuid.sh STAGE_ROOT REPORT_DIR SMOKE_SOURCE" >&2
  exit 2
fi

stage_root=${1%/}
report_dir=$2
smoke_source=$3
target=${TARGET:-aarch64-pc-msys}
target_sysroot=${TARGET_SYSROOT:-/opt/${target}}
build_tree=${TARGET_BUILD_TREE:-}
static_archive=${TARGET_STATIC_ARCHIVE:-}
static_smoke_fixture=${TARGET_STATIC_SMOKE:-}
cc=${TARGET_CC:-/opt/bin/${target}-gcc}
ar=${TARGET_AR:-/opt/bin/${target}-ar}
nm=${TARGET_NM:-/opt/bin/${target}-nm}
objcopy=${TARGET_OBJCOPY:-/opt/bin/${target}-objcopy}
objdump=${TARGET_OBJDUMP:-/opt/bin/${target}-objdump}
canonical_objdump=${CANONICAL_OBJDUMP:-/opt/bin/aarch64-pc-cygwin-objdump.exe}
canonical_nm=${CANONICAL_NM:-/opt/bin/aarch64-pc-cygwin-nm.exe}
canonical_scanner=${CANONICAL_PSEUDO_RELOC_SCANNER:-}
canonical_scanner_sha256=888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9
[[ -n "${stage_root}" ]] || stage_root=/

if [[ "${stage_root}" == / ]]; then
  target_root="/opt/${target}"
else
  target_root="${stage_root}/opt/${target}"
fi
dll="${target_root}/bin/msys-uuid-1.dll"
header="${target_root}/usr/include/uuid/uuid.h"
import_archive="${target_root}/usr/lib/libuuid.dll.a"
pkgconfig="${target_root}/usr/lib/pkgconfig/uuid.pc"
dynamic_smoke="${report_dir}/libuuid-smoke.exe"
static_smoke="${report_dir}/libuuid-static-smoke.exe"

for tool in "${cc}" "${ar}" "${nm}" "${objcopy}" "${objdump}"; do
  [[ -x "${tool}" ]] || {
    printf 'ERROR: missing target tool: %s\n' "${tool}" >&2
    exit 1
  }
done
[[ "$("${cc}" -dumpmachine)" == "${target}" ]]
if [[ -z "${canonical_scanner}" ]]; then
  canonical_scanner="${target_root}/share/msys-sysroot/libuuid/check-aarch64-pseudo-relocs-3356eec.ps1"
fi
[[ -f "${canonical_scanner}" ]]
[[ "$(sha256sum "${canonical_scanner}" | awk '{ print $1 }')" == \
  "${canonical_scanner_sha256}" ]]
[[ -x "${canonical_objdump}" && -x "${canonical_nm}" ]]

canonical_scan_count=0
run_canonical_scanner() {
  local pe=$1
  local label=$2
  local output

  output="${report_dir}/canonical-pseudo-$(
    printf '%03d' "${canonical_scan_count}"
  )-${label//[^[:alnum:]._-]/_}.json"
  powershell.exe \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -ExecutionPolicy Bypass \
    -File "$(cygpath -aw "${canonical_scanner}")" \
    -PePath "$(cygpath -aw "${pe}")" \
    -OutputPath "$(cygpath -aw "${output}")" \
    -Objdump "$(cygpath -aw "${canonical_objdump}")" \
    -Nm "$(cygpath -aw "${canonical_nm}")"
  grep -Eq '"result"[[:space:]]*:[[:space:]]*"pass"' "${output}"
  sed -E -i \
    's|"input_path"[[:space:]]*:[[:space:]]*"[^"]*"|"input_path": "<audited-pe>"|' \
    "${output}"
  canonical_scan_count=$((canonical_scan_count + 1))
}

pseudo_reloc_records=0
validate_pseudo_bits() {
  local bits=$1
  local context=$2

  if (( bits == 12 || bits == 21 )); then
    printf 'ERROR: ambiguous pseudo-reloc bit size in %s: %s\n' \
      "${context}" "${bits}" >&2
    return 1
  fi
  case "${bits}" in
    8|16|32|64)
      ;;
    *)
      printf 'ERROR: unsupported pseudo-reloc bit size in %s: %s\n' \
        "${context}" "${bits}" >&2
      return 1
      ;;
  esac
}
for bits in 8 16 32 64; do
  validate_pseudo_bits "${bits}" policy-positive-control
done
for bits in 12 21; do
  if validate_pseudo_bits "${bits}" policy-negative-control \
      > /dev/null 2>&1; then
    printf 'ERROR: pseudo-reloc negative control was accepted: %s\n' \
      "${bits}" >&2
    exit 1
  fi
done

audit_pseudo_relocs() {
  local pe=$1
  local pe_name=${pe##*/}
  local start_hex end_hex rdata_size_hex rdata_vma_hex
  local start end rdata_size rdata_vma length offset
  local dump magic1 magic2 version record_offset record_size
  local index first second third bits

  start_hex=$(
    "${nm}" -n "${pe}" \
      | awk '$3 == "__RUNTIME_PSEUDO_RELOC_LIST__" { print $1; exit }'
  )
  end_hex=$(
    "${nm}" -n "${pe}" \
      | awk '$3 == "__RUNTIME_PSEUDO_RELOC_LIST_END__" { print $1; exit }'
  )
  [[ -n "${start_hex}" && -n "${end_hex}" ]]
  start=$((16#${start_hex}))
  end=$((16#${end_hex}))
  (( end >= start ))
  length=$((end - start))

  if (( length == 0 )); then
    printf '%s\tempty\t-\t-\t-\t-\t-\n' "${pe_name}" \
      >> "${report_dir}/pseudo-relocs.tsv"
    return
  fi
  (( length >= 8 ))

  read -r rdata_size_hex rdata_vma_hex < <(
    "${objdump}" -h "${pe}" \
      | awk '$2 == ".rdata" { print $3, $4; exit }'
  )
  [[ -n "${rdata_size_hex}" && -n "${rdata_vma_hex}" ]]
  rdata_size=$((16#${rdata_size_hex}))
  rdata_vma=$((16#${rdata_vma_hex}))
  (( start >= rdata_vma ))
  (( end <= rdata_vma + rdata_size ))
  offset=$((start - rdata_vma))
  dump="${report_dir}/${pe_name}.rdata.bin"
  "${objcopy}" --dump-section ".rdata=${dump}" "${pe}"

  read -r magic1 magic2 version < <(
    od -An -v -tu4 -N12 -j "${offset}" "${dump}"
  )
  if (( length >= 12 && magic1 == 0 && magic2 == 0 )); then
    case "${version}" in
      0)
        record_offset=$((offset + 12))
        record_size=8
        ;;
      1)
        record_offset=$((offset + 12))
        record_size=12
        ;;
      *)
        printf 'ERROR: unsupported pseudo-reloc version in %s: %s\n' \
          "${pe_name}" "${version}" >&2
        return 1
        ;;
    esac
    (( (length - 12) % record_size == 0 ))
  else
    version=0
    record_offset=${offset}
    record_size=8
    (( length % record_size == 0 ))
  fi

  index=0
  while (( record_offset < offset + length )); do
    if (( version == 1 )); then
      read -r first second third < <(
        od -An -v -tu4 -N12 -j "${record_offset}" "${dump}"
      )
      bits=$((third & 255))
      validate_pseudo_bits "${bits}" "${pe_name} record ${index}"
      printf '%s\tv2\t%s\t0x%08x\t0x%08x\t0x%08x\t%s\n' \
        "${pe_name}" "${index}" "${first}" "${second}" "${third}" "${bits}" \
        >> "${report_dir}/pseudo-relocs.tsv"
    else
      read -r first second < <(
        od -An -v -tu4 -N8 -j "${record_offset}" "${dump}"
      )
      printf '%s\tv1\t%s\t-\t0x%08x\t0x%08x\t32\n' \
        "${pe_name}" "${index}" "${second}" "${first}" \
        >> "${report_dir}/pseudo-relocs.tsv"
    fi
    index=$((index + 1))
    pseudo_reloc_records=$((pseudo_reloc_records + 1))
    record_offset=$((record_offset + record_size))
  done
  rm -f "${dump}"
}

rm -rf "${report_dir}"
mkdir -p "${report_dir}"

expected_payload=(
  "bin/msys-uuid-1.dll"
  "usr/include/uuid/uuid.h"
  "usr/lib/libuuid.dll.a"
  "usr/lib/pkgconfig/uuid.pc"
)
printf '%s\n' "${expected_payload[@]}" \
  | LC_ALL=C sort > "${report_dir}/expected-payload.txt"
{
  find "${target_root}/bin" -maxdepth 1 -type f -name '*uuid*.dll' \
    -printf 'bin/%f\n'
  find "${target_root}/usr/include/uuid" -type f \
    -printf 'usr/include/uuid/%f\n'
  find "${target_root}/usr/lib" -maxdepth 1 -type f \
    -name 'libuuid.dll.a' -printf 'usr/lib/%f\n'
  find "${target_root}/usr/lib/pkgconfig" -maxdepth 1 \
    -type f -name 'uuid.pc' -printf 'usr/lib/pkgconfig/%f\n'
} | LC_ALL=C sort -u > "${report_dir}/actual-payload.txt"
diff -u \
  "${report_dir}/expected-payload.txt" \
  "${report_dir}/actual-payload.txt"

for path in "${dll}" "${header}" "${import_archive}" \
  "${pkgconfig}" "${smoke_source}"
do
  [[ -f "${path}" ]] || {
    printf 'ERROR: missing libuuid payload: %s\n' "${path}" >&2
    exit 1
  }
done

grep -Fx 'prefix=/usr' "${pkgconfig}"
grep -Fx 'exec_prefix=/usr' "${pkgconfig}"
grep -Fx 'libdir=/usr/lib' "${pkgconfig}"
grep -Fx 'includedir=/usr/include' "${pkgconfig}"
grep -Fx 'Name: uuid' "${pkgconfig}"
grep -Fx 'Version: 2.40.2' "${pkgconfig}"
grep -Fx 'Libs: -L${libdir} -luuid' "${pkgconfig}"
grep -Fx 'Cflags: -I${includedir}/uuid' "${pkgconfig}"

: > "${report_dir}/archive-members.tsv"
: > "${report_dir}/coff-audit.txt"
archives=("${import_archive}")
if [[ -n "${static_archive}" ]]; then
  [[ -f "${static_archive}" ]] || {
    printf 'ERROR: missing static archive fixture: %s\n' \
      "${static_archive}" >&2
    exit 1
  }
  archives+=("${static_archive}")
fi
for archive in "${archives[@]}"; do
  archive_name=${archive##*/}
  members="$("${ar}" t "${archive}")"
  member_count="$(grep -c . <<< "${members}")"
  [[ "${member_count}" -gt 0 ]]
  printf '%s\t%s\n' "${archive_name}" "${member_count}" \
    >> "${report_dir}/archive-members.tsv"
  "${objdump}" -f "${archive}" \
    > "${report_dir}/${archive_name}.objdump"
  cat "${report_dir}/${archive_name}.objdump" \
    >> "${report_dir}/coff-audit.txt"
  format_count="$(grep -c 'file format pe-aarch64-little' \
    "${report_dir}/${archive_name}.objdump")"
  architecture_count="$(grep -c 'architecture: aarch64' \
    "${report_dir}/${archive_name}.objdump")"
  [[ "${format_count}" -eq "${member_count}" ]]
  [[ "${architecture_count}" -eq "${member_count}" ]]
  if grep 'file format' "${report_dir}/${archive_name}.objdump" \
      | grep -Fv 'file format pe-aarch64-little'; then
    printf 'ERROR: foreign COFF member in %s\n' "${archive_name}" >&2
    exit 1
  fi
  "${nm}" --print-armap "${archive}" \
    > "${report_dir}/${archive_name}.armap.txt"
  grep -F 'Archive index:' "${report_dir}/${archive_name}.armap.txt"
  grep -Eq '^uuid_generate in ' \
    "${report_dir}/${archive_name}.armap.txt"
done

if ! "${cc}" \
    --sysroot="${target_sysroot}" \
    -I"${target_root}/usr/include" \
    -L"${target_root}/usr/lib" \
    -Wl,--no-insert-timestamp \
    -Wl,--no-undefined \
    -Wl,-t \
    "${smoke_source}" \
    -luuid \
    -o "${dynamic_smoke}" \
    > "${report_dir}/link-trace.txt" 2>&1; then
  cat "${report_dir}/link-trace.txt" >&2
  exit 1
fi
grep -F "${target_root}/usr/lib/libuuid.dll.a" \
  "${report_dir}/link-trace.txt"
mapfile -t linked_libuuid < <(
  grep -Ei 'libuuid(\.dll)?\.a$' "${report_dir}/link-trace.txt"
)
if [[ "${#linked_libuuid[@]}" -ne 1 ||
      "${linked_libuuid[0]}" != \
        "${target_root}/usr/lib/libuuid.dll.a" ]]; then
  printf 'ERROR: smoke link selected a foreign libuuid\n' >&2
  printf '%s\n' "${linked_libuuid[@]}" >&2
  exit 1
fi

if [[ -n "${static_archive}" ]]; then
  if ! "${cc}" \
      --sysroot="${target_sysroot}" \
      -I"${target_root}/usr/include" \
      -Wl,--no-insert-timestamp \
      -Wl,--no-undefined \
      -Wl,-t \
      "${smoke_source}" \
      "${static_archive}" \
      -lpthread \
      -o "${static_smoke}" \
      > "${report_dir}/static-link-trace.txt" 2>&1; then
    cat "${report_dir}/static-link-trace.txt" >&2
    exit 1
  fi
  grep -F "${static_archive}" "${report_dir}/static-link-trace.txt"
  if grep -Ei 'libuuid(\.dll)?\.a$' \
      "${report_dir}/static-link-trace.txt" \
      | grep -Fv "${static_archive}"; then
    printf 'ERROR: static smoke selected a foreign libuuid\n' >&2
    exit 1
  fi
elif [[ -n "${static_smoke_fixture}" ]]; then
  [[ -f "${static_smoke_fixture}" ]] || {
    printf 'ERROR: missing static smoke fixture: %s\n' \
      "${static_smoke_fixture}" >&2
    exit 1
  }
  cp "${static_smoke_fixture}" "${static_smoke}"
fi

if [[ -n "${build_tree}" ]]; then
  [[ -d "${build_tree}" ]]
  : > "${report_dir}/build-tree-audit.tsv"
  while IFS= read -r -d '' target_file; do
    target_name=${target_file#"${build_tree}/"}
    "${objdump}" -f "${target_file}" \
      > "${report_dir}/build-tree-current.objdump"
    grep -Eq 'file format (pe|pei)-aarch64-little' \
      "${report_dir}/build-tree-current.objdump"
    grep -F 'architecture: aarch64' \
      "${report_dir}/build-tree-current.objdump"
    if grep 'file format' "${report_dir}/build-tree-current.objdump" \
        | grep -Ev 'file format (pe|pei)-aarch64-little'; then
      printf 'ERROR: foreign target file in build tree: %s\n' \
        "${target_name}" >&2
      exit 1
    fi
    case "${target_file}" in
      *.dll|*.exe)
        run_canonical_scanner \
          "${target_file}" \
          "build-${target_name//\//_}"
        ;;
    esac
    printf '%s\t%s\n' \
      "${target_name}" \
      "$(sha256sum "${target_file}" | awk '{ print $1 }')" \
      >> "${report_dir}/build-tree-audit.tsv"
  done < <(
    find "${build_tree}" -type f \
      \( -name '*.o' -o -name '*.a' -o -name '*.dll' -o -name '*.exe' \) \
      -print0
  )
  rm -f "${report_dir}/build-tree-current.objdump"
  LC_ALL=C sort -o "${report_dir}/build-tree-audit.tsv" \
    "${report_dir}/build-tree-audit.tsv"
  [[ -s "${report_dir}/build-tree-audit.tsv" ]]
fi

: > "${report_dir}/imports.tsv"
: > "${report_dir}/pseudo-relocs.tsv"
pe_files=("${dll}" "${dynamic_smoke}")
if [[ -f "${static_smoke}" ]]; then
  pe_files+=("${static_smoke}")
fi
for pe in "${pe_files[@]}"; do
  pe_name=${pe##*/}
  "${objdump}" -f -p "${pe}" > "${report_dir}/${pe_name}.objdump"
  cat "${report_dir}/${pe_name}.objdump" \
    >> "${report_dir}/coff-audit.txt"
  grep -F 'file format pei-aarch64-little' \
    "${report_dir}/${pe_name}.objdump"
  grep -F 'architecture: aarch64' \
    "${report_dir}/${pe_name}.objdump"
  awk -v file="${pe_name}" '/DLL Name:/ { print file "\t" $3 }' \
    "${report_dir}/${pe_name}.objdump" \
    >> "${report_dir}/imports.tsv"
  audit_pseudo_relocs "${pe}"
  run_canonical_scanner "${pe}" "${pe_name}"
done
LC_ALL=C sort -o "${report_dir}/imports.tsv" \
  "${report_dir}/imports.tsv"

grep -F $'msys-uuid-1.dll\tmsys-2.0.dll' \
  "${report_dir}/imports.tsv"
grep -F $'libuuid-smoke.exe\tmsys-uuid-1.dll' \
  "${report_dir}/imports.tsv"
if [[ -f "${static_smoke}" ]] &&
    grep -F $'libuuid-static-smoke.exe\tmsys-uuid-1.dll' \
      "${report_dir}/imports.tsv"; then
  printf 'ERROR: static smoke imports the libuuid DLL\n' >&2
  exit 1
fi
while IFS=$'\t' read -r pe_name import_name; do
  case "${import_name,,}" in
    kernel32.dll|msys-2.0.dll|msys-gcc_s-seh-1.dll|msys-uuid-1.dll)
      ;;
    *)
      printf 'ERROR: unexpected import in %s: %s\n' \
        "${pe_name}" "${import_name}" >&2
      exit 1
      ;;
  esac
done < "${report_dir}/imports.tsv"
if grep -Eiq 'cygwin1\.dll|x86_64|pei-x86-64|pe-x86-64' \
    "${report_dir}/coff-audit.txt" "${report_dir}/imports.tsv"; then
  printf 'ERROR: Cygwin/x64 contamination found in target audit\n' >&2
  exit 1
fi

"${nm}" -g "${dll}" > "${report_dir}/exports.txt"
for symbol in \
  uuid_clear \
  uuid_compare \
  uuid_generate \
  uuid_generate_random \
  uuid_generate_time \
  uuid_is_null \
  uuid_parse \
  uuid_time \
  uuid_unparse \
  uuid_unparse_lower \
  uuid_unparse_upper
do
  grep -Eq "[[:space:]]T[[:space:]]+${symbol}$" \
    "${report_dir}/exports.txt"
done
"${nm}" -g "${import_archive}" \
  > "${report_dir}/import-symbols.txt"
grep -Eq '[[:space:]]I[[:space:]]+__imp_uuid_generate$' \
  "${report_dir}/import-symbols.txt"
grep -Eq '[[:space:]]T[[:space:]]+uuid_generate$' \
  "${report_dir}/import-symbols.txt"

{
  printf 'target\t%s\n' "${target}"
  printf 'compiler\t%s\n' "$("${cc}" -dumpmachine)"
  printf 'payload-files\t%s\n' "${#expected_payload[@]}"
  printf 'pe-files\t%s\n' "${#pe_files[@]}"
  printf 'archives\t%s\n' "${#archives[@]}"
  printf 'pseudo-reloc-records\t%s\n' "${pseudo_reloc_records}"
  printf 'canonical-scans\t%s\n' "${canonical_scan_count}"
  printf 'native-smoke\tdeferred-to-windows-11-arm\n'
} > "${report_dir}/summary.tsv"

(
  cd "${target_root}"
  sha256sum \
    bin/msys-uuid-1.dll \
    usr/include/uuid/uuid.h \
    usr/lib/libuuid.dll.a \
    usr/lib/pkgconfig/uuid.pc
) > "${report_dir}/payload.sha256"
(
  cd "${report_dir}"
  sha256sum ./*smoke.exe
) > "${report_dir}/smoke.sha256"

if [[ "${stage_root}" != / ]]; then
  while IFS= read -r report; do
    sed -E -i \
      -e "s|${stage_root}|<stage>|g" \
      -e "s|${report_dir}|<report>|g" \
      -e "s|${smoke_source}|<smoke-source>|g" \
      -e 's|/[^[:space:]]*/cc[[:alnum:]]+\.o|<compiler-temp>.o|g' \
      "${report}"
  done < <(grep -IlR -e "${stage_root}" -e "${report_dir}" \
    -e "${smoke_source}" "${report_dir}")
fi

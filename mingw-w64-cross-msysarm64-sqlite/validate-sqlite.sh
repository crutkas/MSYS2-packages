#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 PAYLOAD_ROOT REPORT_DIR [EXTRA_PE ...]" >&2
  exit 2
fi

payload_root=$1
report_dir=$2
shift 2
extra_pes=("$@")
target=aarch64-pc-msys
target_prefix=/opt/${target}
if [[ "${payload_root}" == / ]]; then
  payload_prefix=${target_prefix}
else
  payload_prefix=${payload_root%/}${target_prefix}
fi
runtime_prefix=${MSYSARM64_RUNTIME_PREFIX:-${target_prefix}}
objdump=/opt/bin/aarch64-pc-cygwin-objdump
nm=/opt/bin/aarch64-pc-cygwin-nm
ar=/opt/bin/aarch64-pc-cygwin-ar

rm -rf "${report_dir}"
mkdir -p \
  "${report_dir}/archives" \
  "${report_dir}/imports" \
  "${report_dir}/pe"

for tool in "${objdump}" "${nm}" "${ar}"; do
  test -x "${tool}"
done

payload_pes=(
  "${payload_prefix}/bin/msys-sqlite3-0.dll"
  "${payload_prefix}/bin/sqlite3.exe"
)
payload_archives=(
  "${payload_prefix}/lib/libsqlite3.a"
  "${payload_prefix}/lib/libsqlite3.dll.a"
)

if [[ "${MSYSARM64_SQLITE_SHARED_PREFIX:-0}" != 1 ]]; then
  mapfile -d '' discovered_pes < <(
    find "${payload_prefix}" -type f \
      \( -iname '*.dll' -o -iname '*.exe' -o -iname '*.o' \) \
      -print0 \
      | LC_ALL=C sort -z
  )
  mapfile -d '' discovered_archives < <(
    find "${payload_prefix}" -type f \
      \( -iname '*.a' -o -iname '*.dll.a' \) \
      -print0 \
      | LC_ALL=C sort -z
  )
  test "${#discovered_pes[@]}" -eq "${#payload_pes[@]}"
  test "${#discovered_archives[@]}" -eq "${#payload_archives[@]}"
fi

for file in "${payload_pes[@]}" "${payload_archives[@]}"; do
  test -f "${file}"
done
test -f "${payload_prefix}/include/sqlite3.h"
test -f "${payload_prefix}/include/sqlite3ext.h"
test -f "${payload_prefix}/lib/pkgconfig/sqlite3.pc"
test -f "${payload_prefix}/lib/sqlite3.def"

runtime_dll="${payload_root%/}${target_prefix}/bin/msys-2.0.dll"
if [[ "${payload_root}" == / ]]; then
  runtime_dll="${target_prefix}/bin/msys-2.0.dll"
fi
if [[ ! -f "${runtime_dll}" ]]; then
  runtime_dll="${runtime_prefix}/bin/msys-2.0.dll"
fi
test -f "${runtime_dll}"
"${objdump}" -f "${runtime_dll}" \
  > "${report_dir}/pe/msys-2.0.dll.file.txt"
grep -F 'file format pei-aarch64-little' \
  "${report_dir}/pe/msys-2.0.dll.file.txt"
grep -F 'architecture: aarch64' \
  "${report_dir}/pe/msys-2.0.dll.file.txt"

all_pes=("${payload_pes[@]}" "${extra_pes[@]}")
for file in "${all_pes[@]}"; do
  test -f "${file}"
  base=$(basename "${file}")
  file_report="${report_dir}/pe/${base}.file.txt"
  import_report="${report_dir}/imports/${base}.txt"
  pe_report="${report_dir}/pe/${base}.headers.txt"
  symbol_report="${report_dir}/pe/${base}.symbols.txt"

  "${objdump}" -f "${file}" > "${file_report}"
  grep -F 'file format pei-aarch64-little' "${file_report}"
  grep -F 'architecture: aarch64' "${file_report}"

  "${objdump}" -p "${file}" > "${pe_report}"
  sed -n 's/^[[:space:]]*DLL Name: //p' "${pe_report}" \
    > "${import_report}"
  "${nm}" -g "${file}" > "${symbol_report}"
  test -s "${import_report}"
  grep -Fxi 'KERNEL32.dll' "${import_report}"
  grep -Fxi 'msys-2.0.dll' "${import_report}"

  if [[ "${base}" == msys-sqlite3-0.dll ]]; then
    if grep -Fxi 'msys-sqlite3-0.dll' "${import_report}"; then
      echo "SQLite DLL imports itself" >&2
      exit 1
    fi
  else
    grep -Fxi 'msys-sqlite3-0.dll' "${import_report}"
    for symbol in sqlite3_close sqlite3_exec sqlite3_open sqlite3_prepare_v2; do
      grep -Eq "[[:space:]]I[[:space:]]+__imp_${symbol}$" \
        "${symbol_report}"
    done
  fi

  while IFS= read -r import; do
    case "${import,,}" in
      kernel32.dll|msys-2.0.dll|msys-sqlite3-0.dll)
        ;;
      *)
        echo "unexpected import in ${base}: ${import}" >&2
        exit 1
        ;;
    esac
  done < "${import_report}"

done

awk '
    /^EXPORTS$/ {
      active = 1
      next
    }
    active && NF {
      print $1
    }
  ' "${payload_prefix}/lib/sqlite3.def" \
  > "${report_dir}/sqlite-def-exports.txt"
test "$(wc -l < "${report_dir}/sqlite-def-exports.txt")" -eq 354
if grep -Ev \
    '^sqlite3(_|changeset_|changegroup_|session_|rebaser_)[[:alnum:]_]*$' \
    "${report_dir}/sqlite-def-exports.txt"; then
  echo "private symbol found in sqlite3.def" >&2
  exit 1
fi
awk '$2 == "DATA" {print $1}' "${payload_prefix}/lib/sqlite3.def" \
  > "${report_dir}/sqlite-def-data-exports.txt"
printf '%s\n' \
  sqlite3_data_directory \
  sqlite3_temp_directory \
  sqlite3_version \
  | diff -u - "${report_dir}/sqlite-def-data-exports.txt"

awk '
    /^\[Ordinal\/Name Pointer\] Table/ {
      active = 1
      next
    }
    active && /\+base\[/ {
      print $NF
      found = 1
      next
    }
    active && found && !NF {
      exit
    }
  ' "${report_dir}/pe/msys-sqlite3-0.dll.headers.txt" \
  > "${report_dir}/sqlite-dll-exports.txt"
diff -u \
  "${report_dir}/sqlite-def-exports.txt" \
  "${report_dir}/sqlite-dll-exports.txt"

"${nm}" -g "${payload_prefix}/lib/libsqlite3.dll.a" \
  > "${report_dir}/sqlite-import-library-symbols.txt"
awk '
    $2 == "I" && $3 ~ /^__imp_sqlite3/ {
      sub(/^__imp_/, "", $3)
      print $3
    }
  ' "${report_dir}/sqlite-import-library-symbols.txt" \
  | LC_ALL=C sort \
  > "${report_dir}/sqlite-import-library-exports.txt"
diff -u \
  "${report_dir}/sqlite-def-exports.txt" \
  "${report_dir}/sqlite-import-library-exports.txt"
for symbol in sqlite3_data_directory sqlite3_temp_directory sqlite3_version; do
  grep -Eq "[[:space:]]I[[:space:]]+__nm_${symbol}$" \
    "${report_dir}/sqlite-import-library-symbols.txt"
done

for archive in "${payload_archives[@]}"; do
  base=$(basename "${archive}")
  archive_report="${report_dir}/archives/${base}.txt"
  mapfile -t members < <("${ar}" t "${archive}")
  member_count=${#members[@]}
  test "${member_count}" -gt 0
  "${objdump}" -f "${archive}" > "${archive_report}"
  architecture_count=$(grep -c 'architecture: aarch64' "${archive_report}")
  format_count=$(
    grep -Ec 'file format pei?-aarch64-little' "${archive_report}"
  )
  total_architecture_count=$(grep -c 'architecture:' "${archive_report}")
  test "${architecture_count}" -eq "${member_count}"
  test "${format_count}" -eq "${member_count}"
  test "${total_architecture_count}" -eq "${member_count}"
  printf '%s\t%s\n' "${base}" "${member_count}" \
    >> "${report_dir}/archive-member-counts.txt"
done

grep -Fx "prefix=${target_prefix}" \
  "${payload_prefix}/lib/pkgconfig/sqlite3.pc"
grep -Fx 'Libs: -L${libdir} -lsqlite3' \
  "${payload_prefix}/lib/pkgconfig/sqlite3.pc"
if grep -Eiq 'cygwin|mingw|x86_64|i[3-6]86' \
    "${payload_prefix}/lib/pkgconfig/sqlite3.pc"; then
  echo "foreign target leaked into sqlite3.pc" >&2
  exit 1
fi

if [[ "${payload_root}" != / ]]; then
  find "${report_dir}" -type f -exec \
    sed -i "s#${payload_root%/}/##g" {} +
fi
for file in "${extra_pes[@]}"; do
  extra_dir=$(dirname "${file}")
  find "${report_dir}" -type f -exec \
    sed -i "s#${extra_dir%/}/##g" {} +
done

{
  printf 'target\t%s\n' "${target}"
  printf 'payload-pe-files\t%s\n' "${#payload_pes[@]}"
  printf 'extra-pe-files\t%s\n' "${#extra_pes[@]}"
  printf 'archives\t%s\n' "${#payload_archives[@]}"
  printf 'runtime\t%s\n' "${runtime_dll}"
  printf 'imports\tKERNEL32.dll,msys-2.0.dll,msys-sqlite3-0.dll\n'
  printf 'foreign-runtime\tabsent\n'
} > "${report_dir}/summary.txt"

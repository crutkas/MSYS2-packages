#!/usr/bin/env bash
set -euo pipefail

if (( $# != 6 )); then
  echo "usage: $0 DESTDIR REPORT_DIR CONTEXT_SMOKE PIPE_SMOKE TARGET_ROOT EXPORT_MAP" >&2
  exit 2
fi

dest=$1
report=$2
context_source=$3
pipe_source=$4
target_root=$5
export_map=$6
target=aarch64-pc-msys
prefix="${dest}/usr"
objdump="${target}-objdump"
ar="${target}-ar"
cc="${target}-gcc"

rm -rf "${report}"
mkdir -p "${report}/archive-members" "${report}/smoke"

fail() {
  echo "audit failure: $*" >&2
  exit 1
}

audit_pe() {
  local file=$1
  local name=${file#${dest}/}
  local safe=${name//\//_}
  local format="${report}/${safe}.file.txt"
  local imports="${report}/${safe}.imports.txt"
  local sections="${report}/${safe}.sections.txt"

  "${objdump}" -f "${file}" > "${format}"
  grep -Eq 'file format pei?-aarch64-little' "${format}" ||
    fail "${name} is not PE/COFF ARM64"
  ! grep -Eiq 'i386|x86-64|pei-x86-64' "${format}" ||
    fail "${name} contains an x86 architecture marker"
  "${objdump}" -h "${file}" > "${sections}"
  awk '$2 == ".pdata" && $3 !~ /^0+$/ { found=1 } END { exit !found }' \
    "${sections}" || fail "${name} has no nonempty ARM64 SEH .pdata section"

  "${objdump}" -p "${file}" |
    sed -n 's/^[[:space:]]*DLL Name: //p' > "${imports}"
  while IFS= read -r dll; do
    [[ -z "${dll}" ]] && continue
    case "${dll,,}" in
      msys-*.dll|kernel32.dll|ntdll.dll|advapi32.dll|ws2_32.dll|user32.dll|shell32.dll)
        ;;
      cygwin1.dll|msvcrt.dll|ucrtbase.dll|libgcc_s_*.dll|libstdc++-6.dll|libwinpthread-1.dll)
        fail "${name} imports forbidden runtime ${dll}"
        ;;
      *)
        fail "${name} imports unexpected DLL ${dll}"
        ;;
    esac
  done < "${imports}"
}

compiler_macros=$(printf '\n' | "${cc}" -dM -E -)
for macro in \
  '#define __aarch64__ 1' \
  '#define __LP64__ 1' \
  '#define __SEH__ 1' \
  '#define __SIZEOF_LONG__ 8' \
  '#define __SIZEOF_POINTER__ 8'; do
  grep -Fxq "${macro}" <<< "${compiler_macros}" ||
    fail "target compiler is missing required ABI macro: ${macro}"
done
printf '%s\n' "${compiler_macros}" > "${report}/compiler-macros.txt"

mapfile -d '' pe_files < <(
  find "${prefix}" -type f \( -iname '*.dll' -o -iname '*.exe' \) -print0
)
(( ${#pe_files[@]} > 0 )) || fail "no PE files were staged"
for file in "${pe_files[@]}"; do
  audit_pe "${file}"
done

mapfile -d '' archives < <(find "${prefix}" -type f -name '*.a' -print0)
(( ${#archives[@]} > 0 )) || fail "no static or import archives were staged"
for archive in "${archives[@]}"; do
  archive_name=$(basename "${archive}")
  member_dir="${report}/archive-members/${archive_name}"
  mkdir -p "${member_dir}"
  member_count=0
  declare -A member_occurrences=()
  while IFS= read -r member_name; do
    [[ -n "${member_name}" ]] || continue
    member_count=$((member_count + 1))
    previous=${member_occurrences["${member_name}"]:-0}
    occurrence=$((previous + 1))
    member_occurrences["${member_name}"]=${occurrence}
    extract_dir="${member_dir}/extract"
    rm -rf "${extract_dir}"
    mkdir -p "${extract_dir}"
    (
      cd "${extract_dir}"
      "${ar}" xN "${occurrence}" "${archive}" "${member_name}"
    )
    member=$(find "${extract_dir}" -type f -print -quit)
    [[ -n "${member}" ]] ||
      fail "${archive_name}:${member_name} could not be extracted"
    preserved="${member_dir}/${member_count}-$(basename "${member_name}")"
    cp "${member}" "${preserved}"
    member_format="${preserved}.file.txt"
    "${objdump}" -f "${preserved}" > "${member_format}"
    grep -Eq 'file format pei?-aarch64-little' "${member_format}" ||
      fail "${archive_name}:${member_name} is not ARM64"
    ! grep -Eiq 'i386|x86-64|pei-x86-64' "${member_format}" ||
      fail "${archive_name}:${member_name} contains an x86 marker"
  done < <("${ar}" t "${archive}")
  rm -rf "${member_dir}/extract"
  (( member_count > 0 )) || fail "${archive_name} has no auditable members"
done

mapfile -d '' libassuan_dlls < <(
  find "${prefix}/bin" -maxdepth 1 -type f -name 'msys-assuan-*.dll' -print0
)
(( ${#libassuan_dlls[@]} == 1 )) ||
  fail "expected exactly one dynamic libassuan DLL, found ${#libassuan_dlls[@]}"
dll=${libassuan_dlls[0]}
"${objdump}" -p "${dll}" > "${report}/libassuan.exports.txt"
sed -n '/^[[:space:]]*\[Ordinal\/Name Pointer\] Table$/,${
  s/^[[:space:]]*\[[[:space:]]*[0-9][0-9]*\][[:space:]]*\([^[:space:]]\+\).*$/\1/p
}' "${report}/libassuan.exports.txt" | sort -u > "${report}/exports.actual.txt"
sed -n '/global:/,/local:/{
  s/^[[:space:]]*\([_A-Za-z][_A-Za-z0-9]*\);[[:space:]]*$/\1/p
}' "${export_map}" | sort -u > "${report}/exports.expected.txt"
[[ -s "${report}/exports.actual.txt" ]] || fail "DLL export table is empty"
[[ -s "${report}/exports.expected.txt" ]] || fail "sealed source export map is empty"
if ! diff -u "${report}/exports.expected.txt" "${report}/exports.actual.txt" \
  > "${report}/exports.diff.txt"; then
  fail "DLL exports differ from the sealed upstream export map"
fi

pc="${prefix}/lib/pkgconfig/libassuan.pc"
config="${prefix}/bin/libassuan-config"
[[ -f "${pc}" ]] || fail "libassuan.pc is missing"
[[ -x "${config}" ]] || fail "libassuan-config is missing"
grep -Fxq 'prefix=/usr' "${pc}" || fail "pkg-config prefix is not /usr"
grep -Fxq 'Requires.private: gpg-error' "${pc}" ||
  fail "pkg-config private dependency is not gpg-error"
grep -Eq '^Libs: .* -lassuan$' "${pc}" ||
  fail "pkg-config link flags do not expose libassuan"
! grep -Eiq '(^|[ =])([A-Za-z]:|/mingw|/ucrt|/clang|/opt/|/c/|/d/)' "${pc}" ||
  fail "pkg-config metadata leaks a build or host path"
while IFS= read -r -d '' metadata; do
  ! grep -Eiq '([A-Za-z]:|/mingw|/ucrt|/clang|/opt/|/c/|/d/)' "${metadata}" ||
    fail "${metadata#${dest}/} leaks a build or host path"
done < <(
  find "${prefix}" -type f \
    \( -name '*.la' -o -name '*.pc' -o -name '*.m4' -o -name '*-config' \) \
    -print0
)

config_version=$("${config}" --version)
config_host=$("${config}" --host)
config_cflags=$("${config}" --cflags)
config_libs=$("${config}" --libs)
[[ "${config_version}" == '3.0.2' ]] ||
  fail "libassuan-config reports ${config_version}"
[[ "${config_host}" == "${target}" ]] ||
  fail "libassuan-config reports host ${config_host}"
[[ "${config_libs}" == *'-lassuan'* && "${config_libs}" == *'-lgpg-error'* ]] ||
  fail "libassuan-config omits required libraries"
! printf '%s\n' "${config_cflags}" "${config_libs}" |
  grep -Eiq '([A-Za-z]:|/mingw|/ucrt|/clang|/opt/|/c/|/d/)' ||
  fail "libassuan-config leaks a build or host path"

export PKG_CONFIG_SYSROOT_DIR="${target_root}"
export PKG_CONFIG_LIBDIR="${prefix}/lib/pkgconfig:${target_root}/usr/lib/pkgconfig"
pkgconf_flags=$(pkg-config --cflags --libs libassuan)
pkgconf_static_flags=$(pkg-config --static --cflags --libs libassuan)
printf '%s\n' "${pkgconf_flags}" > "${report}/pkg-config.dynamic.txt"
printf '%s\n' "${pkgconf_static_flags}" > "${report}/pkg-config.static.txt"
[[ "${pkgconf_flags}" == *"${target_root}/usr/include"* ]] ||
  fail "pkg-config did not sysroot include flags"
[[ "${pkgconf_flags}" == *'-lassuan'* ]] ||
  fail "pkg-config omitted libassuan"

common_flags=(
  "--sysroot=${target_root}"
  "-I${prefix}/include"
  "-I${target_root}/usr/include"
  "-L${prefix}/lib"
  "-L${target_root}/usr/lib"
)
"${cc}" "${common_flags[@]}" -o "${report}/smoke/context-dynamic.exe" \
  "${context_source}" -lassuan -lgpg-error
"${cc}" "${common_flags[@]}" -o "${report}/smoke/pipe-dynamic.exe" \
  "${pipe_source}" -lassuan -lgpg-error
"${cc}" "--sysroot=${target_root}" \
  "-I${prefix}/include" "-I${target_root}/usr/include" \
  -o "${report}/smoke/context-static.exe" \
  "${context_source}" \
  "${prefix}/lib/libassuan.a" \
  "${target_root}/usr/lib/libgpg-error.a"

for smoke in "${report}/smoke/"*.exe; do
  audit_pe "${smoke}"
done
"${objdump}" -p "${report}/smoke/context-static.exe" \
  > "${report}/context-static.imports-full.txt"
! grep -Eiq 'DLL Name: msys-(lib)?assuan|DLL Name: msys-(lib)?gpg-error' \
  "${report}/context-static.imports-full.txt" ||
  fail "static consumer still imports libassuan or libgpg-error"

{
  printf 'target=%s\n' "${target}"
  printf 'pe_files=%d\n' "${#pe_files[@]}"
  printf 'archives=%d\n' "${#archives[@]}"
  printf 'config_version=%s\n' "${config_version}"
  printf 'config_host=%s\n' "${config_host}"
  printf 'dynamic_flags=%s\n' "${pkgconf_flags}"
  printf 'static_flags=%s\n' "${pkgconf_static_flags}"
} > "${report}/summary.txt"

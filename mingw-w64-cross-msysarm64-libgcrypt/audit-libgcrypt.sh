#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 3 )); then
  echo "usage: $0 TARGET_USR_ROOT [SMOKE_SOURCE [REPORT_DIR]]" >&2
  exit 64
fi

root="$(cd "$1" && pwd)"
smoke_source="${2:-}"
report_dir="${3:-${TMPDIR:-/tmp}/libgcrypt-audit}"
target="${TARGET_TRIPLET:-aarch64-pc-msys}"
dependency_root="${DEPENDENCY_ROOT:-/opt/${target}/usr}"
script_dir="$(cd "$(dirname "$0")" && pwd)"
validator="${PSEUDO_RELOC_VALIDATOR:-${script_dir}/audit-aarch64-pseudo-reloc.ps1}"
policy_validator="${PSEUDO_RELOC_POLICY_VALIDATOR:-${script_dir}/check-aarch64-pseudo-relocs.ps1}"
objdump="${target}-objdump"
ar="${target}-ar"
cc="${target}-gcc"

rm -rf "${report_dir}"
mkdir -p "${report_dir}"

fail() {
  echo "audit: $*" >&2
  exit 1
}

require_file() {
  test -f "$1" || fail "missing file: $1"
}

audit_pseudo_reloc() {
  local pe="$1"
  local name
  local nm_path
  local objdump_path
  local objcopy_path
  local status
  local pwsh="${PWSH:-pwsh.exe}"
  name="$(basename "${pe}")"

  require_file "${validator}"
  require_file "${policy_validator}"
  test "$(sha256sum "${validator}" | cut -d' ' -f1)" = \
    '59bbf47759a56001ec50edc694bcac9b23a095ce035c18f5c90cbcef0def4780' ||
    fail "pseudo-reloc validator seal mismatch"
  test "$(sha256sum "${policy_validator}" | cut -d' ' -f1)" = \
    '9d086e655a8636e733c96a8c514942bc249dd60218fa496507c390110867d201' ||
    fail "pseudo-reloc policy validator seal mismatch"
  command -v "${pwsh}" >/dev/null || fail "PowerShell 7 is required for pseudo-reloc audit"
  nm_path="$(command -v "${target}-nm")" ||
    fail "missing ${target}-nm"
  objdump_path="$(command -v "${target}-objdump")" ||
    fail "missing ${target}-objdump"
  objcopy_path="$(command -v "${target}-objcopy")" ||
    fail "missing ${target}-objcopy"

  set +e
  "${pwsh}" -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "${validator}")" \
    -Image "$(cygpath -w "${pe}")" \
    -Nm "$(cygpath -w "${nm_path}")" \
    -Objdump "$(cygpath -w "${objdump_path}")" \
    -Objcopy "$(cygpath -w "${objcopy_path}")" \
    >"${report_dir}/${name}.pseudo-reloc.txt" 2>&1
  status=$?
  set -e
  cat "${report_dir}/${name}.pseudo-reloc.txt"
  (( status == 0 )) ||
    fail "malformed or ambiguous pseudo-reloc table: ${pe} (exit ${status})"
  grep -Eq '^PASS .* ambiguous=0$' \
    "${report_dir}/${name}.pseudo-reloc.txt" ||
    fail "pseudo-reloc validator did not produce an unambiguous PASS: ${pe}"

  set +e
  "${pwsh}" -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "${policy_validator}")" \
    -PePath "$(cygpath -w "${pe}")" \
    -OutputPath "$(cygpath -w "${report_dir}/${name}.pseudo-reloc.json")" \
    -Nm "$(cygpath -w "${nm_path}")" \
    -Objdump "$(cygpath -w "${objdump_path}")" \
    >"${report_dir}/${name}.pseudo-reloc-policy.txt" 2>&1
  status=$?
  set -e
  cat "${report_dir}/${name}.pseudo-reloc-policy.txt"
  (( status == 0 )) ||
    fail "unknown or rejected pseudo-reloc flags: ${pe} (exit ${status})"
  grep -Eq '"result"[[:space:]]*:[[:space:]]*"pass"' \
    "${report_dir}/${name}.pseudo-reloc.json" ||
    fail "pseudo-reloc policy validator did not produce PASS JSON: ${pe}"
}

audit_pe() {
  local pe="$1"
  local name
  local imports
  name="$(basename "${pe}")"
  "${objdump}" -f "${pe}" >"${report_dir}/${name}.file.txt"
  grep -Fq 'file format pei-aarch64-little' "${report_dir}/${name}.file.txt" ||
    fail "non-AA64 PE: ${pe}"

  "${objdump}" -p "${pe}" >"${report_dir}/${name}.headers.txt"
  imports="$(grep -E 'DLL Name:' "${report_dir}/${name}.headers.txt" || true)"
  printf '%s\n' "${imports}" >"${report_dir}/${name}.imports.txt"
  grep -Fqi 'msys-2.0.dll' "${report_dir}/${name}.imports.txt" ||
    fail "missing msys-2.0.dll import: ${pe}"
  if grep -Eqi 'cygwin1\.dll|lib(winpthread|gcc_s|stdc\+\+)-|msvcrt\.dll|ucrtbase\.dll|mingw' \
      "${report_dir}/${name}.imports.txt"; then
    fail "forbidden runtime import: ${pe}"
  fi
  audit_pseudo_reloc "${pe}"
}

audit_archive() {
  local archive="$1"
  local name
  local members
  local formats
  name="$(basename "${archive}")"
  "${ar}" t "${archive}" >"${report_dir}/${name}.members.txt"
  members="$(grep -cve '^[[:space:]]*$' "${report_dir}/${name}.members.txt")"
  (( members > 0 )) || fail "empty archive: ${archive}"

  "${objdump}" -f "${archive}" >"${report_dir}/${name}.file.txt"
  formats="$(grep -c 'file format pe-aarch64-little' "${report_dir}/${name}.file.txt" || true)"
  (( formats == members )) ||
    fail "archive member architecture mismatch (${formats}/${members} AA64): ${archive}"
  if grep -Eqi 'pe-x86-64|pei-i386|architecture: i386|architecture: x86-64' \
      "${report_dir}/${name}.file.txt"; then
    fail "x86 archive member: ${archive}"
  fi
}

require_file "${root}/include/gcrypt.h"
require_file "${root}/lib/libgcrypt.dll.a"
require_file "${root}/lib/libgcrypt.a"
require_file "${root}/lib/libgcrypt.la"
require_file "${root}/lib/pkgconfig/libgcrypt.pc"
require_file "${root}/bin/libgcrypt-config"

mapfile -d '' pe_files < <(find "${root}/bin" -maxdepth 1 -type f \
  \( -name '*.dll' -o -name '*.exe' \) -print0)
(( ${#pe_files[@]} >= 4 )) || fail "expected one DLL and three tools"
for pe in "${pe_files[@]}"; do
  audit_pe "${pe}"
done

mapfile -d '' dlls < <(find "${root}/bin" -maxdepth 1 -type f -name '*.dll' -print0)
(( ${#dlls[@]} == 1 )) || fail "expected exactly one runtime DLL"
gcrypt_dll="${dlls[0]}"
grep -Fqi 'msys-gpg-error-0.dll' \
  "${report_dir}/$(basename "${gcrypt_dll}").imports.txt" ||
  fail "libgcrypt DLL is not dynamically linked to native MSYS libgpg-error"
"${objdump}" -p "${gcrypt_dll}" >"${report_dir}/libgcrypt.exports.txt"
for symbol in gcry_check_version gcry_control gcry_md_hash_buffer gcry_cipher_open; do
  grep -Fq "${symbol}" "${report_dir}/libgcrypt.exports.txt" ||
    fail "missing export: ${symbol}"
done

mapfile -d '' archives < <(find "${root}/lib" -maxdepth 1 -type f -name '*.a' -print0)
(( ${#archives[@]} >= 2 )) || fail "missing import or static archive"
for archive in "${archives[@]}"; do
  audit_archive "${archive}"
done

grep -Fxq 'prefix=/usr' "${root}/lib/pkgconfig/libgcrypt.pc" ||
  fail "pkg-config prefix is not target /usr"
grep -Eq '^Version:[[:space:]]+1\.12\.2$' "${root}/lib/pkgconfig/libgcrypt.pc" ||
  fail "pkg-config version mismatch"
grep -Eq '^Libs:[[:space:]].*-lgcrypt' "${root}/lib/pkgconfig/libgcrypt.pc" ||
  fail "pkg-config is missing -lgcrypt"
grep -Fq 'prefix="/usr"' "${root}/bin/libgcrypt-config" ||
  fail "libgcrypt-config prefix is not target /usr"
test "$("${root}/bin/libgcrypt-config" --version)" = '1.12.2' ||
  fail "libgcrypt-config version mismatch"

for metadata in \
  "${root}/bin/libgcrypt-config" \
  "${root}/lib/libgcrypt.la" \
  "${root}/lib/pkgconfig/libgcrypt.pc"; do
  if grep -Eqi 'C:/msys64|/mingw(32|64)|/ucrt64|x86_64-pc-msys|aarch64-pc-cygwin' \
      "${metadata}"; then
    fail "host or non-MSYS target path leaked into ${metadata}"
  fi
done

if [[ -n "${smoke_source}" ]]; then
  require_file "${smoke_source}"
  require_file "${dependency_root}/include/gpg-error.h"
  require_file "${dependency_root}/lib/libgpg-error.dll.a"
  require_file "${dependency_root}/lib/libgpg-error.a"

  merged="${report_dir}/link-root/usr"
  mkdir -p "${merged}"
  cp -a "${dependency_root}/." "${merged}/"
  cp -a "${root}/." "${merged}/"

  export PKG_CONFIG_LIBDIR="${merged}/lib/pkgconfig"
  export PKG_CONFIG_SYSROOT_DIR="${report_dir}/link-root"
  dynamic_flags="$(pkg-config --cflags --libs libgcrypt)"
  static_cflags="$(pkg-config --cflags libgcrypt)"
  static_flags="$(pkg-config --static --libs libgcrypt |
    sed -E 's/-l(gcrypt|gpg-error)([[:space:]]|$)/ /g')"
  printf '%s\n' "${dynamic_flags}" >"${report_dir}/dynamic.flags.txt"
  printf '%s\n' "${static_cflags} ${static_flags}" >"${report_dir}/static.flags.txt"

  # shellcheck disable=SC2086
  "${cc}" -o "${report_dir}/version-smoke-dynamic.exe" "${smoke_source}" \
    ${dynamic_flags} -Wl,--no-undefined,-Map,"${report_dir}/dynamic.map"
  # shellcheck disable=SC2086
  "${cc}" -o "${report_dir}/version-smoke-static.exe" "${smoke_source}" \
    ${static_cflags} -L"${merged}/lib" \
    -Wl,-Bstatic -lgcrypt -lgpg-error -Wl,-Bdynamic ${static_flags} \
    -Wl,--no-undefined,-Map,"${report_dir}/static.map"

  audit_pe "${report_dir}/version-smoke-dynamic.exe"
  audit_pe "${report_dir}/version-smoke-static.exe"
  grep -Fqi 'msys-gcrypt-' \
    "${report_dir}/version-smoke-dynamic.exe.imports.txt" ||
    fail "dynamic consumer did not import libgcrypt"
  if grep -Eqi 'msys-(gcrypt|gpg-error)-' \
      "${report_dir}/version-smoke-static.exe.imports.txt"; then
    fail "static consumer imported libgcrypt or libgpg-error DLL"
  fi
fi

printf 'target=%s\nroot=%s\npe_count=%s\narchive_count=%s\nstatus=green\n' \
  "${target}" "${root}" "${#pe_files[@]}" "${#archives[@]}" \
  >"${report_dir}/summary.txt"
cat "${report_dir}/summary.txt"

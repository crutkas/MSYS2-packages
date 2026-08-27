#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: $0 DESTDIR REPORT_DIR SMOKE_SOURCE" >&2
  exit 2
fi

dest=$1
report=$2
smoke_source=$3
target=${TARGET:?TARGET is required}
cc=${TARGET_CC:?TARGET_CC is required}
toolroot=${TARGET_TOOL_ROOT:?TARGET_TOOL_ROOT is required}
root="${dest}/usr"
dll="${root}/bin/msys-crypt-2.dll"
import_lib="${root}/lib/libcrypt.dll.a"
static_lib="${root}/lib/libcrypt.a"
header="${root}/include/crypt.h"
pkgconfig="${root}/lib/pkgconfig/libxcrypt.pc"
objdump="${toolroot}/objdump.exe"
nm="${toolroot}/nm.exe"
ar="${toolroot}/ar.exe"

rm -rf "${report}"
mkdir -p "${report}"

for path in \
  "${dll}" \
  "${import_lib}" \
  "${static_lib}" \
  "${header}" \
  "${pkgconfig}" \
  "${objdump}" \
  "${nm}" \
  "${ar}" \
  "${smoke_source}"
do
  if [[ ! -e "${path}" ]]; then
    echo "missing validation input: ${path}" >&2
    exit 1
  fi
done
if [[ -e "${root}/lib/libxcrypt.a" ]]; then
  echo 'disabled libxcrypt.a compatibility alias was installed' >&2
  exit 1
fi
if [[ ! -L "${root}/lib/pkgconfig/libcrypt.pc" ]]; then
  echo 'libcrypt.pc is not a preserved system symlink' >&2
  exit 1
fi

"${objdump}" -f -p "${dll}" > "${report}/runtime-pe.txt"
grep -F 'file format pei-aarch64-little' "${report}/runtime-pe.txt"
grep -F 'architecture: aarch64' "${report}/runtime-pe.txt"
grep -Fi 'DLL Name: msys-2.0.dll' "${report}/runtime-pe.txt"
if grep -Ei 'cygwin1\.dll|x86_64|pei-i386' "${report}/runtime-pe.txt"; then
  echo 'runtime DLL contains a foreign fallback' >&2
  exit 1
fi
for symbol in crypt crypt_r crypt_gensalt crypt_checksalt; do
  grep -Eq "[[:space:]]${symbol}$" "${report}/runtime-pe.txt"
done

"${ar}" t "${import_lib}" > "${report}/import-library-members.txt"
test -s "${report}/import-library-members.txt"
"${nm}" -A "${import_lib}" > "${report}/import-library-symbols.txt"
grep -Eq '[[:space:]]I[[:space:]]+__imp_crypt$' \
  "${report}/import-library-symbols.txt"
grep -Eq '[[:space:]]T[[:space:]]+crypt$' \
  "${report}/import-library-symbols.txt"

"${ar}" t "${static_lib}" > "${report}/static-library-members.txt"
test -s "${report}/static-library-members.txt"
"${nm}" -g --defined-only "${static_lib}" \
  > "${report}/static-library-symbols.txt"
grep -Eq '[[:space:]]T[[:space:]]+crypt$' \
  "${report}/static-library-symbols.txt"

grep -Eq 'crypt[[:space:]]*\(' "${header}"
grep -Fx 'prefix=/usr' "${pkgconfig}"
grep -Eq '^Libs: .* -lcrypt$' "${pkgconfig}"
grep -Fx "Version: 4.5.2" "${pkgconfig}"

export PATH="/opt/bin:${PATH}"
export LIBRARY_PATH="${root}/lib:/opt/${target}/usr/lib:/opt/${target}/lib"
common_flags=(
  "--sysroot=/opt/${target}"
  "-I${root}/include"
  "-L${root}/lib"
  -Wl,--dynamicbase,--nxcompat
)

"${cc}" "${common_flags[@]}" \
  "${smoke_source}" -lcrypt \
  -o "${report}/native-crypt-smoke.exe"
"${objdump}" -f -p "${report}/native-crypt-smoke.exe" \
  > "${report}/dynamic-smoke-pe.txt"
grep -F 'file format pei-aarch64-little' \
  "${report}/dynamic-smoke-pe.txt"
grep -Fi 'DLL Name: msys-crypt-2.dll' \
  "${report}/dynamic-smoke-pe.txt"
grep -Fi 'DLL Name: msys-2.0.dll' \
  "${report}/dynamic-smoke-pe.txt"
if grep -Ei 'cygwin1\.dll|x86_64|pei-i386' \
    "${report}/dynamic-smoke-pe.txt"; then
  echo 'dynamic smoke contains a foreign fallback' >&2
  exit 1
fi

"${cc}" "${common_flags[@]}" \
  "${smoke_source}" "${static_lib}" \
  -o "${report}/static-crypt-smoke.exe"
"${objdump}" -f -p "${report}/static-crypt-smoke.exe" \
  > "${report}/static-smoke-pe.txt"
grep -F 'file format pei-aarch64-little' \
  "${report}/static-smoke-pe.txt"
grep -Fi 'DLL Name: msys-2.0.dll' \
  "${report}/static-smoke-pe.txt"
if grep -Fi 'DLL Name: msys-crypt-2.dll' \
    "${report}/static-smoke-pe.txt"; then
  echo 'static smoke unexpectedly imports the shared libxcrypt DLL' >&2
  exit 1
fi
if grep -Ei 'cygwin1\.dll|x86_64|pei-i386' \
    "${report}/static-smoke-pe.txt"; then
  echo 'static smoke contains a foreign fallback' >&2
  exit 1
fi

{
  printf 'target\t%s\n' "${target}"
  printf 'runtime-dll\t%s\n' "${dll#${dest}/}"
  printf 'runtime-imports\t'
  grep -i 'DLL Name:' "${report}/runtime-pe.txt" |
    sed -E 's/^[[:space:]]*DLL Name:[[:space:]]*//' |
    LC_ALL=C sort |
    paste -sd, -
  printf 'import-library-members\t%s\n' \
    "$(wc -l < "${report}/import-library-members.txt")"
  printf 'static-library-members\t%s\n' \
    "$(wc -l < "${report}/static-library-members.txt")"
  printf 'header\t%s\n' "${header#${dest}/}"
  printf 'pkgconfig\t%s\n' "${pkgconfig#${dest}/}"
} > "${report}/package-contract.txt"

(
  cd "${dest}"
  find usr -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum
) > "${report}/staged-files.sha256"
sha256sum \
  "${report}/native-crypt-smoke.exe" \
  "${report}/static-crypt-smoke.exe" \
  > "${report}/smoke-binaries.sha256"

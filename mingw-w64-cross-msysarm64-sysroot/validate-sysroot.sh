#!/usr/bin/env bash

set -euo pipefail

target="${TARGET:-aarch64-pc-msys}"
sysroot="${SYSROOT:-/opt/${target}}"
cc="${CC:-${target}-gcc}"
objdump="${OBJDUMP:-${target}-objdump}"
tests="${sysroot}/share/msys-sysroot/tests"
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

command -v "${cc}" >/dev/null
command -v "${objdump}" >/dev/null

macros="$("${cc}" --sysroot="${sysroot}" -dM -E -x c /dev/null)"
grep -q '^#define __aarch64__ 1$' <<<"${macros}"
grep -q '^#define __CYGWIN__ 1$' <<<"${macros}"
grep -q '^#define _WIN64 1$' <<<"${macros}"
grep -q '^#define __LP64__ 1$' <<<"${macros}"
grep -q '^#define __SIZEOF_LONG__ 8$' <<<"${macros}"
grep -q '^#define __SIZEOF_POINTER__ 8$' <<<"${macros}"
grep -q '^#define __SIZEOF_LONG_DOUBLE__ 8$' <<<"${macros}"
grep -q '^#define __LDBL_MANT_DIG__ 53$' <<<"${macros}"

for unit in newlib winsup w32api abi; do
  "${cc}" \
    --sysroot="${sysroot}" \
    -specs="${sysroot}/lib/cygwin-compile-only.specs" \
    -O1 -g -fexceptions -funwind-tables \
    -c "${tests}/${unit}.c" \
    -o "${workdir}/${unit}.o"
  "${objdump}" -f "${workdir}/${unit}.o" \
    | grep -F "file format pe-aarch64-little"
done

"${objdump}" -h "${workdir}/abi.o" | grep -E '\.(pdata|xdata)'
tls_dump="$("${objdump}" -h -r -t "${workdir}/abi.o")"
grep -Eq '(\.tls|TLS|__emutls_(get_address|[tv]\.cygwin_tls_probe))' \
  <<<"${tls_dump}"

cygwin_trace="$(
  "${cc}" \
    --sysroot="${sysroot}" \
    -specs="${sysroot}/lib/cygwin-compile-only.specs" \
    -H -E "${tests}/winsup.c" \
    -o /dev/null 2>&1
)"
w32api_trace="$(
  "${cc}" \
    --sysroot="${sysroot}" \
    -specs="${sysroot}/lib/cygwin-compile-only.specs" \
    -H -E "${tests}/w32api.c" \
    -o /dev/null 2>&1
)"
grep -F "${sysroot}/include/cygwin/" <<<"${cygwin_trace}"
grep -F "${sysroot}/include/w32api/" <<<"${w32api_trace}"

(
  cd /
  sha256sum -c \
    /usr/share/msys-sysroot/sysroot-manifest.sha256
)

#!/usr/bin/env bash

set -euo pipefail

root=${1:?usage: validate-expat.sh ROOT REPORT_DIR}
report=${2:?usage: validate-expat.sh ROOT REPORT_DIR}
target=${TARGET:-aarch64-pc-msys}
prefix=${TARGET_PREFIX:-/usr}
expected_version=${EXPECTED_VERSION:-2.7.1}
run_native=${RUN_NATIVE:-auto}
cc=${TARGET_CC:-${target}-gcc}
objdump=${TARGET_OBJDUMP:-${target}-objdump}
ar=${TARGET_AR:-${target}-ar}
nm=${TARGET_NM:-${target}-nm}
pkg_config=${PKG_CONFIG:-pkg-config}
scanner=${PSEUDO_RELOC_SCANNER:-}
powershell=${POWERSHELL:-pwsh.exe}
scanner_objdump=${SCANNER_OBJDUMP:-/opt/bin/aarch64-pc-cygwin-objdump.exe}
scanner_nm=${SCANNER_NM:-/opt/bin/aarch64-pc-cygwin-nm.exe}

root=${root%/}
tree="${root}${prefix}"
bindir="${tree}/bin"
includedir="${tree}/include"
libdir="${tree}/lib"
pcfile="${libdir}/pkgconfig/expat.pc"
cmake_import="${libdir}/cmake/expat-${expected_version}/expat-noconfig.cmake"
smoke_source="${report}/xml-parser-smoke.c"
smoke_binary="${report}/xml-parser-smoke.exe"
static_smoke_binary="${report}/xml-parser-static-smoke.exe"

mkdir -p "${report}"

for tool in "${cc}" "${objdump}" "${ar}" "${nm}" "${pkg_config}"; do
  command -v "${tool}" > /dev/null
done
if [[ -z "${scanner}" ]] \
    && [[ -f "${root}/share/doc/mingw-w64-cross-msysarm64-expat/check-aarch64-pseudo-relocs.ps1" ]]; then
  scanner="${root}/share/doc/mingw-w64-cross-msysarm64-expat/check-aarch64-pseudo-relocs.ps1"
fi
test -n "${scanner}"
test -f "${scanner}"
command -v "${powershell}" > /dev/null
test -x "${scanner_objdump}"
test -x "${scanner_nm}"

audit_pseudo_relocations() {
  local binary=$1
  local relative=$2
  local start end scanner_output

  start=$(
    "${nm}" -n "${binary}" \
      | awk '$3 == "__RUNTIME_PSEUDO_RELOC_LIST__" {print $1}'
  )
  end=$(
    "${nm}" -n "${binary}" \
      | awk '$3 == "__RUNTIME_PSEUDO_RELOC_LIST_END__" {print $1}'
  )
  test -n "${start}"
  test -n "${end}"
  if [[ "${start}" != "${end}" ]]; then
    printf 'ERROR: non-empty pseudo-relocation list in %s (%s..%s)\n' \
      "${relative}" "${start}" "${end}" >&2
    exit 1
  fi
  printf '%s\t%s\t%s\tempty\n' "${relative}" "${start}" "${end}" \
    >> "${report}/pseudo-relocations.txt"

  scanner_output="${report}/$(basename "${binary}").pseudo-relocs.json"
  "${powershell}" -NoProfile -ExecutionPolicy Bypass \
    -File "${scanner}" \
    -PePath "${binary}" \
    -OutputPath "${scanner_output}" \
    -Objdump "${scanner_objdump}" \
    -Nm "${scanner_nm}"
  grep -Eq '"result"[[:space:]]*:[[:space:]]*"pass"' "${scanner_output}"
  grep -Eq '"record_count"[[:space:]]*:[[:space:]]*0' "${scanner_output}"
}

test -f "${includedir}/expat.h"
test -f "${includedir}/expat_external.h"
test -f "${libdir}/libexpat.a"
test -f "${libdir}/libexpat.dll.a"
test -f "${pcfile}"
test -f "${cmake_import}"
test -f "${bindir}/xmlwf.exe"

mapfile -d '' dlls < <(
  find "${bindir}" -maxdepth 1 -type f -name 'msys-expat-*.dll' -print0
)
test "${#dlls[@]}" -eq 1
expat_dll=${dlls[0]}
binaries=("${expat_dll}" "${bindir}/xmlwf.exe")

: > "${report}/binary-formats.txt"
: > "${report}/imports.txt"
: > "${report}/pseudo-relocations.txt"
for binary in "${binaries[@]}"; do
  relative=${binary#"${root}/"}
  audit="${report}/$(basename "${binary}").objdump.txt"
  "${objdump}" -f -p "${binary}" > "${audit}"
  grep -F 'file format pei-aarch64-little' "${audit}"
  if grep -Eiq \
      'file format (pei?-x86-64|pei?-i386)|architecture: i386|x86_64|DLL Name: cygwin1\.dll' \
      "${audit}"; then
    printf 'ERROR: foreign target payload: %s\n' "${relative}" >&2
    exit 1
  fi
  {
    printf '=== %s ===\n' "${relative}"
    grep -E 'file format|architecture:' "${audit}"
  } >> "${report}/binary-formats.txt"
  {
    printf '=== %s ===\n' "${relative}"
    awk '/DLL Name:/ {print $3}' "${audit}" | LC_ALL=C sort -fu
  } >> "${report}/imports.txt"
  audit_pseudo_relocations "${binary}" "${relative}"
done

grep -F 'DLL Name: msys-2.0.dll' \
  "${report}/$(basename "${expat_dll}").objdump.txt"
grep -F 'DLL Name: msys-2.0.dll' \
  "${report}/xmlwf.exe.objdump.txt"
grep -Fi "DLL Name: $(basename "${expat_dll}")" \
  "${report}/xmlwf.exe.objdump.txt"

archives=(
  "${libdir}/libexpat.a"
  "${libdir}/libexpat.dll.a"
)
: > "${report}/archive-formats.txt"
for archive in "${archives[@]}"; do
  relative=${archive#"${root}/"}
  audit="${report}/$(basename "${archive}").objdump.txt"
  "${objdump}" -f "${archive}" > "${audit}"
  test "$("${ar}" t "${archive}" | wc -l)" -gt 0
  test "$(grep -c 'file format' "${audit}")" -gt 0
  if awk '/file format/ && $NF != "pe-aarch64-little" {bad=1} END {exit bad ? 0 : 1}' \
      "${audit}"; then
    printf 'ERROR: non-AA64 archive member: %s\n' "${relative}" >&2
    exit 1
  fi
  if grep -Eiq 'pe-x86-64|pei-x86-64|architecture: i386|x86_64' "${audit}"; then
    printf 'ERROR: x64 archive member: %s\n' "${relative}" >&2
    exit 1
  fi
  printf '%s\t%s members\tpe-aarch64-little\n' \
    "${relative}" "$("${ar}" t "${archive}" | wc -l)" \
    >> "${report}/archive-formats.txt"
  "${nm}" -s "${archive}" \
    > "${report}/$(basename "${archive}").archive-index.txt"
done
grep -Eq '^[[:space:]]*XML_ParserCreate in ' \
  "${report}/libexpat.a.archive-index.txt"
grep -Eq '^[[:space:]]*__imp_XML_ParserCreate in ' \
  "${report}/libexpat.dll.a.archive-index.txt"

grep -Fx 'prefix=/usr' "${pcfile}"
grep -Fx 'exec_prefix=${prefix}' "${pcfile}"
grep -Fx 'libdir=${exec_prefix}/lib' "${pcfile}"
grep -Fx 'includedir=${prefix}/include' "${pcfile}"
if grep -Eiq '(^|[= ])([A-Za-z]:\\|/cygdrive/|/tmp/)' "${pcfile}"; then
  printf 'ERROR: host path leaked into expat.pc\n' >&2
  exit 1
fi
grep -F '${_IMPORT_PREFIX}/lib/libexpat.dll.a' "${cmake_import}"
grep -F '${_IMPORT_PREFIX}/bin/msys-expat-1.dll' "${cmake_import}"
if grep -Eiq 'cygexpat|x86_64|/cygdrive/|[A-Za-z]:\\' "${cmake_import}"; then
  printf 'ERROR: foreign identity or host path leaked into development metadata\n' >&2
  exit 1
fi

pc_version=$(
  PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 \
  PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 \
  PKG_CONFIG_LIBDIR="${libdir}/pkgconfig" \
  PKG_CONFIG_SYSROOT_DIR="${root}" \
    "${pkg_config}" --modversion expat
)
test "${pc_version}" = "${expected_version}"
pc_cflags=$(
  PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 \
  PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 \
  PKG_CONFIG_LIBDIR="${libdir}/pkgconfig" \
  PKG_CONFIG_SYSROOT_DIR="${root}" \
    "${pkg_config}" --cflags expat
)
pc_libs=$(
  PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 \
  PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 \
  PKG_CONFIG_LIBDIR="${libdir}/pkgconfig" \
  PKG_CONFIG_SYSROOT_DIR="${root}" \
    "${pkg_config}" --libs expat
)
case "${pc_cflags}" in
  *"${includedir}"*) ;;
  *)
    printf 'ERROR: pkg-config did not sysroot include flags: %s\n' \
      "${pc_cflags}" >&2
    exit 1
    ;;
esac
case "${pc_libs}" in
  *"${libdir}"*'-lexpat'*) ;;
  *)
    printf 'ERROR: pkg-config did not sysroot library flags: %s\n' \
      "${pc_libs}" >&2
    exit 1
    ;;
esac
{
  printf 'version\t%s\n' "${pc_version}"
  printf 'cflags\t%s\n' "${pc_cflags}"
  printf 'libs\t%s\n' "${pc_libs}"
} > "${report}/metadata.txt"

cat > "${smoke_source}" <<'EOF'
#include <expat.h>
#include <stdio.h>
#include <string.h>

struct state {
  unsigned int elements;
  int saw_root;
};

static void XMLCALL
start_element(void *data, const XML_Char *name, const XML_Char **attributes) {
  struct state *state = (struct state *)data;
  (void)attributes;
  state->elements++;
  if (strcmp(name, "root") == 0)
    state->saw_root = 1;
}

int
main(void) {
  static const char document[] = "<root><child value=\"AA64\"/></root>";
  struct state state = {0, 0};
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser == NULL)
    return 10;
  XML_SetUserData(parser, &state);
  XML_SetStartElementHandler(parser, start_element);
  if (XML_Parse(parser, document, (int)strlen(document), XML_TRUE)
      != XML_STATUS_OK) {
    XML_ParserFree(parser);
    return 11;
  }
  XML_ParserFree(parser);
  if (state.elements != 2 || !state.saw_root)
    return 12;
  puts("expat-xml-smoke-ok");
  return 0;
}
EOF

"${cc}" -O2 -pipe ${pc_cflags} "${smoke_source}" ${pc_libs} \
  -o "${smoke_binary}"
"${objdump}" -f -p "${smoke_binary}" \
  > "${report}/xml-parser-smoke.objdump.txt"
grep -F 'file format pei-aarch64-little' \
  "${report}/xml-parser-smoke.objdump.txt"
grep -F 'DLL Name: msys-2.0.dll' \
  "${report}/xml-parser-smoke.objdump.txt"
grep -Fi "DLL Name: $(basename "${expat_dll}")" \
  "${report}/xml-parser-smoke.objdump.txt"
if grep -Eiq 'cygwin1\.dll|pei?-x86-64|architecture: i386|x86_64' \
    "${report}/xml-parser-smoke.objdump.txt"; then
  printf 'ERROR: XML parser smoke has a foreign payload or import\n' >&2
  exit 1
fi
audit_pseudo_relocations "${smoke_binary}" xml-parser-smoke.exe

"${cc}" -O2 -pipe -DXML_STATIC ${pc_cflags} \
  "${smoke_source}" "${libdir}/libexpat.a" -lm \
  -o "${static_smoke_binary}"
"${objdump}" -f -p "${static_smoke_binary}" \
  > "${report}/xml-parser-static-smoke.objdump.txt"
grep -F 'file format pei-aarch64-little' \
  "${report}/xml-parser-static-smoke.objdump.txt"
grep -F 'DLL Name: msys-2.0.dll' \
  "${report}/xml-parser-static-smoke.objdump.txt"
if grep -Eiq 'cygwin1\.dll|msys-expat-[0-9]+\.dll|pei?-x86-64|architecture: i386|x86_64' \
    "${report}/xml-parser-static-smoke.objdump.txt"; then
  printf 'ERROR: static XML parser smoke has a foreign payload or Expat DLL import\n' >&2
  exit 1
fi
audit_pseudo_relocations \
  "${static_smoke_binary}" \
  xml-parser-static-smoke.exe

host_arch=${NATIVE_HOST_ARCH:-$(uname -m)}
case "${run_native}" in
  1|yes|true)
    native=1
    ;;
  0|no|false)
    native=0
    ;;
  auto)
    case "${host_arch}" in
      aarch64|arm64)
        native=1
        ;;
      *)
        native=0
        ;;
    esac
    ;;
  *)
    printf 'ERROR: unsupported RUN_NATIVE value: %s\n' "${run_native}" >&2
    exit 2
    ;;
esac

if [[ "${native}" -eq 1 ]]; then
  PATH="${bindir}:${root}/bin:${PATH}" \
    "${smoke_binary}" > "${report}/native-dynamic-execution.txt"
  PATH="${bindir}:${root}/bin:${PATH}" \
    "${static_smoke_binary}" > "${report}/native-static-execution.txt"
  grep -Fx 'expat-xml-smoke-ok' "${report}/native-dynamic-execution.txt"
  grep -Fx 'expat-xml-smoke-ok' "${report}/native-static-execution.txt"
  {
    printf 'dynamic\t'
    cat "${report}/native-dynamic-execution.txt"
    printf 'static\t'
    cat "${report}/native-static-execution.txt"
    printf 'status\texecuted\nhost\t%s\n' "${host_arch}"
  } > "${report}/native-execution.txt"
else
  printf 'status\tskipped\nhost\t%s\nreason\tnon-ARM64 build host\n' \
    "${host_arch}" > "${report}/native-execution.txt"
fi

rm -f "${smoke_binary}" "${static_smoke_binary}"

(
  cd "${root}"
  find "${prefix#/}" -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "${report}/validated-tree.sha256"

printf 'validated %s %s for %s\n' "${expected_version}" "${prefix}" "${target}"

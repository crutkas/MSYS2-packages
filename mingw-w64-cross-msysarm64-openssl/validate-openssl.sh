#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: $0 DESTDIR SOURCE_DIR SMOKE_SOURCE REPORT_DIR SCANNER" >&2
  exit 2
fi

dest=$1
source_dir=$2
smoke_source=$3
report_dir=$4
scanner=$5
target=${TARGET:?TARGET is required}
tool_target=${TOOL_TARGET:?TOOL_TARGET is required}
binutils_release_tag=${BINUTILS_RELEASE_TAG:?BINUTILS_RELEASE_TAG is required}
binutils_version=${BINUTILS_VERSION:?BINUTILS_VERSION is required}
linker_sha256=${LINKER_SHA256:?LINKER_SHA256 is required}
openssl_version=${OPENSSL_VERSION:?OPENSSL_VERSION is required}
runtime_release_tag=${RUNTIME_RELEASE_TAG:?RUNTIME_RELEASE_TAG is required}
runtime_version=${RUNTIME_VERSION:?RUNTIME_VERSION is required}
gcc_release_tag=${GCC_RELEASE_TAG:?GCC_RELEASE_TAG is required}
gcc_version=${GCC_VERSION:?GCC_VERSION is required}
smoke_sources_dir=${SMOKE_SOURCES_DIR:?SMOKE_SOURCES_DIR is required}
pkgroot="${dest}/usr"
cc="${target}-gcc"
objdump="${tool_target}-objdump"
ar="${tool_target}-ar"
nm="${tool_target}-nm"
strings="${tool_target}-strings"
linker="${tool_target}-ld"
pwsh=$(command -v pwsh.exe)
linker_path=$(command -v "${linker}")
[[ "${linker_path}" == *.exe ]] || linker_path="${linker_path}.exe"

rm -rf "${report_dir}"
mkdir -p \
  "${report_dir}/pe" \
  "${report_dir}/pseudo-relocs" \
  "${report_dir}/archives" \
  "${report_dir}/smoke"

test "$(pacman -Q mingw-w64-cross-cygwinarm64-binutils)" = \
  "mingw-w64-cross-cygwinarm64-binutils ${binutils_version}"
test "$(pacman -Qoq "${linker_path}")" = \
  mingw-w64-cross-cygwinarm64-binutils
printf '%s  %s\n' "${linker_sha256}" "${linker_path}" \
  > "${report_dir}/linker.sha256"
sha256sum -c "${report_dir}/linker.sha256"
test "$(sha256sum "${scanner}" | cut -d' ' -f1)" = \
  888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9

test -f "${pkgroot}/bin/openssl.exe"
test -f "${pkgroot}/bin/msys-crypto-3.dll"
test -f "${pkgroot}/bin/msys-ssl-3.dll"
test -f "${pkgroot}/include/openssl/ssl.h"
test -f "${pkgroot}/include/openssl/configuration.h"
test -f "${pkgroot}/lib/libcrypto.a"
test -f "${pkgroot}/lib/libcrypto.dll.a"
test -f "${pkgroot}/lib/libssl.a"
test -f "${pkgroot}/lib/libssl.dll.a"
test -f "${pkgroot}/lib/pkgconfig/libcrypto.pc"
test -f "${pkgroot}/lib/pkgconfig/libssl.pc"
test -f "${pkgroot}/lib/pkgconfig/openssl.pc"
test -f "${pkgroot}/ssl/openssl.cnf"
test -d "${pkgroot}/lib/openssl/engines-3"
test -d "${pkgroot}/lib/ossl-modules"

grep -Eq '^# +define OPENSSL_SYS_CYGWIN 1$' \
  "${pkgroot}/include/openssl/configuration.h"
grep -Fq 'dir		= /usr/ssl' "${pkgroot}/ssl/openssl.cnf"
grep -Fq 'prefix=/usr' "${pkgroot}/lib/pkgconfig/libcrypto.pc"
grep -Fq 'prefix=/usr' "${pkgroot}/lib/pkgconfig/libssl.pc"
grep -Fq 'prefix=/usr' "${pkgroot}/lib/pkgconfig/openssl.pc"
grep -Fq '"Cygwin-aarch64"' "${source_dir}/Configurations/10-main.conf"
grep -Eq 'target.*Cygwin-aarch64' "${source_dir}/configdata.pm"

mapfile -d '' build_objects < <(
  find "${source_dir}" -type f -name '*.obj' -print0 | LC_ALL=C sort -z
)
if [[ "${#build_objects[@]}" -lt 1000 ]]; then
  echo "unexpectedly small OpenSSL object set: ${#build_objects[@]}" >&2
  exit 1
fi
printf '%s\0' "${build_objects[@]}" \
  | xargs -0 -n 128 "${objdump}" -f \
  > "${report_dir}/build-objects.file.txt"
if grep -E 'file format|architecture:' "${report_dir}/build-objects.file.txt" \
    | grep -Ev 'file format pe-aarch64-little|architecture: aarch64'; then
  echo "foreign object emitted by the OpenSSL build" >&2
  exit 1
fi

mapfile -d '' build_archives < <(
  find "${source_dir}" -type f -name '*.a' -print0 | LC_ALL=C sort -z
)
if [[ "${#build_archives[@]}" -lt 5 ]]; then
  echo "unexpectedly small OpenSSL archive set: ${#build_archives[@]}" >&2
  exit 1
fi
printf '%s\0' "${build_archives[@]}" \
  | xargs -0 -n 32 "${objdump}" -f \
  > "${report_dir}/build-archives.file.txt"
if grep -E 'file format|architecture:' "${report_dir}/build-archives.file.txt" \
    | grep -Ev 'file format pei?-aarch64-little|architecture: aarch64'; then
  echo "foreign archive member emitted by the OpenSSL build" >&2
  exit 1
fi

mapfile -d '' pe_files < <(
  find "${pkgroot}" -type f \( -name '*.exe' -o -name '*.dll' \) \
    -print0 | LC_ALL=C sort -z
)
if [[ "${#pe_files[@]}" -lt 4 ]]; then
  echo "expected at least four PE executables, libraries, or modules" >&2
  exit 1
fi

printf '%s\n' "${pe_files[@]#${dest}}" > "${report_dir}/pe-files.txt"
for file in "${pe_files[@]}"; do
  relative=${file#"${pkgroot}/"}
  slug=${relative//\//_}
  "${objdump}" -f "${file}" > "${report_dir}/pe/${slug}.file.txt"
  "${objdump}" -p "${file}" > "${report_dir}/pe/${slug}.imports.txt"
  "${objdump}" -r "${file}" > "${report_dir}/pe/${slug}.relocations.txt"
  "${pwsh}" -NoProfile -File "$(cygpath -w "${scanner}")" \
    -PePath "$(cygpath -w "${file}")" \
    -OutputPath "$(
      cygpath -w "${report_dir}/pseudo-relocs/${slug}.pseudo-relocs.json"
    )" \
    -Objdump "$(cygpath -w "$(command -v "${objdump}")")" \
    -Nm "$(cygpath -w "$(command -v "${nm}")")"
  grep -Fq 'file format pei-aarch64-little' \
    "${report_dir}/pe/${slug}.file.txt"
  grep -Fq 'architecture: aarch64' \
    "${report_dir}/pe/${slug}.file.txt"
  grep -Fiq 'DLL Name: msys-2.0.dll' \
    "${report_dir}/pe/${slug}.imports.txt"
  if grep -Eiq \
      'DLL Name: (cygwin1|msvcrt|ucrtbase|libwinpthread-1|libgcc_s_seh-1)\.dll|x86_64' \
      "${report_dir}/pe/${slug}.imports.txt"; then
    echo "foreign ABI import in ${relative}" >&2
    exit 1
  fi
  if grep -Eiq 'UNKNOWN|ambiguous|0x0*(21|12)([^0-9a-f]|$)' \
      "${report_dir}/pe/${slug}.relocations.txt"; then
    echo "ambiguous AArch64 relocation in ${relative}" >&2
    exit 1
  fi
done

grep -Fiq 'DLL Name: CRYPT32.dll' \
  "${report_dir}/pe/bin_msys-crypto-3.dll.imports.txt"
grep -Fiq 'DLL Name: msys-crypto-3.dll' \
  "${report_dir}/pe/bin_msys-ssl-3.dll.imports.txt"
grep -Fiq 'DLL Name: msys-ssl-3.dll' \
  "${report_dir}/pe/bin_openssl.exe.imports.txt"
grep -Fiq 'DLL Name: msys-crypto-3.dll' \
  "${report_dir}/pe/bin_openssl.exe.imports.txt"

mapfile -d '' modules < <(
  find "${pkgroot}/lib/openssl/engines-3" "${pkgroot}/lib/ossl-modules" \
    -type f -name '*.dll' -print0 | LC_ALL=C sort -z
)
if [[ "${#modules[@]}" -lt 1 ]]; then
  echo "no OpenSSL provider or engine modules were installed" >&2
  exit 1
fi
for module in "${modules[@]}"; do
  relative=${module#"${pkgroot}/"}
  slug=${relative//\//_}
  grep -Fiq 'DLL Name: msys-crypto-3.dll' \
    "${report_dir}/pe/${slug}.imports.txt"
done

mapfile -d '' archives < <(
  find "${pkgroot}/lib" -maxdepth 1 -type f -name '*.a' \
    -print0 | LC_ALL=C sort -z
)
if [[ "${#archives[@]}" -lt 4 ]]; then
  echo "expected static and import libraries for libcrypto and libssl" >&2
  exit 1
fi
for archive in "${archives[@]}"; do
  name=$(basename "${archive}")
  "${ar}" t "${archive}" > "${report_dir}/archives/${name}.members.txt"
  "${objdump}" -f "${archive}" > "${report_dir}/archives/${name}.file.txt"
  "${nm}" -s "${archive}" > "${report_dir}/archives/${name}.armap.txt"
  test -s "${report_dir}/archives/${name}.members.txt"
  grep -Fq 'Archive index:' "${report_dir}/archives/${name}.armap.txt"
  grep -Eq 'file format pei?-aarch64-little' \
    "${report_dir}/archives/${name}.file.txt"
  if grep -Eiq 'pei?-x86-64|architecture: i386:x86-64|cygwin1\.dll' \
      "${report_dir}/archives/${name}.file.txt"; then
    echo "foreign object in ${name}" >&2
    exit 1
  fi
done

find "${pkgroot}/bin" "${pkgroot}/lib" -type f -print0 \
  | xargs -0 "${strings}" > "${report_dir}/compiled-strings.txt"
if ! grep -Fq '/usr/ssl' "${report_dir}/compiled-strings.txt"; then
  echo "compiled OpenSSL payload does not contain /usr/ssl" >&2
  exit 1
fi

pc_flags=$(
  PKG_CONFIG_LIBDIR="${pkgroot}/lib/pkgconfig" \
  PKG_CONFIG_SYSROOT_DIR="${dest}" \
    pkg-config --cflags --libs openssl
)
case "${pc_flags}" in
  *"${dest}/usr/include"* ) ;;
  *)
    echo "pkg-config did not sysroot the include path: ${pc_flags}" >&2
    exit 1
    ;;
esac
case "${pc_flags}" in
  *"${dest}/usr/lib"* ) ;;
  *)
    echo "pkg-config did not sysroot the library path: ${pc_flags}" >&2
    exit 1
    ;;
esac
printf '%s\n' "${pc_flags}" > "${report_dir}/pkg-config-flags.txt"

"${cc}" \
  -I"${pkgroot}/include" \
  "${smoke_source}" \
  -L"${pkgroot}/lib" \
  -lssl \
  -lcrypto \
  -o "${report_dir}/smoke/openssl-smoke.exe"
"${objdump}" -f "${report_dir}/smoke/openssl-smoke.exe" \
  > "${report_dir}/smoke/openssl-smoke.file.txt"
"${objdump}" -p "${report_dir}/smoke/openssl-smoke.exe" \
  > "${report_dir}/smoke/openssl-smoke.imports.txt"
grep -Fq 'file format pei-aarch64-little' \
  "${report_dir}/smoke/openssl-smoke.file.txt"
grep -Fq 'architecture: aarch64' \
  "${report_dir}/smoke/openssl-smoke.file.txt"
grep -Fiq 'DLL Name: msys-2.0.dll' \
  "${report_dir}/smoke/openssl-smoke.imports.txt"
grep -Fiq 'DLL Name: msys-ssl-3.dll' \
  "${report_dir}/smoke/openssl-smoke.imports.txt"
grep -Fiq 'DLL Name: msys-crypto-3.dll' \
  "${report_dir}/smoke/openssl-smoke.imports.txt"
"${pwsh}" -NoProfile -File "$(cygpath -w "${scanner}")" \
  -PePath "$(cygpath -w "${report_dir}/smoke/openssl-smoke.exe")" \
  -OutputPath "$(cygpath -w "${report_dir}/smoke/openssl-smoke.pseudo-relocs.json")" \
  -Objdump "$(cygpath -w "$(command -v "${objdump}")")" \
  -Nm "$(cygpath -w "$(command -v "${nm}")")"

"${cc}" \
  -I"${pkgroot}/include" \
  "${smoke_source}" \
  "${pkgroot}/lib/libssl.a" \
  "${pkgroot}/lib/libcrypto.a" \
  -lcrypt32 \
  -ldl \
  -lpthread \
  -o "${report_dir}/smoke/openssl-static-smoke.exe"
"${objdump}" -f "${report_dir}/smoke/openssl-static-smoke.exe" \
  > "${report_dir}/smoke/openssl-static-smoke.file.txt"
"${objdump}" -p "${report_dir}/smoke/openssl-static-smoke.exe" \
  > "${report_dir}/smoke/openssl-static-smoke.imports.txt"
grep -Fq 'file format pei-aarch64-little' \
  "${report_dir}/smoke/openssl-static-smoke.file.txt"
grep -Fiq 'DLL Name: msys-2.0.dll' \
  "${report_dir}/smoke/openssl-static-smoke.imports.txt"
if grep -Eiq 'DLL Name: msys-(ssl|crypto)-3\.dll' \
    "${report_dir}/smoke/openssl-static-smoke.imports.txt"; then
  echo "static OpenSSL smoke unexpectedly imports shared OpenSSL DLLs" >&2
  exit 1
fi
"${pwsh}" -NoProfile -File "$(cygpath -w "${scanner}")" \
  -PePath "$(cygpath -w "${report_dir}/smoke/openssl-static-smoke.exe")" \
  -OutputPath "$(
    cygpath -w "${report_dir}/smoke/openssl-static-smoke.pseudo-relocs.json"
  )" \
  -Objdump "$(cygpath -w "$(command -v "${objdump}")")" \
  -Nm "$(cygpath -w "$(command -v "${nm}")")"

"${cc}" -O0 -g -shared \
  "${smoke_sources_dir}/dlopen-generic.c" \
  -o "${report_dir}/smoke/dlopen-generic.dll"
"${cc}" -O0 -g -shared \
  "${smoke_sources_dir}/dlopen-nodllmain.c" \
  -o "${report_dir}/smoke/dlopen-nodllmain.dll"
"${cc}" -O0 -g -shared -Wl,-e,0 \
  "${smoke_sources_dir}/dlopen-nodllmain.c" \
  -o "${report_dir}/smoke/dlopen-data-only.dll"
"${cc}" -O0 -g -shared \
  -I"${pkgroot}/include" \
  "${smoke_sources_dir}/dlopen-crypto.c" \
  -L"${pkgroot}/lib" \
  -lcrypto \
  -o "${report_dir}/smoke/dlopen-crypto.dll"
"${cc}" -O0 -g -shared \
  -I"${pkgroot}/include" \
  "${smoke_sources_dir}/provider-minimal.c" \
  -L"${pkgroot}/lib" \
  -lcrypto \
  -o "${report_dir}/smoke/provider-minimal.dll"
"${cc}" -O0 -g \
  "${smoke_sources_dir}/dlopen-smoke.c" \
  -ldl \
  -o "${report_dir}/smoke/dlopen-smoke.exe"
"${cc}" -O0 -g \
  "${smoke_sources_dir}/loadlibrary-smoke.c" \
  -o "${report_dir}/smoke/loadlibrary-smoke.exe"

for name in \
  dlopen-generic.dll \
  dlopen-nodllmain.dll \
  dlopen-data-only.dll \
  dlopen-crypto.dll \
  provider-minimal.dll \
  dlopen-smoke.exe \
  loadlibrary-smoke.exe
do
  "${objdump}" -f "${report_dir}/smoke/${name}" \
    > "${report_dir}/smoke/${name}.file.txt"
  "${objdump}" -p "${report_dir}/smoke/${name}" \
    > "${report_dir}/smoke/${name}.imports.txt"
  grep -Fq 'file format pei-aarch64-little' \
    "${report_dir}/smoke/${name}.file.txt"
  grep -Fq 'architecture: aarch64' \
    "${report_dir}/smoke/${name}.file.txt"
  grep -Fiq 'DLL Name: msys-2.0.dll' \
    "${report_dir}/smoke/${name}.imports.txt"
  if grep -Eiq \
      'DLL Name: (cygwin1|msvcrt|ucrtbase|libwinpthread-1|libgcc_s_seh-1)\.dll|x86_64' \
      "${report_dir}/smoke/${name}.file.txt" \
      "${report_dir}/smoke/${name}.imports.txt"; then
    echo "foreign ABI in ${name}" >&2
    exit 1
  fi
  "${pwsh}" -NoProfile -File "$(cygpath -w "${scanner}")" \
    -PePath "$(cygpath -w "${report_dir}/smoke/${name}")" \
    -OutputPath "$(
      cygpath -w "${report_dir}/smoke/${name}.pseudo-relocs.json"
    )" \
    -Objdump "$(cygpath -w "$(command -v "${objdump}")")" \
    -Nm "$(cygpath -w "$(command -v "${nm}")")"
done
grep -Fiq 'DLL Name: msys-crypto-3.dll' \
  "${report_dir}/smoke/dlopen-crypto.dll.imports.txt"
grep -Fiq 'DLL Name: msys-crypto-3.dll' \
  "${report_dir}/smoke/provider-minimal.dll.imports.txt"
if grep -Fiq 'DLL Name: msys-crypto-3.dll' \
    "${report_dir}/smoke/dlopen-generic.dll.imports.txt"; then
  echo "generic dlopen module unexpectedly links libcrypto" >&2
  exit 1
fi
for name in dlopen-nodllmain.dll dlopen-data-only.dll; do
  if grep -Fiq 'DLL Name: msys-crypto-3.dll' \
      "${report_dir}/smoke/${name}.imports.txt"; then
    echo "${name} unexpectedly links libcrypto" >&2
    exit 1
  fi
done

python - "${report_dir}" <<'PY'
import json
import pathlib
import sys

report_dir = pathlib.Path(sys.argv[1])
reports = sorted(report_dir.rglob("*.pseudo-relocs.json"))
if len(reports) < 16:
    raise SystemExit(f"expected at least 16 pseudo-reloc reports, found {len(reports)}")
for path in reports:
    report = json.loads(path.read_text(encoding="utf-8-sig"))
    if report["result"] != "pass" or report["policy_violations"]:
        raise SystemExit(f"pseudo-reloc policy failed: {path}")
    if any(flag in (12, 21) for flag in report["flags"]):
        raise SystemExit(f"ambiguous pseudo-reloc flag in {path}")
    report["input_path"] = f"<PE>/{path.name.removesuffix('.pseudo-relocs.json')}"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
summary = {
    "schema": 1,
    "reports": len(reports),
    "flags": {
        path.name: json.loads(path.read_text(encoding="utf-8-sig"))["flags"]
        for path in reports
    },
    "rejected_flags": [12, 21],
    "result": "pass",
}
(report_dir / "pseudo-reloc-summary.json").write_text(
    json.dumps(summary, indent=2) + "\n",
    encoding="utf-8",
)
PY

cat > "${report_dir}/source-identity.txt" <<EOF
package-version	${openssl_version}
source-url	https://github.com/openssl/openssl/releases/download/openssl-${openssl_version}/openssl-${openssl_version}.tar.gz
source-sha256	529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f
configure-target	Cygwin-aarch64
configure-options	shared no-asm no-tests
target	${target}
abi	MSYS POSIX LP64
binutils-release	${binutils_release_tag}
binutils-version	${binutils_version}
binutils-package-sha256	3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b
binutils-producer-head	3356eec1411983cc252b04afac32bca5f3b8d824
binutils-producer-run	33044771291
binutils-source-commit	3f05fc4d3e0eeab265f2157e3257a7067b6e7223
binutils-source-tree	ecca625d45883e13128283a8c1750dac7997f729
binutils-source-archive-sha256	d11c2b4453318a6168287fe74655c54aa15bf12f415f9ffe3f0ea32e30a3411e
linker-sha256	${linker_sha256}
scanner-sha256	888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9
runtime-release	${runtime_release_tag}
runtime-version	${runtime_version}
gcc-release	${gcc_release_tag}
gcc-version	${gcc_version}
EOF

{
  cd "${dest}"
  find usr -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
} > "${report_dir}/payload.sha256"

{
  printf 'pe-files\t%s\n' "${#pe_files[@]}"
  printf 'provider-engine-modules\t%s\n' "${#modules[@]}"
  printf 'archives\t%s\n' "${#archives[@]}"
  printf 'build-objects\t%s\n' "${#build_objects[@]}"
  printf 'build-archives\t%s\n' "${#build_archives[@]}"
  printf 'target\t%s\n' "${target}"
  printf 'openssl\t%s\n' "${openssl_version}"
} > "${report_dir}/summary.txt"

find "${report_dir}" -type f \
  \( -name '*.txt' -o -name '*.sha256' -o -name '*.json' \) -print0 \
  | xargs -0 sed -i \
      -e "s|${dest}|<DESTDIR>|g" \
      -e "s|${source_dir}|<SOURCE>|g" \
      -e "s|${report_dir}|<REPORT>|g"

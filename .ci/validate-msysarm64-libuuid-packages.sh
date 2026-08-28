#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

toolchain_dir=$(
  cygpath -u \
    "${MSYSARM64_TOOLCHAIN_DIR:?missing toolchain snapshot directory}"
)
runtime_name=mingw-w64-cross-msysarm64-libuuid
devel_name=mingw-w64-cross-msysarm64-libuuid-devel
runtime_archives=("${runtime_name}-2.40.2-2-x86_64.pkg.tar."*)
devel_archives=("${devel_name}-2.40.2-2-x86_64.pkg.tar."*)
[[ "${#runtime_archives[@]}" -eq 1 ]]
[[ "${#devel_archives[@]}" -eq 1 ]]

all_input_archives=(
  "${toolchain_dir}/mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst"
  "${toolchain_dir}/mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst"
)
for archive in "${all_input_archives[@]}"; do
  [[ -f "${archive}" ]]
done
transaction_archives=("${all_input_archives[@]}")

transaction_root=$(mktemp -d)
report_root=$(mktemp -d)
trap 'rm -rf "${transaction_root}" "${report_root}"' EXIT
evidence_dir=${LIBUUID_TRANSACTION_EVIDENCE_DIR:-"${PWD}/src/libuuid-transaction-report"}
rm -rf "${evidence_dir}"
mkdir -p \
  "${evidence_dir}" \
  "${transaction_root}/var/cache/pacman/pkg" \
  "${transaction_root}/etc/pacman.d/gnupg" \
  "${transaction_root}/var/empty-hooks" \
  "${transaction_root}/var/lib/pacman/local" \
  "${transaction_root}/var/lib/pacman" \
  "${transaction_root}/var/log"

host_db_packages=(gmp isl libiconv libintl libzstd mpc mpfr zlib)
cp /var/lib/pacman/local/ALPM_DB_VERSION \
  "${transaction_root}/var/lib/pacman/local/"
: > "${evidence_dir}/host-db-snapshot.txt"
for package in "${host_db_packages[@]}"; do
  identity=$(pacman -Q "${package}")
  source_db="/var/lib/pacman/local/${identity/ /-}"
  [[ -d "${source_db}" ]]
  cp -a "${source_db}" "${transaction_root}/var/lib/pacman/local/"
  printf '%s\n' "${identity}" >> "${evidence_dir}/host-db-snapshot.txt"
done
(
  cd "${transaction_root}/var/lib/pacman/local"
  find . -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "${evidence_dir}/host-db-files.sha256"
cat > "${transaction_root}/etc/pacman.conf" <<'EOF'
[options]
Architecture = x86_64
SigLevel = Never
LocalFileSigLevel = Never
EOF

pacman_args=(
  --root "${transaction_root}"
  --dbpath "${transaction_root}/var/lib/pacman"
  --cachedir "${transaction_root}/var/cache/pacman/pkg"
  --logfile "${transaction_root}/var/log/pacman.log"
  --config "${transaction_root}/etc/pacman.conf"
  --hookdir "${transaction_root}/var/empty-hooks"
  --gpgdir "${transaction_root}/etc/pacman.d/gnupg"
  --noconfirm
)
pacman_root() {
  pacman "${pacman_args[@]}" "$@"
}

{
  for archive in "${all_input_archives[@]}" \
    "${runtime_archives[0]}" "${devel_archives[0]}"
  do
    printf '%s  %s\n' \
      "$(sha256sum "${archive}" | awk '{ print $1 }')" \
      "${archive##*/}"
  done
} | LC_ALL=C sort -k2 > "${evidence_dir}/input-snapshot.sha256"
(
  cd "${evidence_dir}"
  sha256sum input-snapshot.sha256 > input-snapshot.seal
)
cat "${evidence_dir}/input-snapshot.sha256"
cat "${evidence_dir}/input-snapshot.seal"

MSYS=winsymlinks:sys pacman_root -U "${transaction_archives[@]}"

expected_toolchain=(
  'mingw-w64-cross-cygwinarm64-binutils 2.44.50-2'
  'mingw-w64-cross-cygwinarm64-libstdc++-headers 15.0.1dev-1'
  'mingw-w64-cross-cygwinarm64-gcc-libs-stage1 15.0.1dev-2'
  'mingw-w64-cross-cygwinarm64-gcc-stage1 15.0.1dev-2'
  'mingw-w64-cross-msysarm64-headers 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-windows-default-manifest 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-sysroot 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-runtime 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-runtime-devel 3.6.10.r0.ga527ace21-1'
  'mingw-w64-cross-msysarm64-w32api-runtime 14.0.0.r0.g9b3dd0125-1'
  'mingw-w64-cross-msysarm64-libstdc++-headers 15.0.1dev-1'
  'mingw-w64-cross-msysarm64-gcc-libs 15.0.1dev-1'
  'mingw-w64-cross-msysarm64-gcc 15.0.1dev-1'
)
for identity in "${expected_toolchain[@]}"; do
  package=${identity% *}
  [[ "$(pacman_root -Q "${package}")" == "${identity}" ]]
done
for tool in \
  addr2line ar as c++filt dlltool dllwrap elfedit gprof ld ld.bfd nm \
  objcopy objdump ranlib readelf size strings strip windmc windres
do
  alias_path="${transaction_root}/opt/bin/aarch64-pc-msys-${tool}.exe"
  [[ -L "${alias_path}" ]]
  [[ "$(readlink "${alias_path}")" == \
    "aarch64-pc-cygwin-${tool}.exe" ]]
  [[ "$(pacman_root -Qoq "${alias_path}")" == \
    mingw-w64-cross-cygwinarm64-binutils ]]
done
[[ "$(sha256sum "${transaction_root}/opt/bin/aarch64-pc-msys-ld.exe" \
  | awk '{ print $1 }')" == \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f ]]
for tool in ar nm ranlib; do
  [[ "$(pacman_root -Qoq \
    "${transaction_root}/opt/aarch64-pc-msys/bin/${tool}.exe")" == \
    mingw-w64-cross-msysarm64-gcc ]]
done

key_files=(
  /opt/aarch64-pc-msys/bin/msys-uuid-1.dll
  /opt/aarch64-pc-msys/usr/include/uuid/uuid.h
  /opt/aarch64-pc-msys/usr/lib/libuuid.dll.a
  /opt/aarch64-pc-msys/usr/lib/pkgconfig/uuid.pc
)
for path in "${key_files[@]}"; do
  [[ ! -e "${transaction_root}${path}" ]]
done

foreign_static=/opt/aarch64-pc-msys/usr/lib/libuuid.a
[[ "$(pacman_root -Qoq "${transaction_root}${foreign_static}")" == \
  mingw-w64-cross-msysarm64-w32api-runtime ]]
foreign_static_sha256=$(
  sha256sum "${transaction_root}${foreign_static}" | awk '{ print $1 }'
)
printf '%s  %s\n' "${foreign_static_sha256}" "${foreign_static}" \
  > "${evidence_dir}/foreign-static.sha256"

validate_install() {
  local phase=$1
  local validator="${transaction_root}/opt/aarch64-pc-msys/share/msys-sysroot/libuuid/validate-libuuid.sh"
  local smoke_source="${transaction_root}/opt/aarch64-pc-msys/share/msys-sysroot/libuuid/libuuid-smoke.c"

  [[ "$(pacman_root -Q "${runtime_name}")" == \
    "${runtime_name} 2.40.2-2" ]]
  [[ "$(pacman_root -Q "${devel_name}")" == \
    "${devel_name} 2.40.2-2" ]]
  pacman_root -Qk "${runtime_name}" "${devel_name}"

  [[ "$(pacman_root -Qoq "${transaction_root}${key_files[0]}")" == \
    "${runtime_name}" ]]
  for path in "${key_files[@]:1}"; do
    [[ "$(pacman_root -Qoq "${transaction_root}${path}")" == \
      "${devel_name}" ]]
  done
  [[ "$(pacman_root -Qoq "${transaction_root}${foreign_static}")" == \
    mingw-w64-cross-msysarm64-w32api-runtime ]]
  [[ "$(sha256sum "${transaction_root}${foreign_static}" \
    | awk '{ print $1 }')" == "${foreign_static_sha256}" ]]

  missing=$(pacman_root -T \
    'mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1' \
    'mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
    'mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1')
  [[ -z "${missing}" ]]

  TARGET=aarch64-pc-msys \
  TARGET_SYSROOT="${transaction_root}/opt/aarch64-pc-msys" \
  TARGET_CC="${transaction_root}/opt/bin/aarch64-pc-msys-gcc" \
  TARGET_AR="${transaction_root}/opt/bin/aarch64-pc-msys-ar" \
  TARGET_NM="${transaction_root}/opt/bin/aarch64-pc-msys-nm" \
  TARGET_OBJCOPY="${transaction_root}/opt/bin/aarch64-pc-msys-objcopy" \
  TARGET_OBJDUMP="${transaction_root}/opt/bin/aarch64-pc-msys-objdump" \
  CANONICAL_OBJDUMP="${transaction_root}/opt/bin/aarch64-pc-cygwin-objdump.exe" \
  CANONICAL_NM="${transaction_root}/opt/bin/aarch64-pc-cygwin-nm.exe" \
  TARGET_STATIC_SMOKE="${transaction_root}/opt/aarch64-pc-msys/share/msys-sysroot/libuuid/validation/libuuid-static-smoke.exe" \
    bash "${validator}" \
      "${transaction_root}" \
      "${report_root}/${phase}" \
      "${smoke_source}"
}

MSYS=winsymlinks:sys pacman_root -U \
  "${runtime_archives[0]}" "${devel_archives[0]}"
validate_install first-install

pacman_root -R "${devel_name}" "${runtime_name}"
for package in "${runtime_name}" "${devel_name}"; do
  ! pacman_root -Q "${package}" > /dev/null 2>&1
done
for path in "${key_files[@]}"; do
  [[ ! -e "${transaction_root}${path}" ]]
done
[[ "$(pacman_root -Qoq "${transaction_root}${foreign_static}")" == \
  mingw-w64-cross-msysarm64-w32api-runtime ]]
[[ "$(sha256sum "${transaction_root}${foreign_static}" \
  | awk '{ print $1 }')" == "${foreign_static_sha256}" ]]

MSYS=winsymlinks:sys pacman_root -U \
  "${runtime_archives[0]}" "${devel_archives[0]}"
validate_install reinstall

diff -u \
  "${report_root}/first-install/summary.tsv" \
  "${report_root}/reinstall/summary.tsv"
diff -u \
  "${report_root}/first-install/imports.tsv" \
  "${report_root}/reinstall/imports.tsv"
diff -u \
  "${report_root}/first-install/pseudo-relocs.tsv" \
  "${report_root}/reinstall/pseudo-relocs.tsv"

cp \
  "${report_root}/first-install/summary.tsv" \
  "${evidence_dir}/first-install-summary.tsv"
cp \
  "${report_root}/first-install/imports.tsv" \
  "${evidence_dir}/first-install-imports.tsv"
cp \
  "${report_root}/first-install/pseudo-relocs.tsv" \
  "${evidence_dir}/first-install-pseudo-relocs.tsv"
cp \
  "${report_root}/reinstall/summary.tsv" \
  "${evidence_dir}/reinstall-summary.tsv"
cp \
  "${report_root}/reinstall/imports.tsv" \
  "${evidence_dir}/reinstall-imports.tsv"
cp \
  "${report_root}/reinstall/pseudo-relocs.tsv" \
  "${evidence_dir}/reinstall-pseudo-relocs.tsv"
pacman_root -Q | LC_ALL=C sort > "${evidence_dir}/package-state.txt"
sed \
  -e "s|${transaction_root}|<transaction-root>|g" \
  -e "s|${toolchain_dir}|<toolchain-inputs>|g" \
  "${transaction_root}/var/log/pacman.log" \
  > "${evidence_dir}/pacman.log"
if grep -IRF \
    -e "${transaction_root}" \
    -e "${toolchain_dir}" \
    -e "${PWD}" \
    "${evidence_dir}"; then
  echo 'private path leaked into lifecycle evidence' >&2
  exit 1
fi
printf 'private-path-leaks\t0\n' > "${evidence_dir}/path-scan.tsv"
(
  cd "${evidence_dir}"
  sha256sum \
    first-install-imports.tsv \
    first-install-pseudo-relocs.tsv \
    first-install-summary.tsv \
    foreign-static.sha256 \
    host-db-files.sha256 \
    host-db-snapshot.txt \
    input-snapshot.sha256 \
    package-state.txt \
    pacman.log \
    path-scan.tsv \
    reinstall-imports.tsv \
    reinstall-pseudo-relocs.tsv \
    reinstall-summary.tsv \
    > evidence-manifest.sha256
  sha256sum evidence-manifest.sha256 > evidence.seal
  cat evidence.seal
)

#!/usr/bin/env bash

set -euo pipefail

artifact_dir=${1:?usage: validate-expat-packages.sh ARTIFACT_DIR REPORT_DIR FINAL_INPUT_DIR BOOTSTRAP_INPUT_DIR}
report=${2:?usage: validate-expat-packages.sh ARTIFACT_DIR REPORT_DIR FINAL_INPUT_DIR BOOTSTRAP_INPUT_DIR}
final_input_dir=${3:?usage: validate-expat-packages.sh ARTIFACT_DIR REPORT_DIR FINAL_INPUT_DIR BOOTSTRAP_INPUT_DIR}
bootstrap_input_dir=${4:?usage: validate-expat-packages.sh ARTIFACT_DIR REPORT_DIR FINAL_INPUT_DIR BOOTSTRAP_INPUT_DIR}
target=aarch64-pc-msys
version=2.7.1-1
script_dir=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
pacman_root="${work}/pacman-root"
compiler_wrapper="${work}/aarch64-pc-msys-gcc"

packages=(
  "${artifact_dir}/mingw-w64-cross-msysarm64-expat-${version}-x86_64.pkg.tar.zst"
  "${artifact_dir}/mingw-w64-cross-msysarm64-libexpat-${version}-x86_64.pkg.tar.zst"
  "${artifact_dir}/mingw-w64-cross-msysarm64-libexpat-devel-${version}-x86_64.pkg.tar.zst"
)
names=(
  mingw-w64-cross-msysarm64-expat
  mingw-w64-cross-msysarm64-libexpat
  mingw-w64-cross-msysarm64-libexpat-devel
)
bootstrap_packages=(
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-headers-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-windows-default-manifest-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-sysroot-3.6.10.r0.gee50e0223-1-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst"
  "${bootstrap_input_dir}/mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst"
)
bootstrap_hashes=(
  3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b
  5266346cc10b142f871704ce4277699b1a5daa3121dc869990b4bedce69c0611
  cc089511fede6042a25f83fcb5903fddeede89ddd9655360741513ee9015e3dc
  4ed8a30f592317bf7e4def6f3c773139f2565b0f8afaedd820f7ee46d33cad20
  53478f9a60e2fdad7d3b4357fa4fb937a1afab16af16a55e5a25ae9fac308fa7
  063579211851ed69370a6362f2795e39d9be0235a2bfe2f58da1bbd73a1d108e
  17a8fbc22227c541ff3179179d307045302f6b18fbc6207cf9d863a9e4dad98c
  1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6
)
final_packages=(
  "${final_input_dir}/mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst"
  "${final_input_dir}/mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst"
)
final_hashes=(
  263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21
  33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f
  e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca
  158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e
  c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1
  7727936f4212e5af04e9739eca60f157c0875796c1e82fcfb79fd4398b111e24
  9715aab6894379bf5ab936a3a559f286fb4aedbb64f0774d7457182e00648e08
  990f163cacf9ffce1b58445be91fedc57f135cc26a88d7dba109806446b41438
  a74887c76a933ec424933bf662729d94975b83138af783bd93f2e7acd95c3a22
)
installed_input_identities=(
  mingw-w64-cross-cygwinarm64-binutils=2.44.50-2
  mingw-w64-cross-cygwinarm64-gcc-stage1=15.0.1dev-2
  mingw-w64-cross-cygwinarm64-gcc-libs-stage1=15.0.1dev-2
  mingw-w64-cross-cygwinarm64-libstdc++-headers=15.0.1dev-1
  mingw-w64-cross-msysarm64-headers=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-windows-default-manifest=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-w32api-runtime=14.0.0.r0.g9b3dd0125-1
  mingw-w64-cross-msysarm64-libstdc++-headers=15.0.1dev-1
  mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1
  mingw-w64-cross-msysarm64-gcc=15.0.1dev-1
)

snapshot_db() {
  local db=$1
  local output=$2

  (
    cd "${db}"
    find . -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum
  ) > "${output}"
}

snapshot_tree() {
  local tree=$1
  local output=$2

  (
    cd "${tree}"
    find . -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum
    find . -type l -printf 'symlink\t%p\t%l\n' \
      | LC_ALL=C sort
  ) > "${output}"
}

isolated_pacman() {
  MSYS=winsymlinks:sys pacman \
    --config "${pacman_root}/etc/pacman.conf" \
    --root "${pacman_root}" \
    --dbpath "${pacman_root}/var/lib/pacman" \
    --cachedir "${pacman_root}/var/cache/pacman/pkg" \
    --logfile "${pacman_root}/var/log/pacman.log" \
    --hookdir "${pacman_root}/etc/pacman.d/hooks" \
    --noconfirm \
    "$@"
}

mkdir -p \
  "${report}" \
  "${work}/tree" \
  "${pacman_root}/etc" \
  "${pacman_root}/etc/pacman.d/hooks" \
  "${pacman_root}/var/cache/pacman/pkg" \
  "${pacman_root}/var/lib/pacman/local" \
  "${pacman_root}/var/log"
test "$(sha256sum /opt/bin/aarch64-pc-cygwin-ld.exe | cut -d' ' -f1)" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
cat > "${pacman_root}/etc/pacman.conf" <<'EOF'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
EOF
pacman -Q | LC_ALL=C sort > "${report}/shared-before-packages.txt"
snapshot_db /var/lib/pacman/local "${report}/shared-before-db.sha256"
snapshot_tree "/opt/${target}" "${report}/shared-before-target.sha256"
sha256sum /var/log/pacman.log > "${report}/shared-before-log.sha256"
for entry in /var/lib/pacman/local/*; do
  basename=$(basename "${entry}")
  case "${basename}" in
    mingw-w64-cross-cygwinarm64-*|mingw-w64-cross-msysarm64-*)
      ;;
    *)
      cp -a "${entry}" "${pacman_root}/var/lib/pacman/local/"
      ;;
  esac
done
isolated_pacman -Q | LC_ALL=C sort \
  > "${report}/isolated-host-baseline-packages.txt"

for package in "${packages[@]}"; do
  test -f "${package}"
done
test "$(find "${artifact_dir}" -maxdepth 1 -type f \
  -name 'mingw-w64-cross-msysarm64-*expat*.pkg.tar.zst' | wc -l)" -eq 3

sha256sum "${packages[@]}" > "${report}/package-sha256.txt"
for index in "${!bootstrap_packages[@]}"; do
  package=${bootstrap_packages[index]}
  test -f "${package}"
  printf '%s  %s\n' "${bootstrap_hashes[index]}" "${package}" \
    | sha256sum -c -
done
sha256sum "${bootstrap_packages[@]}" \
  > "${report}/bootstrap-input-sha256.txt"
for index in "${!final_packages[@]}"; do
  package=${final_packages[index]}
  test -f "${package}"
  printf '%s  %s\n' "${final_hashes[index]}" "${package}" \
    | sha256sum -c -
done
sha256sum "${final_packages[@]}" \
  > "${report}/final-input-sha256.txt"

for index in "${!packages[@]}"; do
  package=${packages[index]}
  name=${names[index]}
  info="${report}/${name}.PKGINFO"
  bsdtar -xOf "${package}" .PKGINFO > "${info}"
  grep -Fx "pkgname = ${name}" "${info}"
  grep -Fx "pkgver = ${version}" "${info}"
  grep -Fx 'arch = x86_64' "${info}"
  MSYS=winsymlinks:sys bsdtar -xf "${package}" -C "${work}/tree"
  bsdtar -tf "${package}" \
    | sed -e '/^\./d' -e '/\/$/d' \
    >> "${report}/owned-files.unsorted.txt"
done

sort "${report}/owned-files.unsorted.txt" > "${report}/owned-files.txt"
rm -f "${report}/owned-files.unsorted.txt"
if uniq -d "${report}/owned-files.txt" \
    > "${report}/duplicate-owned-files.txt" \
    && [[ -s "${report}/duplicate-owned-files.txt" ]]; then
  cat "${report}/duplicate-owned-files.txt" >&2
  exit 1
fi
cat > "${report}/expected-target-binaries.txt" <<EOF
opt/${target}/usr/bin/msys-expat-1.dll
opt/${target}/usr/bin/xmlwf.exe
opt/${target}/usr/lib/libexpat.a
opt/${target}/usr/lib/libexpat.dll.a
EOF
find "${work}/tree/opt/${target}" -type f \
  \( -name '*.a' -o -name '*.dll' -o -name '*.exe' -o -name '*.o' \) \
  -printf '%P\n' \
  | sed "s|^|opt/${target}/|" \
  | LC_ALL=C sort \
  > "${report}/actual-target-binaries.txt"
cmp "${report}/expected-target-binaries.txt" \
  "${report}/actual-target-binaries.txt"

grep -Fx 'depend = mingw-w64-cross-msysarm64-libexpat=2.7.1-1' \
  "${report}/mingw-w64-cross-msysarm64-expat.PKGINFO"
grep -Fx 'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
  "${report}/mingw-w64-cross-msysarm64-expat.PKGINFO"
grep -Fx 'depend = mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1' \
  "${report}/mingw-w64-cross-msysarm64-libexpat.PKGINFO"
grep -Fx 'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
  "${report}/mingw-w64-cross-msysarm64-libexpat.PKGINFO"
grep -Fx 'depend = mingw-w64-cross-msysarm64-libexpat=2.7.1-1' \
  "${report}/mingw-w64-cross-msysarm64-libexpat-devel.PKGINFO"
grep -Fx 'depend = mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1' \
  "${report}/mingw-w64-cross-msysarm64-libexpat-devel.PKGINFO"

for name in "${names[@]}"; do
  if pacman -Q "${name}" > /dev/null 2>&1; then
    printf 'ERROR: package exists in shared root before isolated transaction: %s\n' \
      "${name}" >&2
    exit 1
  fi
done

isolated_pacman -U "${bootstrap_packages[@]}" \
  | tee "${report}/bootstrap-transaction.txt"
isolated_pacman -U "${final_packages[@]}" \
  | tee "${report}/final-toolchain-transaction.txt"
for identity in "${installed_input_identities[@]}"; do
  name=${identity%%=*}
  test "$(isolated_pacman -Q "${name}")" = \
    "${name} ${identity#*=}"
  isolated_pacman -Qk "${name}"
done
test "$(sha256sum "${pacman_root}/opt/bin/aarch64-pc-cygwin-ld.exe" | cut -d' ' -f1)" = \
  075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f
cat > "${compiler_wrapper}" <<EOF
#!/usr/bin/env bash
exec /opt/bin/aarch64-pc-msys-gcc.exe -B"${pacman_root}/opt/bin/" "\$@"
EOF
chmod 755 "${compiler_wrapper}"

EXPECTED_VERSION=2.7.1 \
RUN_NATIVE=0 \
TARGET_CC="${compiler_wrapper}" \
TARGET_OBJDUMP="${pacman_root}/opt/bin/aarch64-pc-msys-objdump.exe" \
TARGET_AR="${pacman_root}/opt/bin/aarch64-pc-msys-ar.exe" \
TARGET_NM="${pacman_root}/opt/bin/aarch64-pc-msys-nm.exe" \
PSEUDO_RELOC_SCANNER="${work}/tree/opt/${target}/share/doc/mingw-w64-cross-msysarm64-expat/check-aarch64-pseudo-relocs.ps1" \
SCANNER_OBJDUMP="${pacman_root}/opt/bin/aarch64-pc-cygwin-objdump.exe" \
SCANNER_NM="${pacman_root}/opt/bin/aarch64-pc-cygwin-nm.exe" \
  bash "${script_dir}/validate-expat.sh" \
    "${work}/tree/opt/${target}" \
    "${report}/archive-tree"
snapshot_db "${pacman_root}/var/lib/pacman/local" \
  "${report}/isolated-before-expat-db.sha256"

isolated_pacman -U "${packages[@]}" \
  | tee "${report}/install-transaction.txt"

for name in "${names[@]}"; do
  isolated_pacman -Q "${name}"
  isolated_pacman -Qk "${name}"
done
isolated_pacman -Qi "${names[@]}" > "${report}/installed-metadata.txt"
test -z "$(isolated_pacman -T \
  mingw-w64-cross-msysarm64-libexpat=2.7.1-1 \
  mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1 \
  mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1 \
  mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1)"

test "$(isolated_pacman -Qoq "${pacman_root}/opt/${target}/usr/bin/xmlwf.exe")" = \
  mingw-w64-cross-msysarm64-expat
test "$(isolated_pacman -Qoq "${pacman_root}/opt/${target}/usr/bin/msys-expat-1.dll")" = \
  mingw-w64-cross-msysarm64-libexpat
test "$(isolated_pacman -Qoq "${pacman_root}/opt/${target}/usr/include/expat.h")" = \
  mingw-w64-cross-msysarm64-libexpat-devel

validator="${pacman_root}/opt/${target}/share/doc/mingw-w64-cross-msysarm64-expat/validate-expat.sh"
test -x "${validator}"
EXPECTED_VERSION=2.7.1 \
RUN_NATIVE=auto \
TARGET_CC="${compiler_wrapper}" \
TARGET_OBJDUMP="${pacman_root}/opt/bin/aarch64-pc-msys-objdump.exe" \
TARGET_AR="${pacman_root}/opt/bin/aarch64-pc-msys-ar.exe" \
TARGET_NM="${pacman_root}/opt/bin/aarch64-pc-msys-nm.exe" \
PSEUDO_RELOC_SCANNER="${validator%/validate-expat.sh}/check-aarch64-pseudo-relocs.ps1" \
SCANNER_OBJDUMP="${pacman_root}/opt/bin/aarch64-pc-cygwin-objdump.exe" \
SCANNER_NM="${pacman_root}/opt/bin/aarch64-pc-cygwin-nm.exe" \
  bash "${validator}" \
    "${pacman_root}/opt/${target}" \
    "${report}/installed-tree"
snapshot_db "${pacman_root}/var/lib/pacman/local" \
  "${report}/isolated-installed-db.sha256"

isolated_pacman -R "${names[@]}" \
  | tee "${report}/remove-transaction.txt"
for name in "${names[@]}"; do
  if isolated_pacman -Q "${name}" > /dev/null 2>&1; then
    printf 'ERROR: package remained after remove transaction: %s\n' \
      "${name}" >&2
    exit 1
  fi
done
test ! -e "${pacman_root}/opt/${target}/usr/bin/xmlwf.exe"
test ! -e "${pacman_root}/opt/${target}/usr/bin/msys-expat-1.dll"
test ! -e "${pacman_root}/opt/${target}/usr/include/expat.h"
snapshot_db "${pacman_root}/var/lib/pacman/local" \
  "${report}/isolated-removed-db.sha256"

isolated_pacman -U "${packages[@]}" \
  | tee "${report}/reinstall-transaction.txt"
for name in "${names[@]}"; do
  isolated_pacman -Q "${name}"
done
snapshot_db "${pacman_root}/var/lib/pacman/local" \
  "${report}/isolated-reinstalled-db.sha256"

pacman -Q | LC_ALL=C sort > "${report}/shared-after-packages.txt"
snapshot_db /var/lib/pacman/local "${report}/shared-after-db.sha256"
snapshot_tree "/opt/${target}" "${report}/shared-after-target.sha256"
sha256sum /var/log/pacman.log > "${report}/shared-after-log.sha256"
cmp "${report}/shared-before-packages.txt" \
  "${report}/shared-after-packages.txt"
cmp "${report}/shared-before-db.sha256" \
  "${report}/shared-after-db.sha256"
cmp "${report}/shared-before-target.sha256" \
  "${report}/shared-after-target.sha256"
cmp "${report}/shared-before-log.sha256" \
  "${report}/shared-after-log.sha256"

printf 'validated isolated atomic install/remove/reinstall for Expat %s\n' \
  "${version}"

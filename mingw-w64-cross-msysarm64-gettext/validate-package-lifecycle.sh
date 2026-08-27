#!/usr/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin"

if [[ "$#" -ne 7 ]]; then
  echo "usage: $0 PRIVATE_PACMAN ROOT RUNTIME_DIR LIBICONV_DIR PACKAGE_DIR EVIDENCE_DIR SHARED_MSYS_ROOT" >&2
  exit 2
fi

private_pacman=$1
root=$2
runtime_dir=$3
libiconv_dir=$4
package_dir=$5
evidence=$6
shared_root=$7
target=/opt/aarch64-pc-msys/usr
runtime=mingw-w64-cross-msysarm64-libintl
intl_devel=mingw-w64-cross-msysarm64-libintl-devel
gettext_libs=mingw-w64-cross-msysarm64-gettext-libs
gettext_devel=mingw-w64-cross-msysarm64-gettext-devel
tools=mingw-w64-cross-msysarm64-gettext
packages=("${runtime}" "${intl_devel}" "${gettext_libs}" "${gettext_devel}" "${tools}")

private_root="$(cygpath -am / | tr '[:upper:]' '[:lower:]')"
pacman_windows="$(cygpath -am "${private_pacman}" | tr '[:upper:]' '[:lower:]')"
root_windows="$(cygpath -am "${root}" | tr '[:upper:]' '[:lower:]')"
shared_windows="$(cygpath -am "${shared_root}" | tr '[:upper:]' '[:lower:]')"
test "${private_root}" != c:/msys64
test "${pacman_windows}" != c:/msys64/usr/bin/pacman.exe
case "${pacman_windows}" in
  "${private_root}"/*)
    ;;
  *)
    echo "private pacman escapes private MSYS root" >&2
    exit 1
    ;;
esac
case "${root_windows}" in
  "${private_root}"/*)
    ;;
  *)
    echo "lifecycle root escapes private MSYS root" >&2
    exit 1
    ;;
esac
case "${root_windows}" in
  "${shared_windows}"|"${shared_windows}"/*)
    echo "lifecycle root overlaps shared MSYS root" >&2
    exit 1
    ;;
esac
test -x "${private_pacman}"

dbpath="${root}/var/lib/pacman"
cachedir="${root}/var/cache/pacman/pkg"
logfile="${root}/var/log/pacman.log"
config="${root}/etc/pacman.conf"
hookdir="${root}/etc/pacman.d/hooks"
gpgdir="${root}/etc/pacman.d/gnupg"
mkdir -p \
  "${dbpath}/local" \
  "${cachedir}" \
  "$(dirname "${logfile}")" \
  "${hookdir}" \
  "${gpgdir}" \
  "${evidence}"
cat > "${config}" <<'EOF'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
EOF

pacman_args=(
  --root "${root}"
  --dbpath "${dbpath}"
  --cachedir "${cachedir}"
  --logfile "${logfile}"
  --config "${config}"
  --hookdir "${hookdir}"
  --gpgdir "${gpgdir}"
)

private_query() {
  "${private_pacman}" "${pacman_args[@]}" "$@"
}

tree_snapshot() {
  local path=$1
  local output=$2

  if [[ -d "${path}" ]]; then
    find "${path}" -type f -print0 |
      LC_ALL=C sort -z |
      xargs -0 -r sha256sum > "${output}"
  else
    : > "${output}"
  fi
}

sentinel_snapshot() {
  local name=$1

  tree_snapshot /var/lib/pacman/local \
    "${evidence}/private-host-${name}-db.sha256"
  if [[ -f /var/log/pacman.log ]]; then
    sha256sum /var/log/pacman.log \
      > "${evidence}/private-host-${name}-log.sha256"
  else
    : > "${evidence}/private-host-${name}-log.sha256"
  fi
  tree_snapshot "${shared_root}/var/lib/pacman/local" \
    "${evidence}/shared-host-${name}-db.sha256"
  if [[ -f "${shared_root}/var/log/pacman.log" ]]; then
    sha256sum "${shared_root}/var/log/pacman.log" \
      > "${evidence}/shared-host-${name}-log.sha256"
  else
    : > "${evidence}/shared-host-${name}-log.sha256"
  fi
}

snapshot() {
  local name=$1
  local status

  set +e
  private_query -Q 2>/dev/null | LC_ALL=C sort \
    > "${evidence}/${name}-packages.txt"
  status=${PIPESTATUS[0]}
  set -e
  test "${status}" -eq 0 -o "${status}" -eq 1
  tree_snapshot "${dbpath}/local" "${evidence}/${name}-db.sha256"
}

payload_manifest() {
  local name=$1
  local package path

  : > "${evidence}/${name}-payload.sha256"
  for package in "${packages[@]}"; do
    private_query -Qlq "${package}" |
      while IFS= read -r path; do
        if [[ -f "${root}${path}" ]]; then
          sha256sum "${root}${path}"
        fi
      done >> "${evidence}/${name}-payload.sha256"
  done
  LC_ALL=C sort -o "${evidence}/${name}-payload.sha256" \
    "${evidence}/${name}-payload.sha256"
}

runtime_archives=(
  "${runtime_dir}/mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
)
mapfile -t libiconv_archives < <(
  find "${libiconv_dir}" -maxdepth 1 -type f \
    -name 'mingw-w64-cross-msysarm64-libiconv-*.pkg.tar.zst' |
    LC_ALL=C sort
)
mapfile -t package_archives < <(
  find "${package_dir}" -maxdepth 1 -type f \
    -name 'mingw-w64-cross-msysarm64-*.pkg.tar.zst' |
    LC_ALL=C sort
)
test "${#runtime_archives[@]}" -eq 5
test "${#libiconv_archives[@]}" -eq 2
test "${#package_archives[@]}" -eq 5
for archive in \
  "${runtime_archives[@]}" "${libiconv_archives[@]}" "${package_archives[@]}"
do
  test -f "${archive}"
done

snapshot empty
sentinel_snapshot before
MSYS=winsymlinks:sys private_query --noconfirm -U \
  "${runtime_archives[@]}" "${libiconv_archives[@]}" "${package_archives[@]}"
for package in "${packages[@]}"; do
  test "$(private_query -Q "${package}")" = "${package} 0.22.5-1"
  private_query -Qk "${package}"
done
test "$(private_query -Qoq "${root}${target}/bin/msys-intl-8.dll")" = \
  "${runtime}"
test "$(private_query -Qoq "${root}${target}/include/libintl.h")" = \
  "${intl_devel}"
test "$(private_query -Qoq "${root}${target}/lib/libintl.dll.a")" = \
  "${intl_devel}"
test "$(private_query -Qoq "${root}${target}/bin/msys-gettextpo-0.dll")" = \
  "${gettext_libs}"
test "$(private_query -Qoq "${root}${target}/bin/gettext.exe")" = \
  "${tools}"
snapshot installed
payload_manifest installed

private_query --noconfirm -R \
  "${gettext_devel}" "${tools}" "${gettext_libs}" "${intl_devel}" "${runtime}"
for package in "${packages[@]}"; do
  ! private_query -Q "${package}" >/dev/null 2>&1
done
test ! -e "${root}${target}/bin/msys-intl-8.dll"
test ! -e "${root}${target}/include/libintl.h"
test ! -e "${root}${target}/bin/gettext.exe"
snapshot removed

MSYS=winsymlinks:sys private_query --noconfirm -U "${package_archives[@]}"
for package in "${packages[@]}"; do
  test "$(private_query -Q "${package}")" = "${package} 0.22.5-1"
  private_query -Qk "${package}"
done
snapshot reinstalled
payload_manifest reinstalled
diff -u \
  "${evidence}/installed-payload.sha256" \
  "${evidence}/reinstalled-payload.sha256"

sentinel_snapshot after
for scope in private-host shared-host; do
  cmp "${evidence}/${scope}-before-db.sha256" \
    "${evidence}/${scope}-after-db.sha256"
  cmp "${evidence}/${scope}-before-log.sha256" \
    "${evidence}/${scope}-after-log.sha256"
done

: > "${evidence}/candidate-archives.tsv"
: > "${evidence}/candidate-pkginfo.txt"
for archive in "${package_archives[@]}"; do
  pkginfo="${evidence}/${archive##*/}.PKGINFO"
  zstd -dc -- "${archive}" | bsdtar -xOf - .PKGINFO > "${pkginfo}"
  printf '%s\t%s\t%s\n' \
    "${archive##*/}" \
    "$(stat -c '%s' "${archive}")" \
    "$(sha256sum "${archive}" | cut -d ' ' -f 1)" \
    >> "${evidence}/candidate-archives.tsv"
  printf '%s\n' "--- ${archive##*/}" >> "${evidence}/candidate-pkginfo.txt"
  cat "${pkginfo}" >> "${evidence}/candidate-pkginfo.txt"
done

cat > "${evidence}/isolation-paths.txt" <<EOF
pacman=${private_pacman}
root=${root}
dbpath=${dbpath}
cachedir=${cachedir}
logfile=${logfile}
config=${config}
hookdir=${hookdir}
gpgdir=${gpgdir}
shared_root=${shared_root}
EOF
printf 'empty=0\ninstalled=12\nremaining-after-remove=7\nreinstalled=12\n' \
  > "${evidence}/summary.txt"

#!/usr/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin:${PATH}"

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 ROOT RUNTIME_ARCHIVE_DIR PACKAGE_ARCHIVE_DIR EVIDENCE_DIR" >&2
  exit 2
fi

root=$1
runtime_dir=$2
package_dir=$3
evidence=$4
runtime=mingw-w64-cross-msysarm64-libiconv
devel=mingw-w64-cross-msysarm64-libiconv-devel
cli=mingw-w64-cross-msysarm64-iconv
target=/opt/aarch64-pc-msys/usr

mkdir -p \
  "${root}/etc/pacman.d/hooks" \
  "${root}/var/lib/pacman/local" \
  "${root}/var/cache/pacman/pkg" \
  "${root}/var/log" \
  "${evidence}"
cat > "${root}/etc/pacman.conf" <<'EOF'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
EOF

pacman_args=(
  --root "${root}"
  --dbpath "${root}/var/lib/pacman"
  --cachedir "${root}/var/cache/pacman/pkg"
  --logfile "${root}/var/log/pacman.log"
  --config "${root}/etc/pacman.conf"
  --hookdir "${root}/etc/pacman.d/hooks"
)

shared_snapshot() {
  local name=$1

  find /var/lib/pacman/local -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 -r sha256sum > "${evidence}/shared-${name}-db.sha256"
  if [[ -f /var/log/pacman.log ]]; then
    sha256sum /var/log/pacman.log \
      > "${evidence}/shared-${name}-log.sha256"
  else
    : > "${evidence}/shared-${name}-log.sha256"
  fi
}

snapshot() {
  local name=$1
  local status

  set +e
  pacman "${pacman_args[@]}" -Q 2>/dev/null |
    LC_ALL=C sort > "${evidence}/${name}-packages.txt"
  status=${PIPESTATUS[0]}
  set -e
  test "${status}" -eq 0 -o "${status}" -eq 1
  find "${root}/var/lib/pacman/local" -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 -r sha256sum > "${evidence}/${name}-db.sha256"
}

payload_manifest() {
  local name=$1
  local package path

  {
    for package in "${runtime}" "${devel}" "${cli}"; do
      pacman "${pacman_args[@]}" -Qlq "${package}" 2>/dev/null |
        while IFS= read -r path; do
          if [[ -f "${path}" ]]; then
            sha256sum "${path}"
          fi
        done
    done
  } > "${evidence}/${name}-payload.sha256"
  LC_ALL=C sort -o \
    "${evidence}/${name}-payload.sha256" \
    "${evidence}/${name}-payload.sha256"
}

runtime_archives=(
  "${runtime_dir}/mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${runtime_dir}/mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
)
mapfile -t package_archives < <(
  find "${package_dir}" -maxdepth 1 -type f \
    \( -name 'mingw-w64-cross-msysarm64-libiconv-*.pkg.tar.zst' \
       -o -name 'mingw-w64-cross-msysarm64-iconv-*.pkg.tar.zst' \) |
    LC_ALL=C sort
)
test "${#runtime_archives[@]}" -eq 5
test "${#package_archives[@]}" -eq 3
for archive in "${runtime_archives[@]}" "${package_archives[@]}"; do
  test -f "${archive}"
done

snapshot empty
shared_snapshot before
MSYS=winsymlinks:sys pacman "${pacman_args[@]}" --noconfirm -U \
  "${runtime_archives[@]}" "${package_archives[@]}"
for package in "${runtime}" "${devel}" "${cli}"; do
  test "$(pacman "${pacman_args[@]}" -Q "${package}")" = \
    "${package} 1.19-1"
  pacman "${pacman_args[@]}" -Qk "${package}"
done
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/msys-iconv-2.dll")" = "${runtime}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/iconv.exe")" = "${cli}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/include/iconv.h")" = "${devel}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/msys-charset-1.dll")" = "${runtime}"
{
  printf 'baseline_path\tinstalled_path\tpackage\tversion\n'
  printf 'usr/bin/iconv.exe\topt/aarch64-pc-msys/usr/bin/iconv.exe\t%s\t1.19-1\n' \
    "${cli}"
  printf 'usr/bin/msys-iconv-2.dll\topt/aarch64-pc-msys/usr/bin/msys-iconv-2.dll\t%s\t1.19-1\n' \
    "${runtime}"
} > "${evidence}/residual-ownership.tsv"
snapshot installed
payload_manifest installed

pacman "${pacman_args[@]}" --noconfirm -R \
  "${devel}" "${cli}" "${runtime}"
for package in "${runtime}" "${devel}" "${cli}"; do
  ! pacman "${pacman_args[@]}" -Q "${package}" >/dev/null 2>&1
done
test ! -e "${root}${target}/bin/iconv.exe"
test ! -e "${root}${target}/include/iconv.h"
! compgen -G "${root}${target}/bin/msys-charset-*.dll" >/dev/null
! compgen -G "${root}${target}/bin/msys-iconv-*.dll" >/dev/null
snapshot removed

MSYS=winsymlinks:sys pacman "${pacman_args[@]}" --noconfirm -U \
  "${package_archives[@]}"
for package in "${runtime}" "${devel}" "${cli}"; do
  test "$(pacman "${pacman_args[@]}" -Q "${package}")" = \
    "${package} 1.19-1"
  pacman "${pacman_args[@]}" -Qk "${package}"
done
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/msys-iconv-2.dll")" = "${runtime}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/iconv.exe")" = "${cli}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/include/iconv.h")" = "${devel}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/msys-charset-1.dll")" = "${runtime}"
snapshot reinstalled
payload_manifest reinstalled
diff -u \
  "${evidence}/installed-payload.sha256" \
  "${evidence}/reinstalled-payload.sha256"
shared_snapshot after
cmp "${evidence}/shared-before-db.sha256" \
  "${evidence}/shared-after-db.sha256"
cmp "${evidence}/shared-before-log.sha256" \
  "${evidence}/shared-after-log.sha256"

: > "${evidence}/candidate-archives.tsv"
: > "${evidence}/candidate-pkginfo.txt"
for archive in "${package_archives[@]}"; do
  pkginfo="${evidence}/${archive##*/}.PKGINFO"
  zstd -dc -- "${archive}" |
    bsdtar -xOf - .PKGINFO > "${pkginfo}"
  printf '%s\t%s\t%s\n' \
    "${archive}" \
    "$(stat -c '%s' "${archive}")" \
    "$(sha256sum "${archive}" | cut -d ' ' -f 1)" \
    >> "${evidence}/candidate-archives.tsv"
  printf '%s\n' "--- ${archive##*/}" \
    >> "${evidence}/candidate-pkginfo.txt"
  cat "${pkginfo}" >> "${evidence}/candidate-pkginfo.txt"
done
printf 'root=%s\nempty=0\ninstalled=8\nremaining-after-remove=5\nreinstalled=8\n' \
  "${root}" > "${evidence}/summary.txt"

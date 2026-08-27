#!/usr/bin/env bash

set -euo pipefail

if (( $# < 3 || $# > 4 )); then
  echo "usage: $0 PACKAGE_DIR REPORT_DIR INPUT_DIR [RECIPE_DIR]" >&2
  exit 2
fi

package_dir=$(cd "$1" && pwd)
report_dir=$2
mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
input_dir=$(cd "$3" && pwd)
recipe_dir=$(cd "${4:-$package_dir}" && pwd)
pacman=${PACMAN:-/usr/bin/pacman}
pacman_config=${PACMAN_CONFIG:-/etc/pacman.conf}
pacman_gpgdir=${PACMAN_GPGDIR:-/etc/pacman.d/gnupg}
test -x "$pacman"
parent_pacman=(
  "$pacman"
  --root /
  --dbpath /var/lib/pacman
  --cachedir /var/cache/pacman/pkg
  --logfile /var/log/zlib-private-pacman.log
  --config "$pacman_config"
  --hookdir /etc/pacman.d/hooks
  --gpgdir "$pacman_gpgdir"
)

runtime_name=mingw-w64-cross-msysarm64-zlib
devel_name=mingw-w64-cross-msysarm64-zlib-devel
minigzip_name=mingw-w64-cross-msysarm64-zlib-minigzip
runtime_archive="${package_dir}/${runtime_name}-1.3.1-1-x86_64.pkg.tar.zst"
devel_archive="${package_dir}/${devel_name}-1.3.1-1-x86_64.pkg.tar.zst"
minigzip_archive="${package_dir}/${minigzip_name}-1.3.1-1-x86_64.pkg.tar.zst"
archives=("$devel_archive" "$minigzip_archive" "$runtime_archive")
names=("$runtime_name" "$devel_name" "$minigzip_name")

mapfile -t actual_archives < <(
  find "$package_dir" -maxdepth 1 -type f -name '*.pkg.tar.zst' \
    -printf '%f\n' | LC_ALL=C sort
)
expected_archives=(
  "${runtime_name}-1.3.1-1-x86_64.pkg.tar.zst"
  "${devel_name}-1.3.1-1-x86_64.pkg.tar.zst"
  "${minigzip_name}-1.3.1-1-x86_64.pkg.tar.zst"
)
test "${#actual_archives[@]}" -eq 3
test "$(printf '%s\n' "${actual_archives[@]}")" = \
  "$(printf '%s\n' "${expected_archives[@]}")"

for archive in "${archives[@]}"; do
  test -f "$archive"
done

content_root="${report_dir}/package-content"
/usr/bin/mkdir -p "$content_root"
for archive in "${archives[@]}"; do
  archive_name=$(/usr/bin/basename "$archive")
  archive_root="${content_root}/${archive_name}"
  /usr/bin/mkdir -p "$archive_root"
  /usr/bin/bsdtar -tf "$archive" \
    > "${report_dir}/${archive_name}.files.txt"
  while IFS= read -r path; do
    case "$path" in
      /*|[A-Za-z]:*|..|../*|*/../*|*/..)
        echo "Unsafe package path: $archive: $path" >&2
        exit 1
        ;;
    esac
  done < "${report_dir}/${archive_name}.files.txt"
  /usr/bin/bsdtar --numeric-owner -tvf "$archive" \
    > "${report_dir}/${archive_name}.headers.txt"
  if /usr/bin/awk '$3 != 0 || $4 != 0 {exit 1}' \
      "${report_dir}/${archive_name}.headers.txt"; then
    :
  else
    echo "Non-root tar header: $archive" >&2
    exit 1
  fi
  if /usr/bin/grep -Eq '^[hl]' \
      "${report_dir}/${archive_name}.headers.txt"; then
    echo "Unexpected package hardlink or symlink: $archive" >&2
    exit 1
  fi
  MSYS=winsymlinks:sys \
    /usr/bin/bsdtar -xf "$archive" -C "$archive_root"
  if /usr/bin/find "$archive_root" -type l -print -quit \
      | /usr/bin/grep -q .; then
    echo "Unexpected package symlink: $archive" >&2
    exit 1
  fi
done

assert_metadata() {
  local archive=$1
  local package_name=$2
  shift 2
  local metadata="${report_dir}/${package_name}.PKGINFO"
  local expected_line

  /usr/bin/bsdtar -xOf "$archive" .PKGINFO > "$metadata"
  grep -Fx "pkgname = ${package_name}" "$metadata"
  grep -Fx 'pkgver = 1.3.1-1' "$metadata"
  grep -Fx 'arch = x86_64' "$metadata"
  for expected_line in "$@"; do
    grep -Fx "$expected_line" "$metadata"
  done

  local mtree="${report_dir}/${package_name}.MTREE"
  /usr/bin/bsdtar -xOf "$archive" .MTREE | /usr/bin/gzip -dc > "$mtree"
  /usr/bin/grep -Eq '^/set .*uid=0 .*gid=0' "$mtree"
  if /usr/bin/grep -Eq '(^|[[:space:]])(uid|gid)=[1-9][0-9]*' "$mtree"; then
    echo "Non-root MTREE ownership: $archive" >&2
    return 1
  fi
}

assert_metadata "$runtime_archive" "$runtime_name" \
  'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
  'provides = aarch64-pc-msys-zlib=1.3.1'
assert_metadata "$devel_archive" "$devel_name" \
  'depend = mingw-w64-cross-msysarm64-zlib=1.3.1-1' \
  'depend = mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1' \
  'depend = mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1' \
  'provides = aarch64-pc-msys-zlib-devel=1.3.1'
assert_metadata "$minigzip_archive" "$minigzip_name" \
  'depend = mingw-w64-cross-msysarm64-zlib=1.3.1-1' \
  'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
  'provides = aarch64-pc-msys-minigzip=1.3.1'

snapshot_shared_root() {
  local prefix=$1

  "${parent_pacman[@]}" -Q | LC_ALL=C sort > "${prefix}.packages.txt"
  (
    cd /var/lib/pacman
    find local -type f -printf '%P\0' \
      | LC_ALL=C sort -z \
      | while IFS= read -r -d '' file; do
          sha256sum "local/${file}"
        done
  ) > "${prefix}.local-db.sha256"
  (
    cd /etc/pacman.d/gnupg
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
  ) > "${prefix}.gpg.sha256"
  if [[ -f /var/log/zlib-private-pacman.log ]]; then
    /usr/bin/stat -c '%s' /var/log/zlib-private-pacman.log \
      > "${prefix}.pacman-log.bytes"
    /usr/bin/sha256sum /var/log/zlib-private-pacman.log \
      > "${prefix}.pacman-log.sha256"
  else
    : > "${prefix}.pacman-log.bytes"
    : > "${prefix}.pacman-log.sha256"
  fi
}

snapshot_isolated_root() {
  local output=$1

  (
    cd "$transaction_root"
    find . -mindepth 1 -printf '%P\t%y\t%m\t%s\t%l\n' \
      | LC_ALL=C sort
  ) > "$output"
}

snapshot_owned_payload() {
  local output=$1
  local hash listed logical physical

  {
    "${isolated_pacman[@]}" -Qlq "${names[@]}" \
      | while IFS= read -r listed; do
          if [[ "$listed" == "${transaction_root}/"* ]]; then
            physical=$listed
            logical="/${listed#"${transaction_root}/"}"
          else
            logical=$listed
            physical="${transaction_root}${logical}"
          fi
          if [[ -L "$physical" ]]; then
            printf 'symlink\t%s\t%s\n' \
              "$logical" "$(readlink "$physical")"
          elif [[ -f "$physical" ]]; then
            hash=$(sha256sum "$physical")
            printf 'file\t%s\t%s\n' "$logical" "${hash%% *}"
          elif [[ -d "$physical" ]]; then
            printf 'directory\t%s\n' "$logical"
          else
            echo "missing package path: $logical" >&2
            return 1
          fi
        done
  } | LC_ALL=C sort > "$output"
}

shared_before="${report_dir}/shared-root-before"
shared_after="${report_dir}/shared-root-after"
snapshot_shared_root "$shared_before"

transaction_root="${report_dir}/pacman-root"
dbpath="${transaction_root}/var/lib/pacman"
cachedir="${transaction_root}/var/cache/pacman/pkg"
hookdir="${transaction_root}/etc/pacman.d/hooks"
gpgdir="${transaction_root}/etc/pacman.d/gnupg"
logfile="${transaction_root}/var/log/pacman.log"
pacman_config="${transaction_root}/etc/pacman.conf"
if [[ -e "$transaction_root" ]]; then
  echo "isolated transaction root already exists: $transaction_root" >&2
  exit 1
fi
mkdir -p \
  "$dbpath" \
  "$cachedir" \
  "$hookdir" \
  "$gpgdir" \
  "$(dirname "$logfile")"
/usr/bin/cp -a /etc/pacman.d/gnupg/. "$gpgdir/"
cat > "$pacman_config" <<'EOF'
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional
EOF

isolated_pacman=(
  "$pacman"
  --root "$transaction_root"
  --dbpath "$dbpath"
  --cachedir "$cachedir"
  --hookdir "$hookdir"
  --logfile "$logfile"
  --config "$pacman_config"
  --gpgdir "$gpgdir"
)
snapshot_isolated_root "${report_dir}/isolated-root-before.txt"

runtime_inputs=(
  "${input_dir}/mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${input_dir}/mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${input_dir}/mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${input_dir}/mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
  "${input_dir}/mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst"
)
for package in "${runtime_inputs[@]}"; do
  test -f "$package"
done

MSYS=winsymlinks:sys \
  "${isolated_pacman[@]}" -U --noconfirm -- \
    "${runtime_inputs[@]}" \
    "${archives[@]}"
test -z "$(
  "${isolated_pacman[@]}" -T -- \
    'mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
    'mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1' \
    'mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1' \
    "${runtime_name}=1.3.1-1" \
    "${devel_name}=1.3.1-1" \
    "${minigzip_name}=1.3.1-1"
)"
"${isolated_pacman[@]}" -Qk "${names[@]}" \
  > "${report_dir}/package-integrity.txt"
snapshot_isolated_root "${report_dir}/isolated-root-after-install.txt"
snapshot_owned_payload "${report_dir}/owned-payload-after-install.txt"

isolated_prefix="${transaction_root}/opt/aarch64-pc-msys/usr"
test "$(
  "${isolated_pacman[@]}" -Qoq "${isolated_prefix}/bin/msys-z.dll"
)" = \
  "$runtime_name"
test "$(
  "${isolated_pacman[@]}" -Qoq "${isolated_prefix}/lib/libz.a"
)" = \
  "$devel_name"
test "$(
  "${isolated_pacman[@]}" -Qoq "${isolated_prefix}/lib/libz.dll.a"
)" = \
  "$devel_name"
test "$(
  "${isolated_pacman[@]}" -Qoq "${isolated_prefix}/bin/minigzip.exe"
)" = \
  "$minigzip_name"
test -L /opt/aarch64-pc-msys/bin/ar.exe
test "$(readlink /opt/aarch64-pc-msys/bin/ar.exe)" = \
  ../../aarch64-pc-cygwin/bin/ar.exe

PSEUDO_RELOC_SCANNER="${recipe_dir}/../.ci/check-aarch64-pseudo-relocs.ps1" \
PSEUDO_RELOC_WRAPPER="${recipe_dir}/scan-aarch64-pseudo-relocs.ps1" \
PACMAN="$pacman" \
PACMAN_CONFIG="$pacman_config" \
PACMAN_GPGDIR="$pacman_gpgdir" \
  "${recipe_dir}/validate-zlib.sh" \
  "$isolated_prefix" \
  "${report_dir}/installed-payload"

{
  printf 'package\tversion\n'
  "${isolated_pacman[@]}" -Q "${names[@]}" | sed 's/ /\t/'
} > "${report_dir}/installed-packages.tsv"

"${isolated_pacman[@]}" -R --noconfirm -- \
  "$devel_name" "$minigzip_name" "$runtime_name"
for name in "${names[@]}"; do
  ! "${isolated_pacman[@]}" -Q "$name" >/dev/null 2>&1
done
test ! -e "${isolated_prefix}/bin/msys-z.dll"
test ! -e "${isolated_prefix}/bin/minigzip.exe"
snapshot_isolated_root "${report_dir}/isolated-root-after-remove.txt"

MSYS=winsymlinks:sys \
  "${isolated_pacman[@]}" -U --noconfirm -- "${archives[@]}"
"${isolated_pacman[@]}" -Qk "${names[@]}" \
  > "${report_dir}/package-integrity-after-reinstall.txt"
snapshot_isolated_root "${report_dir}/isolated-root-after-reinstall.txt"
snapshot_owned_payload "${report_dir}/owned-payload-after-reinstall.txt"
cmp \
  "${report_dir}/owned-payload-after-install.txt" \
  "${report_dir}/owned-payload-after-reinstall.txt"

snapshot_shared_root "$shared_after"
cmp "${shared_before}.packages.txt" "${shared_after}.packages.txt"
cmp "${shared_before}.local-db.sha256" "${shared_after}.local-db.sha256"
cmp "${shared_before}.gpg.sha256" "${shared_after}.gpg.sha256"
cmp "${shared_before}.pacman-log.bytes" "${shared_after}.pacman-log.bytes"
cmp "${shared_before}.pacman-log.sha256" \
  "${shared_after}.pacman-log.sha256"
rm -rf "$transaction_root"

(
  cd "$package_dir"
  sha256sum "${expected_archives[@]}"
) > "${report_dir}/release-SHA256SUMS"

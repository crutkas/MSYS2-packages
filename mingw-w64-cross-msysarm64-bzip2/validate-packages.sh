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
python=${VALIDATION_PYTHON:-python}

cli_name=mingw-w64-cross-msysarm64-bzip2
runtime_name=mingw-w64-cross-msysarm64-libbz2
devel_name=mingw-w64-cross-msysarm64-libbz2-devel
cli_archive="${package_dir}/${cli_name}-1.0.8-4-x86_64.pkg.tar.zst"
runtime_archive="${package_dir}/${runtime_name}-1.0.8-4-x86_64.pkg.tar.zst"
devel_archive="${package_dir}/${devel_name}-1.0.8-4-x86_64.pkg.tar.zst"
archives=("$cli_archive" "$devel_archive" "$runtime_archive")
names=("$cli_name" "$runtime_name" "$devel_name")
expected_archives=(
  "${cli_name}-1.0.8-4-x86_64.pkg.tar.zst"
  "${runtime_name}-1.0.8-4-x86_64.pkg.tar.zst"
  "${devel_name}-1.0.8-4-x86_64.pkg.tar.zst"
)

mapfile -t actual_archives < <(
  find "$package_dir" -maxdepth 1 -type f -name '*.pkg.tar.zst' \
    -printf '%f\n' | LC_ALL=C sort
)
test "${#actual_archives[@]}" -eq 3
test "$(printf '%s\n' "${actual_archives[@]}")" = \
  "$(printf '%s\n' "${expected_archives[@]}")"

assert_archive_safe() {
  local archive=$1
  local stem=$2

  bsdtar -tf "$archive" > "${report_dir}/${stem}.files.txt"
  bsdtar -tvf "$archive" > "${report_dir}/${stem}.verbose-files.txt"
  sed -n \
    -e 's/^.* -> //p' \
    -e 's/^.* link to //p' \
    "${report_dir}/${stem}.verbose-files.txt" \
    > "${report_dir}/${stem}.link-targets.txt"
  if grep -E '(^/|(^|/)\.\.(/|$)|^[A-Za-z]:)' \
      "${report_dir}/${stem}.files.txt"; then
    echo "$archive contains an unsafe path" >&2
    return 1
  fi
  if grep -E '(^/|^[A-Za-z]:|(^|/)\.\.(/|$))' \
      "${report_dir}/${stem}.link-targets.txt"; then
    echo "$archive contains an unsafe link target" >&2
    return 1
  fi
}

for archive in "${archives[@]}"; do
  test -f "$archive"
  assert_archive_safe "$archive" "$(basename "$archive" .pkg.tar.zst)"
done

assert_metadata() {
  local archive=$1
  local package_name=$2
  shift 2
  local metadata="${report_dir}/${package_name}.PKGINFO"
  local expected_line

  bsdtar -xOf "$archive" .PKGINFO > "$metadata"
  grep -Fx "pkgname = ${package_name}" "$metadata"
  grep -Fx 'pkgver = 1.0.8-4' "$metadata"
  grep -Fx 'arch = x86_64' "$metadata"
  for expected_line in "$@"; do
    grep -Fx "$expected_line" "$metadata"
  done
  if grep -Ei 'replaces =|[A-Z]:\\|/home/runner|crutkas-redesigned-guacamole' \
      "$metadata"; then
    echo "$metadata contains forbidden metadata" >&2
    return 1
  fi
}

assert_metadata "$cli_archive" "$cli_name" \
  'depend = mingw-w64-cross-msysarm64-libbz2=1.0.8-4' \
  'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
  'provides = aarch64-pc-msys-bzip2=1.0.8' \
  'conflict = aarch64-pc-msys-bzip2'
assert_metadata "$runtime_archive" "$runtime_name" \
  'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
  'provides = aarch64-pc-msys-libbz2=1.0.8' \
  'conflict = aarch64-pc-msys-libbz2'
assert_metadata "$devel_archive" "$devel_name" \
  'depend = mingw-w64-cross-msysarm64-libbz2=1.0.8-4' \
  'depend = mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1' \
  'depend = mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1' \
  'provides = aarch64-pc-msys-libbz2-devel=1.0.8' \
  'conflict = aarch64-pc-msys-libbz2-devel'

transaction_root="${report_dir}/private-lifecycle-root"
dbpath="${transaction_root}/var/lib/pacman"
cachedir="${transaction_root}/var/cache/pacman/pkg"
hookdir="${transaction_root}/etc/pacman.d/hooks"
gpgdir="${transaction_root}/etc/pacman.d/gnupg"
logfile="${transaction_root}/var/log/pacman.log"
pacman_config="${transaction_root}/etc/pacman.conf"
if [[ -e "$transaction_root" ]]; then
  echo "private lifecycle root already exists: $transaction_root" >&2
  exit 1
fi
mkdir -p "$dbpath" "$cachedir" "$hookdir" "$gpgdir" \
  "$(dirname "$logfile")"
cat > "$pacman_config" <<'EOF'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
EOF

private_pacman=(
  /usr/bin/pacman.exe
  --root "$transaction_root"
  --dbpath "$dbpath"
  --cachedir "$cachedir"
  --logfile "$logfile"
  --config "$pacman_config"
  --hookdir "$hookdir"
  --gpgdir "$gpgdir"
)
printf '%q ' "${private_pacman[@]}" > "${report_dir}/private-pacman-command.txt"
printf '\n' >> "${report_dir}/private-pacman-command.txt"

snapshot_payload() {
  local output=$1
  (
    cd "$transaction_root"
    find . -mindepth 1 \
      -path './var/lib/pacman' -prune -o \
      -path './var/cache/pacman' -prune -o \
      -path './var/log/pacman.log' -prune -o \
      -path './etc/pacman.conf' -prune -o \
      -path './etc/pacman.d/hooks' -prune -o \
      -path './etc/pacman.d/gnupg' -prune -o \
      -printf '%P\t%y\t%m\t%s\t%l\n' \
      | LC_ALL=C sort
  ) > "$output"
}

assert_files_equal() {
  local left=$1
  local right=$2
  test "$(sha256sum "$left" | cut -d' ' -f1)" = \
    "$(sha256sum "$right" | cut -d' ' -f1)"
}

snapshot_owned_payload() {
  local output=$1
  local listed logical physical hash

  {
    "${private_pacman[@]}" -Qlq "${names[@]}" \
      | while IFS= read -r listed; do
          if [[ "$listed" == "${transaction_root}/"* ]]; then
            physical=$listed
            logical="/${listed#"${transaction_root}/"}"
          else
            logical=$listed
            physical="${transaction_root}${logical}"
          fi
          if [[ -L "$physical" ]]; then
            printf 'symlink\t%s\t%s\n' "$logical" "$(readlink "$physical")"
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
  "${private_pacman[@]}" -U --noconfirm -- "${runtime_inputs[@]}"
snapshot_payload "${report_dir}/baseline-payload.txt"

MSYS=winsymlinks:sys \
  "${private_pacman[@]}" -U --noconfirm -- "${archives[@]}"
test -z "$(
  "${private_pacman[@]}" -T -- \
    'mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1' \
    'mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1' \
    'mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1' \
    "${cli_name}=1.0.8-4" \
    "${runtime_name}=1.0.8-4" \
    "${devel_name}=1.0.8-4"
)"
"${private_pacman[@]}" -Qk "${names[@]}" \
  > "${report_dir}/package-integrity.txt"
snapshot_owned_payload "${report_dir}/owned-payload-after-install.txt"

target_prefix="${transaction_root}/opt/aarch64-pc-msys/usr"
declare -A owners=(
  ["${target_prefix}/bin/msys-bz2-1.dll"]="$runtime_name"
  ["${target_prefix}/include/bzlib.h"]="$devel_name"
  ["${target_prefix}/lib/libbz2.a"]="$devel_name"
  ["${target_prefix}/lib/libbz2.dll.a"]="$devel_name"
  ["${target_prefix}/lib/pkgconfig/bzip2.pc"]="$devel_name"
  ["${target_prefix}/bin/bzip2.exe"]="$cli_name"
  ["${target_prefix}/bin/bunzip2.exe"]="$cli_name"
  ["${target_prefix}/bin/bzcat.exe"]="$cli_name"
  ["${target_prefix}/bin/bzip2recover.exe"]="$cli_name"
)
for file in "${!owners[@]}"; do
  test -f "$file"
  test "$("${private_pacman[@]}" -Qoq "$file")" = "${owners[$file]}"
done

if "${private_pacman[@]}" -Qlq "${names[@]}" \
    | sed '/\/$/d' | LC_ALL=C sort | uniq -d | grep .; then
  echo "split packages contain overlapping owned files" >&2
  exit 1
fi
if "${private_pacman[@]}" -Qlq "${names[@]}" \
    | grep -E '/usr/bin/.*\.(exe|dll)$' \
    | grep -v '/opt/aarch64-pc-msys/usr/bin/'; then
  echo "a host executable escaped the target prefix" >&2
  exit 1
fi

PSEUDO_RELOC_SCANNER="${recipe_dir}/../.ci/check-aarch64-pseudo-relocs.ps1" \
NATIVE_CONSUMER_SOURCE="${recipe_dir}/native-consumer.c" \
  "${recipe_dir}/validate-bzip2.sh" \
  "$target_prefix" \
  "${report_dir}/installed-payload"

"${private_pacman[@]}" -R --noconfirm -- \
  "$devel_name" "$cli_name" "$runtime_name"
for name in "${names[@]}"; do
  ! "${private_pacman[@]}" -Q "$name" >/dev/null 2>&1
done
snapshot_payload "${report_dir}/payload-after-remove.txt"
assert_files_equal "${report_dir}/baseline-payload.txt" \
  "${report_dir}/payload-after-remove.txt"

MSYS=winsymlinks:sys \
  "${private_pacman[@]}" -U --noconfirm -- "${archives[@]}"
"${private_pacman[@]}" -Qk "${names[@]}" \
  > "${report_dir}/package-integrity-after-reinstall.txt"
snapshot_owned_payload "${report_dir}/owned-payload-after-reinstall.txt"
assert_files_equal \
  "${report_dir}/owned-payload-after-install.txt" \
  "${report_dir}/owned-payload-after-reinstall.txt"

corrupt="${report_dir}/corrupt.pkg.tar.zst"
cp "$runtime_archive" "$corrupt"
"$python" - "$corrupt" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[:4] = b"\0\0\0\0"
path.write_bytes(data)
PY
if "${private_pacman[@]}" -U --noconfirm -- "$corrupt"; then
  echo "pacman accepted a corrupted package archive" >&2
  exit 1
fi
printf 'corrupt-package\trejected\n' > "${report_dir}/negative-lifecycle.tsv"
rm -f "$corrupt"

{
  printf 'package\tversion\n'
  "${private_pacman[@]}" -Q "${names[@]}" | sed 's/ /\t/'
} > "${report_dir}/installed-packages.tsv"
cp "$logfile" "${report_dir}/private-pacman.log"

(
  cd "$package_dir"
  sha256sum "${expected_archives[@]}"
) > "${report_dir}/release-SHA256SUMS"

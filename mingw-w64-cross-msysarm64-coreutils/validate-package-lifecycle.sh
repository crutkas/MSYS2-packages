#!/usr/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin:${PATH}"
export MSYS=winsymlinks:sys

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 ROOT INPUT_ARCHIVE_DIR PACKAGE_ARCHIVE EVIDENCE_DIR" >&2
  exit 2
fi

root=$1
input_dir=$2
candidate=$3
evidence=$4
package=mingw-w64-cross-msysarm64-coreutils
version=8.32-1
target=/opt/aarch64-pc-msys
script_dir="$(cd "$(dirname "$0")" && pwd)"
manifest="${script_dir}/path-manifest.json"
shared_db=${SHARED_DB:-/var/lib/pacman/local}
shared_log=${SHARED_LOG:-/var/log/pacman.log}

case "${root}" in
  /|/c/msys64|/c/msys64/*)
    echo "refusing unsafe private root: ${root}" >&2
    exit 2
    ;;
esac
test -d "${input_dir}"
test -f "${candidate}"
test -f "${manifest}"

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

  find "${shared_db}" -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 -r sha256sum > "${evidence}/shared-${name}-db-files.sha256"
  sha256sum "${evidence}/shared-${name}-db-files.sha256" |
    cut -d ' ' -f 1 > "${evidence}/shared-${name}-db.sha256"
  if [[ -f "${shared_log}" ]]; then
    stat -c '%s' "${shared_log}" > "${evidence}/shared-${name}-log.bytes"
    sha256sum "${shared_log}" |
      cut -d ' ' -f 1 > "${evidence}/shared-${name}-log.sha256"
  else
    printf '0\n' > "${evidence}/shared-${name}-log.bytes"
    : > "${evidence}/shared-${name}-log.sha256"
  fi
}

root_snapshot() {
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
    xargs -0 -r sha256sum > "${evidence}/${name}-db-files.sha256"
}

payload_snapshot() {
  local name=$1
  local path

  : > "${evidence}/${name}-payload.sha256"
  while IFS= read -r path; do
    sha256sum "${root}${target}/${path}" \
      >> "${evidence}/${name}-payload.sha256"
  done < <(
    python - "${manifest}" <<'PY'
import json
import sys
for path in json.load(open(sys.argv[1], encoding="utf-8"))["native_coreutils"]["paths"]:
    print(path)
PY
  )
}

mapfile -t inputs < <(
  find "${input_dir}" -maxdepth 1 -type f -name '*.pkg.tar.zst' |
    LC_ALL=C sort
)
test "${#inputs[@]}" -gt 0

root_snapshot empty
shared_snapshot before
pacman "${pacman_args[@]}" --noconfirm -U "${inputs[@]}" "${candidate}"
test "$(pacman "${pacman_args[@]}" -Q "${package}")" = \
  "${package} ${version}"
pacman "${pacman_args[@]}" -Qk "${package}"

mapfile -t expected < <(
  python - "${manifest}" <<'PY'
import json
import sys
for path in json.load(open(sys.argv[1], encoding="utf-8"))["native_coreutils"]["paths"]:
    print("/opt/aarch64-pc-msys/" + path)
PY
)
mapfile -t owned < <(
  pacman "${pacman_args[@]}" -Qlq "${package}" |
    sed "s|^${root}||" |
    grep -E '^/opt/aarch64-pc-msys/.*\.(exe|dll)$' |
    LC_ALL=C sort
)
test "${#expected[@]}" -eq 30
test "${#owned[@]}" -eq 30
diff -u \
  <(printf '%s\n' "${expected[@]}" | LC_ALL=C sort) \
  <(printf '%s\n' "${owned[@]}")
for path in "${expected[@]}"; do
  test "$(pacman "${pacman_args[@]}" -Qoq "${root}${path}")" = "${package}"
done
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}/usr/share/${package}/path-manifest.json")" = "${package}"

# The package intentionally ships no aliases. Prove the private root still
# preserves native MSYS symlinks for integration-created links.
ln -s "stat.exe" "${root}${target}/usr/bin/coreutils-symlink-check.exe"
test -L "${root}${target}/usr/bin/coreutils-symlink-check.exe"
test "$(readlink "${root}${target}/usr/bin/coreutils-symlink-check.exe")" = \
  stat.exe
rm "${root}${target}/usr/bin/coreutils-symlink-check.exe"

root_snapshot installed
payload_snapshot installed
pacman "${pacman_args[@]}" --noconfirm -R "${package}"
! pacman "${pacman_args[@]}" -Q "${package}" >/dev/null 2>&1
for path in "${expected[@]}"; do
  test ! -e "${root}${path}"
done
root_snapshot removed

pacman "${pacman_args[@]}" --noconfirm -U "${candidate}"
test "$(pacman "${pacman_args[@]}" -Q "${package}")" = \
  "${package} ${version}"
pacman "${pacman_args[@]}" -Qk "${package}"
payload_snapshot reinstalled
diff -u \
  "${evidence}/installed-payload.sha256" \
  "${evidence}/reinstalled-payload.sha256"
shared_snapshot after
cmp "${evidence}/shared-before-db-files.sha256" \
  "${evidence}/shared-after-db-files.sha256"
cmp "${evidence}/shared-before-db.sha256" \
  "${evidence}/shared-after-db.sha256"
cmp "${evidence}/shared-before-log.bytes" \
  "${evidence}/shared-after-log.bytes"
cmp "${evidence}/shared-before-log.sha256" \
  "${evidence}/shared-after-log.sha256"

{
  printf 'root=%s\n' "${root}"
  printf 'pacman-options=%s\n' "${pacman_args[*]}"
  printf 'package=%s\n' "${package}"
  printf 'version=%s\n' "${version}"
  printf 'owned-target-pe=30\n'
  printf 'symlink-policy=winsymlinks:sys\n'
  printf 'shared-db-unchanged=true\n'
  printf 'shared-log-unchanged=true\n'
  printf 'install-remove-reinstall=pass\n'
} > "${evidence}/summary.txt"

printf '%s\t%s\t%s\n' \
  "${candidate}" \
  "$(stat -c '%s' "${candidate}")" \
  "$(sha256sum "${candidate}" | cut -d ' ' -f 1)" \
  > "${evidence}/candidate-archive.tsv"
bsdtar -xOf "${candidate}" .PKGINFO > "${evidence}/candidate.PKGINFO"

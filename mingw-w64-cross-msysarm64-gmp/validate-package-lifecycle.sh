#!/usr/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin"
export MSYS=winsymlinks:sys

if [[ "$#" -ne 6 ]]; then
  echo "usage: $0 ROOT SHARED_ROOT INPUT_DIR PACKAGE_DIR EVIDENCE_DIR LOCK_FILE" >&2
  exit 2
fi

root=$1
shared_root=$2
input_dir=$3
package_dir=$4
evidence=$5
lock_file=$6
recipe_root="$(cd "$(dirname "$0")"; pwd -P)"
binary_scanner="${recipe_root}/scan-forbidden-paths.py"
python_command=${PYTHON:?}
runtime=mingw-w64-cross-msysarm64-gmp
devel=mingw-w64-cross-msysarm64-gmp-devel
target=/opt/aarch64-pc-msys/usr

test -n "${root}"
case "${root}" in
  /*)
    ;;
  *)
    echo "refusing unsafe private root: ${root}" >&2
    exit 2
    ;;
esac
root="$(realpath -m -- "${root}")"
shared_root="$(realpath -m -- "${shared_root}")"
evidence="$(realpath -m -- "${evidence}")"
for protected in \
  / /bin /dev /etc /home /opt /proc /sbin /sys /tmp /usr /var \
  "${shared_root}"
do
  case "${root}" in
    "${protected}"|"${protected}"/*)
      echo "refusing unsafe private root: ${root}" >&2
      exit 2
      ;;
  esac
done
case "${evidence}" in
  "${root}"|"${root}"/*)
    echo "evidence must be outside the private root: ${evidence}" >&2
    exit 2
    ;;
esac
test ! -e "${root}"
test ! -e "${evidence}"
test -d "${input_dir}"
test -d "${package_dir}"
test -f "${binary_scanner}"
test -f "${lock_file}"
mkdir -p \
  "${root}/etc/pacman.d/hooks" \
  "${root}/etc/pacman.d/gnupg" \
  "${root}/var/lib/pacman/local" \
  "${root}/var/cache/pacman/pkg" \
  "${root}/var/log" \
  "${evidence}"
cat > "${root}/etc/gmp-pacman.conf" <<'EOF'
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
EOF

pacman_args=(
  --root "${root}"
  --dbpath "${root}/var/lib/pacman"
  --cachedir "${root}/var/cache/pacman/pkg"
  --logfile "${root}/var/log/gmp-pacman.log"
  --config "${root}/etc/gmp-pacman.conf"
  --hookdir "${root}/etc/pacman.d/hooks"
  --gpgdir "${root}/etc/pacman.d/gnupg"
)

shared_snapshot() {
  local name=$1 path relative
  local -a sentinels=(
    var/lib/pacman
    var/cache/pacman
    var/log/pacman.log
    etc/pacman.conf
    etc/pacman.d/hooks
    etc/pacman.d/gnupg
  )

  : > "${evidence}/shared-${name}.sentinel"
  for relative in "${sentinels[@]}"; do
    path="${shared_root}/${relative}"
    if [[ -L "${path}" ]]; then
      printf 'link\t%s\t%s\n' "${relative}" "$(readlink "${path}")" \
        >> "${evidence}/shared-${name}.sentinel"
    elif [[ -f "${path}" ]]; then
      printf 'file\t%s\t%s\t%s\n' \
        "${relative}" "$(stat -c '%s' "${path}")" \
        "$(sha256sum "${path}" | cut -d ' ' -f 1)" \
        >> "${evidence}/shared-${name}.sentinel"
    elif [[ -d "${path}" ]]; then
      printf 'dir\t%s\n' "${relative}" \
        >> "${evidence}/shared-${name}.sentinel"
      find "${path}" -mindepth 1 -print0 |
        LC_ALL=C sort -z |
        while IFS= read -r -d '' item; do
          if [[ -L "${item}" ]]; then
            printf 'link\t%s\t%s\n' \
              "${item#${shared_root}/}" "$(readlink "${item}")"
          elif [[ -f "${item}" ]]; then
            printf 'file\t%s\t%s\t%s\n' \
              "${item#${shared_root}/}" "$(stat -c '%s' "${item}")" \
              "$(sha256sum "${item}" | cut -d ' ' -f 1)"
          elif [[ -d "${item}" ]]; then
            printf 'dir\t%s\n' "${item#${shared_root}/}"
          fi
        done >> "${evidence}/shared-${name}.sentinel"
    else
      printf 'missing\t%s\n' "${relative}" \
        >> "${evidence}/shared-${name}.sentinel"
    fi
  done
}

root_snapshot() {
  local name=$1
  local allow_empty=${2:-false}
  local status

  set +e
  pacman "${pacman_args[@]}" -Q \
    2> "${evidence}/${name}-packages.stderr.txt" |
    LC_ALL=C sort > "${evidence}/${name}-packages.txt"
  status=${PIPESTATUS[0]}
  set -e
  if [[ "${allow_empty}" = true ]]; then
    test "${status}" -eq 0 -o "${status}" -eq 1
    test ! -s "${evidence}/${name}-packages.txt"
  else
    test "${status}" -eq 0
    test ! -s "${evidence}/${name}-packages.stderr.txt"
  fi
  (
    cd "${root}"
    find var/lib/pacman/local -type f -print0 |
      LC_ALL=C sort -z |
      xargs -0 -r sha256sum
  ) > "${evidence}/${name}-db.sha256"
  if [[ "${allow_empty}" = true ]]; then
    test ! -s "${evidence}/${name}-db.sha256"
  fi
}

mapfile -d '' -t lock_values < <(
  MSYS2_ARG_CONV_EXCL='*' "${python_command}" -c '
import json
import pathlib
import re
import sys

lock = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
runtime = lock["canonical_runtime"]
assets = lock["canonical_prerequisite_assets"]
if lock["schema"] != 2 or lock["canonical_runtime_admitted"] is not True:
    raise SystemExit("canonical runtime admission gate is closed")
if (
    runtime["admitted"] is not True
    or runtime["independent_redownload_verified"] is not True
    or not runtime["coordinator_admission_reference"]
    or lock["build_classification"] != {
        "status": "canonical-runtime-admitted-build-enabled",
        "admissible": False,
        "publishable": False,
        "consumable": False,
    }
):
    raise SystemExit("canonical runtime is not independently admitted")
if runtime["required_version"] != runtime["version"] + "-" + runtime["pkgrel"]:
    raise SystemExit("canonical runtime required_version is inconsistent")
denied = lock["deny_tests"]
if any(
    runtime["version"] == item["version"]
    or runtime["release_tag"] == item["release_tag"]
    for item in denied
):
    raise SystemExit("canonical runtime matches a deny test")
required = {
    "package", "required_version", "release_tag",
    "asset_name", "size", "sha256", "admitted",
}
all_assets = [runtime, *assets]
if not assets or any(
    not required.issubset(asset)
    or asset["admitted"] is not True
    or not asset["package"]
    or not asset["required_version"]
    or not asset["release_tag"]
    or not asset["asset_name"]
    or not isinstance(asset["size"], int)
    or asset["size"] <= 0
    or not isinstance(asset["sha256"], str)
    or re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]) is None
    for asset in all_assets
):
    raise SystemExit("canonical prerequisite asset is not admitted")
if any(
    record["admitted"] is not False
    or record["eligible_for_admission"] is not False
    or record["independent_redownload_verified"] is not False
    or record["coordinator_admission_reference"] is not None
    or record["asset_name"] is not None
    or record["size"] is not None
    or record["sha256"] is not None
    for record in lock["package_candidates"]["records"]
):
    raise SystemExit("GMP package records were populated before validation")
if {
    record["package"] for record in lock["package_candidates"]["records"]
} != {
    "mingw-w64-cross-msysarm64-gmp",
    "mingw-w64-cross-msysarm64-gmp-devel",
}:
    raise SystemExit("GMP package record set is not exact")
if lock["product_ownership"]["product_residual_paths"] != [
    "usr/bin/msys-gmp-10.dll"
]:
    raise SystemExit("frozen product ownership is not the sole GMP DLL")
runtime_devel = [
    asset for asset in assets
    if asset["package"] == runtime["package"] + "-devel"
]
if len(runtime_devel) != 1:
    raise SystemExit("canonical runtime-devel asset must be unique")
values = [
    runtime["package"],
    runtime["version"] + "-" + runtime["pkgrel"],
    runtime_devel[0]["package"],
    runtime_devel[0]["required_version"],
    str(len(all_assets)),
]
for asset in all_assets:
    values.extend([
        asset["asset_name"],
        str(asset["size"]),
        asset["sha256"],
        asset["package"] + "=" + asset["required_version"],
    ])
sys.stdout.buffer.write(b"\0".join(value.encode() for value in values) + b"\0")
' "$(cygpath -w "${lock_file}")"
)
test "${#lock_values[@]}" -ge 6
runtime_dependency=${lock_values[0]}
runtime_dependency_version=${lock_values[1]}
runtime_devel_dependency=${lock_values[2]}
runtime_devel_version=${lock_values[3]}
input_count=${lock_values[4]}
asset_fields=("${lock_values[@]:5}")
test "${#asset_fields[@]}" -eq "$((input_count * 4))"
inputs=()
for ((index = 0; index < ${#asset_fields[@]}; index += 4)); do
  asset_name=${asset_fields[index]}
  asset_size=${asset_fields[index + 1]}
  asset_sha256=${asset_fields[index + 2]}
  asset_identity=${asset_fields[index + 3]}
  asset_path="${input_dir}/${asset_name}"
  test -f "${asset_path}"
  test "$(stat -c '%s' "${asset_path}")" -eq "${asset_size}"
  test "$(sha256sum "${asset_path}" | cut -d ' ' -f 1)" = \
    "${asset_sha256}"
  test -n "${asset_identity}"
  inputs+=("${asset_path}")
done
test "${#inputs[@]}" -eq "${input_count}"

mapfile -t packages < <(
  find "${package_dir}" -maxdepth 1 -type f \
    -name 'mingw-w64-cross-msysarm64-gmp-*.pkg.tar.zst' |
    LC_ALL=C sort
)
test "${#packages[@]}" -eq 2
runtime_package=
devel_package=
for archive in "${inputs[@]}" "${packages[@]}"; do
  test -f "${archive}"
done
for package in "${packages[@]}"; do
  case "${package##*/}" in
    mingw-w64-cross-msysarm64-gmp-6.3.0-2-*.pkg.tar.zst)
      runtime_package=${package}
      ;;
    mingw-w64-cross-msysarm64-gmp-devel-6.3.0-2-*.pkg.tar.zst)
      devel_package=${package}
      ;;
    *)
      echo "unexpected package candidate: ${package}" >&2
      exit 1
      ;;
  esac
done
test -n "${runtime_package}"
test -n "${devel_package}"

runtime_pkginfo="${evidence}/${runtime_package##*/}.PKGINFO"
devel_pkginfo="${evidence}/${devel_package##*/}.PKGINFO"
runtime_mtree="${evidence}/${runtime_package##*/}.MTREE"
devel_mtree="${evidence}/${devel_package##*/}.MTREE"
bsdtar -xOf "${runtime_package}" .PKGINFO > "${runtime_pkginfo}"
bsdtar -xOf "${devel_package}" .PKGINFO > "${devel_pkginfo}"
bsdtar -xOf "${runtime_package}" .MTREE | gzip -dc > "${runtime_mtree}"
bsdtar -xOf "${devel_package}" .MTREE | gzip -dc > "${devel_mtree}"
grep -Fxq 'pkgname = mingw-w64-cross-msysarm64-gmp' "${runtime_pkginfo}"
grep -Fxq 'pkgver = 6.3.0-2' "${runtime_pkginfo}"
grep -Fxq 'pkgname = mingw-w64-cross-msysarm64-gmp-devel' "${devel_pkginfo}"
grep -Fxq 'pkgver = 6.3.0-2' "${devel_pkginfo}"

assert_pkginfo_set() {
  local pkginfo=$1 field=$2
  shift 2
  local actual expected
  actual="$(grep -E "^${field} = " "${pkginfo}" | LC_ALL=C sort)"
  expected="$(
    printf "${field} = %s\n" "$@" | LC_ALL=C sort
  )"
  test "${actual}" = "${expected}"
}
assert_pkginfo_set \
  "${runtime_pkginfo}" depend \
  "${runtime_dependency}=${runtime_dependency_version}"
assert_pkginfo_set \
  "${runtime_pkginfo}" provides \
  'aarch64-pc-msys-gmp=6.3.0'
assert_pkginfo_set \
  "${devel_pkginfo}" depend \
  'mingw-w64-cross-msysarm64-gmp=6.3.0-2' \
  "${runtime_devel_dependency}=${runtime_devel_version}"
assert_pkginfo_set \
  "${devel_pkginfo}" provides \
  'aarch64-pc-msys-gmp-devel=6.3.0'

mapfile -t runtime_target_entries < <(
  bsdtar -tf "${runtime_package}" |
    sed 's|^\./||' |
    grep '^opt/aarch64-pc-msys/usr/' |
    grep -v '/$'
)
test "${#runtime_target_entries[@]}" -eq 1
test "${runtime_target_entries[0]}" = \
  'opt/aarch64-pc-msys/usr/bin/msys-gmp-10.dll'
mapfile -t target_dll_entries < <(
  {
    bsdtar -tf "${runtime_package}"
    bsdtar -tf "${devel_package}"
  } |
    sed 's|^\./||' |
    grep -Ei '^opt/aarch64-pc-msys/usr/.*\.dll$' |
    LC_ALL=C sort
)
test "${#target_dll_entries[@]}" -eq 1
test "${target_dll_entries[0]}" = \
  'opt/aarch64-pc-msys/usr/bin/msys-gmp-10.dll'
grep -Fq './opt/aarch64-pc-msys/usr/bin/msys-gmp-10.dll ' \
  "${runtime_mtree}"
for required in \
  opt/aarch64-pc-msys/usr/include/gmp.h \
  opt/aarch64-pc-msys/usr/lib/libgmp.a \
  opt/aarch64-pc-msys/usr/lib/libgmp.dll.a
do
  bsdtar -tf "${devel_package}" |
    sed 's|^\./||' |
    grep -Fxq "${required}"
  grep -Fq "./${required} " "${devel_mtree}"
done

shared_snapshot before
root_snapshot empty true
pacman "${pacman_args[@]}" --noconfirm -U "${inputs[@]}" "${packages[@]}"
for ((index = 0; index < ${#asset_fields[@]}; index += 4)); do
  asset_identity=${asset_fields[index + 3]}
  asset_package=${asset_identity%%=*}
  asset_version=${asset_identity#*=}
  test "$(pacman "${pacman_args[@]}" -Q "${asset_package}")" = \
    "${asset_package} ${asset_version}"
done
test "$(pacman "${pacman_args[@]}" -Q "${runtime}")" = "${runtime} 6.3.0-2"
test "$(pacman "${pacman_args[@]}" -Q "${devel}")" = "${devel} 6.3.0-2"
check_package_integrity() {
  local phase=$1 package=$2
  pacman "${pacman_args[@]}" -Qkk "${package}" \
    > "${evidence}/${phase}-${package}.qkk.txt" 2>&1
}
check_package_integrity installed "${runtime}"
check_package_integrity installed "${devel}"
test "$(pacman "${pacman_args[@]}" -Qoq \
  "${root}${target}/bin/msys-gmp-10.dll")" = "${runtime}"
for path in \
  include/gmp.h \
  lib/libgmp.a \
  lib/libgmp.dll.a
do
  test "$(pacman "${pacman_args[@]}" -Qoq \
    "${root}${target}/${path}")" = "${devel}"
done
while IFS= read -r owned_path; do
  case "${owned_path}" in
    /opt/|/opt/aarch64-pc-msys/|/opt/aarch64-pc-msys/usr/)
      ;;
    /opt/aarch64-pc-msys/usr/*)
      ;;
    /usr/|/usr/share/|/usr/share/licenses/|/usr/share/doc/)
      ;;
    "/usr/share/licenses/${runtime}/"|\
    "/usr/share/licenses/${runtime}/COPYING.LESSERv3"|\
    "/usr/share/licenses/${devel}/"|\
    "/usr/share/licenses/${devel}/COPYING.LESSERv3"|\
    "/usr/share/doc/${runtime}/"|\
    "/usr/share/doc/${runtime}/README.md"|\
    "/usr/share/doc/${runtime}/dependency-lock.json"|\
    "/usr/share/doc/${devel}/")
      ;;
    *)
      echo "package file escaped exact ownership contract: ${owned_path}" >&2
      exit 1
      ;;
  esac
done < <(
  pacman "${pacman_args[@]}" -Qlq "${runtime}" "${devel}" |
    sed "s|^${root}||" |
    LC_ALL=C sort -u
)
(
  cd "${root}${target}"
  find . -type f -print | LC_ALL=C sort
) > "${evidence}/target-files.txt"
set +e
grep -E 'x86_64|i[3-6]86|mingw' \
  "${evidence}/target-files.txt" \
  > "${evidence}/forbidden-target-files.txt"
forbidden_status=$?
set -e
test "${forbidden_status}" -eq 1
ln -s msys-gmp-10.dll "${root}${target}/bin/gmp-symlink-check.dll"
test -L "${root}${target}/bin/gmp-symlink-check.dll"
test "$(readlink "${root}${target}/bin/gmp-symlink-check.dll")" = \
  msys-gmp-10.dll
rm "${root}${target}/bin/gmp-symlink-check.dll"
root_snapshot installed
(
  cd "${root}${target}"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${evidence}/installed-payload.sha256"

printf '\0DELIBERATE-CORRUPTION\0' \
  >> "${root}${target}/bin/msys-gmp-10.dll"
set +e
pacman "${pacman_args[@]}" -Qkk "${runtime}" \
  > "${evidence}/corruption-qk.txt" 2>&1
corruption_status=$?
set -e
test "${corruption_status}" -ne 0
sed -i "s|${root}|<PRIVATE_ROOT>|g" \
  "${evidence}/corruption-qk.txt"
grep -Eiq 'altered|modified|size mismatch' \
  "${evidence}/corruption-qk.txt"
pacman "${pacman_args[@]}" --noconfirm -U "${runtime_package}"
check_package_integrity restored "${runtime}"
check_package_integrity restored "${devel}"
(
  cd "${root}${target}"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${evidence}/corruption-restored-payload.sha256"
diff -u \
  "${evidence}/installed-payload.sha256" \
  "${evidence}/corruption-restored-payload.sha256"

pacman "${pacman_args[@]}" --noconfirm -R "${devel}" "${runtime}"
! pacman "${pacman_args[@]}" -Q "${runtime}" >/dev/null 2>&1
! pacman "${pacman_args[@]}" -Q "${devel}" >/dev/null 2>&1
test ! -e "${root}${target}/bin/msys-gmp-10.dll"
test ! -e "${root}${target}/include/gmp.h"
test ! -e "${root}${target}/lib/libgmp.a"
test ! -e "${root}${target}/lib/libgmp.dll.a"
root_snapshot removed

pacman "${pacman_args[@]}" --noconfirm -U "${packages[@]}"
test "$(pacman "${pacman_args[@]}" -Q "${runtime}")" = "${runtime} 6.3.0-2"
test "$(pacman "${pacman_args[@]}" -Q "${devel}")" = "${devel} 6.3.0-2"
check_package_integrity reinstalled "${runtime}"
check_package_integrity reinstalled "${devel}"
(
  cd "${root}${target}"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${evidence}/reinstalled-payload.sha256"
diff -u \
  "${evidence}/installed-payload.sha256" \
  "${evidence}/reinstalled-payload.sha256"
shared_snapshot after
cmp "${evidence}/shared-before.sentinel" \
  "${evidence}/shared-after.sentinel"

: > "${evidence}/package-candidates.tsv"
for package in "${packages[@]}"; do
  printf '%s\t%s\t%s\n' \
    "${package##*/}" \
    "$(stat -c '%s' "${package}")" \
    "$(sha256sum "${package}" | cut -d ' ' -f 1)" \
    >> "${evidence}/package-candidates.tsv"
done
{
  printf 'classification=canonical-build-candidate\n'
  printf 'admissible=false\n'
  printf 'runtime-dependency=%s\n' "${runtime_dependency}"
  printf 'runtime-dependency-version=%s\n' "${runtime_dependency_version}"
  printf 'pacman-root=private\n'
  printf 'pacman-db=private\n'
  printf 'pacman-cache=private\n'
  printf 'pacman-log=private\n'
  printf 'pacman-config=repository-free-private\n'
  printf 'pacman-hooks=private\n'
  printf 'pacman-gpg=private\n'
  printf 'runtime=%s\n' "${runtime}"
  printf 'devel=%s\n' "${devel}"
  printf 'version=6.3.0-2\n'
  printf 'shared-sentinels=unchanged\n'
  printf 'corruption-qkk-reinstall=pass\n'
  printf 'install-remove-reinstall=pass\n'
} > "${evidence}/summary.txt"

scan_report="${evidence}.forbidden-path-scan.json"
rm -f "${scan_report}"
scan_inputs=(
  "${inputs[@]}"
  "${packages[@]}"
  "${root}/var/log/gmp-pacman.log"
  "${evidence}"
  "$0"
  "${binary_scanner}"
)
windows_scan_inputs=()
for input in "${scan_inputs[@]}"; do
  windows_scan_inputs+=("$(cygpath -w "${input}")")
done
MSYS2_ARG_CONV_EXCL='*' "${python_command}" \
  "$(cygpath -w "${binary_scanner}")" \
  --bsdtar "$(cygpath -w /usr/bin/bsdtar.exe)" \
  --zstd "$(cygpath -w /usr/bin/zstd.exe)" \
  --forbid "${root}" \
  --forbid "$(cygpath -w "${root}")" \
  --forbid "${recipe_root}" \
  --forbid "$(cygpath -w "${recipe_root}")" \
  --report "$(cygpath -w "${scan_report}")" \
  "${windows_scan_inputs[@]}"
grep -Fq '"status": "pass"' "${scan_report}"
grep -Fq '"unreadable_or_skipped": 0' "${scan_report}"
mv "${scan_report}" "${evidence}/forbidden-path-scan.json"

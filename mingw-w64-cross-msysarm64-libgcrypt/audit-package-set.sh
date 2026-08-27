#!/usr/bin/env bash
set -euo pipefail

if (( $# < 3 )); then
  echo "usage: $0 PACKAGE_DIR EVIDENCE_DIR DEPENDENCY_PACKAGE..." >&2
  exit 64
fi

package_dir="$(cd "$1" && pwd)"
evidence_dir="$2"
shift 2
dependency_packages=("$@")
target=aarch64-pc-msys
base=mingw-w64-cross-msysarm64-libgcrypt
packages=()

rm -rf "${evidence_dir}"
mkdir -p "${evidence_dir}/pkginfo" "${evidence_dir}/splits"

fail() {
  echo "package-audit: $*" >&2
  exit 1
}

db_manifest() {
  local db="${1:-/var/lib/pacman/local}"
  find "${db}" -type f -print0 |
    sort -z |
    xargs -0 sha256sum |
    sha256sum |
    cut -d' ' -f1
}

shared_db_before="$(db_manifest)"
printf '%s\n' "${shared_db_before}" >"${evidence_dir}/shared-db.before.sha256"

for suffix in '' '-devel' '-tools'; do
  expected="${base}${suffix}"
  matches=()
  while IFS= read -r -d '' candidate; do
    if bsdtar -xOf "${candidate}" .PKGINFO |
        grep -Fxq "pkgname = ${expected}"; then
      matches+=("${candidate}")
    fi
  done < <(find "${package_dir}" -maxdepth 1 -type f \
    -name "${base}-*.pkg.tar.*" ! -name '*-debug-*' -print0)
  (( ${#matches[@]} == 1 )) ||
    fail "expected one ${expected} archive, found ${#matches[@]}"
  packages+=("${matches[0]}")
done

declare -A owners=()
for package in "${packages[@]}"; do
  name="$(basename "${package}")"
  split="${evidence_dir}/splits/${name}"
  mkdir -p "${split}"
  bsdtar -xOf "${package}" .PKGINFO >"${evidence_dir}/pkginfo/${name}.PKGINFO"
  grep -Fxq 'arch = x86_64' "${evidence_dir}/pkginfo/${name}.PKGINFO" ||
    fail "wrong package architecture: ${name}"
  bsdtar -xf "${package}" -C "${split}"

  payload_count=0
  while IFS= read -r -d '' path; do
    relative="${path#${split}/}"
    case "${relative}" in
      .BUILDINFO|.MTREE|.PKGINFO) continue ;;
    esac
    [[ -f "${path}" || -L "${path}" ]] || continue
    ((payload_count += 1))
    if [[ -n "${owners[${relative}]:-}" ]]; then
      fail "package overlap: ${relative} (${owners[${relative}]} and ${name})"
    fi
    owners["${relative}"]="${name}"
  done < <(find "${split}" \( -type f -o -type l \) -print0)
  (( payload_count > 1 )) || fail "empty package split: ${name}"
  printf '%s\n' "${payload_count}" >"${evidence_dir}/pkginfo/${name}.payload-count"
done

runtime_pkginfo="${evidence_dir}/pkginfo/$(basename "${packages[0]}").PKGINFO"
devel_pkginfo="${evidence_dir}/pkginfo/$(basename "${packages[1]}").PKGINFO"
tools_pkginfo="${evidence_dir}/pkginfo/$(basename "${packages[2]}").PKGINFO"
grep -Eq '^depend = aarch64-pc-msys-runtime=' "${runtime_pkginfo}" ||
  fail "runtime dependency is not pinned"
grep -Eq '^depend = aarch64-pc-msys-libgpg-error>=' "${runtime_pkginfo}" ||
  fail "runtime is missing native libgpg-error dependency"
grep -Eq '^depend = aarch64-pc-msys-libgcrypt=' "${devel_pkginfo}" ||
  fail "devel is missing exact runtime dependency"
grep -Eq '^depend = aarch64-pc-msys-libgcrypt=' "${tools_pkginfo}" ||
  fail "tools is missing exact runtime dependency"

merged="${evidence_dir}/merged"
mkdir -p "${merged}"
for split in "${evidence_dir}"/splits/*; do
  cp -a "${split}/." "${merged}/"
done
target_usr="${merged}/opt/${target}/usr"
TARGET_TRIPLET="${target}" \
  "$(dirname "$0")/audit-libgcrypt.sh" "${target_usr}" '' \
    "${evidence_dir}/tree-audit"

root="${evidence_dir}/transaction-root"
db="${root}/var/lib/pacman"
cache="${root}/var/cache/pacman/pkg"
mkdir -p "${db}" "${cache}" "${root}/etc"
cat >"${evidence_dir}/pacman.conf" <<EOF
[options]
Architecture = x86_64
SigLevel = Never
LocalFileSigLevel = Never
EOF

pacman_cmd=(
  pacman
  --root "${root}"
  --dbpath "${db}"
  --cachedir "${cache}"
  --config "${evidence_dir}/pacman.conf"
  --noconfirm
)
transaction_inputs=("${dependency_packages[@]}" "${packages[@]}")
"${pacman_cmd[@]}" -U "${transaction_inputs[@]}" \
  >"${evidence_dir}/install.log" 2>&1
"${pacman_cmd[@]}" -Q >"${evidence_dir}/installed.txt"
for package_name in "${base}" "${base}-devel" "${base}-tools"; do
  grep -Eq "^${package_name}[[:space:]]" "${evidence_dir}/installed.txt" ||
    fail "transaction did not install ${package_name}"
done

"${pacman_cmd[@]}" -Rns "${base}-devel" "${base}-tools" "${base}" \
  >"${evidence_dir}/remove.log" 2>&1
for package_name in "${base}" "${base}-devel" "${base}-tools"; do
  if "${pacman_cmd[@]}" -Q "${package_name}" >/dev/null 2>&1; then
    fail "transaction did not remove ${package_name}"
  fi
done

"${pacman_cmd[@]}" -U "${packages[@]}" \
  >"${evidence_dir}/reinstall.log" 2>&1
"${pacman_cmd[@]}" -Q >"${evidence_dir}/reinstalled.txt"

shared_db_after="$(db_manifest)"
printf '%s\n' "${shared_db_after}" >"${evidence_dir}/shared-db.after.sha256"
test "${shared_db_before}" = "${shared_db_after}" ||
  fail "shared pacman database changed"

for package in "${packages[@]}"; do
  sha256sum "${package}"
  stat -c '%n %s bytes' "${package}"
done >"${evidence_dir}/archives.txt"

printf 'packages=3\nownership_overlap=0\ntransaction=install-remove-reinstall\nshared_db_unchanged=1\nstatus=green\n' \
  >"${evidence_dir}/summary.txt"
cat "${evidence_dir}/summary.txt"

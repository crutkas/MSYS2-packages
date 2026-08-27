#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 ARTIFACT_DIR REPORT_DIR REPOSITORY_ROOT TOOLCHAIN_DIR" >&2
  exit 2
fi

artifact_dir=$(realpath "$1")
report_dir=$(realpath -m "$2")
repository_root=$(realpath "$3")
toolchain_dir=$(realpath "$4")
version=3.53.4-1
package_names=(
  mingw-w64-cross-msysarm64-libsqlite
  mingw-w64-cross-msysarm64-libsqlite-devel
  mingw-w64-cross-msysarm64-sqlite
)
package_files=()
extract_root=$(mktemp -d)
transaction_root=$(mktemp -d)
trap 'rm -rf "${extract_root}" "${transaction_root}"' EXIT

rm -rf "${report_dir}"
mkdir -p "${report_dir}/metadata"

for name in "${package_names[@]}"; do
  file="${artifact_dir}/${name}-${version}-x86_64.pkg.tar.zst"
  test -f "${file}"
  package_files+=("${file}")
  bsdtar -xOf "${file}" .PKGINFO \
    > "${report_dir}/metadata/${name}.PKGINFO"
done

require_metadata() {
  local package_name=$1
  local expected=$2
  grep -Fx "${expected}" \
    "${report_dir}/metadata/${package_name}.PKGINFO"
}

require_metadata mingw-w64-cross-msysarm64-libsqlite \
  'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'depend = mingw-w64-cross-msysarm64-libsqlite=3.53.4-1'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'depend = mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'depend = mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'provides = aarch64-pc-msys-sqlite-devel=3.53.4'
require_metadata mingw-w64-cross-msysarm64-sqlite \
  'depend = mingw-w64-cross-msysarm64-libsqlite=3.53.4-1'
require_metadata mingw-w64-cross-msysarm64-sqlite \
  'depend = mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1'
for name in "${package_names[@]}"; do
  require_metadata "${name}" \
    'makedepend = mingw-w64-cross-cygwinarm64-binutils=2.44.50-2'
done

declare -A payload_owners=()
for index in "${!package_files[@]}"; do
  package_file=${package_files[$index]}
  package_name=${package_names[$index]}
  while IFS= read -r path; do
    path=${path#./}
    [[ -n "${path}" && "${path}" != */ ]] || continue
    case "${path}" in
      .BUILDINFO|.MTREE|.PKGINFO)
        continue
        ;;
    esac
    if [[ -n "${payload_owners[$path]:-}" ]]; then
      echo "package payload overlap: ${path}" >&2
      exit 1
    fi
    payload_owners[$path]=${package_name}
    printf '%s\t%s\n' "${package_name}" "${path}" \
      >> "${report_dir}/payload-ownership.tsv"
  done < <(bsdtar -tf "${package_file}")
  MSYS=winsymlinks:sys bsdtar -xf "${package_file}" -C "${extract_root}"
done

bash \
  "${repository_root}/mingw-w64-cross-msysarm64-sqlite/validate-sqlite.sh" \
  "${extract_root}" \
  "${report_dir}/archive-audit"

package_report="${extract_root}/opt/aarch64-pc-msys/share/doc/mingw-w64-cross-msysarm64-sqlite"
grep -Fx $'binutils-version\t2.44.50-2' \
  "${package_report}/source-identity.txt"
grep -Fx $'binutils-package-sha256\t3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b' \
  "${package_report}/source-identity.txt"
grep -Fx $'binutils-linker-sha256\t075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f' \
  "${package_report}/source-identity.txt"
mapfile -t scanner_reports < <(
  find "${package_report}/pseudo-relocs" -maxdepth 1 \
    -type f -name '*.json' | LC_ALL=C sort
)
test "${#scanner_reports[@]}" -eq 4
for scanner_report in "${scanner_reports[@]}"; do
  python -c '
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert data["result"] == "pass"
assert data["policy_violations"] == []
assert all(flag in (8, 16, 32, 64) for flag in data["flags"])
assert not ({12, 21} & set(data["flags"]))
' "${scanner_report}"
done

sha256sum "${package_files[@]}" \
  | sed "s#${artifact_dir}/##" \
  > "${report_dir}/package-sha256.txt"

toolchain_names=(
  mingw-w64-cross-cygwinarm64-binutils-2.44.50-2-x86_64.pkg.tar.zst
  mingw-w64-cross-cygwinarm64-gcc-libs-stage1-15.0.1dev-2-x86_64.pkg.tar.zst
  mingw-w64-cross-cygwinarm64-gcc-stage1-15.0.1dev-2-x86_64.pkg.tar.zst
  mingw-w64-cross-cygwinarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-headers-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-windows-default-manifest-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-sysroot-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-runtime-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-runtime-devel-3.6.10.r0.ga527ace21-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-w32api-runtime-14.0.0.r0.g9b3dd0125-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-libstdc++-headers-15.0.1dev-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-gcc-libs-15.0.1dev-1-x86_64.pkg.tar.zst
  mingw-w64-cross-msysarm64-gcc-15.0.1dev-1-x86_64.pkg.tar.zst
)
toolchain_files=()
for name in "${toolchain_names[@]}"; do
  file="${toolchain_dir}/${name}"
  test -f "${file}"
  toolchain_files+=("${file}")
done

pacman_db="${transaction_root}/var/lib/pacman"
pacman_cache="${transaction_root}/var/cache/pacman/pkg"
pacman_log="${transaction_root}/var/log/pacman.log"
pacman_config="${transaction_root}/etc/pacman-ci.conf"
pacman_gpg="${transaction_root}/etc/pacman.d/gnupg"
pacman_hooks="${transaction_root}/etc/pacman.d/hooks-empty"
mkdir -p \
  "${pacman_db}" \
  "${pacman_cache}" \
  "$(dirname "${pacman_log}")" \
  "$(dirname "${pacman_config}")" \
  "${pacman_gpg}" \
  "${pacman_hooks}"

cat > "${pacman_config}" <<'EOF'
[options]
Architecture = x86_64
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Never

[msys]
Server = https://repo.msys2.org/msys/x86_64/
EOF

pacman-key --gpgdir "${pacman_gpg}" --init
pacman-key --gpgdir "${pacman_gpg}" --populate msys2
pacman-key --gpgdir "${pacman_gpg}" --list-keys \
  > "${report_dir}/isolated-keyring.txt"

pacman_root() {
  pacman \
    --config "${pacman_config}" \
    --root "${transaction_root}" \
    --dbpath "${pacman_db}" \
    --cachedir "${pacman_cache}" \
    --logfile "${pacman_log}" \
    --gpgdir "${pacman_gpg}" \
    --hookdir "${pacman_hooks}" \
    "$@"
}

pacman_root --noconfirm --sync --refresh
MSYS=winsymlinks:sys pacman_root \
  --noconfirm \
  --sync \
  --needed \
  -- \
  gmp isl libiconv libintl libzstd mpc mpfr zlib
MSYS=winsymlinks:sys pacman_root \
  --noconfirm \
  --upgrade \
  -- "${toolchain_files[@]}"
pacman_root --query > "${report_dir}/isolated-before.txt"
pacman_root --query --quiet > "${report_dir}/isolated-before-names.txt"

for name in "${package_names[@]}"; do
  if pacman_root --query "${name}" > /dev/null 2>&1; then
    echo "SQLite package was installed before transaction test: ${name}" >&2
    exit 1
  fi
done

MSYS=winsymlinks:sys pacman_root \
  --noconfirm \
  --upgrade \
  -- "${package_files[@]}"
pacman_root --query > "${report_dir}/isolated-after-install.txt"
pacman_root --query --quiet > "${report_dir}/isolated-after-install-names.txt"

for name in "${package_names[@]}"; do
  test "$(pacman_root --query "${name}")" = "${name} ${version}"
  pacman_root --query --check "${name}"
  pacman_root --query --info --info "${name}" \
    >> "${report_dir}/installed-package-info.txt"
  pacman_root --query --list "${name}" \
    >> "${report_dir}/installed-files.txt"
done

for path in "${!payload_owners[@]}"; do
  installed_path="${transaction_root}/${path}"
  owner=$(pacman_root --query --owns --quiet "${installed_path}")
  test "${owner}" = "${payload_owners[$path]}"
done

requirements=(
  mingw-w64-cross-msysarm64-libsqlite=3.53.4-1
  mingw-w64-cross-msysarm64-libsqlite-devel=3.53.4-1
  mingw-w64-cross-msysarm64-sqlite=3.53.4-1
  mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-gcc=15.0.1dev-1
  mingw-w64-cross-cygwinarm64-binutils=2.44.50-2
)
test -z "$(pacman_root --deptest -- "${requirements[@]}")"

pacman_root --noconfirm --remove -- "${package_names[@]}"
for name in "${package_names[@]}"; do
  if pacman_root --query "${name}" > /dev/null 2>&1; then
    echo "SQLite package remained after removal: ${name}" >&2
    exit 1
  fi
done
pacman_root --query > "${report_dir}/isolated-after-remove.txt"
pacman_root --query --quiet > "${report_dir}/isolated-after-remove-names.txt"
diff -u \
  "${report_dir}/isolated-before.txt" \
  "${report_dir}/isolated-after-remove.txt"
diff -u \
  "${report_dir}/isolated-before-names.txt" \
  "${report_dir}/isolated-after-remove-names.txt"

MSYS=winsymlinks:sys pacman_root \
  --noconfirm \
  --upgrade \
  -- "${package_files[@]}"
for name in "${package_names[@]}"; do
  test "$(pacman_root --query "${name}")" = "${name} ${version}"
done
pacman_root --query > "${report_dir}/isolated-after-reinstall.txt"
pacman_root --query --quiet > "${report_dir}/isolated-after-reinstall-names.txt"
diff -u \
  "${report_dir}/isolated-after-install.txt" \
  "${report_dir}/isolated-after-reinstall.txt"
diff -u \
  "${report_dir}/isolated-after-install-names.txt" \
  "${report_dir}/isolated-after-reinstall-names.txt"

MSYSARM64_SQLITE_SHARED_PREFIX=1 bash \
  "${repository_root}/mingw-w64-cross-msysarm64-sqlite/validate-sqlite.sh" \
  "${transaction_root}" \
  "${report_dir}/installed-audit"

cp "${pacman_log}" "${report_dir}/isolated-pacman-transactions.log"
sha256sum \
  "${pacman_config}" \
  "${report_dir}"/isolated-*.txt \
  > "${report_dir}/isolated-root-evidence.sha256"
grep -F '[ALPM] transaction started' \
  "${report_dir}/isolated-pacman-transactions.log"
grep -F '[ALPM] transaction completed' \
  "${report_dir}/isolated-pacman-transactions.log"

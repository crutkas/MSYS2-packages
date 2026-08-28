#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 ARTIFACT_DIR REPORT_DIR REPOSITORY_ROOT TOOLCHAIN_DIR BASE_ARCHIVE HOST_INPUT_DIR" >&2
  exit 2
fi

artifact_dir=$(realpath "$1")
report_dir=$(realpath -m "$2")
repository_root=$(realpath "$3")
toolchain_dir=$(realpath "$4")
base_archive=$(realpath "$5")
host_input_dir=$(realpath "$6")
version=3.53.4-2
test "$(stat -c %s "${base_archive}")" -eq 53555380
test "$(sha256sum "${base_archive}" | awk '{print $1}')" = \
  a2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221
package_names=(
  mingw-w64-cross-msysarm64-libsqlite
  mingw-w64-cross-msysarm64-libsqlite-devel
  mingw-w64-cross-msysarm64-sqlite
)
package_files=()
extract_root=$(mktemp -d)
transaction_parent=$(mktemp -d)
trap 'rm -rf "${extract_root}" "${transaction_parent}"' EXIT

rm -rf "${report_dir}"
mkdir -p "${report_dir}/metadata"

for name in "${package_names[@]}"; do
  file="${artifact_dir}/${name}-${version}-x86_64.pkg.tar.zst"
  test -f "${file}"
  package_files+=("${file}")
  bsdtar -xOf "${file}" .PKGINFO \
    > "${report_dir}/metadata/${name}.PKGINFO"
done

archive_safety="${repository_root}/.ci/Test-ArchiveSafety.ps1"
archive_safety_dir="${report_dir}/archive-safety"
mkdir -p "${archive_safety_dir}"
pwsh -NoLogo -NoProfile -File "$(cygpath -w "${archive_safety}")" \
  -ArchivePath "$(cygpath -w "${base_archive}")" \
  -OutputPath "$(cygpath -w "${archive_safety_dir}/base.json")"
for package_file in "${package_files[@]}"; do
  name=$(basename "${package_file}")
  pwsh -NoLogo -NoProfile -File "$(cygpath -w "${archive_safety}")" \
    -ArchivePath "$(cygpath -w "${package_file}")" \
    -OutputPath "$(cygpath -w "${archive_safety_dir}/${name}.json")"
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
  'depend = mingw-w64-cross-msysarm64-libsqlite=3.53.4-2'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'depend = mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'depend = mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1'
require_metadata mingw-w64-cross-msysarm64-libsqlite-devel \
  'provides = aarch64-pc-msys-sqlite-devel=3.53.4'
require_metadata mingw-w64-cross-msysarm64-sqlite \
  'depend = mingw-w64-cross-msysarm64-libsqlite=3.53.4-2'
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
grep -Fx $'private-base-sha256\ta2d047e8ee213c3c6a49a8de427eb1069df12207c0422ff1b3cbb5c905c34221' \
  "${package_report}/source-identity.txt"
grep -Fx $'host-isl\t0.27-1\tcdd0a4ce0bf0d9e3f3eff2b770b8143e09e126a614de8b55bb5d30fc596b92d1' \
  "${package_report}/source-identity.txt"
grep -Fx $'host-mpc\t1.4.1-1\t0f5073ec2e8be265854ee3c7cb1079b5e8e02264d53e659d8414988c6c182f16' \
  "${package_report}/source-identity.txt"
scanner="${package_report}/check-aarch64-pseudo-relocs.ps1"
report_binder="${package_report}/validate-pseudo-reloc-reports.ps1"
objdump_path="$(realpath "$(command -v aarch64-pc-msys-objdump)")"
nm_path="$(realpath "$(command -v aarch64-pc-msys-nm)")"
scanned_pes=(
 "${extract_root}/opt/aarch64-pc-msys/bin/msys-sqlite3-0.dll"
 "${extract_root}/opt/aarch64-pc-msys/bin/sqlite3.exe"
 "${artifact_dir}/sqlite-api-dynamic-smoke.exe"
 "${artifact_dir}/sqlite-api-static-smoke.exe"
)
for pe in "${scanned_pes[@]}"; do
 test -f "${pe}"
done
rm -f "${report_dir}/scanner-binding-summary.tsv"
first_report=1
for pe in "${scanned_pes[@]}"; do
 report_args=(
   -ReportDirectory "$(cygpath -w "${package_report}/pseudo-relocs")"
   -PePath "$(cygpath -w "${pe}")"
   -ScannerPath "$(cygpath -w "${scanner}")"
   -ObjdumpPath "$(cygpath -w "${objdump_path}")"
   -NmPath "$(cygpath -w "${nm_path}")"
   -ExpectedScannerSha256 888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9
   -ExpectedObjdumpSha256 bb0d53db4128aff7f6b20c46be4e3625b1d82134476d7b03e58ed22015136e6e
   -ExpectedNmSha256 80b4716108b362ba05f48cd9228d20a4193897b4a5eeb8eb19e80f4c83e3e90a
   -SummaryPath "$(cygpath -w "${report_dir}/scanner-binding-summary.tsv")"
 )
 if [[ "${first_report}" -eq 0 ]]; then
   report_args+=(-AppendSummary)
 fi
 pwsh -NoLogo -NoProfile -File "$(cygpath -w "${report_binder}")" \
   "${report_args[@]}"
 first_report=0
done
test "$(wc -l < "${report_dir}/scanner-binding-summary.tsv")" -eq 4

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
(
  cd "${toolchain_dir}"
  sha256sum -c input-assets.sha256
)

host_names=(
  isl-0.27-1-x86_64.pkg.tar.zst
  mpc-1.4.1-1-x86_64.pkg.tar.zst
)
host_hashes=(
  cdd0a4ce0bf0d9e3f3eff2b770b8143e09e126a614de8b55bb5d30fc596b92d1
  0f5073ec2e8be265854ee3c7cb1079b5e8e02264d53e659d8414988c6c182f16
)
host_files=()
for index in "${!host_names[@]}"; do
  file="${host_input_dir}/${host_names[$index]}"
  test -f "${file}"
  test "$(sha256sum "${file}" | awk '{print $1}')" = \
    "${host_hashes[$index]}"
  host_files+=("${file}")
done
for package_file in "${host_files[@]}" "${toolchain_files[@]}"; do
  name=$(basename "${package_file}")
  pwsh -NoLogo -NoProfile -File "$(cygpath -w "${archive_safety}")" \
    -ArchivePath "$(cygpath -w "${package_file}")" \
    -OutputPath "$(cygpath -w "${archive_safety_dir}/${name}.json")"
done

bsdtar -xf "${base_archive}" -C "${transaction_parent}"
transaction_root="${transaction_parent}/msys64"
test -x "${transaction_root}/usr/bin/pacman.exe"

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
EOF

pacman_root() {
  "${transaction_root}/usr/bin/pacman.exe" \
    --config "${pacman_config}" \
    --root "${transaction_root}" \
    --dbpath "${pacman_db}" \
    --cachedir "${pacman_cache}" \
    --logfile "${pacman_log}" \
    --gpgdir "${pacman_gpg}" \
    --hookdir "${transaction_root}/usr/share/libalpm/hooks" \
    --hookdir "${pacman_hooks}" \
    "$@"
}

MSYS=winsymlinks:sys pacman_root \
  --noconfirm \
  --upgrade \
  -- "${host_files[@]}" "${toolchain_files[@]}"
find "${pacman_gpg}" -type f -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum \
  > "${report_dir}/isolated-keyring-files.sha256"
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
  mingw-w64-cross-msysarm64-libsqlite=3.53.4-2
  mingw-w64-cross-msysarm64-libsqlite-devel=3.53.4-2
  mingw-w64-cross-msysarm64-sqlite=3.53.4-2
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
test "$(
  cat "${report_dir}/isolated-before.txt"
)" = "$(
  cat "${report_dir}/isolated-after-remove.txt"
)"
test "$(
  cat "${report_dir}/isolated-before-names.txt"
)" = "$(
  cat "${report_dir}/isolated-after-remove-names.txt"
)"

MSYS=winsymlinks:sys pacman_root \
  --noconfirm \
  --upgrade \
  -- "${package_files[@]}"
for name in "${package_names[@]}"; do
  test "$(pacman_root --query "${name}")" = "${name} ${version}"
done
pacman_root --query > "${report_dir}/isolated-after-reinstall.txt"
pacman_root --query --quiet > "${report_dir}/isolated-after-reinstall-names.txt"
test "$(
  cat "${report_dir}/isolated-after-install.txt"
)" = "$(
  cat "${report_dir}/isolated-after-reinstall.txt"
)"
test "$(
  cat "${report_dir}/isolated-after-install-names.txt"
)" = "$(
  cat "${report_dir}/isolated-after-reinstall-names.txt"
)"

MSYSARM64_SQLITE_SHARED_PREFIX=1 bash \
  "${repository_root}/mingw-w64-cross-msysarm64-sqlite/validate-sqlite.sh" \
  "${transaction_root}" \
  "${report_dir}/installed-audit"

cp "${pacman_log}" "${report_dir}/isolated-pacman-transactions.log"
cp "${pacman_config}" "${report_dir}/isolated-pacman.conf"
grep -F '[ALPM] transaction started' \
  "${report_dir}/isolated-pacman-transactions.log"
grep -F '[ALPM] transaction completed' \
  "${report_dir}/isolated-pacman-transactions.log"

sanitizer="${repository_root}/.ci/Sanitize-Evidence.ps1"
for sensitive in \
  "${repository_root}" \
  "${artifact_dir}" \
  "${toolchain_dir}" \
  "${host_input_dir}" \
  "${transaction_parent}" \
  "${extract_root}" \
  "$(dirname "${base_archive}")"
do
  find "${report_dir}" -type f -exec \
    sed -i "s#${sensitive}#<private-root>#g" {} +
  pwsh -NoLogo -NoProfile -File "$(cygpath -w "${sanitizer}")" \
    -EvidenceRoot "$(cygpath -w "${report_dir}")" \
    -SensitivePath "$(cygpath -w "${sensitive}")"
  if grep -RIlF "${sensitive}" "${report_dir}" | grep -q .; then
    echo "unsanitized evidence path: ${sensitive}" >&2
    exit 1
  fi
done

(
  cd "${report_dir}"
  find . -type f ! -name isolated-root-evidence.sha256 -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "${report_dir}/isolated-root-evidence.sha256"

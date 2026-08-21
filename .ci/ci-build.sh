#!/bin/bash

set -eo pipefail

# AppVeyor and Drone Continuous Integration for MSYS2
# Author: Renato Silva <br.renatosilva@gmail.com>
# Author: Qian Hong <fracting@gmail.com>

DIR="$( cd "$( dirname "$0" )" && pwd )"

# Configure
mkdir artifacts
ci_base_remote=ci-base
ci_base_repository=${CI_BASE_REPOSITORY:-https://github.com/crutkas/MSYS2-packages}
ci_base_ref=${CI_BASE_REF:-master}
git remote remove "${ci_base_remote}" > /dev/null 2>&1 || true
git remote add "${ci_base_remote}" "${ci_base_repository}"
git fetch --quiet "${ci_base_remote}" \
    "${ci_base_ref}:refs/remotes/${ci_base_remote}/${ci_base_ref}"
export CI_BASE_REV="${ci_base_remote}/${ci_base_ref}"
# reduce time required to install packages by disabling pacman's disk space checking
sed -i 's/^CheckSpace/#CheckSpace/g' /etc/pacman.conf

pacman --noconfirm -Fy

# Enable colors
normal=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
cyan=$(tput setaf 6)

# Basic status function
_status() {
    local type="${1}"
    local status="${package:+${package}: }${2}"
    local items=("${@:3}")
    case "${type}" in
        failure) local -n nameref_color='red';   title='[MSYS2 CI] FAILURE:' ;;
        success) local -n nameref_color='green'; title='[MSYS2 CI] SUCCESS:' ;;
        message) local -n nameref_color='cyan';  title='[MSYS2 CI]'
    esac
    printf "\n${nameref_color}${title}${normal} ${status}\n\n"
    printf "${items:+\t%s\n}" "${items:+${items[@]}}"
}

# Run command with status
execute(){
    local status="${1}"
    local command="${2}"
    local arguments=("${@:3}")
    cd "${package:-.}"
    message "${status}"
    if [[ "${command}" != *:* ]]
        then ${command} ${arguments[@]}
        else ${command%%:*} | ${command#*:} ${arguments[@]}
    fi || failure "${status} failed"
    cd - > /dev/null
}

# Get changed packages in correct build order
list_packages() {
    # readarray doesn't work with a plain pipe
    readarray -t packages < <("$DIR/ci-get-build-order.py")
}

install_packages() {
    pacman "${pacman_local_arch_args[@]}" --noprogressbar --upgrade --noconfirm *.pkg.tar.*
}

# Status functions
failure() { local status="${1}"; local items=("${@:2}"); _status failure "${status}." "${items[@]}"; exit 1; }
success() { local status="${1}"; local items=("${@:2}"); _status success "${status}." "${items[@]}"; exit 0; }
message() { local status="${1}"; local items=("${@:2}"); _status message "${status}"  "${items[@]}"; }

# Detect
list_packages || failure 'Could not detect changed files'
message 'Processing changes'
test -z "${packages}" && success 'No changes in package recipes'

# Build
message 'Building packages' "${packages[@]}"

message 'Adding an empty local repository'
repo-add $PWD/artifacts/ci.db.tar.gz
sed -i '1s|^|[ci]\nServer = file://'"$PWD"'/artifacts/\nSigLevel = Never\n|' /etc/pacman.conf
pacman -Sy

# Remove git and python
pacman -R --recursive --unneeded --noconfirm --noprogressbar git python

pacman_local_arch_args=()
if [[ -n "${CI_PACKAGE_ARCH:-}" ]]; then
    pacman_local_arch_args=(--arch "${CI_PACKAGE_ARCH}")
fi

# Enable linting
export MAKEPKG_LINT_PKGBUILD=1

message 'Building packages'
for package in "${packages[@]}"; do
    echo "::group::[build] ${package}"
    execute 'Clear cache' pacman -Scc --noconfirm
    execute 'Fetch keys' "$DIR/fetch-validpgpkeys.sh"
    makepkg_args=(--noconfirm --noprogressbar --syncdeps --rmdeps --cleanbuild)
    if [[ "${CI_RUN_CHECK:-0}" != 1 ]]; then
        makepkg_args+=(--nocheck)
    fi
    execute 'Building binary' makepkg "${makepkg_args[@]}"
    if [[ "${CI_CANONICALIZE_PACKAGES:-0}" == 1 ]]; then
        execute 'Canonicalizing package containers' \
            bash "$DIR/canonicalize-packages.sh" *.pkg.tar.zst
    fi
    cp $PWD/$package/*.pkg.tar.* $PWD/artifacts
    sync
    repo-add $PWD/artifacts/ci.db.tar.gz $PWD/artifacts/*.pkg.tar.*
    pacman "${pacman_local_arch_args[@]}" -Sy
    echo "::endgroup::"

    cd "$package"
    for pkg in *.pkg.tar.*; do
        pkgname="$(echo "$pkg" | rev | cut -d- -f4- | rev)"
        echo "::group::[install] ${pkgname}"
        grep -qFx "${package}" "$DIR/ci-dont-install-list.txt" || pacman "${pacman_local_arch_args[@]}" --noprogressbar --upgrade --noconfirm $pkg
        if [[ -n "${CI_PACKAGE_ARCH:-}" ]]; then
            pacman --arch "${CI_PACKAGE_ARCH}" -Qip "${pkg}" | grep -q '^Architecture[[:space:]]*:[[:space:]]*aarch64$'
        fi
        echo "::endgroup::"

        echo "::group::[meta-diff] ${pkgname}"
        message "Package info diff for ${pkgname}"
        diff -Nur <(pacman "${pacman_local_arch_args[@]}" -Si ${MSYSTEM,,}/"${pkgname}") <(pacman -Qip "${pkg}") || true
        echo "::endgroup::"

        echo "::group::[file-diff] ${pkgname}"
        message "File listing diff for ${pkgname}"
        diff -Nur <(pacman "${pacman_local_arch_args[@]}" -Fl ${MSYSTEM,,}/"$pkgname" | sed -e 's|^[^ ]* |/|' | sort) <(pacman "${pacman_local_arch_args[@]}" -Ql "$pkgname" | sed -e 's|^[^/]*||' | sort) || true
        echo "::endgroup::"

        echo "::group::[dll check] ${pkgname}"
        declare -a binaries=($(pacman "${pacman_local_arch_args[@]}" -Qlq $pkgname | grep -E ${MINGW_PREFIX}/.+\.\(dll\|exe\|pyd\)$))
        if [ "${#binaries[@]}" -ne 0 ]; then
            message "Runtime dependencies for ${pkgname}"
            for binary in ${binaries[@]}; do
                echo "${binary}:"
                ldd ${binary} | GREP_COLOR="1;35" grep --color=always "msys-.*\|" \
                    || echo "        None"
            done
            message "DLL bases for ${pkgname}"
            rebase -i "${binaries[@]}" | GREP_COLOR="1;35" grep --color=always "msys-.*\|" \
                || echo "        None"
        fi
        echo "::endgroup::"

        echo "::group::[uninstall] ${pkgname}"
        message "Uninstalling $pkgname"
        grep -qFx "${package}" "$DIR/ci-dont-install-list.txt" || pacman "${pacman_local_arch_args[@]}" -R --recursive --unneeded --noconfirm --noprogressbar "$pkgname"
        echo "::endgroup::"
    done
    cd - > /dev/null

    rm -f "${package}"/*.pkg.tar.*
    unset package
done
success 'All packages built successfully'

cd artifacts
execute 'SHA-256 checksums' sha256sum *

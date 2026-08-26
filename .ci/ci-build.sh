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
    pacman --noprogressbar --upgrade --noconfirm *.pkg.tar.*
}

prepare_gcc_dependencies() {
    local srcinfo_file dependency dependency_name self_package is_self
    local requirement requirement_name requirement_version actual_identity
    local missing_external external_rc missing_self self_rc
    local -a raw_self_packages self_packages raw_declared_dependencies
    local -a declared_dependencies self_dependencies external_dependencies
    local -a expected_external_dependencies ci_requirements

    if compgen -G "$package/*.pkg.tar.*" > /dev/null; then
        failure 'Stale GCC package archives exist'
    fi
    srcinfo_file=$(mktemp)
    if ! (cd "$package" && makepkg --printsrcinfo > "$srcinfo_file"); then
        rm -f "$srcinfo_file"
        failure 'Generating GCC SRCINFO failed'
    fi
    readarray -t raw_self_packages < <(
        awk -F ' = ' '
            {
                key = $1
                sub(/^[[:space:]]*/, "", key)
                if (key == "pkgname")
                    print $2
            }
        ' "$srcinfo_file"
    )
    readarray -t self_packages < <(
        printf '%s\n' "${raw_self_packages[@]}" | LC_ALL=C sort -u
    )
    readarray -t raw_declared_dependencies < <(
        awk -F ' = ' '
            {
                key = $1
                sub(/^[[:space:]]*/, "", key)
                if (key ~ /^(depends|makedepends|checkdepends)(_[[:alnum:]_]+)?$/)
                    print $2
            }
        ' "$srcinfo_file"
    )
    rm -f "$srcinfo_file"
    test "${#raw_self_packages[@]}" -eq 2
    readarray -t declared_dependencies < <(
        printf '%s\n' "${raw_declared_dependencies[@]}" |
            LC_ALL=C sort -u
    )
    test "${#self_packages[@]}" -eq 2
    test "$(printf '%s\n' "${self_packages[@]}")" = \
        $'mingw-w64-cross-msysarm64-gcc\nmingw-w64-cross-msysarm64-gcc-libs'
    test "${#declared_dependencies[@]}" -gt 0

    self_dependencies=()
    external_dependencies=()
    for dependency in "${declared_dependencies[@]}"; do
        dependency_name=${dependency%%[<>=]*}
        is_self=0
        for self_package in "${self_packages[@]}"; do
            if [[ "$dependency_name" == "$self_package" ]]; then
                is_self=1
                break
            fi
        done
        if [[ "$is_self" == 1 ]]; then
            self_dependencies+=("$dependency")
        else
            external_dependencies+=("$dependency")
        fi
    done
    test "${#self_dependencies[@]}" -eq 1
    test "${self_dependencies[0]}" = \
        mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1
    expected_external_dependencies=(
        gcc
        gmp-devel
        isl-devel
        libiconv-devel
        libzstd-devel
        make
        mingw-w64-cross-cygwinarm64-binutils\>=2.44.50
        mingw-w64-cross-cygwinarm64-gcc-stage1=15.0.1dev-2
        mingw-w64-cross-msysarm64-libstdc++-headers=15.0.1dev-1
        mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1
        mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1
        mingw-w64-cross-msysarm64-w32api-runtime=14.0.0.r0.g9b3dd0125-1
        mpc-devel
        mpfr-devel
        python
        zlib-devel
    )
    test "${#external_dependencies[@]}" -eq 16
    test "$(printf '%s\n' "${external_dependencies[@]}")" = \
        "$(printf '%s\n' "${expected_external_dependencies[@]}")"

    ci_requirements=(
        mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1
        mingw-w64-cross-msysarm64-w32api-runtime=14.0.0.r0.g9b3dd0125-1
        mingw-w64-cross-msysarm64-libstdc++-headers=15.0.1dev-1
        mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1
    )
    for requirement in "${ci_requirements[@]}"; do
        requirement_name=${requirement%%=*}
        requirement_version=${requirement#*=}
        actual_identity=$(
            pacman -Sddp --print-format '%r|%n|%v' -- \
                "ci/$requirement_name"
        )
        test "$actual_identity" = \
            "ci|$requirement_name|$requirement_version"
    done

    execute 'Installing GCC non-self dependencies' \
        pacman -S --needed --asdeps --noconfirm --noprogressbar -- \
        "${external_dependencies[@]}"
    set +e
    missing_external=$(pacman -T -- "${external_dependencies[@]}")
    external_rc=$?
    set -e
    test "$external_rc" -eq 0
    test -z "$missing_external"
    if pacman -Q mingw-w64-cross-msysarm64-gcc-libs \
            > /dev/null 2>&1; then
        failure 'GCC sibling dependency is unexpectedly installed'
    fi
    set +e
    missing_self=$(pacman -T -- "${self_dependencies[@]}")
    self_rc=$?
    set -e
    test "$self_rc" -eq 127
    test "$missing_self" = "${self_dependencies[0]}"

    makepkg_args=(--noconfirm --noprogressbar --nodeps --cleanbuild)
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

# Enable linting
export MAKEPKG_LINT_PKGBUILD=1

message 'Building packages'
for package in "${packages[@]}"; do
    echo "::group::[build] ${package}"
    execute 'Clear cache' pacman -Scc --noconfirm
    execute 'Fetch keys' "$DIR/fetch-validpgpkeys.sh"
    if [[ "$package" == mingw-w64-cross-msysarm64-gcc ]]; then
        prepare_gcc_dependencies
    else
        makepkg_args=(--noconfirm --noprogressbar --syncdeps --rmdeps --cleanbuild)
    fi
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
    pacman -Sy
    echo "::endgroup::"

    cd "$package"
    for pkg in *.pkg.tar.*; do
        pkgname="$(echo "$pkg" | rev | cut -d- -f4- | rev)"
        echo "::group::[install] ${pkgname}"
        grep -qFx "${package}" "$DIR/ci-dont-install-list.txt" || pacman --noprogressbar --upgrade --noconfirm $pkg
        echo "::endgroup::"

        echo "::group::[meta-diff] ${pkgname}"
        message "Package info diff for ${pkgname}"
        diff -Nur <(pacman -Si ${MSYSTEM,,}/"${pkgname}") <(pacman -Qip "${pkg}") || true
        echo "::endgroup::"

        echo "::group::[file-diff] ${pkgname}"
        message "File listing diff for ${pkgname}"
        diff -Nur <(pacman -Fl ${MSYSTEM,,}/"$pkgname" | sed -e 's|^[^ ]* |/|' | sort) <(pacman -Ql "$pkgname" | sed -e 's|^[^/]*||' | sort) || true
        echo "::endgroup::"

        echo "::group::[dll check] ${pkgname}"
        declare -a binaries=($(pacman -Qlq $pkgname | grep -E ${MINGW_PREFIX}/.+\.\(dll\|exe\|pyd\)$))
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
        grep -qFx "${package}" "$DIR/ci-dont-install-list.txt" || pacman -R --recursive --unneeded --noconfirm --noprogressbar "$pkgname"
        echo "::endgroup::"
    done
    cd - > /dev/null

    rm -f "${package}"/*.pkg.tar.*
    unset package
done
success 'All packages built successfully'

cd artifacts
execute 'SHA-256 checksums' sha256sum *

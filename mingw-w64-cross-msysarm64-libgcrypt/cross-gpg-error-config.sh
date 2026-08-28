#!/usr/bin/env bash
set -euo pipefail

: "${REAL_GPG_ERROR_CONFIG:?set REAL_GPG_ERROR_CONFIG to the target gpg-error-config}"
: "${TARGET_SYSROOT_USR:?set TARGET_SYSROOT_USR to the staged target /usr}"

output="$("${REAL_GPG_ERROR_CONFIG}" "$@")"
output="${output//-I\/usr/-I${TARGET_SYSROOT_USR}}"
output="${output//-L\/usr/-L${TARGET_SYSROOT_USR}}"

case " $* " in
  *" --libs "*)
    case " ${output} " in
      *" -L${TARGET_SYSROOT_USR}/lib "*) ;;
      *) output="-L${TARGET_SYSROOT_USR}/lib ${output}" ;;
    esac
    ;;
esac

printf '%s\n' "${output}"

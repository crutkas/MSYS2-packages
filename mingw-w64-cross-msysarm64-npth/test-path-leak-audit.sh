#!/usr/bin/env bash
# Negative-test harness that proves audit-path-leaks.sh fails closed on every
# forbidden build-path class (narrow and UTF-16) and still accepts the sealed
# deterministic /usr/src/debug recipe path. Runs locally with only GNU strings.
set -euo pipefail

if (( $# != 4 )); then
  echo "usage: $0 OBJDUMP OBJCOPY STRINGS REPORT_DIR" >&2
  exit 2
fi

objdump=$1
objcopy=$2
strings=$3
report=$4
auditor="$(cd "$(dirname "$0")" && pwd)/audit-path-leaks.sh"
fixtures="${report}/fixtures"
rm -rf "${report}"
mkdir -p "${fixtures}"

expect_rejected() {
  local file=$1
  local name=$2
  if "${auditor}" "${file}" "${name}" "${report}" \
      "${objdump}" "${objcopy}" "${strings}" no; then
    echo "path leak fixture was accepted: ${name}" >&2
    exit 1
  fi
}

printf '%s\n' 'D:\a\MSYS2-packages\source.c' > "${fixtures}/drive.txt"
expect_rejected "${fixtures}/drive.txt" drive

printf '%s\n' '/d/a/MSYS2-packages/source.c' > "${fixtures}/actions.txt"
expect_rejected "${fixtures}/actions.txt" actions

printf '%s\n' '/cygdrive/d/build/source.c' > "${fixtures}/cygdrive.txt"
expect_rejected "${fixtures}/cygdrive.txt" cygdrive

printf '%s\n' '/home/runner/work/source.c' > "${fixtures}/home.txt"
expect_rejected "${fixtures}/home.txt" home

printf '%s\n' '\\server\share\source.c' > "${fixtures}/unc.txt"
expect_rejected "${fixtures}/unc.txt" unc

perl -MEncode -e \
  'print encode("UTF-16LE", "D:\\a\\utf16le\\source.c")' \
  > "${fixtures}/utf16le.bin"
expect_rejected "${fixtures}/utf16le.bin" utf16le

perl -MEncode -e \
  'print encode("UTF-16BE", "/home/utf16be/source.c")' \
  > "${fixtures}/utf16be.bin"
expect_rejected "${fixtures}/utf16be.bin" utf16be

printf '%s\n' \
  '/usr/src/debug/mingw-w64-cross-msysarm64-npth-1.8/npth.c' \
  'https://gnupg.org/software/npth/index.html' \
  > "${fixtures}/deterministic.txt"
"${auditor}" "${fixtures}/deterministic.txt" deterministic "${report}" \
  "${objdump}" "${objcopy}" "${strings}" no

echo 'Path leak negative fixtures passed.'

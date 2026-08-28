#!/usr/bin/env bash
set -euo pipefail

if (( $# != 7 )); then
  echo "usage: $0 FILE NAME REPORT_DIR OBJDUMP OBJCOPY STRINGS INSPECT_DEBUG" >&2
  exit 2
fi

file=$1
name=$2
report=$3
objdump=$4
objcopy=$5
strings=$6
inspect_debug=$7
safe=${name//\//_}
safe=${safe//:/_}
leaks="${report}/${safe}.path-leaks.txt"
scan_input="${file}"
decompressed="${report}/${safe}.debug-decompressed"
scan_strings="${report}/${safe}.path-strings.txt"
pattern='((^|[^[:alnum:]])[A-Za-z]:[/\\]|/[A-Za-z]/[Uu]sers[/\\]|/[dD]/a([/\\]|$)|/cygdrive/[A-Za-z]([/\\]|$)|/home/[^/[:space:]]|\\\\[^\\[:space:]]+\\|(^|[^:])//[A-Za-z0-9_.-]+/)'

mkdir -p "${report}"
if [[ "${inspect_debug}" == yes ]] &&
    "${objdump}" -h "${file}" 2>/dev/null |
      grep -Eq '[[:space:]]\.(zdebug|debug_)'; then
  "${objcopy}" --decompress-debug-sections "${file}" "${decompressed}" ||
    {
      echo "${name}: debug sections could not be decompressed" >&2
      exit 1
    }
  scan_input="${decompressed}"
fi

: > "${scan_strings}"
for encoding in s l b; do
  "${strings}" -a -e "${encoding}" "${scan_input}" >> "${scan_strings}"
done
if grep -Ein "${pattern}" "${scan_strings}" > "${leaks}"; then
  cat "${leaks}" >&2
  echo "${name}: drive, Actions, cygdrive, home, or UNC build path found" >&2
  exit 1
fi
: > "${leaks}"
rm -f "${scan_strings}" "${decompressed}"

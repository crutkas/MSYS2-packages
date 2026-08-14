#!/usr/bin/env bash

set -euo pipefail

if (( $# != 4 )); then
  echo "usage: $0 LIBDIR MANIFEST_RC SMOKE_SOURCE REPORT_DIR" >&2
  exit 2
fi

libdir=$(cd "$1" && pwd)
manifest_rc=$(realpath "$2")
smoke_source=$(realpath "$3")
report_dir=$4

cross_prefix=${CROSS_PREFIX:-aarch64-w64-mingw32}
cygwin_prefix=${CYGWIN_PREFIX:-aarch64-pc-cygwin}
cc=${CC:-${cross_prefix}-gcc}
nm=${NM:-${cross_prefix}-nm}
objdump=${OBJDUMP:-${cross_prefix}-objdump}
windres=${WINDRES:-${cygwin_prefix}-windres}

for tool in "$cc" "$nm" "$objdump" "$windres"; do
  command -v "$tool" >/dev/null
done

mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

find "$libdir" -maxdepth 1 -type f -name 'lib*.a' -printf '%f\n' \
  | LC_ALL=C sort > "$report_dir/import-libraries.txt"
test -s "$report_dir/import-libraries.txt"

required_libraries=(
  libadvapi32.a
  libkernel32.a
  libntdll.a
  libshell32.a
  libuser32.a
  libws2_32.a
)

for library in "${required_libraries[@]}"; do
  grep -Fx "$library" "$report_dir/import-libraries.txt" >/dev/null
done

"$objdump" -f "$libdir"/lib*.a \
  | awk -v manifest="$report_dir/import-libraries.txt" '
      BEGIN {
        while ((getline library < manifest) > 0)
          libraries[library] = 1
      }
      /^In archive / {
        archive = $3
        sub(/:$/, "", archive)
        sub(/^.*\//, "", archive)
        next
      }
      /file format/ {
        if ($NF !~ /^pei?-aarch64-little$/) {
          print archive " contains " $NF > "/dev/stderr"
          bad = 1
        }
        members[archive]++
      }
      END {
        for (library in libraries) {
          count = members[library] + 0
          status = count ? "aarch64" : "empty"
          print library "\t" count "\t" status
        }
        exit bad
      }
    ' \
  | LC_ALL=C sort > "$report_dir/archive-formats.txt"

awk '$3 == "empty" { print $1 }' \
  "$report_dir/archive-formats.txt" \
  > "$report_dir/empty-archives.txt"

for library in "${required_libraries[@]}"; do
  awk -v library="$library" \
    '$1 == library && $2 > 0 && $3 == "aarch64" { found = 1 }
     END { exit !found }' \
    "$report_dir/archive-formats.txt"
done

required_symbols=(
  'kernel32:CreateEventW'
  'kernel32:CreateFileW'
  'kernel32:ExitProcess'
  'ntdll:NtClose'
  'ntdll:NtQueryInformationProcess'
  'ntdll:RtlInitUnicodeString'
)

: > "$report_dir/required-symbols.txt"
for requirement in "${required_symbols[@]}"; do
  library=${requirement%%:*}
  symbol=${requirement#*:}
  archive="$libdir/lib${library}.a"
  symbols=$("$nm" -g --defined-only "$archive")

  grep -Eq "[[:space:]](__imp_)?${symbol}$" <<<"$symbols"
  printf '%s\t%s\n' "$library" "$symbol" \
    >> "$report_dir/required-symbols.txt"
done

(
  cd "$(dirname "$manifest_rc")"
  "$windres" \
    --preprocessor=/usr/bin/cpp \
    --input="$(basename "$manifest_rc")" \
    --output="$workdir/default-manifest.o"
)

"$objdump" -f "$workdir/default-manifest.o" \
  | grep -F 'file format pe-aarch64-little'

"$cc" \
  -ffreestanding \
  -fno-stack-protector \
  -nostdlib \
  -Wl,--entry,mainCRTStartup \
  -Wl,--subsystem,console \
  -Wl,--image-base,0x400000 \
  "$smoke_source" \
  "$workdir/default-manifest.o" \
  -L"$libdir" \
  -lkernel32 \
  -lntdll \
  -o "$workdir/w32api-link-smoke.exe"

"$objdump" -f "$workdir/w32api-link-smoke.exe" \
  | tee "$report_dir/link-file.txt" \
  | grep -F 'file format pei-aarch64-little'
"$objdump" -h "$workdir/w32api-link-smoke.exe" \
  > "$report_dir/link-sections.txt"
grep -E '\.pdata|\.rsrc' "$report_dir/link-sections.txt"

"$objdump" -p "$workdir/w32api-link-smoke.exe" \
  | sed -n 's/^[[:space:]]*DLL Name: //p' \
  > "$report_dir/link-imports.txt"
grep -F 'KERNEL32.dll' "$report_dir/link-imports.txt"
grep -F 'ntdll.dll' "$report_dir/link-imports.txt"
! grep -Ei '^(cygwin1|msys-2\.0)\.dll$' \
  "$report_dir/link-imports.txt"

strings "$workdir/w32api-link-smoke.exe" \
  > "$workdir/link-strings.txt"
grep -F -m1 '<assembly' "$workdir/link-strings.txt" \
  > "$report_dir/manifest-marker.txt"

cp "$workdir/default-manifest.o" "$report_dir/"
cp "$workdir/w32api-link-smoke.exe" "$report_dir/"
sha256sum \
  "$report_dir/default-manifest.o" \
  "$report_dir/w32api-link-smoke.exe" \
  > "$report_dir/SHA256SUMS"

{
  printf 'libraries\t%s\n' \
    "$(wc -l < "$report_dir/import-libraries.txt")"
  printf 'archive-members\t%s\n' \
    "$(awk '{ total += $2 } END { print total }' \
      "$report_dir/archive-formats.txt")"
  printf 'empty-archives\t%s\n' \
    "$(wc -l < "$report_dir/empty-archives.txt")"
  printf 'x64-members\t0\n'
  printf 'required-symbols\t%s\n' \
    "$(wc -l < "$report_dir/required-symbols.txt")"
  printf 'linked-format\tpei-aarch64-little\n'
  printf 'default-manifest\tembedded\n'
  printf 'cygwin1-imports\t0\n'
  printf 'msys-2.0-imports\t0\n'
} > "$report_dir/summary.txt"

cat "$report_dir/summary.txt"

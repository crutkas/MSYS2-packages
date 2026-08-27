#!/usr/bin/env bash

set -euo pipefail

if (( $# < 2 || $# > 3 )); then
  echo "usage: $0 PACKAGE REPORT_DIR [EXPECTED_VERSION]" >&2
  exit 2
fi

package=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
report_dir=$2
expected_version=${3:-}
mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
work_dir="$report_dir/package-root"
rm -rf "$work_dir"
mkdir -p "$work_dir"

MSYS=winsymlinks:sys bsdtar -xf "$package" -C "$work_dir"
cp "$work_dir/.PKGINFO" "$report_dir/PKGINFO"
grep -Fx 'pkgname = mingw-w64-cross-cygwinarm64-binutils' \
  "$report_dir/PKGINFO"
if [[ -n "$expected_version" ]]; then
  grep -Fx "pkgver = $expected_version" "$report_dir/PKGINFO"
fi

mapfile -t cygwin_tools < <(
  find "$work_dir/opt/bin" -maxdepth 1 -type f \
    -name 'aarch64-pc-cygwin-*.exe' -printf '%f\n' | LC_ALL=C sort
)
mapfile -t msys_aliases < <(
  find "$work_dir/opt/bin" -maxdepth 1 -type l \
    -name 'aarch64-pc-msys-*.exe' -printf '%f\n' | LC_ALL=C sort
)
if (( ${#cygwin_tools[@]} != 20 || ${#msys_aliases[@]} != 20 )); then
  echo "expected 20 Cygwin tools and 20 MSYS aliases" >&2
  exit 1
fi

cat > "$report_dir/expected-tools.txt" <<'EOF'
addr2line
ar
as
c++filt
dlltool
dllwrap
elfedit
gprof
ld.bfd
ld
nm
objcopy
objdump
ranlib
readelf
size
strings
strip
windmc
windres
EOF
LC_ALL=C sort -o "$report_dir/expected-tools.txt" \
  "$report_dir/expected-tools.txt"

printf 'tool\talias\ttarget\tlink_type\ttarget_sha256\n' \
  > "$report_dir/alias-audit.tsv"
for tool in $(cat "$report_dir/expected-tools.txt"); do
  source_name="aarch64-pc-cygwin-${tool}.exe"
  alias_name="aarch64-pc-msys-${tool}.exe"
  source_path="$work_dir/opt/bin/$source_name"
  alias_path="$work_dir/opt/bin/$alias_name"
  test -f "$source_path"
  test -L "$alias_path"
  target=$(readlink "$alias_path")
  if [[ "$target" != "$source_name" ]]; then
    echo "bad alias target: $alias_name -> $target" >&2
    exit 1
  fi
  printf '%s\t/opt/bin/%s\t%s\tsymlink\t%s\n' \
    "$tool" "$alias_name" "$target" \
    "$(sha256sum "$source_path" | awk '{print $1}')" \
    >> "$report_dir/alias-audit.tsv"
done

if find "$work_dir/opt/aarch64-pc-msys/bin" -mindepth 1 -print -quit \
    2>/dev/null | grep -q .; then
  echo "binutils overlaps GCC-owned /opt/aarch64-pc-msys/bin bridges" >&2
  exit 1
fi

python - "$work_dir" "$report_dir/package-host-machines.json" <<'PY'
import json
import hashlib
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
rows = []
for path in sorted(root.rglob("*.exe")):
    if path.is_symlink():
        continue
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SystemExit(f"not PE: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 6 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise SystemExit(f"malformed PE: {path}")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    if machine != 0x8664:
        raise SystemExit(f"packaged executable is not x86_64: {path}: {machine:#x}")
    rows.append({
        "path": "/" + path.relative_to(root).as_posix(),
        "machine": "x86_64",
        "machine_value": "0x8664",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    })
if len(rows) != 31:
    raise SystemExit(f"expected 31 real packaged executables, found {len(rows)}")
output.write_text(
    json.dumps({"schema_version": 1, "executables": rows}, indent=2) + "\n",
    encoding="utf-8",
)
PY

python - "$report_dir/PKGINFO" "$report_dir/alias-audit.tsv" \
  "$report_dir/package-audit.json" <<'PY'
import json
import pathlib
import sys

pkginfo = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
aliases = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()[1:]
fields = {}
for line in pkginfo.splitlines():
    if " = " in line:
        key, value = line.split(" = ", 1)
        fields.setdefault(key, []).append(value)
json.dump(
    {
        "schema_version": 1,
        "package_name": fields["pkgname"][0],
        "package_version": fields["pkgver"][0],
        "architecture": fields["arch"][0],
        "host_executable_count": 31,
        "public_alias_count": len(aliases),
        "public_alias_type": "relative-symlink",
        "gcc_bridge_overlap": False,
    },
    open(sys.argv[3], "w", encoding="utf-8"),
    indent=2,
)
with open(sys.argv[3], "a", encoding="utf-8") as stream:
    stream.write("\n")
PY

rm -rf "$work_dir"

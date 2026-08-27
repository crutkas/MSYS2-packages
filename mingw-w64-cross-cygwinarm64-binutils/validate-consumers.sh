#!/usr/bin/env bash

set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 REPORT_DIR PSEUDO_RELOC_CHECKER SOURCE_PSEUDO_RELOC_CHECKER" >&2
  exit 2
fi

report_dir=$1
pseudo_checker=$2
source_pseudo_checker=$3
mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
work_dir="$report_dir/work"
rm -rf "$work_dir"
mkdir -p "$work_dir/src" "$work_dir/bin" "$work_dir/audit"

export PATH=/usr/bin:/opt/bin
cc=/opt/bin/aarch64-pc-msys-gcc.exe
cxx=/opt/bin/aarch64-pc-msys-g++.exe
objdump=/opt/bin/aarch64-pc-msys-objdump.exe
ar=/opt/bin/aarch64-pc-msys-ar.exe
nm=/opt/bin/aarch64-pc-msys-nm.exe
ranlib=/opt/bin/aarch64-pc-msys-ranlib.exe
pwsh='/c/Program Files/PowerShell/7/pwsh.exe'

for path in "$cc" "$cxx" "$objdump" "$ar" "$nm" "$ranlib" "$pwsh"; do
  test -x "$path"
done
test "$("$cc" -dumpmachine)" = aarch64-pc-msys
test "$("$cxx" -dumpmachine)" = aarch64-pc-msys
"$cxx" -v > /dev/null 2> "$work_dir/audit/cxx-version.txt"
grep -Fx 'Thread model: posix' "$work_dir/audit/cxx-version.txt"

printf 'tool\tresolved\towner\n' > "$report_dir/gcc-tool-resolution.tsv"
for tool in ld as ar nm ranlib; do
  resolved=$("$cc" "-print-prog-name=$tool")
  case "$tool:$resolved" in
    ld:/opt/bin/aarch64-pc-cygwin-ld|as:/opt/bin/aarch64-pc-cygwin-as)
      ;;
    ar:/opt/lib/gcc/aarch64-pc-msys/*/../../../../aarch64-pc-msys/bin/ar.exe|\
    nm:/opt/lib/gcc/aarch64-pc-msys/*/../../../../aarch64-pc-msys/bin/nm.exe|\
    ranlib:/opt/lib/gcc/aarch64-pc-msys/*/../../../../aarch64-pc-msys/bin/ranlib.exe)
      ;;
    *)
      echo "unexpected GCC tool resolution: $tool -> $resolved" >&2
      exit 1
      ;;
  esac
  selected_path=$resolved
  if [[ "$selected_path" != *.exe ]]; then
    selected_path="${selected_path}.exe"
  fi
  selected_owner=$(pacman -Qoq "$selected_path")
  canonical=$(realpath "$selected_path")
  executable_owner=$(pacman -Qoq "$canonical")
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$tool" "$resolved" "$selected_owner" "$canonical" "$executable_owner" \
    >> "$report_dir/gcc-tool-resolution.tsv"
done
sed -i '1c tool\tselected\tselected_owner\tcanonical\tcanonical_owner' \
  "$report_dir/gcc-tool-resolution.tsv"
grep -Fx $'ld\t/opt/bin/aarch64-pc-cygwin-ld\tmingw-w64-cross-cygwinarm64-binutils\t/opt/bin/aarch64-pc-cygwin-ld.exe\tmingw-w64-cross-cygwinarm64-binutils' \
  "$report_dir/gcc-tool-resolution.tsv"
sha256sum /opt/bin/aarch64-pc-cygwin-ld.exe \
  > "$report_dir/gcc-selected-linker.sha256"

for tool in \
  addr2line ar as c++filt dlltool dllwrap elfedit gprof ld ld.bfd nm \
  objcopy objdump ranlib readelf size strings strip windmc windres
do
  alias="/opt/bin/aarch64-pc-msys-${tool}.exe"
  test -L "$alias"
  test "$(readlink "$alias")" = "aarch64-pc-cygwin-${tool}.exe"
  test "$(pacman -Qoq "$alias")" = mingw-w64-cross-cygwinarm64-binutils
done

cat > "$work_dir/src/basic.c" <<'EOF'
#include <stdio.h>
int main(void) {
  puts("basic-c-ok");
  return 0;
}
EOF

cat > "$work_dir/src/cxx-runtime.cc" <<'EOF'
#include <iostream>
#include <stdexcept>
int main() {
  try {
    throw std::runtime_error("aarch64-msys");
  } catch (const std::exception& error) {
    std::cout << error.what() << std::endl;
  }
  return 0;
}
EOF

cat > "$work_dir/src/thread-runtime.cc" <<'EOF'
#include <pthread.h>
#include <iostream>
#include <mutex>
#include <thread>
constinit std::mutex gate;
int total = 0;
void add(int value) {
  std::lock_guard<std::mutex> lock(gate);
  total += value;
}
void* pthread_entry(void* value) {
  add(*static_cast<int*>(value));
  return nullptr;
}
int main() {
  int value = 17;
  pthread_t native;
  if (pthread_create(&native, nullptr, pthread_entry, &value) != 0)
    return 1;
  std::thread cpp(add, 25);
  cpp.join();
  if (pthread_join(native, nullptr) != 0 || total != 42)
    return 2;
  std::cout << "thread-runtime-ok" << std::endl;
  return 0;
}
EOF

cat > "$work_dir/src/process-runtime.c" <<'EOF'
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
  pid_t child = fork();
  int status = 0;
  if (child < 0)
    return 1;
  if (child == 0)
    _exit(23);
  if (waitpid(child, &status, 0) != child)
    return 2;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 23)
    return 3;
  puts("process-runtime-ok");
  return 0;
}
EOF

common=(-O2 -g -Wall -Wextra -Werror)
"$cc" "${common[@]}" -c "$work_dir/src/basic.c" \
  -o "$work_dir/bin/basic.o"
"$ar" rcs "$work_dir/bin/libbasic.a" "$work_dir/bin/basic.o"
"$ranlib" "$work_dir/bin/libbasic.a"
"$nm" "$work_dir/bin/libbasic.a" > "$work_dir/audit/libbasic.nm.txt"
"$cc" "${common[@]}" "$work_dir/src/basic.c" \
  -o "$work_dir/bin/basic.exe"
"$cxx" "${common[@]}" -std=gnu++20 "$work_dir/src/cxx-runtime.cc" \
  -o "$work_dir/bin/cxx-runtime.exe"
"$cxx" "${common[@]}" -std=gnu++20 -pthread \
  "$work_dir/src/thread-runtime.cc" -o "$work_dir/bin/thread-runtime.exe"
"$cc" "${common[@]}" "$work_dir/src/process-runtime.c" \
  -o "$work_dir/bin/process-runtime.exe"

audit_target() {
  local path=$1
  local expected_format=$2
  local label=$3
  "$objdump" -f "$path" > "$work_dir/audit/${label}.format.txt"
  grep -F "file format ${expected_format}" \
    "$work_dir/audit/${label}.format.txt"
  grep -F 'architecture: aarch64' "$work_dir/audit/${label}.format.txt"
}

audit_target "$work_dir/bin/basic.o" pe-aarch64-little basic-object
member_dir="$work_dir/archive-member"
mkdir -p "$member_dir"
(cd "$member_dir" && "$ar" x "$work_dir/bin/libbasic.a")
audit_target "$member_dir/basic.o" pe-aarch64-little basic-archive-member

for name in basic cxx-runtime thread-runtime process-runtime; do
  image="$work_dir/bin/${name}.exe"
  audit_target "$image" pei-aarch64-little "$name"
  "$objdump" -p "$image" > "$work_dir/audit/${name}.pe.txt"
  sed -n 's/^[[:space:]]*DLL Name: //p' \
    "$work_dir/audit/${name}.pe.txt" \
    > "$work_dir/audit/${name}.imports.txt"
  grep -Fxi 'msys-2.0.dll' "$work_dir/audit/${name}.imports.txt"
  if grep -Eiq \
      'cygwin1\.dll|msvcrt\.dll|ucrtbase\.dll|libwinpthread|(^|/)mingw|x86_64' \
      "$work_dir/audit/${name}.imports.txt" \
      "$work_dir/audit/${name}.format.txt"; then
    echo "foreign target contamination: $image" >&2
    exit 1
  fi
  "$pwsh" -NoProfile -File "$(cygpath -w "$pseudo_checker")" \
    -PePath "$(cygpath -w "$image")" \
    -Objdump "$(cygpath -w "$objdump")" \
    -Nm "$(cygpath -w "$nm")" \
    -OutputPath "$(
      cygpath -w "$work_dir/audit/${name}.pseudo-relocs.json"
    )"
  "$pwsh" -NoProfile -File "$(cygpath -w "$source_pseudo_checker")" \
    -PePath "$(cygpath -w "$image")" \
    -Objdump "$(cygpath -w "$objdump")" \
    -Nm "$(cygpath -w "$nm")" \
    -OutputPath "$(
      cygpath -w "$work_dir/audit/${name}.source-pseudo-relocs.json"
    )"
done

python - "$work_dir/audit" "$report_dir/consumer-summary.json" <<'PY'
import json
import pathlib
import sys

audit = pathlib.Path(sys.argv[1])
reports = []
for path in sorted(audit.glob("*.pseudo-relocs.json")):
    if path.name.endswith(".source-pseudo-relocs.json"):
        continue
    reports.append(json.loads(path.read_text(encoding="utf-8")))
source_reports = [
    json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(audit.glob("*.source-pseudo-relocs.json"))
]
if len(reports) != len(source_reports):
    raise SystemExit("pseudo-reloc scanner report count mismatch")
for report in reports + source_reports:
    if report["result"] != "pass" or report["policy_violations"]:
        raise SystemExit("pseudo-reloc scanner did not report a clean pass")
json.dump(
    {
        "schema_version": 1,
        "target": "aarch64-pc-msys",
        "compiler_package": "mingw-w64-cross-msysarm64-gcc",
        "binutils_package": "mingw-w64-cross-cygwinarm64-binutils",
        "probes": ["basic-c", "dynamic-cxx", "thread-constinit", "process"],
        "pseudo_reloc_reports": reports,
        "source_contract_pseudo_reloc_reports": source_reports,
        "baseline_negative": {
            "evidence_seal_sha256": "bc2403d4054eb1880f69e5f241610cc6bbbdffd262f217136beffa04aa6b7de1",
            "flags": [64, 21, 12, 21, 12],
            "policy_violations": [12, 21],
        },
        "target_machine": "AArch64",
        "foreign_target_contamination": False,
    },
    open(sys.argv[2], "w", encoding="utf-8"),
    indent=2,
)
with open(sys.argv[2], "a", encoding="utf-8") as stream:
    stream.write("\n")
PY

rm -rf "$member_dir"

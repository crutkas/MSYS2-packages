#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export PATH="/opt/bin:/usr/bin:${PATH}"

if (( $# != 1 )); then
  echo "usage: $0 REPORT_DIR" >&2
  exit 2
fi
if [[ -z "${CANDIDATE_BINUTILS_VERSION:-}" || -z "${CANDIDATE_LD_SHA256:-}" ]]; then
  echo "CANDIDATE_BINUTILS_VERSION and CANDIDATE_LD_SHA256 are required" >&2
  exit 2
fi

report_dir=$1
source_dir="$report_dir/sources"
binary_dir="$report_dir/binaries"
audit_dir="$report_dir/audits"
mkdir -p "$source_dir" "$binary_dir" "$audit_dir"

target=aarch64-pc-msys
cc="/opt/bin/${target}-gcc.exe"
cxx="/opt/bin/${target}-g++.exe"
objdump=aarch64-pc-cygwin-objdump
objcopy=aarch64-pc-cygwin-objcopy
nm=aarch64-pc-cygwin-nm

require_package() {
  local package=$1 version=$2 actual
  actual=$(pacman -Q "$package")
  [[ "$actual" == "$package $version" ]] || {
    echo "package mismatch: expected '$package $version', got '$actual'" >&2
    return 1
  }
  printf '%s\n' "$actual" >> "$report_dir/installed-packages.txt"
  pacman -Qk "$package" >> "$report_dir/pacman-files.txt"
}

require_owner() {
  local path=$1 expected=$2 actual
  actual=$(pacman -Qoq -- "$path")
  [[ "$actual" == "$expected" ]] || {
    echo "owner mismatch for $path: expected $expected, got $actual" >&2
    return 1
  }
  printf '%s\t%s\n' "$path" "$actual" >> "$report_dir/pacman-ownership.tsv"
}

require_import() {
  local report=$1 import=$2
  grep -Fxi "$import" "$report" >/dev/null || {
    echo "missing dynamic import $import in $report" >&2
    return 1
  }
}

: > "$report_dir/installed-packages.txt"
: > "$report_dir/pacman-files.txt"
: > "$report_dir/pacman-ownership.tsv"

require_package mingw-w64-cross-cygwinarm64-binutils "$CANDIDATE_BINUTILS_VERSION"
require_package mingw-w64-cross-cygwinarm64-gcc-stage1 15.0.1dev-2
require_package mingw-w64-cross-cygwinarm64-gcc-libs-stage1 15.0.1dev-2
require_package mingw-w64-cross-cygwinarm64-libstdc++-headers 15.0.1dev-1
require_package mingw-w64-cross-msysarm64-headers 3.6.10.r0.ga527ace21-1
require_package mingw-w64-cross-msysarm64-windows-default-manifest 3.6.10.r0.ga527ace21-1
require_package mingw-w64-cross-msysarm64-sysroot 3.6.10.r0.ga527ace21-1
require_package mingw-w64-cross-msysarm64-w32api-runtime 14.0.0.r0.g9b3dd0125-1
require_package mingw-w64-cross-msysarm64-runtime 3.6.10.r0.ga527ace21-1
require_package mingw-w64-cross-msysarm64-runtime-devel 3.6.10.r0.ga527ace21-1
require_package mingw-w64-cross-msysarm64-libstdc++-headers 15.0.1dev-1
require_package mingw-w64-cross-msysarm64-gcc-libs 15.0.1dev-1
require_package mingw-w64-cross-msysarm64-gcc 15.0.1dev-1

requirements=(
  "mingw-w64-cross-cygwinarm64-binutils=${CANDIDATE_BINUTILS_VERSION}"
  mingw-w64-cross-cygwinarm64-gcc-stage1=15.0.1dev-2
  mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-w32api-runtime=14.0.0.r0.g9b3dd0125-1
  mingw-w64-cross-msysarm64-libstdc++-headers=15.0.1dev-1
  mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1
  mingw-w64-cross-msysarm64-gcc=15.0.1dev-1
)
if ! pacman -T -- "${requirements[@]}" > "$report_dir/missing-dependencies.txt"; then
  cat "$report_dir/missing-dependencies.txt" >&2
  exit 1
fi
test ! -s "$report_dir/missing-dependencies.txt"

require_owner /opt/bin/aarch64-pc-cygwin-ld.exe mingw-w64-cross-cygwinarm64-binutils
require_owner /opt/bin/aarch64-pc-cygwin-objdump.exe mingw-w64-cross-cygwinarm64-binutils
require_owner /opt/bin/aarch64-pc-msys-g++.exe mingw-w64-cross-msysarm64-gcc
require_owner /opt/aarch64-pc-msys/bin/msys-2.0.dll mingw-w64-cross-msysarm64-runtime
require_owner /opt/lib/gcc/aarch64-pc-msys/msys-gcc_s-seh-1.dll mingw-w64-cross-msysarm64-gcc-libs
require_owner /opt/lib/gcc/aarch64-pc-msys/15.0.1/msys-stdc++-6.dll mingw-w64-cross-msysarm64-gcc-libs

for tool in "$cc" "$cxx" "$objdump" "$objcopy" "$nm" \
    aarch64-pc-msys-gcc-ar.exe aarch64-pc-msys-gcc-nm.exe \
    aarch64-pc-msys-gcc-ranlib.exe; do
  command -v "$tool" >/dev/null
done
[[ $("$cc" -dumpmachine) == "$target" ]]
[[ $("$cxx" -dumpmachine) == "$target" ]]
"$cxx" -v > "$audit_dir/cxx-version.stdout.txt" 2> "$audit_dir/cxx-version.stderr.txt"
grep -Fx 'Thread model: posix' "$audit_dir/cxx-version.stderr.txt"
aarch64-pc-cygwin-ld --version > "$audit_dir/candidate-ld-version.txt"
sha256sum --binary /opt/bin/aarch64-pc-cygwin-ld.exe > "$audit_dir/candidate-ld.sha256"
resolved_ld=$("$cc" -print-prog-name=ld)
canonical_ld=$(realpath "$resolved_ld")
[[ "$canonical_ld" == /opt/bin/aarch64-pc-cygwin-ld || "$canonical_ld" == /opt/bin/aarch64-pc-cygwin-ld.exe ]]
[[ $(sha256sum --binary "$canonical_ld" | awk '{print $1}') == "$CANDIDATE_LD_SHA256" ]]
printf '%s\t%s\t%s\n' "$resolved_ld" "$canonical_ld" "$CANDIDATE_LD_SHA256" > "$audit_dir/linker-resolution.tsv"

cat > "$source_dir/basic.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("basic-c-ok"); return fflush(stdout) == 0 ? 0 : 1; }
EOF

cat > "$source_dir/cxx-runtime.cc" <<'EOF'
#include <iostream>
#include <stdexcept>
#include <string>
namespace { int state; struct Startup { Startup() { state = 41; } } startup; }
int main() {
  if (state != 41) return 1;
  try { throw std::runtime_error("fixed-linker"); }
  catch (const std::exception& e) {
    if (std::string(e.what()) != "fixed-linker") return 2;
  }
  std::cout << "cxx-runtime-ok" << std::endl;
  return 0;
}
EOF

cat > "$source_dir/thread-runtime.cc" <<'EOF'
#include <pthread.h>
#include <iostream>
#include <mutex>
#include <thread>
constinit std::mutex gate;
int total;
void add(int value) { std::lock_guard<std::mutex> lock(gate); total += value; }
void* pthread_entry(void* p) { add(*static_cast<int*>(p)); return nullptr; }
int main() {
  pthread_t pt; int value = 17;
  if (pthread_create(&pt, nullptr, pthread_entry, &value) != 0) return 1;
  std::thread cpp(add, 25); cpp.join();
  if (pthread_join(pt, nullptr) != 0 || total != 42) return 2;
  std::cout << "thread-runtime-ok" << std::endl;
  return 0;
}
EOF

cat > "$source_dir/process-runtime.c" <<'EOF'
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile sig_atomic_t seen;
static void handler(int sig) { seen = sig; }
int main(void) {
  static const char message[] = "fork-pipe-ok";
  char received[sizeof(message)] = {0};
  struct sigaction action; memset(&action, 0, sizeof(action));
  action.sa_handler = handler; sigemptyset(&action.sa_mask);
  alarm(30);
  if (sigaction(SIGUSR1, &action, NULL) != 0 || raise(SIGUSR1) != 0 || seen != SIGUSR1) return 1;
  int fds[2]; if (pipe(fds) != 0) return 2;
  pid_t child = fork(); if (child < 0) return 3;
  if (child == 0) { close(fds[0]); ssize_t n = write(fds[1], message, sizeof(message)); close(fds[1]); _exit(n == (ssize_t)sizeof(message) ? 23 : 24); }
  close(fds[1]); ssize_t n = read(fds[0], received, sizeof(received)); close(fds[0]);
  int status; pid_t waited; do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  if (n != (ssize_t)sizeof(message) || memcmp(received, message, sizeof(message)) != 0) return 4;
  if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 23) return 5;
  puts("process-runtime-ok"); return 0;
}
EOF

cat > "$source_dir/lto-library.c" <<'EOF'
int fixed_linker_lto_value(void) { return 42; }
EOF
cat > "$source_dir/lto-main.c" <<'EOF'
#include <stdio.h>
int fixed_linker_lto_value(void);
int main(void) { if (fixed_linker_lto_value() != 42) return 1; puts("lto-bridge-ok"); return 0; }
EOF

cat > "$source_dir/provider.S" <<'EOF'
.text
.global DllMainCRTStartup
DllMainCRTStartup:
  mov w0, 1
  ret
.data
.balign 16
.global aarch64_near_value
aarch64_near_value: .quad 0x1122334455667788
.balign 16
.global aarch64_far_value
aarch64_far_value: .quad 0x8877665544332211
EOF
cat > "$source_dir/near.def" <<'EOF'
LIBRARY "aarch64-near-import.dll" BASE=0x140040000
EXPORTS
  aarch64_near_value DATA
EOF
cat > "$source_dir/far.def" <<'EOF'
LIBRARY "aarch64-far-import.dll" BASE=0x600040000
EXPORTS
  aarch64_far_value DATA
EOF
cat > "$source_dir/far-map.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
extern volatile uint64_t aarch64_near_value;
extern volatile uint64_t aarch64_far_value;
static uintptr_t distance(uintptr_t a, uintptr_t b) { return a >= b ? a - b : b - a; }
int main(void) {
  HMODULE image = GetModuleHandleW(NULL);
  HMODULE near_module = GetModuleHandleA("aarch64-near-import.dll");
  HMODULE far_module = GetModuleHandleA("aarch64-far-import.dll");
  if ((uintptr_t)image != UINT64_C(0x100400000) || (uintptr_t)near_module != UINT64_C(0x140040000) || (uintptr_t)far_module != UINT64_C(0x600040000)) return 1;
  if (distance((uintptr_t)image, (uintptr_t)far_module) <= UINT64_C(0x100000000)) return 2;
  if (aarch64_near_value != UINT64_C(0x1122334455667788) || aarch64_far_value != UINT64_C(0x8877665544332211)) return 3;
  aarch64_near_value = UINT64_C(0xa5a55a5adeadbeef);
  if (aarch64_near_value != UINT64_C(0xa5a55a5adeadbeef)) return 4;
  printf("far-map-addresses image=0x%llx near=0x%llx far=0x%llx delta=0x%llx\n", (unsigned long long)(uintptr_t)image, (unsigned long long)(uintptr_t)near_module, (unsigned long long)(uintptr_t)far_module, (unsigned long long)distance((uintptr_t)image, (uintptr_t)far_module));
  puts("far-map-ok");
  return 0;
}
EOF

common=(-O2 -g -Wall -Wextra -Werror -Wl,--no-insert-timestamp)
"$cc" "${common[@]}" "$source_dir/basic.c" -o "$binary_dir/basic-c.exe"
"$cxx" "${common[@]}" -std=gnu++20 -Wl,-Map,"$audit_dir/cxx-runtime.link.map" "$source_dir/cxx-runtime.cc" -o "$binary_dir/cxx-runtime.exe"
"$cxx" "${common[@]}" -std=gnu++20 -pthread "$source_dir/thread-runtime.cc" -o "$binary_dir/thread-runtime.exe"
"$cc" "${common[@]}" "$source_dir/process-runtime.c" -o "$binary_dir/process-runtime.exe"
"$cc" -O2 -g -Wall -Wextra -Werror -flto -c "$source_dir/lto-library.c" -o "$binary_dir/lto-library.o"
aarch64-pc-msys-gcc-ar.exe rcs "$binary_dir/liblto.a" "$binary_dir/lto-library.o"
aarch64-pc-msys-gcc-nm.exe "$binary_dir/liblto.a" > "$audit_dir/lto-nm.txt"
aarch64-pc-msys-gcc-ranlib.exe "$binary_dir/liblto.a"
"$cc" "${common[@]}" -flto "$source_dir/lto-main.c" "$binary_dir/liblto.a" -o "$binary_dir/lto-bridge.exe"

"$cc" -c "$source_dir/provider.S" -o "$binary_dir/provider.o"
"$cc" -shared -nostdlib -Wl,--no-insert-timestamp -Wl,--disable-dynamicbase -Wl,--image-base,0x140040000 -Wl,-e,DllMainCRTStartup -Wl,--out-implib,"$binary_dir/libnear.a" -o "$binary_dir/aarch64-near-import.dll" "$binary_dir/provider.o" "$source_dir/near.def"
"$cc" -shared -nostdlib -Wl,--no-insert-timestamp -Wl,--disable-dynamicbase -Wl,--image-base,0x600040000 -Wl,-e,DllMainCRTStartup -Wl,--out-implib,"$binary_dir/libfar.a" -o "$binary_dir/aarch64-far-import.dll" "$binary_dir/provider.o" "$source_dir/far.def"
"$cc" "${common[@]}" -Wl,--disable-dynamicbase -Wl,--image-base,0x100400000 "$source_dir/far-map.c" -L"$binary_dir" -lnear -lfar -o "$binary_dir/far-map.exe"


 audit_binary() {
  local file=$1 label=$2
  "$objdump" -f "$file" > "$audit_dir/$label.file.txt"
  grep -F 'file format pei-aarch64-little' "$audit_dir/$label.file.txt"
  grep -F 'architecture: aarch64' "$audit_dir/$label.file.txt"
  "$objdump" -p "$file" > "$audit_dir/$label.pe.txt"
  sed -n 's/^[[:space:]]*DLL Name: //p' "$audit_dir/$label.pe.txt" > "$audit_dir/$label.imports.txt"
  if grep -Eiq 'cygwin1\.dll|pei-x86-64|i386:x86-64|x86_64' "$audit_dir/$label.file.txt" "$audit_dir/$label.imports.txt"; then
    echo "foreign contamination: $file" >&2
    return 1
  fi
}

 audit_no_ambiguous_pseudo() {
  local file=$1
  local label=$2
  local symbols="$audit_dir/$label.symbols.txt"
  "$nm" -an "$file" > "$symbols"
  local start end
  start=$(awk '$3 == "__RUNTIME_PSEUDO_RELOC_LIST__" { print $1; exit }' "$symbols")
  end=$(awk '$3 == "__RUNTIME_PSEUDO_RELOC_LIST_END__" { print $1; exit }' "$symbols")
  if [[ -z "$start" && -z "$end" ]]; then
    printf '%s\tabsent\t0\n' "$label" >> "$audit_dir/pseudo-reloc-summary.tsv"
    return 0
  fi
  [[ -n "$start" && -n "$end" ]] || { echo "incomplete pseudo-reloc symbols: $file" >&2; return 1; }
  local start_value=$((16#$start)) end_value=$((16#$end))
  (( end_value >= start_value )) || { echo "reversed pseudo-reloc range: $file" >&2; return 1; }
  if (( end_value == start_value )); then
    printf '%s\tempty\t0\n' "$label" >> "$audit_dir/pseudo-reloc-summary.tsv"
    return 0
  fi
  local section='' section_vma=0
  while read -r index name size vma lma fileoff align; do
    [[ $index =~ ^[0-9]+$ ]] || continue
    local begin=$((16#$vma)) finish=$((16#$vma + 16#$size))
    if (( start_value >= begin && end_value <= finish )); then section=$name; section_vma=$begin; break; fi
  done < <("$objdump" -h "$file")
  [[ -n "$section" ]] || { echo "pseudo-reloc table section not found: $file" >&2; return 1; }
  local raw="$audit_dir/$label.$section.bin" table="$audit_dir/$label.pseudo-table.bin"
  "$objcopy" --dump-section "$section=$raw" "$file"
  dd if="$raw" of="$table" bs=1 skip=$((start_value-section_vma)) count=$((end_value-start_value)) status=none
  od -An -v -tu4 -w12 "$table" > "$audit_dir/$label.pseudo-table.txt"
  awk '
    NR == 1 { if ($1 != 0 || $2 != 0 || $3 != 1) exit 2; next }
    NF != 3 { exit 3 }
    $3 == 12 || $3 == 21 { exit 4 }
    { ++records }
    END { if (NR < 1) exit 5 }
  ' "$audit_dir/$label.pseudo-table.txt" || {
    echo "ambiguous or malformed pseudo-reloc table: $file" >&2
    return 1
  }
  local records=$(( (end_value-start_value-12) / 12 ))
  printf '%s\tpresent\t%s\n' "$label" "$records" >> "$audit_dir/pseudo-reloc-summary.tsv"
}

: > "$audit_dir/pseudo-reloc-summary.tsv"
for name in basic-c cxx-runtime thread-runtime process-runtime lto-bridge far-map; do
  audit_binary "$binary_dir/$name.exe" "$name"
  audit_no_ambiguous_pseudo "$binary_dir/$name.exe" "$name"
done
for name in aarch64-near-import aarch64-far-import; do
  audit_binary "$binary_dir/$name.dll" "$name"
  audit_no_ambiguous_pseudo "$binary_dir/$name.dll" "$name"
done

for label in cxx-runtime thread-runtime; do
  require_import "$audit_dir/$label.imports.txt" msys-2.0.dll
  require_import "$audit_dir/$label.imports.txt" msys-gcc_s-seh-1.dll
  require_import "$audit_dir/$label.imports.txt" msys-stdc++-6.dll
done
require_import "$audit_dir/far-map.imports.txt" aarch64-near-import.dll
require_import "$audit_dir/far-map.imports.txt" aarch64-far-import.dll
require_import "$audit_dir/far-map.imports.txt" msys-2.0.dll

cat > "$report_dir/native-binaries.tsv" <<'EOF'
basic-c.exe	basic-c-ok
cxx-runtime.exe	cxx-runtime-ok
thread-runtime.exe	thread-runtime-ok
process-runtime.exe	process-runtime-ok
lto-bridge.exe	lto-bridge-ok
far-map.exe	far-map-ok
EOF

cat > "$report_dir/bash-summary.txt" <<EOF
target	$target
candidate-binutils	$CANDIDATE_BINUTILS_VERSION
ambiguous-pseudo-relocs	zero flags 12/21
native-tests	basic,cxx,thread,constinit,process,lto,far-map
EOF

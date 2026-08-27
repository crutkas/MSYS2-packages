#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export PATH="/opt/bin:/usr/bin:${PATH}"

if (( $# != 1 )); then
  echo "usage: $0 REPORT_DIR" >&2
  exit 2
fi

report_dir=$1
source_dir="${report_dir}/sources"
binary_dir="${report_dir}/binaries"
audit_dir="${report_dir}/audits"
mkdir -p "$source_dir" "$binary_dir" "$audit_dir"

target=aarch64-pc-msys
cc="/opt/bin/${target}-gcc.exe"
cxx="/opt/bin/${target}-g++.exe"
objdump=aarch64-pc-cygwin-objdump

require_package() {
  local package=$1
  local version=$2
  local actual

  actual=$(pacman -Q "$package")
  if [[ "$actual" != "$package $version" ]]; then
    echo "package identity mismatch: expected '$package $version', got '$actual'" >&2
    return 1
  fi
  printf '%s\n' "$actual" >> "$report_dir/installed-packages.txt"
  pacman -Qk "$package" >> "$report_dir/pacman-integrity.txt"
}

require_owner() {
  local path=$1
  local expected=$2
  local actual

  actual=$(pacman -Qoq -- "$path")
  if [[ "$actual" != "$expected" ]]; then
    echo "owner mismatch for $path: expected $expected, got $actual" >&2
    return 1
  fi
  printf '%s\t%s\n' "$path" "$actual" >> "$report_dir/pacman-ownership.tsv"
}

: > "$report_dir/installed-packages.txt"
: > "$report_dir/pacman-integrity.txt"
: > "$report_dir/pacman-ownership.tsv"

require_package mingw-w64-cross-cygwinarm64-binutils 2.44.50-1
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
  mingw-w64-cross-cygwinarm64-binutils\>=2.44.50
  mingw-w64-cross-cygwinarm64-gcc-stage1=15.0.1dev-2
  mingw-w64-cross-msysarm64-headers=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-windows-default-manifest=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-sysroot=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-w32api-runtime=14.0.0.r0.g9b3dd0125-1
  mingw-w64-cross-msysarm64-runtime=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-runtime-devel=3.6.10.r0.ga527ace21-1
  mingw-w64-cross-msysarm64-libstdc++-headers=15.0.1dev-1
  mingw-w64-cross-msysarm64-gcc-libs=15.0.1dev-1
  mingw-w64-cross-msysarm64-gcc=15.0.1dev-1
)
if ! pacman -T -- "${requirements[@]}" > "$report_dir/missing-dependencies.txt"; then
  cat "$report_dir/missing-dependencies.txt" >&2
  exit 1
fi
test ! -s "$report_dir/missing-dependencies.txt"

require_owner \
  /opt/aarch64-pc-msys/include/cygwin/version.h \
  mingw-w64-cross-msysarm64-headers
require_owner \
  /opt/aarch64-pc-msys/lib/default-manifest.o \
  mingw-w64-cross-msysarm64-windows-default-manifest
require_owner \
  /opt/aarch64-pc-msys/usr/lib/libkernel32.a \
  mingw-w64-cross-msysarm64-w32api-runtime
require_owner \
  /opt/aarch64-pc-msys/bin/msys-2.0.dll \
  mingw-w64-cross-msysarm64-runtime
require_owner \
  /opt/aarch64-pc-msys/lib/libmsys-2.0.a \
  mingw-w64-cross-msysarm64-runtime-devel
require_owner \
  /opt/aarch64-pc-msys/include/c++/15.0.1/vector \
  mingw-w64-cross-msysarm64-libstdc++-headers
require_owner \
  /opt/bin/aarch64-pc-msys-gcc.exe \
  mingw-w64-cross-msysarm64-gcc
require_owner \
  /opt/lib/gcc/aarch64-pc-msys/msys-gcc_s-seh-1.dll \
  mingw-w64-cross-msysarm64-gcc-libs
require_owner \
  /opt/lib/gcc/aarch64-pc-msys/15.0.1/msys-stdc++-6.dll \
  mingw-w64-cross-msysarm64-gcc-libs

: > "$report_dir/relative-bridges.tsv"
for tool in ar nm ranlib; do
  bridge="/opt/aarch64-pc-msys/bin/${tool}.exe"
  expected="../../aarch64-pc-cygwin/bin/${tool}.exe"
  test -L "$bridge"
  actual=$(readlink "$bridge")
  if [[ "$actual" != "$expected" ]]; then
    echo "bridge target mismatch for $bridge: expected $expected, got $actual" >&2
    exit 1
  fi
  resolved=$(realpath "$bridge")
  if [[ "$resolved" != "/opt/aarch64-pc-cygwin/bin/${tool}.exe" ]]; then
    echo "bridge resolution mismatch for $bridge: $resolved" >&2
    exit 1
  fi
  require_owner "$bridge" mingw-w64-cross-msysarm64-gcc
  require_owner "$resolved" mingw-w64-cross-cygwinarm64-binutils
  "$bridge" --version > "$audit_dir/${tool}-bridge-version.txt"
  printf '%s\t%s\t%s\n' "$bridge" "$actual" "$resolved" \
    >> "$report_dir/relative-bridges.tsv"
done

for tool in "$cc" "$cxx" "$objdump" \
  /opt/bin/aarch64-pc-msys-gcc-ar.exe \
  /opt/bin/aarch64-pc-msys-gcc-nm.exe \
  /opt/bin/aarch64-pc-msys-gcc-ranlib.exe
do
  test -x "$(command -v "$tool")"
done

cc_machine=$("$cc" -dumpmachine)
cxx_machine=$("$cxx" -dumpmachine)
if [[ "$cc_machine" != "$target" || "$cxx_machine" != "$target" ]]; then
  echo "compiler target mismatch: CC=$cc_machine CXX=$cxx_machine" >&2
  exit 1
fi
"$cxx" -v > "$audit_dir/cxx-version.stdout.txt" \
  2> "$audit_dir/cxx-version.stderr.txt"
grep -Fx 'Thread model: posix' "$audit_dir/cxx-version.stderr.txt"
"$cc" -print-search-dirs > "$audit_dir/gcc-search-dirs.txt"
"$cc" -dumpspecs > "$audit_dir/gcc-specs.txt"
grep -F -- '-lmsys-2.0' "$audit_dir/gcc-specs.txt"
if grep -Eq '(^|[[:space:]])-lcygwin([[:space:]]|$)' \
    "$audit_dir/gcc-specs.txt"; then
  echo "installed GCC specs reference Cygwin" >&2
  exit 1
fi

cat > "$source_dir/basic.c" <<'EOF'
#include <stdio.h>
#include <sys/utsname.h>

int main(void) {
  struct utsname info;
  if (uname(&info) != 0) {
    perror("uname");
    return 1;
  }
  printf("runtime-machine=%s\n", info.machine);
  puts("basic-c-ok");
  return fflush(stdout) == 0 ? 0 : 2;
}
EOF

cat > "$source_dir/cxx-runtime.cc" <<'EOF'
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
int startup_state = 0;

struct Startup {
  Startup() { startup_state = 41; }
};

Startup startup;
}

int main() {
  if (startup_state != 41)
    return 1;

  try {
    throw std::runtime_error("arm64-msys");
  } catch (const std::exception& error) {
    if (std::string(error.what()) != "arm64-msys")
      return 2;
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
int total = 0;

void add(int value) {
  std::lock_guard<std::mutex> lock(gate);
  total += value;
}

void* pthread_entry(void* context) {
  add(*static_cast<int*>(context));
  return nullptr;
}

int main() {
  pthread_t pthread;
  int pthread_value = 17;
  if (pthread_create(&pthread, nullptr, pthread_entry, &pthread_value) != 0)
    return 1;

  std::thread cpp_thread(add, 25);
  cpp_thread.join();
  if (pthread_join(pthread, nullptr) != 0)
    return 2;
  if (total != 42)
    return 3;

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

static volatile sig_atomic_t signal_seen = 0;

static void signal_handler(int signal_number) {
  signal_seen = signal_number;
}

int main(void) {
  static const char child_message[] = "fork-pipe-ok";
  char received[sizeof(child_message)] = {0};
  struct sigaction action;
  int pipe_fds[2];
  int status;
  pid_t child;
  pid_t waited;
  ssize_t bytes;

  alarm(30);
  memset(&action, 0, sizeof(action));
  action.sa_handler = signal_handler;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0) {
    perror("sigaction");
    return 1;
  }
  if (raise(SIGUSR1) != 0 || signal_seen != SIGUSR1)
    return 2;

  if (pipe(pipe_fds) != 0) {
    perror("pipe");
    return 3;
  }
  child = fork();
  if (child < 0) {
    perror("fork");
    return 4;
  }
  if (child == 0) {
    close(pipe_fds[0]);
    bytes = write(pipe_fds[1], child_message, sizeof(child_message));
    close(pipe_fds[1]);
    _exit(bytes == (ssize_t) sizeof(child_message) ? 23 : 24);
  }

  close(pipe_fds[1]);
  bytes = read(pipe_fds[0], received, sizeof(received));
  close(pipe_fds[0]);
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);

  if (bytes != (ssize_t) sizeof(child_message))
    return 5;
  if (memcmp(received, child_message, sizeof(child_message)) != 0)
    return 6;
  if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 23)
    return 7;

  puts("process-runtime-ok");
  return 0;
}
EOF

cat > "$source_dir/lto-library.c" <<'EOF'
int lto_bridge_value(void) {
  return 42;
}
EOF

cat > "$source_dir/lto-main.c" <<'EOF'
#include <stdio.h>

int lto_bridge_value(void);

int main(void) {
  if (lto_bridge_value() != 42)
    return 1;
  puts("lto-bridge-ok");
  return 0;
}
EOF

common_flags=(-O2 -g -Wall -Wextra -Werror)
"$cc" "${common_flags[@]}" "$source_dir/basic.c" \
  -o "$binary_dir/basic-c.exe"
"$cxx" "${common_flags[@]}" -std=gnu++20 "$source_dir/cxx-runtime.cc" \
  -o "$binary_dir/cxx-runtime.exe"
"$cxx" "${common_flags[@]}" -std=gnu++20 -pthread \
  "$source_dir/thread-runtime.cc" -o "$binary_dir/thread-runtime.exe"
"$cc" "${common_flags[@]}" "$source_dir/process-runtime.c" \
  -o "$binary_dir/process-runtime.exe"

"$cc" "${common_flags[@]}" -flto -c "$source_dir/lto-library.c" \
  -o "$binary_dir/lto-library.o"
/opt/bin/aarch64-pc-msys-gcc-ar.exe rcs \
  "$binary_dir/liblto-bridge.a" "$binary_dir/lto-library.o"
/opt/bin/aarch64-pc-msys-gcc-nm.exe \
  "$binary_dir/liblto-bridge.a" > "$audit_dir/lto-bridge-nm.txt"
/opt/bin/aarch64-pc-msys-gcc-ranlib.exe "$binary_dir/liblto-bridge.a"
"$cc" "${common_flags[@]}" -flto "$source_dir/lto-main.c" \
  "$binary_dir/liblto-bridge.a" -o "$binary_dir/lto-bridge.exe"

audit_binary() {
  local file=$1
  local label=$2
  local file_report="$audit_dir/${label}.file.txt"
  local pe_report="$audit_dir/${label}.pe.txt"
  local import_report="$audit_dir/${label}.imports.txt"

  if ! "$objdump" -f "$file" > "$file_report" 2>&1; then
    echo "format-mismatch: $file" >&2
    return 1
  fi
  if ! grep -F 'file format pei-aarch64-little' "$file_report"; then
    echo "format-mismatch: $file" >&2
    return 1
  fi
  grep -F 'architecture: aarch64' "$file_report" || return 1

  "$objdump" -p "$file" > "$pe_report" || return 1
  sed -n 's/^[[:space:]]*DLL Name: //p' "$pe_report" \
    > "$import_report"
  grep -Fxi 'msys-2.0.dll' "$import_report" || return 1
  grep -Fxi 'KERNEL32.dll' "$import_report" || return 1
  if grep -Eiq \
      'cygwin1\.dll|pei-x86-64|i386:x86-64|x86_64' \
      "$file_report" "$import_report"; then
    echo "foreign architecture/runtime contamination: $file" >&2
    return 1
  fi
}

set +e
audit_binary "$cc" negative-host-compiler \
  > "$audit_dir/negative-host-compiler.log" 2>&1
negative_rc=$?
set -e
if (( negative_rc == 0 )); then
  echo "wrong-architecture negative control unexpectedly passed" >&2
  exit 1
fi
grep -F 'format-mismatch:' "$audit_dir/negative-host-compiler.log"

for binary in \
  basic-c \
  cxx-runtime \
  thread-runtime \
  process-runtime \
  lto-bridge
do
  audit_binary "$binary_dir/${binary}.exe" "$binary"
done

cat > "$report_dir/native-binaries.tsv" <<'EOF'
basic-c.exe	basic-c-ok
cxx-runtime.exe	cxx-runtime-ok
thread-runtime.exe	thread-runtime-ok
process-runtime.exe	process-runtime-ok
lto-bridge.exe	lto-bridge-ok
EOF

cat > "$report_dir/bash-smoke-summary.txt" <<EOF
target	$target
cc-dumpmachine	$cc_machine
cxx-dumpmachine	$cxx_machine
thread-model	posix
bridges	ar,nm,ranlib
negative-control	host-x86-64-rejected
audited-format	pei-aarch64-little
audited-imports	msys-2.0.dll,KERNEL32.dll
EOF

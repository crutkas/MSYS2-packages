#!/usr/bin/env bash

set -euo pipefail

if (( $# != 7 )); then
  echo "usage: $0 <prefix-root> <report-dir> <gcc-build> <gcc-source> <runtime-source> <runtime-build> <fixtures>" >&2
  exit 2
fi

prefix_root=$(cd "$1" && pwd)
report_dir=$2
gcc_build=$(cd "$3" && pwd)
gcc_source=$(cd "$4" && pwd)
runtime_source=$(cd "$5" && pwd)
runtime_build=$6
fixtures=$(cd "$7" && pwd)
target=aarch64-pc-cygwin
gcc_version=15.0.1
package=mingw-w64-cross-cygwinarm64-gcc-libs-stage1
libdir="${prefix_root}/lib/gcc/${target}/${gcc_version}"
work=$(mktemp -d "${TMPDIR:-/tmp}/cygwinarm64-static-runtime.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$report_dir"
report_dir=$(cd "$report_dir" && pwd)
rm -rf "$runtime_build"

export PATH="${prefix_root}/bin:/opt/bin:${PATH}"
cc="${prefix_root}/bin/${target}-gcc"
cxx="${prefix_root}/bin/${target}-g++"
ar=/opt/bin/${target}-ar
ld=/opt/bin/${target}-ld
nm=/opt/bin/${target}-nm
objdump=/opt/bin/${target}-objdump
gcc_nm="${prefix_root}/bin/${target}-gcc-nm"
sysroot=/opt/${target}
target_tool=("-B${sysroot}/bin/" "--sysroot=${sysroot}")

for tool in "$cc" "$cxx" "$ar" "$ld" "$nm" "$objdump" "$gcc_nm"; do
  test -x "$tool"
done
test "$("$cc" -dumpmachine)" = "$target"
test "$("$cxx" -dumpmachine)" = "$target"

archives=(libgcc.a libgcc_eh.a libgcov.a)
startup_objects=(crtbegin.o crtbeginS.o crtend.o crtfastmath.o)
for artifact in "${archives[@]}" "${startup_objects[@]}"; do
  test -f "${libdir}/${artifact}"
done
test -f "${libdir}/include/unwind.h"
test -f "${libdir}/include/gcov.h"
if find "$libdir" -maxdepth 1 -type f \
    \( -name '*.dll' -o -name '*.dll.a' -o -name 'libstdc++*' \
       -o -name 'libsupc++*' -o -name 'libcygwin.a' \
       -o -name 'libmsys-2.0.a' -o -name 'libc.a' -o -name 'libm.a' \) \
    | grep -q .; then
  echo "forbidden target runtime artifact found in ${libdir}" >&2
  exit 1
fi

make -C "${gcc_build}/${target}/libgcc" MAKEINFO=true all \
  > "$report_dir/libgcc-make-all.log" 2>&1
make -C "${gcc_build}/${target}/libgcc" enable_shared=yes libgcc_eh.a \
  >> "$report_dir/libgcc-make-all.log" 2>&1

"$cc" "${target_tool[@]}" -dM -E -x c /dev/null \
  > "$work/compiler-macros.txt"
"$cxx" "${target_tool[@]}" -v -E -x c++ /dev/null \
  > /dev/null 2> "$work/cxx-search.txt"
grep -Eq '^#define _WIN64( 1)?$' "$work/compiler-macros.txt"
grep -Eq '^#define __CYGWIN__( 1)?$' "$work/compiler-macros.txt"
grep -Eq '^#define __SEH__( 1)?$' "$work/compiler-macros.txt"
grep -Fx '#define __SIZEOF_LONG__ 8' "$work/compiler-macros.txt"
grep -Fx '#define __SIZEOF_POINTER__ 8' "$work/compiler-macros.txt"
grep -Fx '#define __SIZEOF_LONG_DOUBLE__ 8' "$work/compiler-macros.txt"
grep -Fx '#define __SIZEOF_WCHAR_T__ 2' "$work/compiler-macros.txt"
grep -Fx 'Thread model: posix' "$work/cxx-search.txt"
if grep -q -- '-D_WIN64' "$work/cxx-search.txt"; then
  echo "compiler search unexpectedly injects recipe-level -D_WIN64" >&2
  exit 1
fi

"$cc" "${target_tool[@]}" -O2 -c "$fixtures/abi.c" -o "$work/abi.o"
test "$(od -An -tx2 -N2 "$work/abi.o" | tr -d '[:space:]')" = aa64
"$objdump" -f "$work/abi.o" > "$report_dir/abi-file.txt"
grep -F 'file format pe-aarch64-little' "$report_dir/abi-file.txt"
"$cc" "${target_tool[@]}" -O2 -fexceptions -funwind-tables \
  -c "$fixtures/unwind.c" -o "$work/unwind.o"
"$objdump" -h "$work/unwind.o" > "$report_dir/unwind-sections.txt"
grep -Eq '[[:space:]]\.pdata[[:space:]]' "$report_dir/unwind-sections.txt"
grep -Eq '[[:space:]]\.xdata[[:space:]]' "$report_dir/unwind-sections.txt"

: > "$report_dir/archive-members.txt"
: > "$report_dir/archive-object-sha256.txt"
: > "$report_dir/section-audit.txt"
total_members=0
total_pdata=0
total_xdata=0
total_eh_frame=0
total_debug_frame=0

for archive_name in "${archives[@]}"; do
  archive="${libdir}/${archive_name}"
  archive_work="${work}/${archive_name%.a}"
  members="${archive_work}/members.txt"
  mkdir -p "$archive_work"
  "$ar" t "$archive" > "$members"
  member_count=$(wc -l < "$members")
  test "$member_count" -gt 0
  if sort "$members" | uniq -d | grep -q .; then
    echo "duplicate archive member names in ${archive_name}" >&2
    exit 1
  fi
  (
    cd "$archive_work"
    "$ar" x "$archive"
  )
  extracted_count=$(find "$archive_work" -maxdepth 1 -type f ! -name members.txt | wc -l)
  test "$extracted_count" -eq "$member_count"

  archive_pdata=0
  archive_xdata=0
  archive_eh_frame=0
  archive_debug_frame=0
  while IFS= read -r object; do
    member=$(basename "$object")
    test "$(od -An -tx2 -N2 "$object" | tr -d '[:space:]')" = aa64
    "$objdump" -f "$object" > "$work/object-file.txt"
    grep -F 'file format pe-aarch64-little' "$work/object-file.txt" > /dev/null
    "$objdump" -h "$object" > "$work/object-sections.txt"
    grep -Eq '[[:space:]]\.pdata[[:space:]]' "$work/object-sections.txt" \
      && ((archive_pdata += 1)) || true
    grep -Eq '[[:space:]]\.xdata[[:space:]]' "$work/object-sections.txt" \
      && ((archive_xdata += 1)) || true
    grep -Eq '[[:space:]]\.eh_frame[[:space:]]' "$work/object-sections.txt" \
      && ((archive_eh_frame += 1)) || true
    grep -Eq '[[:space:]]\.debug_frame[[:space:]]' "$work/object-sections.txt" \
      && ((archive_debug_frame += 1)) || true
    printf '%s/%s  %s\n' \
      "$archive_name" "$member" "$(sha256sum "$object" | cut -d' ' -f1)" \
      >> "$report_dir/archive-object-sha256.txt"
  done < <(find "$archive_work" -maxdepth 1 -type f ! -name members.txt | LC_ALL=C sort)

  archive_hash=$(sha256sum "$archive" | cut -d' ' -f1)
  printf '%s\t%s\t%s\n' "$archive_name" "$member_count" "$archive_hash" \
    >> "$report_dir/archive-members.txt"
  printf '%s\tmembers=%s\t.pdata=%s\t.xdata=%s\t.eh_frame=%s\t.debug_frame=%s\n' \
    "$archive_name" "$member_count" "$archive_pdata" "$archive_xdata" \
    "$archive_eh_frame" "$archive_debug_frame" \
    >> "$report_dir/section-audit.txt"
  ((total_members += member_count))
  ((total_pdata += archive_pdata))
  ((total_xdata += archive_xdata))
  ((total_eh_frame += archive_eh_frame))
  ((total_debug_frame += archive_debug_frame))
done

test "$total_pdata" -gt 0
test "$total_xdata" -gt 0
printf 'total\tmembers=%s\t.pdata=%s\t.xdata=%s\t.eh_frame=%s\t.debug_frame=%s\n' \
  "$total_members" "$total_pdata" "$total_xdata" \
  "$total_eh_frame" "$total_debug_frame" \
  >> "$report_dir/section-audit.txt"

: > "$report_dir/startup-objects.txt"
for object_name in "${startup_objects[@]}"; do
  object="${libdir}/${object_name}"
  test "$(od -An -tx2 -N2 "$object" | tr -d '[:space:]')" = aa64
  "$objdump" -f "$object" > "$work/startup-file.txt"
  grep -F 'file format pe-aarch64-little' "$work/startup-file.txt" > /dev/null
  "$objdump" -h "$object" > "$report_dir/${object_name}.sections.txt"
  "$objdump" -r "$object" > "$report_dir/${object_name}.relocations.txt"
  "$nm" -a "$object" > "$report_dir/${object_name}.symbols.txt"
  printf '%s\t%s\n' "$object_name" "$(sha256sum "$object" | cut -d' ' -f1)" \
    >> "$report_dir/startup-objects.txt"
done

"$cc" "${target_tool[@]}" -O2 -c "$fixtures/ctor-order.c" \
  -o "$work/ctor-order.o"
"$cxx" "${target_tool[@]}" -O2 -c "$fixtures/cxa-order.cc" \
  -o "$work/cxa-order.o"
"$objdump" -h "$work/ctor-order.o" > "$report_dir/ctor-order.sections.txt"
"$objdump" -r "$work/ctor-order.o" > "$report_dir/ctor-order.relocations.txt"
"$nm" -u "$work/cxa-order.o" > "$report_dir/cxa-order.undefined.txt"
grep -Eq '[[:space:]]\.ctors[[:space:]]' "$report_dir/ctor-order.sections.txt"
grep -Eq '[[:space:]]\.dtors[[:space:]]' "$report_dir/ctor-order.sections.txt"
grep -F '__cxa_atexit' "$report_dir/cxa-order.undefined.txt"
grep -F '__cxa_atexit' "$report_dir/crtbegin.o.relocations.txt"
grep -F 'register_frame_ctor' "$report_dir/crtend.o.symbols.txt"

"$ld" -r \
  -Map="$report_dir/ctor-order.map" \
  -o "$work/ctor-order-linked.o" \
  "${libdir}/crtbegin.o" \
  "$work/ctor-order.o" \
  "$work/cxa-order.o" \
  "${libdir}/crtend.o"
python - "$report_dir/ctor-order.map" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
begin = text.find("crtbegin.o")
user = text.find("ctor-order.o")
end = text.find("crtend.o")
if min(begin, user, end) < 0 or not begin < user < end:
    raise SystemExit("crtbegin/user/crtend load order is not preserved")

ctors = re.search(r"\.ctors(?P<body>.*?)(?:\n\.[A-Za-z]|\Z)", text, re.S)
if not ctors:
    raise SystemExit("linked map has no .ctors output section")
body = ctors.group("body")
if body.find("ctor-order.o") < 0 or body.find("crtend.o") < 0:
    raise SystemExit("linked map lacks user or crtend .ctors contribution")
if body.find("ctor-order.o") > body.find("crtend.o"):
    raise SystemExit("crtend .ctors contribution does not follow user constructors")
PY

"$cc" "${target_tool[@]}" -O2 -flto -ffunction-sections -fdata-sections \
  -c "$fixtures/lto-gc.c" -o "$work/lto-gc.o"
"$gcc_nm" "$work/lto-gc.o" > "$report_dir/lto-input.symbols.txt"
grep -F 'lto_gc_entry' "$report_dir/lto-input.symbols.txt"
"$cc" "${target_tool[@]}" -nostdlib -flto \
  -Wl,--gc-sections,-e,lto_gc_entry,-Map="$report_dir/lto-gc.map" \
  "$work/lto-gc.o" -lgcc -o "$work/lto-gc.exe"
"$objdump" -f "$work/lto-gc.exe" > "$report_dir/lto-gc.file.txt"
"$objdump" -h "$work/lto-gc.exe" > "$report_dir/lto-gc.sections.txt"
"$nm" "$work/lto-gc.exe" > "$report_dir/lto-gc.symbols.txt"
grep -F 'file format pei-aarch64-little' "$report_dir/lto-gc.file.txt"
grep -F '__divti3' "$report_dir/lto-gc.symbols.txt"
if grep -F 'discarded_by_gc' "$report_dir/lto-gc.symbols.txt"; then
  echo "section GC retained the deliberately unused function" >&2
  exit 1
fi

"$cc" -dumpspecs > "$report_dir/gcc.specs"
"$cc" -print-search-dirs > "$report_dir/search-dirs.txt"
"$cc" -print-multi-lib > "$report_dir/multilib.txt"
grep -Fx '.;' "$report_dir/multilib.txt"
grep -F 'crtbegin.o%s' "$report_dir/gcc.specs"
grep -F 'crtbeginS.o%s' "$report_dir/gcc.specs"
grep -F 'crtend.o%s' "$report_dir/gcc.specs"
grep -F -- '-lcygwin' "$report_dir/gcc.specs"
if grep -Eq -- '-lmsys-2\.0|_msys_dll_entry|--dll-search-prefix=msys-' \
    "$report_dir/gcc.specs"; then
  echo "Cygwin target specs contain MSYS target state" >&2
  exit 1
fi

: > "$report_dir/compiler-discovery.txt"
for artifact in libgcc.a "${startup_objects[@]}"; do
  found=$("$cc" "-print-file-name=${artifact}")
  found=$(realpath -m "$found")
  expected=$(realpath -m "${libdir}/${artifact}")
  test "$found" = "$expected"
  printf '%s\t%s\n' "$artifact" "$found" \
    >> "$report_dir/compiler-discovery.txt"
done
test "$(realpath -m "$("$cc" -print-libgcc-file-name)")" = \
  "$(realpath -m "${libdir}/libgcc.a")"
if grep -Eiq 'aarch64-w64-mingw32|/usr/lib/gcc/x86_64|/(mingw32|mingw64|ucrt64|clang64)/' \
    "$report_dir/search-dirs.txt" "$work/cxx-search.txt"; then
  echo "host or MinGW toolchain leakage detected" >&2
  exit 1
fi

if "$cc" "${target_tool[@]}" "$fixtures/abi.c" \
    -o "$work/ordinary.exe" > "$report_dir/ordinary-link.log" 2>&1; then
  echo "ordinary Cygwin link unexpectedly succeeded without the runtime" >&2
  exit 1
fi
test ! -e "$work/ordinary.exe"
grep -Eiq 'crt0|cygwin|cannot find' "$report_dir/ordinary-link.log"
if "$cc" "${target_tool[@]}" -shared "$fixtures/abi.c" \
    -o "$work/shared.dll" > "$report_dir/shared-link.log" 2>&1; then
  echo "shared Cygwin link unexpectedly succeeded without the runtime import library" >&2
  exit 1
fi
test ! -e "$work/shared.dll"
grep -Eiq 'cygwin|cannot find' "$report_dir/shared-link.log"
if grep -Eiq 'msys-2\.0|x86_64|aarch64-w64-mingw32' \
    "$report_dir/ordinary-link.log" "$report_dir/shared-link.log"; then
  echo "failed target link leaked into a host, MSYS, or MinGW runtime" >&2
  exit 1
fi

(cd "${runtime_source}/winsup" && ./autogen.sh)
mkdir -p "$runtime_build"
generic_include="${sysroot}/include/c++/${gcc_version}"
target_include="${generic_include}/${target}"
backward_include="${generic_include}/backward"
(
  cd "$runtime_build"
  PATH="${prefix_root}/bin:/opt/bin:${PATH}" \
  CC="${target}-gcc -B${sysroot}/bin/ --sysroot=${sysroot}" \
  CXX="${target}-g++ -B${sysroot}/bin/ --sysroot=${sysroot}" \
  CFLAGS='-O2 -pipe' \
  CXXFLAGS="-O2 -pipe -I${sysroot}/include -nostdinc++ -isystem ${generic_include} -isystem ${target_include} -isystem ${backward_include}" \
  LDFLAGS="-L${sysroot}/usr/lib" \
  ac_cv_lib_sframe_sframe_decode=no \
  ac_cv_lib_zstd_ZSTD_isError=no \
    "${runtime_source}/winsup/configure" \
      --host="$target" \
      --target="$target" \
      --disable-doc \
      --disable-dumper \
      --with-cross-bootstrap \
      > "$report_dir/runtime-configure.log" 2>&1
)

runtime_cygwin="${runtime_build}/cygwin"
make -C "$runtime_cygwin" V=1 globals.h \
  > "$report_dir/runtime-generated-headers.log" 2>&1
make -C "$runtime_cygwin" V=1 \
  cxx.o create_posix_thread.o autoload.o \
  > "$report_dir/runtime-objects.log" 2>&1
if grep -q -- '-D_WIN64' \
    "$report_dir/runtime-configure.log" "$report_dir/runtime-objects.log"; then
  echo "runtime object build used recipe-level -D_WIN64" >&2
  exit 1
fi

: > "$report_dir/runtime-objects.txt"
for object_name in cxx create_posix_thread autoload; do
  object="${runtime_cygwin}/${object_name}.o"
  test -f "$object"
  test "$(od -An -tx2 -N2 "$object" | tr -d '[:space:]')" = aa64
  "$objdump" -f "$object" > "$report_dir/runtime-${object_name}.file.txt"
  "$objdump" -h "$object" > "$report_dir/runtime-${object_name}.sections.txt"
  "$nm" -a "$object" > "$report_dir/runtime-${object_name}.symbols.txt"
  grep -F 'file format pe-aarch64-little' \
    "$report_dir/runtime-${object_name}.file.txt"
  grep -Eq '[[:space:]]\.pdata[[:space:]]' \
    "$report_dir/runtime-${object_name}.sections.txt"
  grep -Eq '[[:space:]]\.xdata[[:space:]]' \
    "$report_dir/runtime-${object_name}.sections.txt"
  printf '%s.o\t%s\n' "$object_name" "$(sha256sum "$object" | cut -d' ' -f1)" \
    >> "$report_dir/runtime-objects.txt"
done
"$nm" -C "$runtime_cygwin/cxx.o" > "$report_dir/runtime-cxx.demangled.txt"
grep -F 'operator new(unsigned long)' "$report_dir/runtime-cxx.demangled.txt"
grep -F '__cxa_pure_virtual' "$report_dir/runtime-cxx.symbols.txt"

: > "$report_dir/ownership-collisions.txt"
for artifact in "${archives[@]}" "${startup_objects[@]}"; do
  installed_path="/opt/lib/gcc/${target}/${gcc_version}/${artifact}"
  owner=$(pacman -Qoq "$installed_path" 2> /dev/null || true)
  if [[ -n "$owner" && "$owner" != "$package" ]]; then
    printf '%s\t%s\n' "$installed_path" "$owner" \
      >> "$report_dir/ownership-collisions.txt"
  fi
done
test ! -s "$report_dir/ownership-collisions.txt"

cat > "$report_dir/source-identity.txt" <<EOF
package-version	15.0.1dev-2
gcc-repository	https://github.com/crutkas/gcc-woarm64
gcc-commit	e1a057af466f066d86b20270fb7864764951420d
gcc-archive-sha256	8194893d7093f3cadedc2ec42375ffbbc02a22e30d943e5f1c1aefa273af8122
gcc-source-chain	9b0c288d8f337d685017621b2e9d84579f8aa391,3053d5071151031574f9ea272031d1dcba053f62,626c500b14b8eac6754b80b3a175acc305426c06,e1a057af466f066d86b20270fb7864764951420d
runtime-validation-repository	https://github.com/crutkas/msys2-runtime
runtime-validation-commit	a29cc9938c0d8d31d7ac1fc1a286cfa17f1df90c
runtime-validation-archive-sha256	e53b4ce39430398fe6edb515c99e9bb0a37d2d36aedf146ce8f49c87ca7f5819
stage0-package-base	389051fb5aab566707a95fd69d73f5659e02c696
target	${target}
abi	aapcs64-lp64-cygwin
thread-model	posix
shared-runtime-boundary	missing legitimate libcygwin.a/libmsys-2.0.a
EOF

cat > "$report_dir/install-order.txt" <<'EOF'
1	mingw-w64-cross-cygwinarm64-binutils	2.44.50-1	8908cb690952788153b60bc4fb659826bbd8a03a26c1073f76c0be7ed6f97518
2	mingw-w64-cross-cygwinarm64-headers	3.6.10.r0.gee50e0223-1	5266346cc10b142f871704ce4277699b1a5daa3121dc869990b4bedce69c0611
3	mingw-w64-cross-cygwinarm64-windows-default-manifest	3.6.10.r0.gee50e0223-1	cc089511fede6042a25f83fcb5903fddeede89ddd9655360741513ee9015e3dc
4	mingw-w64-cross-cygwinarm64-sysroot	3.6.10.r0.gee50e0223-1	4ed8a30f592317bf7e4def6f3c773139f2565b0f8afaedd820f7ee46d33cad20
5	mingw-w64-cross-cygwinarm64-w32api-runtime	14.0.0.r0.g9b3dd0125-1	53478f9a60e2fdad7d3b4357fa4fb937a1afab16af16a55e5a25ae9fac308fa7
6	mingw-w64-cross-cygwinarm64-gcc-stage1	15.0.1dev-1	f6260f3190fd602a5311c0c4cc47381405e96d9d049a679589f0b5c7be25fffe
7	mingw-w64-cross-cygwinarm64-libstdc++-headers	15.0.1dev-1	1e018d384e5e16b76524b69677819b660e6611480a85a7f7b8a412403bf15ea6
8	mingw-w64-cross-cygwinarm64-gcc-libs-stage1	15.0.1dev-2	see release SHA256SUMS
9	mingw-w64-cross-cygwinarm64-gcc-stage1	15.0.1dev-2	see release SHA256SUMS
EOF

cat > "$report_dir/shared-link-boundary.txt" <<'EOF'
available	headers, default manifest, w32api import libraries, static libgcc, GCC startup/end objects
validated	runtime source cxx.o, create_posix_thread.o, and autoload.o compile as AArch64 PE/COFF
missing	source-built newlib libc/libm target archives
missing	remaining source-built winsup/newlib runtime objects
missing	first-link export definition and linker-created libmsys-2.0.dll.a/libcygwin.a
missing	msys-2.0.dll, which can only be produced after all legitimate runtime inputs exist
boundary	ordinary and shared target links must fail rather than use host, MinGW, or fabricated runtime inputs
EOF

cp "$work/compiler-macros.txt" "$report_dir/compiler-macros.txt"
cp "$work/cxx-search.txt" "$report_dir/cxx-search.txt"
sed -E -i \
  's#/tmp/cc[[:alnum:]]+\.ltrans([0-9]+)\.ltrans\.o#<lto-object>.\1.o#g' \
  "$report_dir/lto-gc.map"

python - "$report_dir" "$total_members" "$total_pdata" "$total_xdata" \
  "$total_eh_frame" "$total_debug_frame" <<'PY'
import json
import pathlib
import sys

report_dir = pathlib.Path(sys.argv[1])

archives = {}
for line in (report_dir / "archive-members.txt").read_text().splitlines():
    name, members, digest = line.split("\t")
    archives[name] = {"members": int(members), "sha256": digest}

startup = {}
for line in (report_dir / "startup-objects.txt").read_text().splitlines():
    name, digest = line.split("\t")
    startup[name] = digest

report = {
    "schema_version": 1,
    "package": "mingw-w64-cross-cygwinarm64-gcc-libs-stage1",
    "version": "15.0.1dev-2",
    "target": "aarch64-pc-cygwin",
    "source_commit": "e1a057af466f066d86b20270fb7864764951420d",
    "natural_win64": True,
    "recipe_win64_define": False,
    "thread_model": "posix",
    "archives": archives,
    "startup_objects": startup,
    "archive_object_audit": {
        "members": int(sys.argv[2]),
        "foreign_objects": 0,
        "pdata_members": int(sys.argv[3]),
        "xdata_members": int(sys.argv[4]),
        "eh_frame_members": int(sys.argv[5]),
        "debug_frame_members": int(sys.argv[6]),
    },
    "crt_order": {
        "crtbegin_before_user": True,
        "crtend_after_user": True,
        "crtend_constructor_after_user_constructors": True,
        "cxa_atexit_reference": True,
    },
    "lto_gc": {
        "linked": True,
        "libgcc_divti3_resolved": True,
        "unused_section_discarded": True,
    },
    "runtime_objects": ["cxx.o", "create_posix_thread.o", "autoload.o"],
    "ownership_collisions": 0,
    "shared_link_boundary": "missing legitimate Cygwin/MSYS runtime import library",
}

(report_dir / "validation-report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

for report_file in "$report_dir"/*; do
  sed -i \
    -e "s#${prefix_root}#/opt#g" \
    -e "s#${gcc_build}#<gcc-build>#g" \
    -e "s#${gcc_source}#<gcc-source>#g" \
    -e "s#${runtime_source}#<runtime-source>#g" \
    -e "s#${runtime_build}#<runtime-build>#g" \
    -e "s#${fixtures}#<fixtures>#g" \
    -e "s#${report_dir}#<report>#g" \
    -e "s#${work}#<work>#g" \
    "$report_file"
done

python -m json.tool "$report_dir/validation-report.json" > /dev/null
echo "static runtime validation passed: ${report_dir}/validation-report.json"

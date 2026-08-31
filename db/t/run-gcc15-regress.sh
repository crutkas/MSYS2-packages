#!/usr/bin/env bash
#
# Red/green regression driver for the DB 6.2.32 GCC 15 (C23) callback fix.
# Compiles db/t/gcc15-callback-regress.c with the package's real flags plus
# -Werror, using GCC 15's default (C23) standard.
#
#   GREEN: with the fix (CFG_FN cast) it must compile, link, run and print PASS.
#   RED:   with -DREGRESS_NO_FIX (fix reverted) it must FAIL to compile with an
#          incompatible-pointer-types error.
#
# Exit 0 only if both controls behave as required.
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/gcc15-callback-regress.c"
cc="${CC:-gcc}"
# The package's real compile flags (db/PKGBUILD build env).
flags="-march=nocona -msahf -mtune=generic -O2 -pipe -Werror -Wall"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== compiler =="
"$cc" --version | head -1
echo | "$cc" -dM -E -x c - | grep __STDC_VERSION__ || true

echo "== RED control: fix reverted (-DREGRESS_NO_FIX) must NOT compile =="
if "$cc" $flags -DREGRESS_NO_FIX -c "$src" -o "$tmp/red.o" 2> "$tmp/red.log"; then
	echo "FAIL: reverted patch compiled but must not"
	sed -n '1,20p' "$tmp/red.log"
	exit 1
fi
if ! grep -q "incompatible pointer" "$tmp/red.log"; then
	echo "FAIL: reverted build failed for the wrong reason:"
	sed -n '1,20p' "$tmp/red.log"
	exit 1
fi
echo "OK: reverted patch is rejected with incompatible-pointer-types (as expected)"
grep -m1 "incompatible pointer" "$tmp/red.log"

echo "== GREEN control: with fix must compile, link and run =="
if ! "$cc" $flags "$src" -o "$tmp/green" 2> "$tmp/green.log"; then
	echo "FAIL: fixed build did not compile"
	sed -n '1,20p' "$tmp/green.log"
	exit 1
fi
out="$("$tmp/green")"; rc=$?
echo "$out"
if [ $rc -ne 0 ] || [ "$out" != "gcc15-callback-regress: PASS" ]; then
	echo "FAIL: fixed build ran but did not PASS (rc=$rc)"
	exit 1
fi

echo "== regression OK: red fails, green passes =="

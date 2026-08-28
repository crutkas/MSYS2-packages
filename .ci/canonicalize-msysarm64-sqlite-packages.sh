#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  echo "SOURCE_DATE_EPOCH is required" >&2
  exit 2
fi

for package in "$@"; do
  work=$(mktemp -d)
  output="${package}.canonical"
  trap 'rm -rf "$work" "$output"' EXIT

  MSYS=winsymlinks:sys bsdtar -xf "$package" -C "$work"
  test -f "${work}/.BUILDINFO"
  sed -E -i \
    's#^(builddir|startdir) = .*$#\1 = <private-build-root>#' \
    "${work}/.BUILDINFO"
  grep -Fx 'builddir = <private-build-root>' "${work}/.BUILDINFO"
  grep -Fx 'startdir = <private-build-root>' "${work}/.BUILDINFO"
  find "${work}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
  (
    cd "$work"
    export LC_COLLATE=C
    shopt -s dotglob globstar
    printf '%s\0' **/* \
      | LANG=C bsdtar -cnf - --format=mtree \
        --options='!all,use-set,type,uid,gid,mode,time,size,sha256,link' \
        --null --files-from - --exclude .MTREE
  ) \
    | gzip -c -f -n > "${work}/.MTREE"
  touch -d "@${SOURCE_DATE_EPOCH}" "${work}/.MTREE"

  (
    cd "$work"
    mapfile -d '' entries < <(
      find . -mindepth 1 -maxdepth 1 -printf '%P\0' | LC_ALL=C sort -z
    )
    tar \
      --sort=name \
      "--mtime=@${SOURCE_DATE_EPOCH}" \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf - \
      "${entries[@]}"
  ) | zstd -q -19 -T0 -o "$output"

  mv -f "$output" "$package"
  rm -rf "$work"
  trap - EXIT
done

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

  bsdtar -xf "$package" -C "$work"
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

#!/usr/bin/env python3

import pathlib
import struct
import sys

pkgname = sys.argv[1]
pkgfile = sys.argv[2]
paths = sys.argv[3:]

bad = []
for raw_path in paths:
    path = pathlib.Path(raw_path)
    data = path.read_bytes()
    if data[:2] != b'MZ':
        bad.append(f"{pkgname}: {pkgfile}: {path}: missing MZ header")
        continue
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        bad.append(f"{pkgname}: {pkgfile}: {path}: missing PE signature")
        continue
    machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
    if machine != 0xAA64:
        bad.append(f"{pkgname}: {pkgfile}: {path}: machine 0x{machine:04x}")

if bad:
    print('\n'.join(bad))
    raise SystemExit(1)

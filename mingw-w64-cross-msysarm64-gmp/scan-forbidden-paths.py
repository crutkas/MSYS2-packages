#!/usr/bin/env python3

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import zlib


AR_MAGIC = b"!<arch>\n"
MAX_NESTING = 8
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
JSON_STRING = re.compile(
    r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')


class ScanError(RuntimeError):
    pass


def _read_stream_limited(stream, label):
    chunks = []
    total = 0
    try:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EXPANDED_BYTES:
                raise ScanError(f"input exceeds scan limit: {label}")
            chunks.append(chunk)
    except OSError as error:
        raise ScanError(f"unreadable input: {label}: {error}") from error
    return b"".join(chunks)


def _read_bytes(path):
    try:
        with path.open("rb") as stream:
            return _read_stream_limited(stream, path)
    except OSError as error:
        raise ScanError(f"unreadable input: {path}: {error}") from error


def _needle_variants(value):
    slash = value.replace("\\", "/")
    backslash = value.replace("/", "\\")
    variants = {
        value,
        slash,
        backslash,
        value.replace("\\", "\\\\"),
        backslash.replace("\\", "\\\\"),
        slash.replace("/", "\\/"),
    }
    escaped = backslash
    for _ in range(2):
        escaped = escaped.replace("\\", "\\\\")
        variants.add(escaped)
    return sorted((item for item in variants if item), key=len, reverse=True)


def _find_direct_matches(data, forbidden, mode_prefix=""):
    matches = []
    lowered = data.lower()
    without_nuls = lowered.replace(b"\0", b"")
    for index, value in enumerate(forbidden):
        for variant in _needle_variants(value):
            encoded = (
                ("ascii", variant.encode("utf-8")),
                ("utf16le", variant.encode("utf-16le")),
                ("utf16be", variant.encode("utf-16be")),
            )
            for mode, needle in encoded:
                offset = lowered.find(needle.lower())
                if offset >= 0:
                    matches.append((index, mode_prefix + mode, offset))
            nul_offset = without_nuls.find(variant.encode("utf-8").lower())
            if nul_offset >= 0:
                matches.append((index, mode_prefix + "nul-rich", nul_offset))
    return sorted(set(matches))


def _find_matches(data, forbidden):
    matches = _find_direct_matches(data, forbidden)
    for encoding in ("utf-8", "utf-16le", "utf-16be"):
        text = data.decode(encoding, errors="replace")
        for token in JSON_STRING.finditer(text):
            try:
                decoded = json.loads(token.group())
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, str):
                matches.extend(_find_direct_matches(
                    decoded.encode("utf-8", errors="surrogatepass"),
                    forbidden,
                    f"json-{encoding}-",
                ))
    return sorted(set(matches))


def _decompress_limited(data, label, opener):
    chunks = []
    total = 0
    try:
        with opener(io.BytesIO(data)) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_EXPANDED_BYTES:
                    raise ScanError(f"expanded input exceeds limit: {label}")
                chunks.append(chunk)
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        raise ScanError(f"invalid compressed stream: {label}: {error}") from error
    return b"".join(chunks)


def _parse_ar(data, label):
    if not data.startswith(AR_MAGIC):
        raise ScanError(f"invalid ar archive: {label}")
    offset = len(AR_MAGIC)
    string_table = b""
    members = []
    while offset < len(data):
        if offset + 60 > len(data):
            raise ScanError(f"truncated ar header: {label}@{offset}")
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            raise ScanError(f"invalid ar header trailer: {label}@{offset}")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise ScanError(f"invalid ar member size: {label}@{offset}") from error
        start = offset + 60
        end = start + size
        if size < 0 or end > len(data):
            raise ScanError(f"truncated ar member: {label}@{offset}")
        try:
            raw_name = header[:16].decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise ScanError(f"invalid ar member name: {label}@{offset}") from error
        payload = data[start:end]
        name = raw_name.rstrip("/")
        if raw_name == "//":
            string_table = payload
            name = "//"
        elif raw_name.startswith("#1/"):
            try:
                name_size = int(raw_name[3:])
            except ValueError as error:
                raise ScanError(
                    f"invalid BSD ar member name: {label}@{offset}") from error
            if name_size < 0 or name_size > len(payload):
                raise ScanError(f"truncated BSD ar name: {label}@{offset}")
            name = payload[:name_size].decode("utf-8", errors="surrogateescape")
            payload = payload[name_size:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit():
            table_offset = int(raw_name[1:])
            if table_offset >= len(string_table):
                raise ScanError(f"invalid GNU ar name offset: {label}@{offset}")
            table_end = string_table.find(b"/\n", table_offset)
            if table_end < 0:
                raise ScanError(f"unterminated GNU ar name: {label}@{offset}")
            name = string_table[table_offset:table_end].decode(
                "utf-8", errors="surrogateescape")
        members.append((name or "/", payload))
        offset = end + (size & 1)
    if offset != len(data):
        raise ScanError(f"invalid ar alignment: {label}")
    if not members:
        raise ScanError(f"empty ar archive: {label}")
    return members


class Scanner:
    def __init__(self, forbidden):
        self.forbidden = forbidden
        self.entries = 0
        self.bytes = 0
        self.archives = 0
        self.archive_members = 0
        self.matches = []

    def scan_bytes(self, data, label):
        self.entries += 1
        self.bytes += len(data)
        for forbidden_index, mode, offset in _find_matches(
                data, self.forbidden):
            self.matches.append({
                "entry": label,
                "forbidden_index": forbidden_index,
                "mode": mode,
                "offset": offset,
            })

    def scan_blob(self, data, label, depth=0):
        self.scan_bytes(data, label)
        recognized = data.startswith(AR_MAGIC) or data.startswith(
            (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\0"))
        if not recognized:
            return
        if depth >= MAX_NESTING:
            raise ScanError(f"nested format depth exceeded: {label}")
        if data.startswith(AR_MAGIC):
            self.scan_ar(data, label, depth + 1)
        else:
            self.scan_compressed(data, label, depth + 1)

    def scan_ar(self, data, label, depth=0):
        self.archives += 1
        for name, payload in _parse_ar(data, label):
            self.archive_members += 1
            self.scan_bytes(
                name.encode("utf-8", errors="surrogateescape"),
                f"{label}!{name}@name",
            )
            self.scan_blob(payload, f"{label}!{name}", depth)

    def scan_compressed(self, data, label, depth=0):
        formats = (
            (
                b"\x1f\x8b",
                "gzip",
                lambda stream: gzip.GzipFile(fileobj=stream, mode="rb"),
            ),
            (b"BZh", "bzip2", bz2.BZ2File),
            (b"\xfd7zXZ\0", "xz", lzma.LZMAFile),
        )
        for magic, name, opener in formats:
            if not data.startswith(magic):
                continue
            expanded = _decompress_limited(data, f"{label}!{name}", opener)
            self.scan_blob(expanded, f"{label}!{name}", depth)
            return

    def scan_path(self, path, label):
        self.scan_bytes(os.fsencode(path.name), f"{label}@name")
        try:
            is_symlink = path.is_symlink()
        except OSError as error:
            raise ScanError(f"unreadable input metadata: {path}: {error}") from error
        if is_symlink:
            try:
                target = os.readlink(path)
            except OSError as error:
                raise ScanError(f"unreadable symlink: {path}: {error}") from error
            self.scan_bytes(os.fsencode(target), f"{label}@symlink")
            return
        if path.is_file():
            data = _read_bytes(path)
            self.scan_blob(data, label)
            if path.name.endswith((".a", ".dll.a")) and not data.startswith(
                    AR_MAGIC):
                raise ScanError(f"invalid ar archive: {label}")
            return
        if path.is_dir():
            try:
                children = sorted(path.iterdir(), key=lambda item: item.name)
            except OSError as error:
                raise ScanError(f"unreadable directory: {path}: {error}") from error
            for child in children:
                self.scan_path(child, f"{label}/{child.name}")
            return
        raise ScanError(f"unsupported input type: {path}")


def _canonical_package_name(name, archive):
    if "\\" in name or "\0" in name or ":" in name:
        raise ScanError(f"unsafe package entry: {archive}!{name}")
    pure = pathlib.PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise ScanError(f"unsafe package entry: {archive}!{name}")
    parts = tuple(part for part in pure.parts if part not in ("", "."))
    if not parts:
        raise ScanError(f"empty package entry name: {archive}!{name}")
    return "/".join(parts)


def _validate_extraction_path(destination, canonical, archive):
    root = destination.resolve()
    target = destination.joinpath(
        *pathlib.PurePosixPath(canonical).parts).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ScanError(
            f"package entry escapes extraction root: {archive}!{canonical}"
        ) from error


def _validate_link_target(member, canonical, label):
    if not member.linkname:
        raise ScanError(f"package link has no target: {label}!{canonical}")
    if ("\\" in member.linkname or "\0" in member.linkname
            or ":" in member.linkname):
        raise ScanError(f"unsafe package link: {label}!{canonical}")
    link = pathlib.PurePosixPath(member.linkname)
    if link.is_absolute():
        raise ScanError(f"unsafe package link: {label}!{canonical}")
    if member.issym():
        combined = pathlib.PurePosixPath(canonical).parent / link
    else:
        combined = link
    stack = []
    for part in combined.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise ScanError(f"package link escapes root: {label}!{canonical}")
            stack.pop()
        else:
            stack.append(part)


def _extract_package(archive, destination, bsdtar):
    try:
        listing = subprocess.run(
            [bsdtar, "-tf", str(archive)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScanError(f"cannot list package archive: {archive}: {error}") from error
    names = [line for line in listing.stdout.splitlines() if line]
    if not names:
        raise ScanError(f"package archive is empty: {archive}")
    canonical_names = [
        _canonical_package_name(name, archive) for name in names
    ]
    if len(canonical_names) != len(set(canonical_names)):
        raise ScanError(
            f"package archive has duplicate resolved entries: {archive}")
    for name in names:
        canonical = _canonical_package_name(name, archive)
        _validate_extraction_path(destination, canonical, archive)
    try:
        subprocess.run(
            [bsdtar, "-xf", str(archive), "-C", str(destination)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScanError(f"cannot extract package archive: {archive}: {error}") from error
    for name in names:
        extracted = destination.joinpath(*pathlib.PurePosixPath(name).parts)
        if not os.path.lexists(extracted):
            raise ScanError(f"package entry was not extracted: {archive}!{name}")
    return canonical_names


def _decompress_package(archive, zstd):
    try:
        process = subprocess.Popen(
            [zstd, "--decompress", "--stdout", "--quiet", str(archive)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ScanError(f"cannot decompress package: {archive}: {error}") from error
    chunks = []
    total = 0
    assert process.stdout is not None
    while True:
        chunk = process.stdout.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EXPANDED_BYTES:
            process.kill()
            process.communicate()
            raise ScanError(f"decompressed package exceeds limit: {archive}")
        chunks.append(chunk)
    _, stderr = process.communicate()
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise ScanError(f"cannot decompress package: {archive}: {detail}")
    return b"".join(chunks)


def _scan_tar_stream(scanner, data, label):
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, OSError) as error:
        raise ScanError(f"invalid package tar stream: {label}: {error}") from error
    canonical_names = []
    try:
        members = archive.getmembers()
        if not members:
            raise ScanError(f"package tar stream is empty: {label}")
        for member in members:
            canonical = _canonical_package_name(member.name, label)
            canonical_names.append(canonical)
            scanner.scan_bytes(
                member.name.encode("utf-8", errors="surrogateescape"),
                f"{label}!{canonical}@name",
            )
            scanner.scan_bytes(
                member.linkname.encode("utf-8", errors="surrogateescape"),
                f"{label}!{canonical}@link",
            )
            scanner.scan_bytes(
                json.dumps(
                    member.pax_headers,
                    ensure_ascii=True,
                    sort_keys=True,
                ).encode("ascii"),
                f"{label}!{canonical}@pax",
            )
            if member.isreg():
                if member.size < 0 or member.size > MAX_EXPANDED_BYTES:
                    raise ScanError(
                        f"package member exceeds limit: {label}!{canonical}")
                if getattr(member, "sparse", None) is not None:
                    raise ScanError(
                        f"sparse package member is forbidden: {label}!{canonical}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ScanError(
                        f"cannot read package member: {label}!{canonical}")
                payload = _read_stream_limited(
                    extracted,
                    f"{label}!{canonical}",
                )
                scanner.scan_blob(payload, f"{label}!{canonical}@content", 1)
            elif member.issym() or member.islnk():
                _validate_link_target(member, canonical, label)
            elif not member.isdir():
                raise ScanError(
                    f"unsupported package member type: {label}!{canonical}")
    finally:
        archive.close()
    if len(canonical_names) != len(set(canonical_names)):
        raise ScanError(
            f"package tar has duplicate resolved entries: {label}")
    return canonical_names


def scan(inputs, forbidden, bsdtar, zstd="zstd"):
    scanner = Scanner(forbidden)
    for position, raw_path in enumerate(inputs):
        path = pathlib.Path(raw_path)
        if not os.path.lexists(path):
            raise ScanError(f"missing input: {path}")
        label = f"input-{position}:{path.name}"
        scanner.scan_path(path, label)
        if path.is_file() and path.name.endswith(".pkg.tar.zst"):
            scanner.archives += 1
            tar_data = _decompress_package(path, zstd)
            scanner.scan_bytes(tar_data, f"{label}!raw-tar")
            tar_names = _scan_tar_stream(
                scanner,
                tar_data,
                f"{label}!tar",
            )
            with tempfile.TemporaryDirectory(prefix="gmp-package-scan-") as temp:
                extracted = pathlib.Path(temp)
                member_names = _extract_package(path, extracted, bsdtar)
                if member_names != tar_names:
                    raise ScanError(
                        f"package listings disagree: {path}")
                scanner.archive_members += len(member_names)
                scanner.scan_path(extracted, f"{label}!package")
    if scanner.entries == 0:
        raise ScanError("no inputs were scanned")
    return scanner


def _report(scanner, forbidden, status, error=None):
    return {
        "schema": 1,
        "status": status,
        "modes": ["ascii", "utf16le", "utf16be", "nul-rich"],
        "forbidden": [{
            "index": index,
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        } for index, value in enumerate(forbidden)],
        "entries_scanned": scanner.entries if scanner else 0,
        "bytes_scanned": scanner.bytes if scanner else 0,
        "archives_scanned": scanner.archives if scanner else 0,
        "archive_members_scanned": scanner.archive_members if scanner else 0,
        "matches": scanner.matches if scanner else [],
        "unreadable_or_skipped": 0 if status in ("pass", "match") else 1,
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--forbid", action="append", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--bsdtar", default="bsdtar")
    parser.add_argument("--zstd", default="zstd")
    parser.add_argument("inputs", nargs="+")
    args = parser.parse_args()
    report_path = pathlib.Path(args.report)
    scanner = None
    try:
        if any(not value or "\0" in value for value in args.forbid):
            raise ScanError("forbidden values must be nonempty and NUL-free")
        scanner = scan(args.inputs, args.forbid, args.bsdtar, args.zstd)
        status = "match" if scanner.matches else "pass"
        report = _report(scanner, args.forbid, status)
        exit_code = 1 if scanner.matches else 0
    except ScanError as error:
        report = _report(scanner, args.forbid, "error", str(error))
        exit_code = 2
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

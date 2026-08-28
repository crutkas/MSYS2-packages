#!/usr/bin/env python3

import importlib.util
import gzip
import io
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "scan_forbidden_paths", ROOT / "scan-forbidden-paths.py")
SCANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCANNER)


class BinaryScannerTests(unittest.TestCase):
    def test_detects_every_required_encoding(self):
        value = r"C:\private\gmp-root"
        fixtures = {
            "ascii": value.encode(),
            "utf16le": value.encode("utf-16le"),
            "utf16be": value.encode("utf-16be"),
            "nul-rich": b"\0\0".join(
                bytes((item,)) for item in value.encode()),
        }
        for expected, data in fixtures.items():
            with self.subTest(expected=expected):
                modes = {
                    mode for _, mode, _ in
                    SCANNER._find_matches(b"prefix" + data + b"suffix", [value])
                }
                self.assertIn(expected, modes)

    def test_detects_slash_and_case_variants(self):
        matches = SCANNER._find_matches(
            b"prefix c:/PRIVATE/GMP-root suffix",
            [r"C:\private\gmp-root"],
        )
        self.assertTrue(matches)

    def test_detects_json_escaped_windows_path(self):
        matches = SCANNER._find_matches(
            b'{"input_path":"C:\\\\\\\\private\\\\\\\\gmp-root\\\\\\\\probe.exe"}',
            [r"C:\private\gmp-root"],
        )
        self.assertTrue(matches)

    def test_detects_json_unicode_escaped_path(self):
        value = '{"input_path":"C:\\u005cprivate\\u005cgmp-root"}'
        for encoding in ("utf-8", "utf-16le", "utf-16be"):
            with self.subTest(encoding=encoding):
                matches = SCANNER._find_matches(
                    value.encode(encoding),
                    [r"C:\private\gmp-root"],
                )
                self.assertTrue(matches)

    def test_detects_json_path_amid_invalid_bytes(self):
        data = b'\xff{"x":"C:\\u005cprivate\\u005cgmp-root"}\xfe'
        self.assertTrue(
            SCANNER._find_matches(data, [r"C:\private\gmp-root"]))

    def test_clean_binary_passes(self):
        self.assertEqual(
            [], SCANNER._find_matches(bytes(range(256)), [r"C:\private\root"]))

    def test_scans_ar_members_and_symbol_table(self):
        needle = b"C:\\private\\root"

        def member(name, payload):
            header = (
                name.ljust(16) +
                "0".ljust(12) +
                "0".ljust(6) +
                "0".ljust(6) +
                "100644".ljust(8) +
                str(len(payload)).ljust(10) +
                "`\n"
            ).encode("ascii")
            return header + payload + (b"\n" if len(payload) & 1 else b"")

        archive = SCANNER.AR_MAGIC + member("/", b"index") + member(
            "probe.o/", b"prefix" + needle)
        scanner = SCANNER.Scanner([needle.decode()])
        scanner.scan_ar(archive, "libprobe.a")
        self.assertEqual(2, scanner.archive_members)
        self.assertTrue(scanner.matches)

    def test_scans_compressed_package_metadata(self):
        scanner = SCANNER.Scanner([r"C:\private\root"])
        scanner.scan_compressed(
            gzip.compress(b"prefix C:\\private\\root suffix"),
            ".MTREE",
        )
        self.assertTrue(scanner.matches)

    def test_scans_complete_package_entry_names(self):
        with tempfile.TemporaryDirectory() as temp:
            package = pathlib.Path(temp) / "probe.pkg.tar.zst"
            package.write_bytes(b"not-zstd-for-mocked-extraction")
            tar_bytes = io.BytesIO()
            with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
                member = tarfile.TarInfo(
                    name="opt/c/private/root/probe.exe")
                member.size = 0
                archive.addfile(member, io.BytesIO())
            with (
                mock.patch.object(
                    SCANNER,
                    "_decompress_package",
                    return_value=tar_bytes.getvalue(),
                ),
                mock.patch.object(
                    SCANNER,
                    "_extract_package",
                    return_value=["opt/c/private/root/probe.exe"],
                ),
            ):
                scanner = SCANNER.scan(
                    [package],
                    ["/c/private/root"],
                    "bsdtar",
                )
        self.assertTrue(scanner.matches)
        self.assertEqual(1, scanner.archive_members)

    def test_scans_package_pax_metadata(self):
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo(name="probe")
            member.pax_headers = {"private-path": r"C:\private\root"}
            member.size = 0
            archive.addfile(member, io.BytesIO())
        scanner = SCANNER.Scanner([r"C:\private\root"])
        SCANNER._scan_tar_stream(scanner, tar_bytes.getvalue(), "package")
        self.assertTrue(scanner.matches)

    def test_recursively_scans_nested_compression(self):
        scanner = SCANNER.Scanner([r"C:\private\root"])
        scanner.scan_blob(
            gzip.compress(gzip.compress(b"C:\\private\\root")),
            "nested",
        )
        self.assertTrue(scanner.matches)

    def test_rejects_duplicate_package_entries(self):
        listing = mock.Mock(stdout="./same\n./same\n")
        with tempfile.TemporaryDirectory() as temp:
            archive = pathlib.Path(temp) / "probe.pkg.tar.zst"
            with mock.patch.object(
                    SCANNER.subprocess, "run", return_value=listing):
                with self.assertRaisesRegex(
                        SCANNER.ScanError, "duplicate.*entries"):
                    SCANNER._extract_package(
                        archive,
                        pathlib.Path(temp),
                        "bsdtar",
                    )

    def test_rejects_unsafe_package_entries(self):
        listing = mock.Mock(stdout="../../escape\n")
        with tempfile.TemporaryDirectory() as temp:
            archive = pathlib.Path(temp) / "probe.pkg.tar.zst"
            with mock.patch.object(
                    SCANNER.subprocess, "run", return_value=listing):
                with self.assertRaisesRegex(SCANNER.ScanError, "unsafe"):
                    SCANNER._extract_package(
                        archive,
                        pathlib.Path(temp),
                        "bsdtar",
                    )

    def test_rejects_windows_package_entry_escapes(self):
        for name in (
                r"opt\C:\outside\probe",
                "C:/outside/probe",
                "//server/share/probe"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(SCANNER.ScanError, "unsafe"):
                    SCANNER._canonical_package_name(name, "package")

    def test_rejects_corrupt_compressed_metadata(self):
        scanner = SCANNER.Scanner(["private"])
        with self.assertRaises(SCANNER.ScanError):
            scanner.scan_compressed(b"\x1f\x8bcorrupt", ".MTREE")

    def test_rejects_malformed_archive(self):
        with self.assertRaises(SCANNER.ScanError):
            SCANNER._parse_ar(SCANNER.AR_MAGIC + b"truncated", "bad.a")

    def test_rejects_negative_bsd_archive_name_size(self):
        header = (
            "#1/-1".ljust(16)
            + "0".ljust(12)
            + "0".ljust(6)
            + "0".ljust(6)
            + "100644".ljust(8)
            + "1".ljust(10)
            + "`\n"
        ).encode("ascii")
        with self.assertRaisesRegex(SCANNER.ScanError, "BSD ar name"):
            SCANNER._parse_ar(
                SCANNER.AR_MAGIC + header + b"x" + b"\n",
                "bad.a",
            )

    def test_stream_limit_is_enforced_before_unbounded_read(self):
        with mock.patch.object(SCANNER, "MAX_EXPANDED_BYTES", 4):
            with self.assertRaisesRegex(SCANNER.ScanError, "scan limit"):
                SCANNER._read_stream_limited(io.BytesIO(b"12345"), "fixture")

    def test_missing_input_is_fatal(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = pathlib.Path(temp) / "missing"
            with self.assertRaises(SCANNER.ScanError):
                SCANNER.scan([missing], ["private"], "bsdtar")

    def test_unreadable_input_is_fatal(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "input.bin"
            path.write_bytes(b"clean")
            with mock.patch.object(
                    pathlib.Path, "open", side_effect=OSError("denied")):
                with self.assertRaises(SCANNER.ScanError):
                    SCANNER.scan([path], ["private"], "bsdtar")


if __name__ == "__main__":
    unittest.main()

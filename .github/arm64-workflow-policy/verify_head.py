#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys
from pathlib import Path


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an exact checked-out commit")
    parser.add_argument("expected_head")
    parser.add_argument("--repository", type=Path, default=Path("."))
    args = parser.parse_args()

    expected = args.expected_head.lower()
    if not SHA_RE.fullmatch(expected):
        print("expected head must be a full lowercase 40-hex commit", file=sys.stderr)
        return 2

    result = subprocess.run(
        ["git", "-C", str(args.repository), "rev-parse", "HEAD^{commit}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr.strip() or "unable to resolve HEAD", file=sys.stderr)
        return 2

    actual = result.stdout.strip().lower()
    if actual != expected:
        print(f"checked-out HEAD {actual} does not match expected {expected}", file=sys.stderr)
        return 1

    print(f"verified-head={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

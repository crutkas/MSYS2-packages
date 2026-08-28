from __future__ import annotations

import base64
import pathlib
import sys
import unittest


POLICY_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POLICY_DIR))

from policy_lib import (  # noqa: E402
    PolicyError,
    decode_github_blob,
    git_blob_sha,
)


class BlobHandlingTests(unittest.TestCase):
    def test_github_wrapped_base64_is_strictly_decoded(self):
        content = (b"semantic candidate data only\n" * 20) + b"end\n"
        encoded = base64.b64encode(content).decode("ascii")
        wrapped = "\n".join(
            encoded[index : index + 60]
            for index in range(0, len(encoded), 60)
        )
        sha = git_blob_sha(content)
        payload = {
            "sha": sha,
            "encoding": "base64",
            "size": len(content),
            "content": wrapped,
        }
        self.assertEqual(decode_github_blob(payload, sha), content)

    def test_non_wrapping_whitespace_and_digest_mismatch_deny(self):
        content = b"data"
        sha = git_blob_sha(content)
        invalid = {
            "sha": sha,
            "encoding": "base64",
            "size": len(content),
            "content": "Z GF0YQ==",
        }
        with self.assertRaises(PolicyError) as raised:
            decode_github_blob(invalid, sha)
        self.assertEqual(raised.exception.code, "BLOB_ENCODING")

        wrong_digest = {
            "sha": "0" * 40,
            "encoding": "base64",
            "size": len(content),
            "content": base64.b64encode(content).decode("ascii"),
        }
        with self.assertRaises(PolicyError) as raised:
            decode_github_blob(wrong_digest, "0" * 40)
        self.assertEqual(raised.exception.code, "BLOB_DIGEST")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Validate the protocol-owned File backend vectors with Python stdlib."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "file-backend.json"


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def expected_reader_action(reserved: int, flags: int, expiry: int, now: int) -> str:
    """spec/file-backend-format.md: unknown reserved/flags fail closed before expiry."""
    if reserved != 0 or flags != 0:
        return "miss_preserve"
    if expiry != 0 and now >= expiry:
        return "miss_expired"
    return "return_payload"


def verify(document: dict) -> int:
    for vector in document["vectors"]:
        name = vector["name"]
        key = vector["key_utf8"].encode("utf-8")
        filename = hashlib.blake2b(key, digest_size=16).hexdigest()
        check(filename == vector["filename"], name, "filename mismatch")

        image = bytes.fromhex(vector["file_hex"])
        check(len(image) >= 14, name, "file shorter than 14-byte header")
        check(image[:14].hex() == vector["header_hex"], name, "header_hex mismatch")
        check(image[14:].hex() == vector["payload_hex"], name, "payload_hex mismatch")
        check(image[:2] == b"CK" and image[2] == 1, name, "bad magic or version")

        reserved = image[3]
        flags = struct.unpack(">H", image[4:6])[0]
        expiry = struct.unpack(">Q", image[6:14])[0]
        check(reserved == vector.get("reserved", 0), name, "reserved mismatch")
        check(flags == vector["flags"], name, "flags mismatch")
        check(expiry == vector["expiry_unix_seconds"], name, "expiry mismatch")

        now = vector.get("reader_now_unix_seconds", 0)
        expected = expected_reader_action(reserved, flags, expiry, now)
        check(vector["reader_action"] == expected, name, "reader_action mismatch")

    return len(document["vectors"])


def main() -> None:
    try:
        document = json.loads(VECTORS.read_text(encoding="utf-8"))
    except OSError as exc:
        sys.exit(f"cannot read {VECTORS}: {exc}")
    except json.JSONDecodeError as exc:
        sys.exit(f"invalid JSON in {VECTORS}: {exc}")

    try:
        count = verify(document)
    except ValueError as exc:
        sys.exit(f"invalid vector file: {exc}")
    except (KeyError, TypeError, AttributeError) as exc:
        sys.exit(f"invalid vector file: malformed structure ({exc!r})")

    print("validated", count, "File backend vectors")


if __name__ == "__main__":
    main()

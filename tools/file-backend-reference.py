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


def main() -> None:
    try:
        document = json.loads(VECTORS.read_text(encoding="utf-8"))
    except OSError as exc:
        sys.exit(f"cannot read {VECTORS}: {exc}")
    except json.JSONDecodeError as exc:
        sys.exit(f"invalid JSON in {VECTORS}: {exc}")

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
        check(image[3] == 0, name, "reserved byte not zero")

        flags = struct.unpack(">H", image[4:6])[0]
        expiry = struct.unpack(">Q", image[6:14])[0]
        check(flags == vector["flags"], name, "flags mismatch")
        check(expiry == vector["expiry_unix_seconds"], name, "expiry mismatch")
        expected_action = "return_payload" if flags == 0 else "miss_preserve"
        check(vector["reader_action"] == expected_action, name, "reader_action mismatch")

    print("validated", len(document["vectors"]), "File backend vectors")


if __name__ == "__main__":
    main()

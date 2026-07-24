#!/usr/bin/env python3
"""Validate the protocol-owned File backend vectors with Python stdlib."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "file-backend.json"


def main() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    for vector in document["vectors"]:
        key = vector["key_utf8"].encode("utf-8")
        filename = hashlib.blake2b(key, digest_size=16).hexdigest()
        assert filename == vector["filename"], vector["name"]

        image = bytes.fromhex(vector["file_hex"])
        assert len(image) >= 14, vector["name"]
        assert image[:14].hex() == vector["header_hex"], vector["name"]
        assert image[14:].hex() == vector["payload_hex"], vector["name"]
        assert image[:2] == b"CK" and image[2] == 1, vector["name"]
        assert image[3] == 0, vector["name"]

        flags = struct.unpack(">H", image[4:6])[0]
        expiry = struct.unpack(">Q", image[6:14])[0]
        assert flags == vector["flags"], vector["name"]
        assert expiry == vector["expiry_unix_seconds"], vector["name"]
        expected_action = "return_payload" if flags == 0 else "miss_preserve"
        assert vector["reader_action"] == expected_action, vector["name"]

    print("validated", len(document["vectors"]), "File backend vectors")


if __name__ == "__main__":
    main()

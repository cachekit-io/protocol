#!/usr/bin/env python3
"""Validate test-vectors/path-encoding.json with Python stdlib.

spec/saas-api.md § Cache-Key Path Encoding. Every row's `encoded` must be the
reference form (`quote(key, safe="")`, all-dot result rewritten to `%2E`), decode
once back to `key`, carry no raw `/ ? # %`, and be a WHATWG dot segment only when
the row says so. A mutation self-test runs first so the guard cannot degrade to
silently reporting OK (same doctrine as tools/test_wire_format_reference.py).
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
import re
import sys
from urllib.parse import quote, unquote

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "path-encoding.json"

# Reference form: RFC 3986 unreserved characters and uppercase %HH escapes only.
SEGMENT = re.compile(r"^(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+$")
# Encoder-variance form: additionally the five sub-delims encodeURIComponent leaves raw
# (legal pchar in a path segment, decode to themselves — spec rule 4).
ALT_SEGMENT = re.compile(r"^(?:[A-Za-z0-9._~!*'()-]|%[0-9A-F]{2})+$")
# WHATWG URL Standard § 4.1: single-/double-dot path segments, ASCII case-insensitive.
WHATWG_DOT_SEGMENTS = {".", "%2e", "..", ".%2e", "%2e.", "%2e%2e"}


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def reference_encode(key: str) -> str:
    """cachekit-py ``CachekitIOBackend._encode_key`` (f000ba3)."""
    encoded = quote(key, safe="")
    return encoded.replace(".", "%2E") if encoded in (".", "..") else encoded


def check_segment(name: str, segment: str, dot_segment: bool, key: str, pattern: re.Pattern[str] = SEGMENT) -> None:
    check(pattern.fullmatch(segment) is not None, name, f"{segment!r} has a raw reserved character (or lowercase/incomplete %HH)")
    check(segment not in (".", ".."), name, f"{segment!r} is a literal dot segment")
    check((segment.lower() in WHATWG_DOT_SEGMENTS) == dot_segment, name, f"{segment!r} WHATWG dot-segment status does not match dot_segment={dot_segment}")
    check(unquote(segment) == key, name, f"single decode of {segment!r} != key")


def verify(document: dict) -> int:
    for vector in document["vectors"]:
        key = vector["key"]
        name = repr(key)
        dot_segment = vector.get("dot_segment", False)
        check(vector["decoded"] == key, name, "decoded != key (interop is defined on the decoded key)")
        check(vector["encoded"] == reference_encode(key), name, f"encoded {vector['encoded']!r} != reference {reference_encode(key)!r}")
        check_segment(name, vector["encoded"], dot_segment, key)
        for alt in vector.get("encoded_alternates", []):
            check(alt != vector["encoded"], name, "encoded_alternates repeats encoded")
            check_segment(name, alt, dot_segment, key, ALT_SEGMENT)
    return len(document["vectors"])


def self_test(document: dict) -> None:
    """Each poisoned copy must be rejected — otherwise the verify above is toothless."""
    def poisoned(mutate) -> dict:
        doc = copy.deepcopy(document)
        mutate(doc["vectors"])
        return doc

    def row(vectors: list, key: str) -> dict:
        return next(v for v in vectors if v["key"] == key)

    mutations = {
        "raw slash": lambda v: row(v, "x/../../health").__setitem__("encoded", "x/..%2F..%2Fhealth"),
        "raw percent": lambda v: row(v, "100%").__setitem__("encoded", "100%"),
        "double-encoded": lambda v: row(v, "100%").__setitem__("encoded", "100%2525"),
        "literal dot segment": lambda v: row(v, "..").__setitem__("encoded", ".."),
        "unflagged WHATWG dot segment": lambda v: row(v, "..").__delitem__("dot_segment"),
        "flag on inert row": lambda v: row(v, "a:..").__setitem__("dot_segment", True),
        "decoded drift": lambda v: row(v, "ns:key").__setitem__("decoded", "ns:kex"),
        "lowercase hex": lambda v: row(v, "ns:key").__setitem__("encoded", "ns%3akey"),
        "bad alternate": lambda v: row(v, "f(x)!*'")["encoded_alternates"].append("f(x)!*'/"),
    }
    for label, mutate in mutations.items():
        try:
            verify(poisoned(mutate))
        except ValueError:
            continue
        raise ValueError(f"self-test: mutation {label!r} was not rejected")


def main() -> None:
    try:
        document = json.loads(VECTORS.read_text(encoding="utf-8"))
    except OSError as exc:
        sys.exit(f"cannot read {VECTORS}: {exc}")
    except json.JSONDecodeError as exc:
        sys.exit(f"invalid JSON in {VECTORS}: {exc}")

    try:
        self_test(document)
        count = verify(document)
    except ValueError as exc:
        sys.exit(f"invalid vector file: {exc}")
    except (KeyError, TypeError, AttributeError, StopIteration) as exc:
        sys.exit(f"invalid vector file: malformed structure ({exc!r})")

    logging.info("validated %d path-encoding vectors (self-test passed)", count)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()

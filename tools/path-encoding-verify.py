#!/usr/bin/env python3
"""Validate test-vectors/path-encoding.json with Python stdlib.

spec/saas-api.md § Cache-Key Path Encoding. A transmittable row's `encoded` must be
the reference form (`quote(key, safe="")`) and decode once back to `key`; a key whose
reference form is a reserved segment (WHATWG dot segment or route token) must be a
`reject` row with no wire form. A mutation self-test runs first so the guard cannot
degrade to silently reporting OK (same doctrine as tools/test_wire_format_reference.py).
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

# WHATWG URL Standard § 4.1: single-/double-dot path segments, ASCII case-insensitive.
WHATWG_DOT_SEGMENTS = {".", "%2e", "..", ".%2e", "%2e.", "%2e%2e"}
# saas router: `/v1/cache/health` is the health endpoint; a final `ttl`/`lock` selects a sub-resource.
ROUTE_TOKENS = {"health", "ttl", "lock"}
# A conformant alternate wire form: RFC 3986 unreserved, the five sub-delims
# encodeURIComponent leaves raw (spec rule 4), and uppercase %HH escapes.
ALT_SEGMENT = re.compile(r"^(?:[A-Za-z0-9._~!*'()-]|%[0-9A-F]{2})+$")


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def is_reserved(segment: str) -> bool:
    return segment.lower() in WHATWG_DOT_SEGMENTS or segment in ROUTE_TOKENS


def verify(document: dict) -> int:
    for vector in document["vectors"]:
        key = vector["key"]
        name = repr(key)
        reference = quote(key, safe="")
        if vector.get("reject"):
            check(is_reserved(reference), name, "reject flag on a transmittable key")
            check(vector["encoded"] is None and vector["decoded"] is None, name, "reject row carries a wire form")
            continue
        check(not is_reserved(reference), name, "reserved segment must be a reject row")
        check(vector["decoded"] == key, name, "decoded != key (interop is defined on the decoded key)")
        check(vector["encoded"] == reference, name, f"encoded {vector['encoded']!r} != reference {reference!r}")
        for alt in vector.get("encoded_alternates", []):
            check(ALT_SEGMENT.fullmatch(alt) is not None, name, f"alternate {alt!r} has a raw reserved character or bad %HH")
            check(unquote(alt) == key, name, f"alternate {alt!r} does not decode to key")
    return len(document["vectors"])


def self_test(document: dict) -> None:
    """Each poisoned copy must trip a distinct guard — otherwise verify() is toothless."""
    def row(vectors: list, key: str) -> dict:
        return next(v for v in vectors if v["key"] == key)

    def set_field(key: str, field: str, value: object):
        return lambda v: row(v, key).__setitem__(field, value)

    mutations = {
        "encoded drift": set_field("x/../../health", "encoded", "x/..%2F..%2Fhealth"),
        "decoded drift": set_field("ns:key", "decoded", "ns:kex"),
        "reject row with wire form": set_field("..", "encoded", "%2E%2E"),
        "reject flag on transmittable key": set_field("a:..", "reject", True),
        "reserved key not flagged": lambda v: row(v, "..").update(reject=False, encoded="%2E%2E", decoded=".."),
        "alternate raw slash": lambda v: row(v, "f(x)!*'")["encoded_alternates"].append("f(x)!*'/"),
        "alternate decodes elsewhere": lambda v: row(v, "f(x)!*'")["encoded_alternates"].append("f%28x%29"),
    }
    for label, mutate in mutations.items():
        poisoned = copy.deepcopy(document)
        mutate(poisoned["vectors"])
        try:
            verify(poisoned)
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

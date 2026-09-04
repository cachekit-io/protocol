#!/usr/bin/env python3
"""Validate test-vectors/path-encoding.json with Python stdlib.

spec/saas-api.md § Cache-Key Path Encoding. A transmittable row's `encoded` must be
the reference form (`quote(key, safe="")`) and decode once back to `key`; a key whose
reference form is a reserved segment (WHATWG dot segment or route token) must be a
`reject` row with no wire form. A mutation self-test runs first so the guard cannot
degrade to silently reporting OK, and each mutation must trip the guard it names (same doctrine as tools/test_wire_format_reference.py).
"""

from __future__ import annotations

import copy
import json
import logging
import re
import sys
from pathlib import Path
from urllib.parse import quote, unquote

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "path-encoding.json"

# spec rule 2. `.`/`..` are dot segments (the server's WHATWG parse also collapses the
# `%2e` forms, but quote() never emits those for `.`, so only the literals can appear here);
# `health`/`ttl`/`lock` are saas route tokens at the `/v1/cache/` level.
RESERVED_SEGMENTS = {".", "..", "health", "ttl", "lock"}
# A conformant alternate wire form: RFC 3986 unreserved, the five sub-delims
# encodeURIComponent leaves raw (spec rule 4), and uppercase %HH escapes.
ALT_SEGMENT = re.compile(r"^(?:[A-Za-z0-9._~!*'()-]|%[0-9A-F]{2})+$")


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def decodes_to(segment: str, key: str) -> bool:
    """True iff percent-unescaping ``segment`` yields exactly ``key`` as valid UTF-8.

    ``unquote`` defaults to ``errors="replace"``, which maps a non-UTF-8 escape such as
    ``%FF`` to U+FFFD instead of rejecting it (spec rule 1 forbids non-UTF-8 wire forms).
    Decode strictly so an invalid escape can never masquerade as a conformant alternate.
    """
    try:
        return unquote(segment, errors="strict") == key
    except UnicodeDecodeError:
        return False


def verify(document: dict) -> int:
    for vector in document["vectors"]:
        key = vector["key"]
        name = repr(key)
        reference = quote(key, safe="")
        if vector.get("reject"):
            check(reference in RESERVED_SEGMENTS, name, "reject flag on a transmittable key")
            check(vector["encoded"] is None and vector["decoded"] is None, name, "reject row carries a wire form")
            continue
        check(reference not in RESERVED_SEGMENTS, name, "reserved segment must be a reject row")
        check(vector["decoded"] == key, name, "decoded != key (interop is defined on the decoded key)")
        check(vector["encoded"] == reference, name, f"encoded {vector['encoded']!r} != reference {reference!r}")
        for alt in vector.get("encoded_alternates", []):
            check(alt != vector["encoded"], name, f"alternate {alt!r} repeats the reference encoded form")
            check(ALT_SEGMENT.fullmatch(alt) is not None, name, f"alternate {alt!r} has a raw reserved character or bad %HH")
            check(decodes_to(alt, key), name, f"alternate {alt!r} does not decode to key")
    return len(document["vectors"])


def self_test(document: dict) -> None:
    """Each poisoned copy must trip a distinct guard — otherwise verify() is toothless."""
    def row(vectors: list, key: str) -> dict:
        return next(v for v in vectors if v["key"] == key)

    def set_field(key: str, field: str, value: object):
        return lambda v: row(v, key).__setitem__(field, value)

    # label: (poison, substring the tripped guard's message must contain)
    mutations = {
        "encoded drift": (set_field("x/../../health", "encoded", "x/..%2F..%2Fhealth"), "!= reference"),
        "decoded drift": (set_field("ns:key", "decoded", "ns:kex"), "decoded != key"),
        "reject row with wire form": (set_field("..", "encoded", "%2E%2E"), "carries a wire form"),
        "reject flag on transmittable key": (set_field("a:..", "reject", True), "reject flag on a transmittable"),
        "reserved key not flagged": (lambda v: row(v, "..").update(reject=False, encoded="%2E%2E", decoded=".."), "must be a reject row"),
        "alternate raw slash": (lambda v: row(v, "f(x)!*'")["encoded_alternates"].append("f(x)!*'/"), "raw reserved character"),
        "alternate decodes elsewhere": (lambda v: row(v, "f(x)!*'")["encoded_alternates"].append("f%28x%29"), "does not decode to key"),
        "alternate repeats encoded": (lambda v: row(v, "f(x)!*'")["encoded_alternates"].append(row(v, "f(x)!*'")["encoded"]), "repeats the reference"),
        "alternate non-utf8 escape": (lambda v: row(v, "f(x)!*'")["encoded_alternates"].append("%FF"), "does not decode to key"),
    }
    for label, (mutate, expected) in mutations.items():
        poisoned = copy.deepcopy(document)
        mutate(poisoned["vectors"])
        try:
            verify(poisoned)
        except ValueError as exc:
            check(expected in str(exc), "self-test", f"mutation {label!r} tripped the wrong guard: {exc}")
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

#!/usr/bin/env python3
"""Validate test-vectors/path-encoding.json with Python stdlib.

spec/saas-api.md § Cache-Key Path Encoding. A transmittable row's `encoded` must be
the reference form (`quote(key, safe="")`) and decode once back to `key`; its
`encoded_alternates` must be exactly the `encodeURIComponent` form where that differs.
The reject rows must be exactly the reserved keys of spec rule 2, with no wire form. A
mutation self-test runs first so the guard cannot degrade to silently reporting OK, and
each mutation must trip the guard it names (same doctrine as
tools/test_wire_format_reference.py).
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "path-encoding.json"

# spec rule 2: `.`/`..` are dot segments; `health`/`ttl`/`lock` are route tokens at the
# `/v1/cache/` level. Each encodes to itself under rule 1.
RESERVED_SEGMENTS = {".", "..", "health", "ttl", "lock"}
# The sub-delims encodeURIComponent leaves raw (spec rule 4); quote() with these as safe
# is byte-for-byte encodeURIComponent.
ENCODE_URI_COMPONENT_SAFE = "!*'()"


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def verify(document: dict) -> int:
    vectors = document["vectors"]
    keys = [vector["key"] for vector in vectors]
    check(len(keys) == len(set(keys)), "vectors", "duplicate key")
    for vector in vectors:
        check(isinstance(vector.get("reject", False), bool), repr(vector["key"]), "reject must be absent or a bool")
    rejected = {vector["key"] for vector in vectors if vector.get("reject") is True}
    check(rejected == RESERVED_SEGMENTS, "vectors", f"reject rows {sorted(rejected)} != reserved set {sorted(RESERVED_SEGMENTS)}")

    for vector in vectors:
        key = vector["key"]
        name = repr(key)
        if key in RESERVED_SEGMENTS:
            check(vector["encoded"] is None and vector["decoded"] is None, name, "reject row carries a wire form")
            check("encoded_alternates" not in vector, name, "reject row carries encoded_alternates")
            continue
        reference = quote(key, safe="")
        check(vector["decoded"] == key, name, "decoded != key (interop is defined on the decoded key)")
        check(vector["encoded"] == reference, name, f"encoded {vector['encoded']!r} != reference {reference!r}")
        uri_component = quote(key, safe=ENCODE_URI_COMPONENT_SAFE)
        expected = [uri_component] if uri_component != reference else []
        alternates = vector.get("encoded_alternates", [])
        check(alternates == expected, name, f"encoded_alternates {alternates!r} != encodeURIComponent form {expected!r}")
    return len(vectors)


def self_test(document: dict) -> None:
    """Each poisoned copy must trip the guard it names — otherwise verify() is toothless."""

    def row(vectors: list, key: str) -> dict:
        return next(v for v in vectors if v["key"] == key)

    def set_field(key: str, field: str, value: object) -> Callable[[list], None]:
        return lambda v: row(v, key).__setitem__(field, value)

    def drop_row(key: str) -> Callable[[list], None]:
        return lambda v: v.remove(row(v, key))

    # label: (poison, substring the tripped guard's message must contain)
    mutations = {
        "encoded drift": (set_field("x/../../health", "encoded", "x/..%2F..%2Fhealth"), "!= reference"),
        "decoded drift": (set_field("ns:key", "decoded", "ns:kex"), "decoded != key"),
        "duplicate key": (lambda v: v.append(copy.deepcopy(row(v, "ns:key"))), "duplicate key"),
        "reject row dropped": (drop_row("health"), "!= reserved set"),
        "reject flag on transmittable key": (set_field("a:..", "reject", True), "!= reserved set"),
        "non-bool reject flag": (set_field("a:..", "reject", 1), "absent or a bool"),
        "reserved key not flagged": (set_field("..", "reject", False), "!= reserved set"),
        "reject row with wire form": (set_field("..", "encoded", "%2E%2E"), "carries a wire form"),
        "reject row with alternates": (set_field("lock", "encoded_alternates", ["lock"]), "carries encoded_alternates"),
        "alternate over-encoded": (set_field("f(x)!*'", "encoded_alternates", ["%66(x)!*'"]), "!= encodeURIComponent form"),
        "alternate missing": (set_field("f(x)!*'", "encoded_alternates", []), "!= encodeURIComponent form"),
        "alternate where none differs": (set_field("ns:key", "encoded_alternates", ["ns%3Akey"]), "!= encodeURIComponent form"),
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

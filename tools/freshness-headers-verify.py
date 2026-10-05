#!/usr/bin/env python3
"""Validate test-vectors/freshness-headers.json with Python stdlib.

spec/saas-api.md § GET /v1/cache/{key} (response headers) and § Remaining Freshness. Each row
is one header's field value on a GET 200, or null when the header is absent. A
`freshness_vectors` row's `stale` must be what X-CacheKit-Freshness means (fresh when absent or
exactly `fresh`, stale otherwise), and a `fresh_for_vectors` row's `fresh_for` what
X-CacheKit-Fresh-For means (1-7 ASCII digits at most 2,592,000, otherwise 0; null when absent).
Every value must be one an HTTP stack can deliver: one byte per character, no leading or
trailing space or tab, no other control character. A mutation self-test runs first, as in
tools/path-encoding-verify.py: each poisoned copy of the fixture must trip the guard it names,
and each plausible wrong reader of the headers must disagree with at least one row.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "freshness-headers.json"

# The 30-day TTL cap. It has seven digits, so no valid X-CacheKit-Fresh-For is longer.
FRESH_FOR_MAX = 2_592_000
FRESH_FOR_MAX_DIGITS = 7
# Each table, and the field that holds its rows' result.
TABLES = {"freshness_vectors": "stale", "fresh_for_vectors": "fresh_for"}

Reader = Callable[[str | None], object]


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def is_stale(value: str | None) -> bool:
    """X-CacheKit-Freshness on a GET: absent is fresh (pre-SWR servers omit it); anything but `fresh` is stale."""
    return value is not None and value != "fresh"


def fresh_for(value: str | None) -> int | None:
    """X-CacheKit-Fresh-For: None when absent, the number for 1-7 ASCII digits at most the cap, else 0.

    The length check runs first, so nothing longer than seven digits reaches a conversion.
    """
    if value is None:
        return None
    if not 1 <= len(value) <= FRESH_FOR_MAX_DIGITS or not all("0" <= c <= "9" for c in value):
        return 0
    seconds = int(value)
    return seconds if seconds <= FRESH_FOR_MAX else 0


READERS: dict[str, Reader] = {"stale": is_stale, "fresh_for": fresh_for}


def field_value_problem(value: str) -> str | None:
    """Why no HTTP stack could deliver `value` as a field value (RFC 9110 §5.5), or None."""
    if any(ord(c) > 0xFF for c in value):
        return "a character above U+00FF is not one byte"
    if any(c != "\t" and (c < " " or c == "\x7f") for c in value):
        return "a control character other than tab"
    if value[:1] in (" ", "\t") or value[-1:] in (" ", "\t"):
        return "leading or trailing white space, which HTTP strips"
    return None


def verify(document: dict, readers: dict[str, Reader] = READERS) -> int:
    unknown = sorted(key for key in document if key.endswith("vectors") and key not in TABLES)
    check(not unknown, "document", f"unknown table(s) {unknown}: tools/conformance.py would index rows this verifier skips")
    names: set[str] = set()
    for table, result in TABLES.items():
        rows = document[table]
        check(isinstance(rows, list) and len(rows) > 0, table, "must be a non-empty list")
        for row in rows:
            name = row.get("name") if isinstance(row, dict) else None
            check(isinstance(name, str) and name != "", table, f"a row has no string name: {row!r}")
            check(name not in names, name, "duplicate name")
            names.add(name)
            fields = {"name", "value", result, "note"}
            check(set(row) == fields, name, f"fields {sorted(row)} != {sorted(fields)}")
            check(isinstance(row["note"], str) and row["note"].strip() != "", name, "note must be a non-empty string")
            value = row["value"]
            check(value is None or isinstance(value, str), name, "value must be a string or null")
            if value is not None:
                problem = field_value_problem(value)
                check(problem is None, name, f"value {value!r} is no field value: {problem}")
            expected = row[result]
            if result == "stale":
                check(type(expected) is bool, name, "stale must be a bool")
            else:
                check(expected is None or type(expected) is int, name, "fresh_for must be an integer or null")
            reference = readers[result](value)
            check(expected == reference, name, f"{result} {expected!r} != reference {reference!r}")
    return len(names)


def self_test(document: dict) -> None:
    """Each poisoned copy must trip the guard it names, and each wrong reader must miss a row."""

    def row(doc: dict, name: str) -> dict:
        return next(r for table in TABLES for r in doc[table] if r["name"] == name)

    def set_field(name: str, field: str, value: object) -> Callable[[dict], None]:
        return lambda doc: row(doc, name).__setitem__(field, value)

    # label: (poison, substring the tripped guard's message must contain)
    mutations = {
        "stale drift": (set_field("freshness_capitalised", "stale", False), "!= reference"),
        "fresh_for drift": (set_field("fresh_for_wraps_32_bit", "fresh_for", FRESH_FOR_MAX), "!= reference"),
        # Absent means no server-side bound, which is not a bound of 0.
        "absent Fresh-For as 0": (set_field("fresh_for_absent", "fresh_for", 0), "!= reference"),
        # True == 1 in Python, so the equality test alone would pass it.
        "bool fresh_for": (set_field("fresh_for_one", "fresh_for", True), "integer or null"),
        "non-bool stale": (set_field("freshness_stale", "stale", 1), "must be a bool"),
        "leading space": (set_field("fresh_for_one", "value", " 1"), "leading or trailing"),
        "trailing tab": (set_field("freshness_fresh", "value", "fresh\t"), "leading or trailing"),
        "control character": (set_field("freshness_fresh", "value", "fre\rsh"), "control character"),
        "character wider than a byte": (set_field("fresh_for_arabic_indic_one", "value", "\u0661"), "above U+00FF"),
        "value not a string": (set_field("fresh_for_one", "value", 1), "string or null"),
        "nameless row": (set_field("fresh_for_one", "name", None), "no string name"),
        "empty note": (set_field("fresh_for_zero", "note", " "), "note must be"),
        "duplicate name": (
            lambda doc: doc["fresh_for_vectors"].append(copy.deepcopy(row(doc, "fresh_for_zero"))),
            "duplicate name",
        ),
        "unknown field": (set_field("fresh_for_zero", "reject", True), "fields"),
        "empty table": (lambda doc: doc.__setitem__("freshness_vectors", []), "non-empty list"),
        "unknown table": (lambda doc: doc.__setitem__("extra_vectors", []), "unknown table"),
    }
    for label, (mutate, expected) in mutations.items():
        poisoned = copy.deepcopy(document)
        mutate(poisoned)
        try:
            verify(poisoned)
        except ValueError as exc:
            check(expected in str(exc), "self-test", f"mutation {label!r} tripped the wrong guard: {exc}")
            continue
        raise ValueError(f"self-test: mutation {label!r} was not rejected")

    def converted(text: str) -> int:
        """What a reader built on int() and a range check returns: none of the grammar."""
        try:
            seconds = int(text)
        except ValueError:
            return 0
        return seconds if 0 <= seconds <= FRESH_FOR_MAX else 0

    def digits_by_isdigit(text: str) -> int:
        """The grammar with str.isdigit() for "ASCII digits". int() refuses some digits isdigit() accepts (`²`), so it can raise."""
        if not 1 <= len(text) <= FRESH_FOR_MAX_DIGITS or not text.isdigit():
            return 0
        seconds = int(text)
        return seconds if seconds <= FRESH_FOR_MAX else 0

    def present(reader: Callable[[str], object]) -> Reader:
        return lambda v: None if v is None else reader(v)

    # Plausible wrong readers, each a mistake a row's note names: (result field, reader).
    wrong_readers: dict[str, tuple[str, Reader]] = {
        "case-insensitive label": ("stale", lambda v: v is not None and v.lower() != "fresh"),
        "only `stale` is stale": ("stale", lambda v: v == "stale"),
        "empty label read as absent": ("stale", lambda v: bool(v) and v != "fresh"),
        "absent label read as stale": ("stale", lambda v: v != "fresh"),
        "first list item": ("stale", lambda v: v is not None and v.split(",")[0].strip() != "fresh"),
        "label prefix match": ("stale", lambda v: v is not None and not v.startswith("fresh")),
        "absent Fresh-For read as 0": ("fresh_for", lambda v: 0 if v is None else fresh_for(v)),
        "empty Fresh-For read as absent": ("fresh_for", lambda v: None if not v else fresh_for(v)),
        "leading zeros refused": ("fresh_for", present(lambda v: 0 if len(v) > 1 and v.startswith("0") else fresh_for(v))),
        "cap excluded": ("fresh_for", present(lambda v: 0 if fresh_for(v) == FRESH_FOR_MAX else fresh_for(v))),
        "no range check": ("fresh_for", present(lambda v: int(v) if re.fullmatch(r"[0-9]{1,7}", v) else 0)),
        "sign accepted": ("fresh_for", present(lambda v: int(v) if re.fullmatch(r"[+-]?[0-9]{1,7}", v) else 0)),
        "int()": ("fresh_for", present(converted)),
        "leading digits only (parseInt, radix 10)": (
            "fresh_for",
            present(lambda v: converted(m[0]) if (m := re.match(r"[+-]?[0-9]+", v)) else 0),
        ),
        "white space dropped": ("fresh_for", present(lambda v: fresh_for(v.replace(" ", "")))),
        "no length check": ("fresh_for", present(lambda v: converted(v) if v.isascii() and v.isdigit() else 0)),
        "no length check, 32-bit wrap": (
            "fresh_for",
            present(lambda v: converted(str(int(v) % 2**32)) if v.isascii() and v.isdigit() else 0),
        ),
        "str.isdigit() for ASCII digits": ("fresh_for", present(digits_by_isdigit)),
        "UTF-8 decode, then str.isdigit()": (
            "fresh_for",
            present(lambda v: digits_by_isdigit(v.encode("latin-1").decode("utf-8", "replace"))),
        ),
    }
    for label, (result, reader) in wrong_readers.items():

        def total(v: str | None, reader: Reader = reader) -> object:
            """A reader that raises (int() on `²`, say) disagrees with every row, so it must not pass."""
            try:
                return reader(v)
            except ValueError as exc:
                return f"raised {exc!r}"

        try:
            verify(document, {**READERS, result: total})
        except ValueError as exc:
            check("!= reference" in str(exc), "self-test", f"wrong reader {label!r} tripped the wrong guard: {exc}")
            continue
        raise ValueError(f"self-test: wrong reader {label!r} agrees with every row; add a row it misreads")


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

    logging.info("validated %d freshness-header vectors (self-test passed)", count)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()

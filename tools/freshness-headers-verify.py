#!/usr/bin/env python3
"""Validate test-vectors/freshness-headers.json with Python stdlib.

spec/saas-api.md § GET /v1/cache/{key} (response headers) and § Remaining Freshness. Each row
is one header's field value on a GET 200, or null when the header is absent. A
`freshness_vectors` row's `stale` must be what X-CacheKit-Freshness means (fresh when absent or
exactly `fresh`, stale otherwise), and a `fresh_for_vectors` row's `fresh_for` what
X-CacheKit-Fresh-For means (1-7 ASCII digits at most 2,592,000, otherwise 0; null when absent).
Every value must be a field value under RFC 9110 §5.5: one byte per character, no leading or
trailing space or tab, no other control character. A mutation self-test runs first, as in
tools/path-encoding-verify.py: each poisoned copy of the fixture must trip the guard it names,
and each mistake a row's note names, written out as a wrong reader, must misread that row.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import sys
from collections.abc import Callable, Iterator
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
    """Why `value` is no field value under RFC 9110 §5.5, or None."""
    if any(ord(c) > 0xFF for c in value):
        return "a character above U+00FF is not one byte"
    if any(c != "\t" and (c < " " or c == "\x7f") for c in value):
        return "a control character other than tab"
    if value[:1] in (" ", "\t") or value[-1:] in (" ", "\t"):
        return "leading or trailing white space, which RFC 9110 excludes from a field value"
    return None


def tables(node: object, path: str = "") -> Iterator[str]:
    """The path of every list under a key ending in "vectors", at any depth, as tools/conformance.py finds them."""
    if isinstance(node, dict):
        for key, value in node.items():
            where = f"{path}.{key}" if path else key
            if key.endswith("vectors") and isinstance(value, list):
                yield where
            else:
                yield from tables(value, where)


def verify(document: dict) -> int:
    unknown = sorted(set(tables(document)) - set(TABLES))
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
            reference = READERS[result](value)
            check(expected == reference, name, f"{result} {expected!r} != reference {reference!r}")
    return len(names)


def converted(text: str) -> int:
    """What a reader built on int() and a range check returns: none of the grammar."""
    try:
        seconds = int(text)
    except ValueError:
        return 0
    return seconds if 0 <= seconds <= FRESH_FOR_MAX else 0


def as_float(text: str) -> int:
    """What a reader built on float() returns, as JavaScript's Number() reads a decimal point or an exponent."""
    try:
        number = float(text)
    except ValueError:
        return 0
    return int(number) if number.is_integer() and 0 <= number <= FRESH_FOR_MAX else 0


def digits_by_isdigit(text: str) -> int:
    """The grammar with str.isdigit() for "ASCII digits". int() refuses some digits isdigit() accepts (`²`), so it can raise."""
    if not 1 <= len(text) <= FRESH_FOR_MAX_DIGITS or not text.isdigit():
        return 0
    seconds = int(text)
    return seconds if seconds <= FRESH_FOR_MAX else 0


def converted_first(text: str) -> int:
    """ASCII digits, converted with int() before the length and range checks: CPython raises past 4,300 digits."""
    if not re.fullmatch("[0-9]+", text):
        return 0
    seconds = int(text)
    return seconds if len(text) <= FRESH_FOR_MAX_DIGITS and seconds <= FRESH_FOR_MAX else 0


def known_labels_only(value: str | None) -> bool:
    """A reader that knows only `fresh`, as one written before stale-while-revalidate would."""
    if value is None or value == "fresh":
        return False
    raise ValueError(f"unexpected X-CacheKit-Freshness {value!r}")


def present(reader: Callable[[str], object]) -> Reader:
    return lambda v: None if v is None else reader(v)


def digits(reader: Callable[[str], object]) -> Reader:
    """`reader` behind an ASCII-digit check alone: no length check."""
    return present(lambda v: reader(v) if re.fullmatch("[0-9]+", v) else 0)


# Each mistake a row's note names: (result field, wrong reader, the rows that must show it). A reader
# returns its wrong answer; only those in RAISING make their mistake by raising, as int() does on `²`.
WRONG_READERS: dict[str, tuple[str, Reader, tuple[str, ...]]] = {
    "case-insensitive label": ("stale", lambda v: v is not None and v.lower() != "fresh", ("freshness_capitalised",)),
    "only `stale` is stale": ("stale", lambda v: v == "stale", ("freshness_uppercase_stale", "freshness_empty")),
    "empty label read as absent": ("stale", lambda v: bool(v) and v != "fresh", ("freshness_empty",)),
    "absent label read as stale": ("stale", lambda v: v != "fresh", ("freshness_absent",)),
    "only `fresh` known, so `stale` raises": ("stale", known_labels_only, ("freshness_stale",)),
    "first list item": (
        "stale",
        lambda v: v is not None and v.split(",")[0].strip() != "fresh",
        ("freshness_list_fresh_first",),
    ),
    "label prefix match": ("stale", lambda v: v is not None and not v.startswith("fresh"), ("freshness_list_fresh_first",)),
    "`fresh` anywhere": ("stale", lambda v: v is not None and "fresh" not in v, ("freshness_list_fresh_first",)),
    "last list item": (
        "stale",
        lambda v: v is not None and v.split(",")[-1].strip() != "fresh",
        ("freshness_list_fresh_last",),
    ),
    "absent Fresh-For read as 0": ("fresh_for", lambda v: 0 if v is None else fresh_for(v), ("fresh_for_absent",)),
    "0 read as no value (`or None`)": ("fresh_for", present(lambda v: fresh_for(v) or None), ("fresh_for_zero",)),
    "empty Fresh-For read as absent": ("fresh_for", lambda v: None if not v else fresh_for(v), ("fresh_for_empty",)),
    "leading zeros refused": (
        "fresh_for",
        present(lambda v: 0 if len(v) > 1 and v.startswith("0") else fresh_for(v)),
        ("fresh_for_seven_digits",),
    ),
    "cap excluded": (
        "fresh_for",
        present(lambda v: 0 if fresh_for(v) == FRESH_FOR_MAX else fresh_for(v)),
        ("fresh_for_cap",),
    ),
    "no range check": ("fresh_for", present(lambda v: int(v) if re.fullmatch("[0-9]{1,7}", v) else 0), ("fresh_for_over_cap",)),
    "sign accepted": (
        "fresh_for",
        present(lambda v: int(v) if re.fullmatch("[+-]?[0-9]{1,7}", v) else 0),
        ("fresh_for_negative", "fresh_for_plus_sign"),
    ),
    "int()": ("fresh_for", present(converted), ("fresh_for_plus_sign", "fresh_for_digit_separator")),
    "float(), as Number() reads a decimal point or an exponent": (
        "fresh_for",
        present(as_float),
        ("fresh_for_decimal", "fresh_for_exponent"),
    ),
    "hex prefix read as hex (Number(), parseInt without a radix)": (
        "fresh_for",
        present(lambda v: converted(str(int(v, 16))) if re.fullmatch("0[xX][0-9a-fA-F]+", v) else fresh_for(v)),
        ("fresh_for_hex",),
    ),
    "leading digits only (parseInt, radix 10)": (
        "fresh_for",
        present(lambda v: converted(m[0]) if (m := re.match("[+-]?[0-9]+", v)) else 0),
        ("fresh_for_decimal", "fresh_for_exponent", "fresh_for_digit_separator", "fresh_for_inner_space", "fresh_for_list"),
    ),
    "white space dropped": ("fresh_for", present(lambda v: fresh_for(v.replace(" ", ""))), ("fresh_for_inner_space",)),
    "white space trimmed (str.strip(), trim())": (
        "fresh_for",
        present(lambda v: fresh_for(v.strip())),
        ("fresh_for_nbsp_prefix",),
    ),
    "no length check": ("fresh_for", digits(converted), ("fresh_for_eight_digits",)),
    "no length check, 32-bit wrap": ("fresh_for", digits(lambda v: converted(str(int(v) % 2**32))), ("fresh_for_wraps_32_bit",)),
    "no length check, 64-bit wrap": ("fresh_for", digits(lambda v: converted(str(int(v) % 2**64))), ("fresh_for_over_64_bits",)),
    "64-bit overflow read as no value": (
        "fresh_for",
        digits(lambda v: None if int(v) >= 2**64 else fresh_for(v)),
        ("fresh_for_over_64_bits",),
    ),
    "int() before the length check": ("fresh_for", present(converted_first), ("fresh_for_4301_digits",)),
    "str.isdigit() for ASCII digits": ("fresh_for", present(digits_by_isdigit), ("fresh_for_superscript_two",)),
    "UTF-8 decode, then str.isdigit()": (
        "fresh_for",
        present(lambda v: digits_by_isdigit(v.encode("latin-1").decode("utf-8", "replace"))),
        ("fresh_for_arabic_indic_one",),
    ),
}
RAISING = {"only `fresh` known, so `stale` raises", "int() before the length check", "str.isdigit() for ASCII digits"}


def self_test(document: dict) -> None:
    """Each poisoned copy must trip the guard it names, and each wrong reader must misread the rows it names."""

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
        "nested table": (lambda doc: doc.__setitem__("legacy", {"old_vectors": []}), "unknown table"),
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

    rows = {r["name"]: r for table in TABLES for r in document[table]}
    for label, (result, reader, targets) in WRONG_READERS.items():
        for target in targets:
            check(target in rows, "self-test", f"wrong reader {label!r} names {target}, which the fixture lacks")
            try:
                read = reader(rows[target]["value"])
            except ValueError as exc:
                # Any other reader that raises is broken, and counting its raise as a misread would hide that.
                check(label in RAISING, "self-test", f"wrong reader {label!r} raised on {target}: {exc}")
                continue
            check(
                read != rows[target][result],
                "self-test",
                f"wrong reader {label!r} reads {target} correctly, so the row no longer shows the mistake its note names",
            )


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

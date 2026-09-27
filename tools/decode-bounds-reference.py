#!/usr/bin/env python3
"""Reference tool for test-vectors/decode-bounds.json (untrusted-decode bounds).

Normative rules and the measurements behind them: spec/interop-mode.md → Decode
bounds. This file pins the bytes every SDK's decoder MUST reject and MUST accept
(so the bound cannot over-tighten).

Usage:
    verify    (default) stdlib-only. Checks the file equals the recipes below,
              derives each vector's depth and declared slots with a header-only
              structural walk (never trusting the hand-entered tags), checks the
              reject reasons against them, and checks the set still holds a vector
              each named near-miss structural guard would pass. When `msgpack`
              (msgpack-python) is importable, additionally checks the real decoder
              rejects every reject vector and accepts every accept vector.
              A verdict says nothing about WHEN a reader rejected: a stock decoder
              rejects every reject vector by its own limits or at end of input,
              possibly after pre-allocating. Whether an SDK's structural guard
              rejects each vector before materialising it is asserted in that SDK
              (spec: Decode bounds), not here. `--require-extras` turns a missing
              msgpack into a failure (CI's optional-deps leg).
    generate  Rewrites the vector file from the recipes below.
"""

from __future__ import annotations

from collections.abc import Callable
import json
import logging
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "decode-bounds.json"

MAX_DEPTH_CEILING = 1024
MIN_DEPTH_FLOOR = 32


def u16(n: int) -> str:
    return n.to_bytes(2, "big").hex()


def u32(n: int) -> str:
    return n.to_bytes(4, "big").hex()


def recipe(name: str, description: str, repeat_hex: str, count: int, suffix_hex: str = "", *,
           depth: int, slots: int, reasons: list[str]) -> dict:
    data = bytes.fromhex(repeat_hex) * count + bytes.fromhex(suffix_hex)
    return {
        "name": name,
        "description": description,
        "construction": {"repeat_hex": repeat_hex, "count": count, "suffix_hex": suffix_hex},
        "input_hex": data.hex(),
        "input_len": len(data),
        "nesting_depth": depth,
        "declared_slots": slots,
        "reject_reasons": reasons,
    }


def build() -> dict:
    reject = [
        recipe("nested_array16_depth_2048",
               "2048 nested array16 headers each claiming 2000 elements, 0 backing bytes. The measured "
               "amplifier shape: an eager decoder pre-allocates 2000 slots per level before hitting EOF. "
               "2000 < input_len, so a per-collection cap of len(input) does NOT reject it.",
               "dc" + u16(2000), 2048, depth=2048, slots=2048 * 2000, reasons=["depth", "overclaim"]),
        recipe("nested_array32_input_len_depth_1100",
               "1100 nested array32 headers each claiming exactly len(input)=5500 elements. Defeats a "
               "per-collection cap of len(input): peak pre-allocation is depth x len(input) x slot size.",
               "dd" + u32(5500), 1100, depth=1100, slots=1100 * 5500, reasons=["depth", "overclaim"]),
        recipe("nested_map16_depth_2048",
               "Map twin of nested_array16_depth_2048 (map pre-allocation is typically larger per slot).",
               "de" + u16(2000), 2048, depth=2048, slots=2048 * 2 * 2000, reasons=["depth", "overclaim"]),
        recipe("nested_array16_each_header_fits_sum_overclaims",
               "30 nested array16 headers each claiming 2000 elements, then 2000 nils. Every header fits the bytes "
               "that follow it and the nesting is below the depth floor, so of the structural rules only the sum "
               "over the whole document (60 000 > input_len - 1) catches it. A reader with per-header checks alone "
               "pre-allocates 30 x 2000 slots and then rejects at end of input, so the verdict cannot tell the two "
               "apart: only an SDK test asserting its guard's rejection can.",
               "dc" + u16(2000), 30, "c0" * 2000, depth=30, slots=30 * 2000, reasons=["overclaim"]),
        recipe("nested_fixarray_depth_1025_complete",
               "Structurally COMPLETE document nested 1025 deep, one level past the ceiling: only the depth bound "
               "rejects it, and a reader whose bound exceeds 1024 accepts it.",
               "91", MAX_DEPTH_CEILING + 1, "c0", depth=MAX_DEPTH_CEILING + 1, slots=MAX_DEPTH_CEILING + 1,
               reasons=["depth"]),
        recipe("nested_fixmap_depth_1025_complete",
               "Map twin of nested_fixarray_depth_1025_complete ({\"\": {\"\": ... null}}): a guard that counts "
               "depth on array headers only accepts it.",
               "81a0", MAX_DEPTH_CEILING + 1, "c0", depth=MAX_DEPTH_CEILING + 1, slots=2 * (MAX_DEPTH_CEILING + 1),
               reasons=["depth"]),
        recipe("array16_overclaim_shallow",
               "One array16 header claiming 10 000 elements with 3 backing bytes.",
               "dc" + u16(10000), 1, "010203", depth=1, slots=10000, reasons=["overclaim"]),
        recipe("array32_max_claim_alone",
               "A lone 5-byte array32 header claiming 2^32-1 elements.",
               "dd" + u32(0xFFFFFFFF), 1, depth=1, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("map32_max_claim_alone",
               "A lone 5-byte map32 header claiming 2^32-1 pairs (2^33-2 slots: each pair is a key and a value).",
               "df" + u32(0xFFFFFFFF), 1, depth=1, slots=2 * 0xFFFFFFFF, reasons=["overclaim"]),
        recipe("array32_sum_wraps_u32",
               "array32 claiming 2^32-1 elements whose first element is an array32 claiming 1: the declared "
               "slots sum to exactly 2^32, which a 32-bit accumulator checked only once the sum is complete wraps "
               "to 0 and passes. One checked after every add rejects it at the first header; see "
               "array32_sum_wraps_u32_small_first.",
               "dd" + u32(0xFFFFFFFF), 1, "dd" + u32(1), depth=2, slots=0xFFFFFFFF + 1, reasons=["overclaim"]),
        recipe("array32_sum_wraps_u32_small_first",
               "fixarray claiming 1 element that is an array32 claiming 2^32-1: the running sum is 1, then exactly "
               "2^32, so a 32-bit accumulator checked after every add sees 1 and then 0 and passes both checks.",
               "91", 1, "dd" + u32(0xFFFFFFFF), depth=2, slots=1 + 0xFFFFFFFF, reasons=["overclaim"]),
        recipe("map32_half_claim_wraps_u32_mul",
               "A lone map32 header claiming 2^31 pairs: the per-header term 2 x pairs is exactly 2^32, which a "
               "32-bit multiply wraps to 0 before it is ever added to the budget.",
               "df" + u32(0x80000000), 1, depth=1, slots=2 * 0x80000000, reasons=["overclaim"]),
        recipe("fixmap_short_by_one",
               "fixmap claiming 1 pair with the key present and the value missing: the map twin of "
               "fixarray_short_by_one. Counting one slot per pair (instead of two) accepts it.",
               "81", 1, "c0", depth=1, slots=2, reasons=["overclaim"]),
        recipe("bin32_overclaim",
               "bin32 header claiming 2^32-1 bytes with 1 backing byte (a 6-byte document declaring a 4 GiB buffer).",
               "c6" + u32(0xFFFFFFFF), 1, "41", depth=0, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("str32_overclaim",
               "str32 twin of bin32_overclaim.",
               "db" + u32(0xFFFFFFFF), 1, "41", depth=0, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("ext32_overclaim",
               "ext32 twin of bin32_overclaim (type 5, 1 backing byte): ext lengths count as slots too.",
               "c9" + u32(0xFFFFFFFF), 1, "0541", depth=0, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("fixarray_short_by_one",
               "fixarray claiming 5 elements with 4 present: the minimal truncated document.",
               "95", 1, "c0c0c0c0", depth=1, slots=5, reasons=["overclaim"]),
    ]
    accept = [
        recipe("nested_fixarray_depth_32",
               "[[...[null]...]] nested 32 deep, complete. A conforming reader MUST accept it: the depth "
               "bound may not be tighter than 32.",
               "91", MIN_DEPTH_FLOOR, "c0", depth=MIN_DEPTH_FLOOR, slots=MIN_DEPTH_FLOOR, reasons=[]),
        recipe("nested_fixmap_depth_32",
               "Map twin of nested_fixarray_depth_32: a map counts one level, and a pair two slots.",
               "81a0", MIN_DEPTH_FLOOR, "c0", depth=MIN_DEPTH_FLOOR, slots=2 * MIN_DEPTH_FLOOR, reasons=[]),
        recipe("array16_256_backed_nils",
               "array16 header claiming 256 elements with all 256 present. A *16 header that is fully "
               "backed by input is legitimate; the allocation rule is about backing, not header width.",
               "dc" + u16(256), 1, "c0" * 256, depth=1, slots=256, reasons=[]),
    ]
    for v in accept:
        del v["reject_reasons"]
    return {
        "version": "1.1.0",
        "spec": "spec/interop-mode.md#decode-bounds",
        "generator": "tools/decode-bounds-reference.py generate (CPython stdlib)",
        "scope": "Any untrusted MessagePack decode in any SDK: interop/v1 values, the ByteStorage envelope bytes "
                 "before StorageEnvelope is materialised, auto-mode payloads after the envelope is unwrapped, "
                 "invalidation events. The bytes are plain MessagePack with no envelope.",
        "rules": {
            "depth": f"Readers MUST bound nesting depth. The bound MUST be >= {MIN_DEPTH_FLOOR} and MUST be "
                     f"<= {MAX_DEPTH_CEILING}; every reject vector tagged 'depth' nests deeper than "
                     f"{MAX_DEPTH_CEILING}.",
            "overclaim": "Readers MUST NOT pre-allocate beyond what the input can back (each element or byte needs "
                         ">= 1 input byte): declared slots summed over the whole document MUST NOT exceed "
                         "input_len - 1, checked before anything is materialised. Checking each header against the "
                         "remaining input does not satisfy this. Readers MUST reject a structurally incomplete "
                         "document. Every reject vector tagged 'overclaim' has "
                         "declared_slots > input_len - 1 (the root header is the only byte that is not an element). "
                         "A map pair counts as two slots (key + value). Every per-header term and the running sum "
                         "MUST be computed in >= 64 bits or with checked/saturating arithmetic; an overflow is "
                         "itself a rejection.",
            "failure_mode": "Rejection MUST surface as a catchable decode error that the SDK read path turns "
                            "into a cache miss (fail-closed), never an uncaught crash or an OOM abort.",
        },
        "field_notes": {
            "construction": "input = bytes.fromhex(repeat_hex) * count + bytes.fromhex(suffix_hex)",
            "nesting_depth": "collection headers along the deepest spine; a map counts one level, like an array "
                             "(str/bin/ext and scalars count as 0)",
            "declared_slots": "sum of every header's declared element/byte count (collections, str, bin, ext; fixext "
                              "declares none); a map pair counts as two slots (key + value); a nested header counts "
                              "as one element of its parent",
            "reject_reasons": "which rule(s) the vector violates; a maintainer note, not a normative message",
        },
        "reject_vectors": reject,
        "accept_vectors": accept,
    }


# type byte -> (kind, bytes in its length field or fixed payload); fix* types are handled in walk().
_WIDE = {
    0xC4: ("bytes", 1), 0xC5: ("bytes", 2), 0xC6: ("bytes", 4),
    0xD9: ("bytes", 1), 0xDA: ("bytes", 2), 0xDB: ("bytes", 4),
    0xC7: ("ext", 1), 0xC8: ("ext", 2), 0xC9: ("ext", 4),
    0xDC: ("array", 2), 0xDD: ("array", 4), 0xDE: ("map", 2), 0xDF: ("map", 4),
    0xC0: ("fixed", 0), 0xC2: ("fixed", 0), 0xC3: ("fixed", 0),
    0xCA: ("fixed", 4), 0xCB: ("fixed", 8),
    0xCC: ("fixed", 1), 0xCD: ("fixed", 2), 0xCE: ("fixed", 4), 0xCF: ("fixed", 8),
    0xD0: ("fixed", 1), 0xD1: ("fixed", 2), 0xD2: ("fixed", 4), 0xD3: ("fixed", 8),
    0xD4: ("fixed", 2), 0xD5: ("fixed", 3), 0xD6: ("fixed", 5), 0xD7: ("fixed", 9), 0xD8: ("fixed", 17),
}


def walk(data: bytes) -> dict:
    """Header-only structural walk, the reference for the `nesting_depth` and `declared_slots` tags.

    Reads headers in document order and skips str/bin/ext payloads; stops at the end of the
    root item or of the input. `complete` is framing only (one root item, nothing owed, no
    trailing bytes): it does not check str UTF-8 or ext contents, so `a1ff` is complete.

    Also reports what four near-miss structural guards conclude, for the coverage checks:
    `per_header_fits` (every claim <= the bytes after its header), `u32_add_fits` (a 32-bit
    running sum checked after every add; a term past 2^32 - 1 does not fit it), `u32_mul_fits`
    (the map term 2 x pairs computed in 32 bits, summed exactly) and `array_depth` (depth
    counted on array headers only).
    """
    budget = len(data) - 1
    pos = depth = array_depth = arrays_open = slots = sum_add32 = sum_mul = 0
    per_header_fits = u32_add_fits = u32_mul_fits = True
    complete = False
    owed: list[list[int]] = []  # [children still owed, 1 if array] per open collection
    while pos < len(data):
        t = data[pos]
        pos += 1
        if t <= 0x7F or t >= 0xE0:
            kind, width, n = "fixed", 0, 0
        elif t <= 0x8F:
            kind, width, n = "map", 0, t & 0x0F
        elif t <= 0x9F:
            kind, width, n = "array", 0, t & 0x0F
        elif t <= 0xBF:
            kind, width, n = "bytes", 0, t & 0x1F
        elif t in _WIDE:
            kind, width = _WIDE[t]
            n = 0
        else:
            raise ValueError(f"walk: type byte {t:#04x} is never used")  # noqa: TRY003
        if kind != "fixed" and width:
            if pos + width > len(data):
                break
            n = int.from_bytes(data[pos:pos + width], "big")
            pos += width
        if kind == "fixed":
            pos += width
        else:
            claim = 2 * n if kind == "map" else n
            slots += claim
            per_header_fits &= claim <= len(data) - pos
            if claim < 2**32:
                sum_add32 = (sum_add32 + claim) % 2**32
                u32_add_fits &= sum_add32 <= budget
            else:
                u32_add_fits = False
            sum_mul += claim % 2**32
            u32_mul_fits &= sum_mul <= budget
            if kind in ("array", "map"):
                is_array = int(kind == "array")
                depth = max(depth, len(owed) + 1)
                array_depth = max(array_depth, arrays_open + is_array)
                if claim:
                    owed.append([claim, is_array])
                    arrays_open += is_array
                    continue
            else:
                pos += n + (kind == "ext")  # payload (+ the ext type byte)
        if pos > len(data):
            break
        while owed:  # one item completed: settle every collection it finishes
            owed[-1][0] -= 1
            if owed[-1][0]:
                break
            arrays_open -= owed.pop()[1]
        if not owed:
            complete = pos == len(data)
            break
    return {"nesting_depth": depth, "declared_slots": slots, "complete": complete, "array_depth": array_depth,
            "per_header_fits": per_header_fits, "u32_add_fits": u32_add_fits, "u32_mul_fits": u32_mul_fits}


def check(condition: bool, name: str, detail: str) -> None:  # noqa: FBT001
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")  # noqa: TRY003


def verify(document: dict, *, require_extras: bool = False) -> tuple[int, str]:
    fresh = build()
    check(document == fresh, "document", "vector file differs from the recipes; run `generate`")
    # input_hex / input_len are derived from `construction` by recipe(), so the equality
    # above already proves them; the hand-entered tags are checked against the walk.
    walked = {}
    for v in document["reject_vectors"] + document["accept_vectors"]:
        w = walked[v["name"]] = walk(bytes.fromhex(v["input_hex"]))
        check(w["nesting_depth"] == v["nesting_depth"], v["name"], "nesting_depth differs from the walk")
        check(w["declared_slots"] == v["declared_slots"], v["name"], "declared_slots differs from the walk")
        reasons = v.get("reject_reasons", [])
        check(("depth" in reasons) == (v["nesting_depth"] > MAX_DEPTH_CEILING), v["name"], "depth tag mismatch")
        # Slot budget: every declared element (including a nested header) costs >= 1 input
        # byte; only the root header is not itself an element. So sum(declared) <= len - 1.
        check(("overclaim" in reasons) == (v["declared_slots"] > v["input_len"] - 1), v["name"], "overclaim tag mismatch")
        if not reasons:
            check(v["nesting_depth"] <= MIN_DEPTH_FLOOR, v["name"], "accept vector deeper than the floor")
            check(w["complete"], v["name"], "accept vector is not one complete document")

    # Coverage: the set holds a vector each named near-miss STRUCTURAL GUARD would pass. These are
    # guard-level facts from the walk. A decoder may still reject the same bytes later, at end of
    # input, so they bind only an SDK test that asserts its guard rejected (spec: Decode bounds).
    def some_reject(test: Callable[[dict, dict], bool]) -> bool:
        return any(test(v, walked[v["name"]]) for v in document["reject_vectors"])
    check(some_reject(lambda v, w: v["reject_reasons"] == ["overclaim"] and w["per_header_fits"]
                      and 2 <= v["nesting_depth"] < MIN_DEPTH_FLOOR),
          "coverage", "no reject vector that per-header checks pass, nested below the depth floor")
    check(some_reject(lambda v, w: v["reject_reasons"] == ["overclaim"] and w["u32_add_fits"]),
          "coverage", "no reject vector passes a 32-bit running sum checked after every add")
    check(some_reject(lambda v, w: v["reject_reasons"] == ["overclaim"] and w["u32_mul_fits"]),
          "coverage", "no reject vector passes a map term computed in 32 bits")
    check(some_reject(lambda v, w: v["reject_reasons"] == ["depth"] and w["complete"]
                      and w["array_depth"] == MAX_DEPTH_CEILING + 1),
          "coverage", "no complete array spine one level past the depth ceiling")
    check(some_reject(lambda v, w: v["reject_reasons"] == ["depth"] and w["complete"]
                      and v["nesting_depth"] == MAX_DEPTH_CEILING + 1 and w["array_depth"] <= MAX_DEPTH_CEILING),
          "coverage", "no complete map spine one level past the depth ceiling")
    # Negative controls: each near-miss model must also reject something, or the guards above are vacuous.
    for name, flag in (("array16_overclaim_shallow", "per_header_fits"), ("array32_sum_wraps_u32", "u32_add_fits"),
                       ("array32_sum_wraps_u32", "u32_mul_fits")):
        check(name in walked and not walked[name][flag], "coverage", f"{flag} passes {name}: the model is vacuous")

    total = len(document["reject_vectors"]) + len(document["accept_vectors"])
    try:
        import msgpack  # type: ignore[import-not-found]
    except ImportError:
        if require_extras:
            raise ValueError("--require-extras set but msgpack is not importable") from None  # noqa: TRY003
        return total, "stdlib only (msgpack absent)"

    for v in document["reject_vectors"]:
        data = bytes.fromhex(v["input_hex"])
        try:
            msgpack.unpackb(data)
        # unpackb surfaces every unpack failure as a ValueError (StackError, FormatError,
        # ExtraData, max_*_len; it wraps OutOfData — the streaming Unpacker does not). Anything
        # else is the failure_mode rule being violated, so it must fail the run, not count.
        except ValueError:
            continue
        except (MemoryError, RecursionError) as e:
            raise ValueError(f"{v['name']}: msgpack-python violated failure_mode ({type(e).__name__})") from e  # noqa: TRY003
        raise ValueError(f"{v['name']}: msgpack-python decoded a reject vector")  # noqa: TRY003
    for v in document["accept_vectors"]:
        try:
            msgpack.unpackb(bytes.fromhex(v["input_hex"]))
        except ValueError as e:
            raise ValueError(f"{v['name']}: msgpack-python rejected an accept vector") from e  # noqa: TRY003
    return total, f"msgpack-python {msgpack.version} rejects/accepts as required"


def main() -> None:
    usage = f"usage: {sys.argv[0]} [verify|generate] [--require-extras]"
    args = sys.argv[1:]
    require_extras = "--require-extras" in args
    modes = [a for a in args if a != "--require-extras"]
    mode = modes[0] if modes else "verify"
    # Fail closed on anything unexpected: a typo in the flag must not silently drop the
    # extras requirement CI relies on.
    if len(modes) > 1 or mode not in ("verify", "generate"):
        sys.exit(usage)
    if mode == "generate":
        VECTORS.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
        logging.info("wrote %s", VECTORS.relative_to(ROOT))
        return
    try:
        count, leg = verify(json.loads(VECTORS.read_text(encoding="utf-8")), require_extras=require_extras)
    except ValueError as e:
        sys.exit(f"decode-bounds verify FAILED: {e}")
    logging.info("decode-bounds: %d vectors OK (%s)", count, leg)


if __name__ == "__main__":
    # stdout, matching the pre-logging behaviour and the other tools' report lines.
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    main()

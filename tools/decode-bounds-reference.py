#!/usr/bin/env python3
"""Reference tool for test-vectors/decode-bounds.json (untrusted-decode bounds).

Normative rules and the measurements behind them: spec/interop-mode.md → Decode
bounds. This file pins the bytes every SDK's decoder MUST reject (10) and MUST
accept (2, so the bound cannot over-tighten).

Usage:
    verify    (default) stdlib-only. Checks the file equals the recipes below and
              that each vector's depth/slot tags match its arithmetic. When
              `msgpack` (msgpack-python) is importable, additionally checks the
              real decoder rejects every reject vector and accepts every accept
              vector — rejection only; the allocation rule is each SDK's guard.
    generate  Rewrites the vector file from the recipes below.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "decode-bounds.json"

# Every SDK's current depth bound is <= MAX_DEPTH_CEILING (ts 100, rs 100, py
# 1024), so a reject vector nested deeper than this is rejected by all of them;
# every SDK accepts at least MIN_DEPTH_FLOOR levels.
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
               "2048 nested array16 headers each claiming 2000 elements, 0 backing bytes. The LAB-2487 "
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
        recipe("nested_fixarray_depth_2048_complete",
               "Structurally COMPLETE document ([[...[null]...]]) nested 2048 deep: every header is backed, "
               "so only the depth bound rejects it. Isolates the depth rule from the allocation rule.",
               "91", 2048, "c0", depth=2048, slots=2048, reasons=["depth"]),
        recipe("array16_overclaim_shallow",
               "One array16 header claiming 10 000 elements with 3 backing bytes.",
               "dc" + u16(10000), 1, "010203", depth=1, slots=10000, reasons=["overclaim"]),
        recipe("array32_max_claim_alone",
               "A lone 5-byte array32 header claiming 2^32-1 elements.",
               "dd" + u32(0xFFFFFFFF), 1, depth=1, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("map32_max_claim_alone",
               "A lone 5-byte map32 header claiming 2^32-1 pairs.",
               "df" + u32(0xFFFFFFFF), 1, depth=1, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("bin32_overclaim",
               "bin32 header claiming 2^32-1 bytes with 1 backing byte (a 6-byte document declaring a 4 GiB buffer).",
               "c6" + u32(0xFFFFFFFF), 1, "41", depth=0, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("str32_overclaim",
               "str32 twin of bin32_overclaim.",
               "db" + u32(0xFFFFFFFF), 1, "41", depth=0, slots=0xFFFFFFFF, reasons=["overclaim"]),
        recipe("fixarray_short_by_one",
               "fixarray claiming 5 elements with 4 present: the minimal truncated document.",
               "95", 1, "c0c0c0c0", depth=1, slots=5, reasons=["overclaim"]),
    ]
    accept = [
        recipe("nested_fixarray_depth_32",
               "[[...[null]...]] nested 32 deep, complete. A conforming reader MUST accept it: the depth "
               "bound may not be tighter than 32.",
               "91", MIN_DEPTH_FLOOR, "c0", depth=MIN_DEPTH_FLOOR, slots=MIN_DEPTH_FLOOR, reasons=[]),
        recipe("array16_256_backed_nils",
               "array16 header claiming 256 elements with all 256 present. A *16 header that is fully "
               "backed by input is legitimate; the allocation rule is about backing, not header width.",
               "dc" + u16(256), 1, "c0" * 256, depth=1, slots=256, reasons=[]),
    ]
    for v in accept:
        del v["reject_reasons"]
    return {
        "version": "1.0.0",
        "spec": "spec/interop-mode.md#decode-bounds",
        "generator": "tools/decode-bounds-reference.py generate (CPython stdlib)",
        "scope": "Any untrusted MessagePack decode in any SDK: interop/v1 values, auto-mode payloads after "
                 "the ByteStorage envelope is unwrapped, invalidation events. The bytes are plain MessagePack "
                 "with no envelope.",
        "rules": {
            "depth": f"Readers MUST bound nesting depth. The bound MUST be >= {MIN_DEPTH_FLOOR} and MUST be "
                     f"<= {MAX_DEPTH_CEILING}; every reject vector tagged 'depth' nests deeper than "
                     f"{MAX_DEPTH_CEILING}.",
            "overclaim": "Readers MUST NOT pre-allocate for a collection/str/bin header more than the remaining "
                         "input can back (each element or byte needs >= 1 input byte), and MUST reject a "
                         "structurally incomplete document. Every reject vector tagged 'overclaim' has "
                         "declared_slots > input_len - 1 (the root header is the only byte that is not an element).",
            "failure_mode": "Rejection MUST surface as a catchable decode error that the SDK read path turns "
                            "into a cache miss (fail-closed), never an uncaught crash or an OOM abort.",
        },
        "field_notes": {
            "construction": "input = bytes.fromhex(repeat_hex) * count + bytes.fromhex(suffix_hex)",
            "nesting_depth": "collection headers along the deepest spine (str/bin count as 0)",
            "declared_slots": "sum of every header's declared element/byte count (a nested header counts as one element of its parent)",
            "reject_reasons": "which rule(s) the vector violates; a maintainer note, not a normative message",
        },
        "reject_vectors": reject,
        "accept_vectors": accept,
    }


def check(condition: bool, name: str, detail: str) -> None:
    """Fail closed even under ``python -O`` (asserts would be stripped)."""
    if not condition:
        raise ValueError(f"{name}: {detail}")


def verify(document: dict) -> tuple[int, str]:
    fresh = build()
    check(document == fresh, "document", "vector file differs from the recipes; run `generate`")
    # input_hex / input_len are derived from `construction` by recipe(), so the equality
    # above already proves them; what still needs checking is the hand-entered tags.
    for v in document["reject_vectors"] + document["accept_vectors"]:
        reasons = v.get("reject_reasons", [])
        check(("depth" in reasons) == (v["nesting_depth"] > MAX_DEPTH_CEILING), v["name"], "depth tag mismatch")
        # Slot budget: every declared element (including a nested header) costs >= 1 input
        # byte; only the root header is not itself an element. So sum(declared) <= len - 1.
        check(("overclaim" in reasons) == (v["declared_slots"] > v["input_len"] - 1), v["name"], "overclaim tag mismatch")
        if not reasons:
            check(v["nesting_depth"] <= MIN_DEPTH_FLOOR, v["name"], "accept vector deeper than the floor")

    try:
        import msgpack  # type: ignore[import-not-found]
    except ImportError:
        return len(document["reject_vectors"]) + len(document["accept_vectors"]), "stdlib only (msgpack absent)"

    for v in document["reject_vectors"]:
        data = bytes.fromhex(v["input_hex"])
        try:
            msgpack.unpackb(data)
        except Exception:  # noqa: BLE001 — any decode error is a conforming rejection
            continue
        raise ValueError(f"{v['name']}: msgpack-python decoded a reject vector")
    for v in document["accept_vectors"]:
        msgpack.unpackb(bytes.fromhex(v["input_hex"]))
    return len(document["reject_vectors"]) + len(document["accept_vectors"]), f"msgpack-python {msgpack.version} rejects/accepts as required"


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if mode == "generate":
        VECTORS.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {VECTORS.relative_to(ROOT)}")
        return
    if mode != "verify":
        sys.exit(f"usage: {sys.argv[0]} [verify|generate]")
    try:
        count, leg = verify(json.loads(VECTORS.read_text(encoding="utf-8")))
    except ValueError as e:
        sys.exit(f"decode-bounds verify FAILED: {e}")
    print(f"decode-bounds: {count} vectors OK ({leg})")


if __name__ == "__main__":
    main()

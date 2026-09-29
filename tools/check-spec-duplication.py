#!/usr/bin/env python3
"""Fail if the ratio-product rule drifts between wire-format.md and interop-v2.md.

The >=64-bit ratio-product rule is stated in full in BOTH spec documents rather
than in one with a cross-link, because a third-party implementer reads one
document standalone and a bound stated only elsewhere is a bound they can miss.
That is a deliberate duplication, and it is exactly the shape of the bug LAB-2594
closed: the two documents already carried divergent normative text for this bound
once (interop-v2 bound the integer width, wire-format said nothing), so an
implementer working from wire-format alone could legally compute the product in
32-bit pointer-width arithmetic. Hand-maintained duplicate prose re-arms that bug
silently -- nothing else in this repo reads spec prose for agreement.

So the duplication is guarded instead of trusted. Two blocks are shared: the
normative prose, and the ratio line of each document's pseudocode -- the line an
implementer actually copies, and the one the prose makes claims about. Each copy
is delimited by a sentinel pair on lines of their own, in whatever comment syntax
the context needs (an HTML comment in prose, `//` inside a pseudocode fence).
This compares the copies modulo each document's operand name (`compressed_size`
in wire-format, `payload.length` in interop-v2) and per-line indentation, which
are the only differences the copies are permitted to have.

**Scope, and what this does NOT catch.** It proves the two blocks say the same
thing. It cannot prove either one is *correct*, and it does not police any other
shared text in the repo -- extending it means adding a sentinel pair and a row to
BLOCKS, not writing a second tool.

Fails closed: a missing sentinel, an unterminated block, an empty block, or a
BLOCKS row with fewer than two members is an error, not a pass. A guard that silently checks nothing is worse than no guard.
Uses explicit failures rather than `assert`, so it cannot be defanged by `-O`.

Usage: python3 tools/check-spec-duplication.py [repo-root]   (exit 1 on drift)
"""

from __future__ import annotations

import difflib
import re
import sys
from pathlib import Path

# (spec path, operand name normalised away)
RATIO_MEMBERS = [
    ("spec/wire-format.md", "compressed_size"),
    ("spec/interop-v2.md", "payload.length"),
]
# block-id -> members; every member holds one copy of the block
BLOCKS: dict[str, list[tuple[str, str]]] = {
    "ratio-product-rule": RATIO_MEMBERS,
    "ratio-product-pseudocode": RATIO_MEMBERS,
}
PLACEHOLDER = "<OPERAND>"
SENTINEL = re.compile(r"\b(BEGIN|END) shared-block: (\S+)")


def extract(text: str, block_id: str) -> str:
    """Return the block body, or raise ValueError naming the exact defect."""
    lines = text.splitlines()
    tags = [m.groups() if (m := SENTINEL.search(line)) else None for line in lines]
    begins = [i for i, tag in enumerate(tags) if tag == ("BEGIN", block_id)]
    ends = [i for i, tag in enumerate(tags) if tag == ("END", block_id)]
    if len(begins) != 1:
        raise ValueError(f"expected exactly 1 BEGIN sentinel, found {len(begins)}")
    if len(ends) != 1:
        raise ValueError(f"expected exactly 1 END sentinel, found {len(ends)}")
    if ends[0] < begins[0]:
        raise ValueError("END sentinel precedes BEGIN sentinel")
    body = "\n".join(line.strip() for line in lines[begins[0] + 1 : ends[0]]).strip()
    if not body:
        raise ValueError("block is empty")
    return body


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    failures: list[str] = []

    for block_id, members in BLOCKS.items():
        if len(members) < 2:
            failures.append(f"BLOCKS['{block_id}'] has {len(members)} member(s) — nothing to compare")
            continue
        bodies: list[tuple[str, str]] = []
        for rel, operand in members:
            path = root / rel
            try:
                body = extract(path.read_text(encoding="utf-8"), block_id)
            except OSError as exc:
                failures.append(f"{rel}: cannot read ({exc})")
                continue
            except ValueError as exc:
                failures.append(f"{rel}: shared-block '{block_id}' — {exc}")
                continue
            if operand not in body:
                failures.append(
                    f"{rel}: shared-block '{block_id}' never mentions its operand "
                    f"'{operand}' — the normalisation cannot be trusted"
                )
                continue
            bodies.append((rel, body.replace(operand, PLACEHOLDER)))

        if len(bodies) != len(members):
            continue  # already reported; a partial comparison would be misleading

        (ref_path, ref_body), *rest = bodies
        for rel, body in rest:
            if body == ref_body:
                continue
            diff = "\n".join(
                difflib.unified_diff(
                    ref_body.splitlines(), body.splitlines(),
                    fromfile=ref_path, tofile=rel, lineterm="",
                )
            )
            failures.append(
                f"shared-block '{block_id}' differs between {ref_path} and {rel} "
                f"(after normalising operand names):\n{diff}"
            )

    if failures:
        print(
            "check-spec-duplication: the ratio-product rule has drifted between the\n"
            "spec documents. Both copies are normative and MUST agree — see the\n"
            "rationale at the top of this tool.\n",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(
        f"check-spec-duplication: OK — {len(BLOCKS)} shared block(s), "
        "every copy identical modulo its operand name"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

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

So the duplication is guarded instead of trusted. Each copy is delimited by
sentinel HTML comments; this compares them modulo each document's operand name
(`compressed_size` in wire-format, `payload.length` in interop-v2), which is the
only difference the two copies are permitted to have.

**Scope, and what this does NOT catch.** It proves the two blocks say the same
thing. It cannot prove either one is *correct*, and it does not police any other
shared text in the repo -- extending it means adding a sentinel pair and a row to
BLOCKS, not writing a second tool.

Fails closed: a missing sentinel, an unterminated block, or an empty block is an
error, not a pass. A guard that silently checks nothing is worse than no guard.
Uses explicit failures rather than `assert`, so it cannot be defanged by `-O`.

Usage: python3 tools/check-spec-duplication.py [repo-root]   (exit 1 on drift)
"""

from __future__ import annotations

import sys
from pathlib import Path

# block-id -> [(spec path, operand name normalised away), ...]
BLOCKS: dict[str, list[tuple[str, str]]] = {
    "ratio-product-rule": [
        ("spec/wire-format.md", "compressed_size"),
        ("spec/interop-v2.md", "payload.length"),
    ],
}
PLACEHOLDER = "<OPERAND>"


def extract(text: str, block_id: str) -> str:
    """Return the block body, or raise ValueError naming the exact defect."""
    begin = f"<!-- BEGIN shared-block: {block_id}"
    end = f"<!-- END shared-block: {block_id} -->"
    if text.count(begin) != 1:
        raise ValueError(f"expected exactly 1 BEGIN sentinel, found {text.count(begin)}")
    if text.count(end) != 1:
        raise ValueError(f"expected exactly 1 END sentinel, found {text.count(end)}")
    start = text.index(begin)
    start = text.index("-->", start) + len("-->")
    stop = text.index(end)
    if stop < start:
        raise ValueError("END sentinel precedes BEGIN sentinel")
    body = text[start:stop].strip()
    if not body:
        raise ValueError("block is empty")
    return body


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    failures: list[str] = []
    checked = 0

    for block_id, members in BLOCKS.items():
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
        checked += 1

        (ref_path, ref_body), *rest = bodies
        for rel, body in rest:
            if body == ref_body:
                continue
            import difflib

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

    if checked != len(BLOCKS):
        print("check-spec-duplication: no block was fully compared", file=sys.stderr)
        return 1

    print(
        f"check-spec-duplication: OK — {checked} shared block(s), "
        "every copy identical modulo its operand name"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

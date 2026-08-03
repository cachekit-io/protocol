#!/usr/bin/env python3
"""Fail if the SDK Overview table states a package version as a snapshot.

Versions in the SDK Overview table answer "which release do I need?", so they must
be floors (`0.6.0+`) — a floor stays true as new releases publish, while a snapshot
is wrong the moment the next one lands and misleads silently until someone notices.

Scope is deliberately just that table. Versions elsewhere in the matrix are exact
facts about a specific published artifact (an embedded `cachekit-core-0.2.0`, a
caret-free npm pin), historical statements, or dependency requirements — all
correctly bare. Policing them would mean an allowlist that rots faster than the
thing it guards.

Rationale, and the four failures that motivated it:
decisions/matrix-version-verification.md

This catches a snapshot masquerading as fact. It cannot catch a *wrong* floor —
verifying a floor is accurate means opening the published artifact, which stays
reviewer discipline (rules 1-3 of the decision record).

Usage: python3 tools/check-version-floors.py [path]   (exit 1 on violations)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_TARGET = "sdk-feature-matrix.md"
HEADING = "## SDK Overview"

# Accept a floor (0.6.0+, 1.2.3-rc.1+), an em-dash placeholder, or empty.
FLOOR = re.compile(r"^(?:\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\+|—|-{1,2}|)$")
SEMVER = re.compile(r"\d+\.\d+\.\d+")


def overview_rows(text: str) -> list[tuple[int, list[str]]]:
    """Data rows of the SDK Overview table, as (line number, cells)."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == HEADING)
    except StopIteration:
        print(f"check-version-floors: {HEADING!r} section not found", file=sys.stderr)
        sys.exit(1)

    rows: list[tuple[int, list[str]]] = []
    for offset, line in enumerate(lines[start + 1 :], start=start + 2):
        stripped = line.strip()
        if stripped.startswith("## ") or stripped == "---":
            break
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        # Skip the header row and the |:---| separator.
        if any(set(c) <= set(":- ") and "-" in c for c in cells):
            continue
        if cells and cells[0].lower() == "sdk":
            continue
        rows.append((offset, cells))
    return rows


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET)
    if not target.is_file():
        print(f"check-version-floors: {target} not found", file=sys.stderr)
        return 1

    text = target.read_text(encoding="utf-8")
    rows = overview_rows(text)
    if not rows:
        print("check-version-floors: no SDK Overview data rows found", file=sys.stderr)
        return 1

    violations: list[tuple[int, str, str]] = []
    for lineno, cells in rows:
        if len(cells) < 3:
            continue
        sdk, version = cells[0], cells[2]
        if not FLOOR.match(version):
            reason = (
                "bare snapshot — write it as a floor"
                if SEMVER.fullmatch(version)
                else "not a recognised floor or placeholder"
            )
            violations.append((lineno, sdk, f"{version!r}: {reason}"))

    if not violations:
        print(
            f"check-version-floors: OK — all {len(rows)} SDK Overview versions are floors"
        )
        return 0

    print(
        f"check-version-floors: {len(violations)} non-floor version(s) in the "
        f"{target} SDK Overview table.\n"
        "Versions there must be floors ('0.6.0+'), not snapshots ('0.6.0'), so they\n"
        "stay true as new releases publish.\n"
        "See decisions/matrix-version-verification.md.\n",
        file=sys.stderr,
    )
    for lineno, sdk, detail in violations:
        print(f"  {target}:{lineno}: {sdk} — {detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

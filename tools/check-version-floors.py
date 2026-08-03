#!/usr/bin/env python3
"""Fail if the SDK Overview table states a package version as a snapshot.

Versions in that table answer "which release do I need?", so they must be floors
(`0.6.0+`) — a floor stays true as new releases publish, while a snapshot is wrong
the moment the next one lands and misleads silently until someone notices. That is
the one failure this guard exists for, and the only one it can see.

**Scope, and what this does NOT catch.** It checks the SDK Overview table only. It
cannot tell whether a floor is *accurate* (that means opening the published
artifact — rules 1-3 of the decision record), and it does not police versions
elsewhere in the matrix, because those are a mix it cannot safely tell apart: some
are floors too (Compliance Status, the Architecture Notes release bullets), others
are exact facts about one specific artifact (an embedded `cachekit-core-0.2.0`, a
caret-free npm pin) that appending `+` to would make false. Telling those apart
needs the claim's intent, which a regex cannot read.

So of the six matrix incidents behind this work it catches exactly one: the
`cachekit-rs` 0.5.0 snapshot that sat in this table against a published 0.6.0.
LAB-388 (a ✅ on dead code), LAB-998 (a ship-status boolean) and the two footnote
regressions are all invisible to it. Rationale and the full incident list:
decisions/matrix-version-verification.md

Fails closed: if the table cannot be located or parsed, that is an error, not a
pass — a guard that silently checks nothing is worse than no guard.

Usage: python3 tools/check-version-floors.py [path]   (exit 1 on violations)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NoReturn

DEFAULT_TARGET = "sdk-feature-matrix.md"
HEADING = "## SDK Overview"
VERSION_HEADER = "version"

# A GFM separator cell: ---, :---, ---:, :---:
SEPARATOR_CELL = re.compile(r"^:?-{3,}:?$")
# A floor: 0.6.0+, 1.2.3-rc.1+
FLOOR = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\+$")
# Placeholder for an unreleased SDK: em-dash, en-dash, or plain hyphen(s).
PLACEHOLDER = re.compile(r"^[—–-]{1,3}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+")
# Markdown emphasis and footnote markers a version cell may legitimately carry.
DECORATION = re.compile(r"[`*_\u2070\u00b9\u00b2\u00b3\u2074-\u2079]")


def fail(msg: str) -> NoReturn:
    print(f"check-version-floors: {msg}", file=sys.stderr)
    sys.exit(1)


def split_row(line: str) -> list[str]:
    """Cells of a GFM table row. Tolerates a missing leading/trailing pipe."""
    return [c.strip() for c in line.strip().strip("|").split("|")]


def overview_table(text: str) -> tuple[int, list[tuple[int, list[str]]]]:
    """(version column index, [(line number, cells)]) for the SDK Overview table."""
    lines = text.splitlines()
    try:
        start = next(i for i, raw in enumerate(lines) if raw.strip() == HEADING)
    except StopIteration:
        fail(f"{HEADING!r} section not found — cannot verify anything")

    header: list[str] | None = None
    version_idx = -1
    table_ended = False
    rows: list[tuple[int, list[str]]] = []

    for offset, line in enumerate(lines[start + 1 :], start=start + 2):
        stripped = line.strip()
        if stripped.startswith("## "):
            break
        if "|" not in stripped:
            # Blank lines and the `---` section rule before the table. Once the
            # table has started, a non-pipe line ends it — but keep scanning so a
            # SECOND table under this heading is caught rather than ignored.
            if header is not None and rows:
                table_ended = True
            continue

        if table_ended:
            fail(
                f"a second table appears under {HEADING!r} (line {offset}) — this "
                "checker verifies the first one only, so refusing to report OK on "
                "a section it cannot fully account for"
            )

        cells = split_row(stripped)

        if header is None:
            header = cells
            lowered = [c.lower() for c in cells]
            if VERSION_HEADER not in lowered:
                fail(
                    f"{HEADING!r} table header has no {VERSION_HEADER!r} column "
                    f"(saw {cells}) — refusing to guess which column holds versions"
                )
            version_idx = lowered.index(VERSION_HEADER)
            continue

        # The separator row: every cell is a GFM alignment marker.
        if cells and all(SEPARATOR_CELL.match(c) for c in cells):
            continue

        rows.append((offset, cells))

    if header is None:
        fail(f"no table found under {HEADING!r}")
    if not rows:
        fail(f"{HEADING!r} table has no data rows")
    return version_idx, rows


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET)
    if not target.is_file():
        fail(f"{target} not found")

    version_idx, rows = overview_table(target.read_text(encoding="utf-8"))

    violations: list[tuple[int, str, str]] = []
    for lineno, cells in rows:
        sdk = cells[0] if cells else "?"
        if len(cells) <= version_idx:
            violations.append(
                (lineno, sdk, f"row has {len(cells)} cells, no version column")
            )
            continue

        raw = cells[version_idx]
        value = DECORATION.sub("", raw).strip()

        if PLACEHOLDER.match(value) or FLOOR.match(value):
            continue
        if not value:
            violations.append((lineno, sdk, "version cell is empty"))
        elif SEMVER.match(value):
            violations.append(
                (lineno, sdk, f"{raw!r} is a bare snapshot — write it as a floor")
            )
        else:
            violations.append((lineno, sdk, f"{raw!r} is not a floor or placeholder"))

    if not violations:
        print(
            f"check-version-floors: OK — {len(rows)} SDK Overview rows, "
            "every version a floor or placeholder"
        )
        return 0

    print(
        f"check-version-floors: {len(violations)} non-floor version(s) in the "
        f"{target} SDK Overview table.\n"
        "Versions there must be floors ('0.6.0+'), not snapshots ('0.6.0'), so they\n"
        "stay true as new releases publish. See\n"
        "decisions/matrix-version-verification.md.\n",
        file=sys.stderr,
    )
    for lineno, sdk, detail in violations:
        print(f"  {target}:{lineno}: {sdk} — {detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

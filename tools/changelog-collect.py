#!/usr/bin/env python3
"""Collect changelog.d/ fragments into a new CHANGELOG.md version section.

Each fragment is inserted verbatim, in filename order, under `## [VERSION] - DATE`
at the insert marker; the collected fragments are then deleted. Nothing is parsed,
regrouped or reordered. That is the reason this exists instead of scriv: scriv reads
every `###` heading as a category, so it merged same-titled entries (`### SaaS API`)
and shuffled entry order across the release. These entries are curated normative
prose, so a verbatim concatenation is the only safe transform.

Fails closed: a missing or repeated marker, an existing version, no fragments, or an
empty fragment is an error, and nothing is written.

Usage: python3 tools/changelog-collect.py VERSION [--date YYYY-MM-DD] [--root PATH]
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

MARKER = "<!-- changelog-insert-here -->"
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


def collect(root: Path, version: str, date: str) -> list[Path]:
    """Write the version section; return the fragments it collected (already deleted)."""
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"version must be MAJOR.MINOR.PATCH, got {version!r}")
    changelog = root / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    if text.count(MARKER) != 1:
        raise ValueError(f"{changelog} must contain {MARKER} exactly once, found {text.count(MARKER)}")
    if re.search(rf"^## \[{re.escape(version)}\]", text, re.MULTILINE):
        raise ValueError(f"{changelog} already has a {version} section")
    fragments = sorted(p for p in (root / "changelog.d").glob("*.md") if p.name != "README.md")
    if not fragments:
        raise ValueError("no fragments in changelog.d/")
    bodies = [p.read_text(encoding="utf-8").strip() for p in fragments]
    empty = [p.name for p, body in zip(fragments, bodies) if not body]
    if empty:
        raise ValueError(f"empty fragment(s): {', '.join(empty)}")

    head, rest = text.split(MARKER)
    section = f"## [{version}] - {date}\n\n" + "\n\n".join(bodies) + "\n\n"
    changelog.write_text(f"{head}{MARKER}\n\n{section}{rest.lstrip(chr(10))}", encoding="utf-8")
    for p in fragments:
        p.unlink()
    return fragments


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version")
    ap.add_argument("--date", type=datetime.date.fromisoformat, default=datetime.datetime.now(datetime.UTC).date())
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    try:
        collected = collect(args.root, args.version, args.date.isoformat())
    except (ValueError, OSError) as e:
        print(f"changelog-collect: {e}", file=sys.stderr)
        return 1
    print(f"collected {len(collected)} fragment(s) into [{args.version}]:")
    for p in collected:
        print(f"  {p.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

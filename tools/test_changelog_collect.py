#!/usr/bin/env python3
"""Tests for changelog-collect.py.

The tool replaced scriv after scriv merged same-titled `###` entries and reordered
a release, so the properties pinned here are the ones scriv broke: every fragment
byte lands verbatim, in filename order, with duplicate headings kept apart. Each
fail-closed refusal must also leave CHANGELOG.md and the fragments untouched.

Run: python3 tools/test_changelog_collect.py     (exit 1 on any failure)
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
_spec = importlib.util.spec_from_file_location("changelog_collect", HERE / "changelog-collect.py")
assert _spec and _spec.loader
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

BASE = f"# Changelog\n\n## [Unreleased]\n\nPointer.\n\n{cc.MARKER}\n\n## [1.0.0] - 2026-03-28\n\nInitial.\n"
FAILURES: list[str] = []


def check(name: str, cond: bool) -> None:
    print(f"{'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        FAILURES.append(name)


def make(tmp: Path, changelog: str, fragments: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(dir=tmp))
    (root / "changelog.d").mkdir()
    (root / "changelog.d" / "README.md").write_text("readme\n")
    (root / "CHANGELOG.md").write_text(changelog)
    for name, body in fragments.items():
        (root / "changelog.d" / name).write_text(body)
    return root


def refuses(tmp: Path, name: str, changelog: str, fragments: dict[str, str], version: str = "1.1.0") -> None:
    root = make(tmp, changelog, fragments)
    try:
        cc.collect(root, version, "2026-10-01")
        raised = False
    except ValueError:
        raised = True
    untouched = (root / "CHANGELOG.md").read_text() == changelog and all((root / "changelog.d" / n).exists() for n in fragments)
    check(f"refuses {name}, writes nothing", raised and untouched)


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    try:
        # The scriv failure: filename order disagrees with lexical order, and a repeated
        # heading is split by another entry, so sorting, regrouping or merging all show.
        frags = {
            "20260930_lab-2.md": "### SaaS API\n\n- second\n",
            "20260929_lab-1.md": "### Wire format\n\n- first\n  continued `code`\n",
            "20261001_lab-3.md": "### Wire format\n\n- third\n",
        }
        root = make(tmp, BASE, frags)
        cc.collect(root, "1.1.0", "2026-10-01")
        out = (root / "CHANGELOG.md").read_text()
        want = (
            f"# Changelog\n\n## [Unreleased]\n\nPointer.\n\n{cc.MARKER}\n\n## [1.1.0] - 2026-10-01\n\n"
            "### Wire format\n\n- first\n  continued `code`\n\n### SaaS API\n\n- second\n\n"
            "### Wire format\n\n- third\n\n"
            "## [1.0.0] - 2026-03-28\n\nInitial.\n"
        )
        check("section is the verbatim fragments in filename order", out == want)
        left = sorted(p.name for p in (root / "changelog.d").iterdir())
        check("collected fragments deleted, README kept", left == ["README.md"])

        # A second release lands above the first.
        (root / "changelog.d" / "20261002_lab-4.md").write_text("### Later\n\n- third\n")
        cc.collect(root, "1.2.0", "2026-10-02")
        out2 = (root / "CHANGELOG.md").read_text()
        check(
            "second release sits above the first, first unchanged",
            out2.index("## [1.2.0]") < out2.index("## [1.1.0]") < out2.index("## [1.0.0]")
            and want.split(cc.MARKER)[1].lstrip("\n") in out2,
        )

        # The real repo: the first release carries the whole pre-fragment block verbatim.
        real = Path(tempfile.mkdtemp(dir=tmp))
        shutil.copy(REPO / "CHANGELOG.md", real / "CHANGELOG.md")
        shutil.copytree(REPO / "changelog.d", real / "changelog.d")
        legacy = [p.read_text().strip() for p in sorted((real / "changelog.d").glob("*.md")) if p.name != "README.md"]
        cc.collect(real, "1.1.0", "2026-10-01")
        body = (real / "CHANGELOG.md").read_text().split("## [1.1.0] - 2026-10-01\n\n", 1)[1].split("\n## [1.0.0]", 1)[0]
        check("repo: first release holds every pending fragment verbatim", body.strip() == "\n\n".join(legacy))

        refuses(tmp, "missing marker", BASE.replace(cc.MARKER, ""), {"a.md": "x\n"})
        refuses(tmp, "repeated marker", BASE + cc.MARKER + "\n", {"a.md": "x\n"})
        refuses(tmp, "existing version", BASE, {"a.md": "x\n"}, version="1.0.0")
        refuses(tmp, "malformed version", BASE, {"a.md": "x\n"}, version="v1.1")
        refuses(tmp, "no fragments", BASE, {})
        refuses(tmp, "empty fragment", BASE, {"a.md": "x\n", "b.md": " \n\n"})
    finally:
        shutil.rmtree(tmp)
    print(f"\n{len(FAILURES)} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

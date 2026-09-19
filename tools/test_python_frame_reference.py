#!/usr/bin/env python3
"""Regression test for the twin-equivalence check in python-frame-reference.py.

LAB-1203 fix-loop (Cobel G3(b) HIGH, 2026-09-19): _require_twin_equivalence()
used to `_require()` (raise ValueError) on any divergence between the
`_bin` twin and the frozen `legacy` vector. Since the legacy (array-of-ints)
wheel is gone from every installable release, `legacy` can never be
regenerated — so any LEGITIMATE future default-write-path change would
permanently deadlock `generate()`. The fix downgrades the check to a stderr
warning. This test pins that: a real divergence must be reported, but must
never raise.

Run: python3 tools/test_python_frame_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("python_frame_reference", HERE / "python-frame-reference.py")
assert spec and spec.loader
pfr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pfr)

LEGACY = {
    "name": "default_saas_write_msgpack_bytestorage",
    "value_json": {"a": 1},
    "frame_hex": "aabbccddpayload",
    "expected_payload_hex": "payload",
    "payload_envelope": {
        "compressed_data_hex": "11",
        "checksum_hex": "22",
        "original_size": 3,
        "format": "msgpack",
        "inner_msgpack_hex": "33",
    },
}

FAILURES = 0


def check(name: str, cond: bool) -> None:
    global FAILURES
    print(f"{'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        FAILURES += 1


# --- identical pair: no warning, no raise ---
twin_ok = {**LEGACY, "name": "default_saas_write_msgpack_bytestorage_bin"}
buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    pfr._require_twin_equivalence([LEGACY, twin_ok])
check("identical twin: no warning emitted", buf.getvalue() == "")

# --- diverged pair (legitimate protocol evolution OR a wheel bug): warns, does not raise ---
twin_diverged = {
    **LEGACY,
    "name": "default_saas_write_msgpack_bytestorage_bin",
    "payload_envelope": {**LEGACY["payload_envelope"], "inner_msgpack_hex": "ff"},
}
buf = io.StringIO()
raised = False
try:
    with contextlib.redirect_stderr(buf):
        pfr._require_twin_equivalence([LEGACY, twin_diverged])
except ValueError:
    raised = True
check("diverged twin: does not raise (no generator deadlock)", not raised)
check("diverged twin: warning names the diverging field", "inner_msgpack_hex" in buf.getvalue())

# --- partial fixture: unchanged no-op-with-note behavior ---
buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    pfr._require_twin_equivalence([LEGACY])
check("partial fixture: skip note, no warning text", "incomplete" in buf.getvalue())

if FAILURES:
    print(f"\n{FAILURES} failure(s)")
    sys.exit(1)
print("\nall twin-equivalence checks passed")

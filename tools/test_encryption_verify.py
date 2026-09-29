#!/usr/bin/env python3
"""Mutation tests for encryption-verify.py's keyring guards.

Same doctrine as test_wire_format_reference.py: a conformance gate is proven by
poisoning the fixture and watching it go red, not by reading it. Every case below
exited 0 on protocol#60's first revision (LAB-687 expert panel, 2026-09-02) — the
keyring block sat behind the `cryptography` guard, so the stdlib CI lane verified
nothing, and a blanked fingerprint selection printed `ok ... None`.

Stdlib cases always run. Seal cases run only when `cryptography` imports, which
is the optional-deps CI lane. The fixture is loaded once and every case mutates a
deep copy; nothing is ever written.

Run: python3 tools/test_encryption_verify.py     (exit 1 on any failure)
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import sys
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("encryption_verify", HERE / "encryption-verify.py")
if spec is None or spec.loader is None:
    sys.exit("cannot load encryption-verify.py as a module")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)

DOC = json.loads(ev.VECTORS_PATH.read_text())
HAVE_SEAL = importlib.util.find_spec("cryptography") is not None


def run(mutate: Callable[[dict], None]) -> tuple[int, str]:
    doc = copy.deepcopy(DOC)
    mutate(doc)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = ev.verify(doc, require_seal=HAVE_SEAL)
    return rc, out.getvalue()


def k1(doc: dict) -> dict:
    return next(v for v in doc["keyring"]["vectors"] if v["name"] == "encrypted_with_k1")


def k2(doc: dict) -> dict:
    return next(v for v in doc["keyring"]["vectors"] if v["name"] == "encrypted_with_k2")


def dt(doc: dict) -> dict:
    return next(v for v in doc["default_tenant"]["vectors"] if v["name"] == "default_tenant_interop")


def master_fingerprint(doc: dict, key_id: str) -> str:
    entry = next(e for e in doc["keyring"]["entries"] if e["id"] == key_id)
    return ev.key_fingerprint(bytes.fromhex(entry["master_key_hex"]))


# The sealed bytes and the AAD that binds them; swapping these between vectors leaves each vector's identity in place.
PAYLOAD_FIELDS = ("cache_key", "aad_hex", "ciphertext_hex", "plaintext_hex")


STDLIB_CASES: dict[str, Callable[[dict], None]] = {
    "keyring block deleted": lambda d: d.pop("keyring"),
    "fingerprint selection removed": lambda d: k1(d).pop("key_fingerprint_hex"),
    "fingerprint selection blanked": lambda d: k1(d).__setitem__("key_fingerprint_hex", ""),
    "fingerprint is the MASTER key's": lambda d: k1(d).__setitem__("key_fingerprint_hex", master_fingerprint(d, "k1")),
    "fingerprint selects the other entry": lambda d: k1(d).__setitem__("key_fingerprint_hex", k2(d)["key_fingerprint_hex"]),
    # Not isolating: the mapping and fingerprint guards also reject an unknown id, so this proves the input is
    # rejected, not that the KEYRING_ORDER membership check alone does it.
    "encrypted_with unknown id": lambda d: k1(d).__setitem__("encrypted_with", "kx"),
    # k1's vector becomes k2's in every field but its frozen name, so only the FROZEN_KEYRING_VECTORS mapping guard
    # can reject it. A bare encrypted_with flip is also caught by the fingerprint guard and could not detect that
    # mapping guard's removal.
    "encrypted_with contradicts frozen name": lambda d: k1(d).update({k: v for k, v in k2(d).items() if k != "name"}),
    "duplicate entry ids": lambda d: d["keyring"]["entries"].insert(0, copy.deepcopy(d["keyring"]["entries"][0])),
    "entry k1 missing": lambda d: d["keyring"]["entries"].pop(0),
    "entry fingerprint corrupted": lambda d: d["keyring"]["entries"][0].__setitem__("derived_key_fingerprint_hex", "00" * 16),
    "compressed as JSON int": lambda d: k1(d).__setitem__("compressed", 0),
    # AAD rebuilt for the bogus format so the AAD guard passes and only the FORMAT_REGISTRY check can reject it
    # (stdlib lane; in the seal lane the changed AAD also fails the decrypt).
    "format off-registry": lambda d: k1(d).update(
        format="pickle",
        aad_hex=ev.aad_v3(d["keyring"]["tenant_id"], k1(d)["cache_key"], fmt="pickle", compressed=k1(d)["compressed"]).hex(),
    ),
    "aad corrupted": lambda d: k1(d).__setitem__("aad_hex", "03" + k1(d)["aad_hex"][2:].replace("6b", "6c", 1)),
    "cache_key substituted": lambda d: k1(d).__setitem__("cache_key", "keyring:attacker:entry"),
    "frozen keyring vector renamed": lambda d: k1(d).__setitem__("name", "renamed"),
    # intent-presets.md rule 5 — the default-tenant block is ground truth for "no tenant configured".
    "default_tenant block deleted": lambda d: d.pop("default_tenant"),
    "default_tenant is not the literal": lambda d: d["default_tenant"].__setitem__("tenant_id", "cross-sdk-test"),
    "default_tenant fingerprint corrupted": lambda d: d["default_tenant"].__setitem__("derived_key_fingerprint_hex", "00" * 16),
    "default_tenant aad tenant component swapped": lambda d: dt(d).__setitem__(
        "aad_hex", ev.aad_v3("cross-sdk-test", dt(d)["cache_key"], fmt="msgpack", compressed=False).hex()
    ),
    "frozen default_tenant vector renamed": lambda d: dt(d).__setitem__("name", "renamed"),
}

SEAL_CASES: dict[str, Callable[[dict], None]] = {
    "ciphertext corrupted": lambda d: k1(d).__setitem__("ciphertext_hex", k1(d)["ciphertext_hex"][:-2] + "00"),
    "plaintext pinned wrong": lambda d: k1(d).__setitem__("plaintext_hex", "00"),
    # k1-labelled vector carrying k2's sealed bytes: decrypts, but at the wrong entry, and [k2] alone accepts it.
    "decrypts at the wrong keyring entry": lambda d: k1(d).update({f: k2(d)[f] for f in PAYLOAD_FIELDS}),
    # The current entry carrying k1's sealed bytes: encrypted_with is KEYRING_ORDER[0], so the current-only guard is
    # skipped and only the entry-index guard can reject it — the case above is caught by both guards.
    "current vector sealed under retired key": lambda d: k2(d).update({f: k1(d)[f] for f in PAYLOAD_FIELDS}),
    # Bytes sealed under tenant "cross-sdk-test" must not verify as the default-tenant vector.
    "default_tenant sealed under another tenant": lambda d: dt(d).__setitem__(
        "ciphertext_hex", next(v for v in d["vectors"] if v["name"] == "basic_bytes")["ciphertext_hex"]
    ),
}


def main() -> int:
    bad = 0
    rc, out = run(lambda _: None)
    if rc != 0:
        print(f"FAIL baseline fixture does not verify:\n{out}")
        return 1
    print(f"ok  baseline verifies ({'seal' if HAVE_SEAL else 'stdlib'} lane)")

    cases = dict(STDLIB_CASES)
    if HAVE_SEAL:
        cases.update(SEAL_CASES)
    else:
        print(f"note: {len(SEAL_CASES)} seal cases skipped — cryptography not installed")
    for name, mutate in cases.items():
        rc, out = run(mutate)
        if rc == 0:
            print(f"FAIL mutation '{name}' exited 0:\n{out}")
            bad += 1
        else:
            print(f"ok  mutation '{name}' goes red")
    if bad:
        print(f"{bad} mutation(s) NOT caught")
        return 1
    print(f"all {len(cases)} mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())

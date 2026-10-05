#!/usr/bin/env python3
"""Mutation tests for encryption-verify.py's keyring, default-tenant and master key input guards.

Same doctrine as test_wire_format_reference.py: a conformance gate is proven by
poisoning the fixture and watching it go red, not by reading it. Every case below
exited 0 on protocol#60's first revision (2026-09-02) — the
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


def mk(doc: dict, name: str) -> dict:
    return next(r for table in ev.FROZEN_MASTER_KEY_INPUT_VECTORS for r in doc["master_key_input"][table] if r["name"] == name)


def accept_row(doc: dict) -> dict:
    return mk(doc, ev.ACCEPT_ROW)


def set_key(name: str, text: str) -> Callable[[dict], None]:
    return lambda d: mk(d, name).__setitem__("master_key_hex", text)


def set_raw(name: str, raw: bytes) -> Callable[[dict], None]:
    return lambda d: mk(d, name).__setitem__("raw_key_hex", raw.hex())


def rekey(key: bytes) -> Callable[[dict], None]:
    """The accept row under another key with its fingerprint recomputed, so only a property the key lacks can fail it.

    The sealed entry is left as it was, so in the seal lane the decrypt fails as well.
    """

    def mutate(doc: dict) -> None:
        accept_row(doc).update(
            master_key_hex=key.hex(),
            derived_key_fingerprint_hex=ev.key_fingerprint(ev.derive_encryption_key(key, ev.DEFAULT_TENANT_ID)),
        )

    return mutate


def retenant(doc: dict) -> None:
    """The master_key_input block moved to another tenant with the accept row's fingerprint and AAD rebuilt for it."""
    tenant, row = "cross-sdk-test", accept_row(doc)
    doc["master_key_input"]["tenant_id"] = tenant
    row["derived_key_fingerprint_hex"] = ev.key_fingerprint(ev.derive_encryption_key(bytes.fromhex(row["master_key_hex"]), tenant))
    row["aad_hex"] = ev.aad_v3(tenant, row["cache_key"], fmt=row["format"], compressed=row["compressed"]).hex()


# The key every master_key_input row comes from, and its hex string.
KEY = bytes.fromhex("00ff807fa55ac33c1ee12dd24bb469968778f00f01102332455467768998abba")
H = KEY.hex()
# Keys that each lack one property of KEY. 00..1f: no byte above 7f, and no letter in a byte's first digit.
LOW_KEY = bytes(range(32))
# Digits only, with a leading 00 and bytes above 7f.
ALL_DIGITS = bytes.fromhex("00" + "".join(f"{n:02d}" for n in range(99, 79, -1)) + "".join(f"{n:02d}" for n in range(79, 68, -1)))
# A leading 00, bytes above 7f and letters in both digits, reading the same reversed.
PALINDROME = bytes.fromhex("001a2b3c4d5e6f708192a3b4c5d6e7f8") + bytes.fromhex("001a2b3c4d5e6f708192a3b4c5d6e7f8")[::-1]
# Equal digits in every byte (00, 11, ... ff, twice): swapping them reads the same key.
EQUAL_DIGITS = bytes(0x11 * (i % 16) for i in range(32))

# The two readings of what rule 1 leaves open, which the row guard compares: the strict one refuses each of these
# strings, and the lenient one reads KEY from it.
READING_CASES = {
    "uppercase digits": H.upper(),
    "white space between pairs and after": " ".join(H[i : i + 2] for i in range(0, len(H), 2)) + "\r\n",
    "a 0x prefix": "0x" + H,
    "a 0X prefix": "0X" + H,
}

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
    # intent-presets.md § Master Key Input — keys a hex or raw-bytes entry point must accept or refuse.
    "master_key_input block deleted": lambda d: d.pop("master_key_input"),
    "unknown vector table": lambda d: d["master_key_input"].__setitem__("legacy_vectors", [{"name": "legacy"}]),
    # Fingerprint and AAD rebuilt for the other tenant, so only the literal guard rejects it (stdlib lane; in the seal
    # lane the entry also fails to decrypt).
    "master_key_input tenant is not the literal": retenant,
    "accept row fingerprint corrupted": lambda d: accept_row(d).__setitem__("derived_key_fingerprint_hex", "00" * 16),
    "accept row aad tenant component swapped": lambda d: accept_row(d).__setitem__(
        "aad_hex", ev.aad_v3("cross-sdk-test", accept_row(d)["cache_key"], fmt="msgpack", compressed=False).hex()
    ),
    # 33 bytes: a conformant entry point that takes exactly 32 refuses it, and one that takes 32 or more accepts it, so
    # it can be neither an accept row nor a reject row.
    "accept row refused by a conformant length rule": rekey(KEY + b"\x20"),
    "reject row accepted by a conformant length rule": set_key("master_key_31_bytes", (KEY + b"\x20").hex()),
    "raw reject row of exactly 32 bytes": set_raw("raw_key_33_bytes", KEY),
    # A valid key that one reading of rule 1 refuses and the other accepts: a reject row holding one would decide it.
    "valid key with an uppercase digit as a reject row": set_key("master_key_non_hex_digit", H[:-1] + "A"),
    "valid key with a trailing newline as a reject row": set_key("master_key_odd_65_digits", H + "\n"),
    "non-ASCII character in a row": set_key("master_key_non_hex_digit", H[:-1] + "\ufeff"),
    "raw_key_hex in uppercase": lambda d: mk(d, "raw_key_33_bytes").__setitem__("raw_key_hex", (KEY + b"\x20").hex().upper()),
    "row note blank": lambda d: mk(d, "master_key_16_bytes").__setitem__("note", " "),
    "unknown field on a row": lambda d: mk(d, "master_key_16_bytes").__setitem__("reject", True),
    "duplicate row name": lambda d: d["master_key_input"]["reject_vectors"].append(copy.deepcopy(mk(d, "master_key_16_bytes"))),
    # Deleted, not renamed: a renamed row is also a row no wrong entry point lists, which the next case's guard catches.
    "frozen master_key_input row deleted": lambda d: d["master_key_input"]["raw_reject_vectors"].remove(mk(d, "raw_key_31_bytes")),
    "row added with no wrong entry point to show its mistake": lambda d: d["master_key_input"]["reject_vectors"].append(
        {"name": "master_key_20_bytes", "master_key_hex": H[:40], "note": "The accept row's first 20 bytes."}
    ),
    # Each row edited so that a mistake its note names no longer misjudges it; only the wrong-entry-point check
    # rejects these (the accept-row keys also fail to decrypt in the seal lane).
    "65-digit row cut to 63 digits": set_key("master_key_odd_65_digits", H[:63]),
    "63-digit row cut to 61 digits": set_key("master_key_odd_63_digits", H[:61]),
    "non-hex row also short": set_key("master_key_non_hex_digit", H[:61] + "g"),
    "non-hex digit first, where a start-anchored pattern sees it": set_key("master_key_non_hex_digit", "g" + H[1:]),
    "trailing row made odd, which an even-length check refuses": set_key("master_key_trailing_non_hex", H + "g"),
    "plus sign moved inside a pair": set_key("master_key_plus_sign", "0+" + H[2:]),
    "31-byte row cut to 30 bytes": set_key("master_key_31_bytes", H[:60]),
    "24-byte row grown to 25 bytes": set_key("master_key_24_bytes", H[:50]),
    "16-byte row grown to 20 bytes": set_key("master_key_16_bytes", H[:40]),
    "CRLF row without the CR LF": set_key("master_key_31_bytes_and_crlf", H[:62]),
    "0x row without the 0x": set_key("master_key_0x_and_31_bytes", H[:62]),
    "raw 31-byte row cut to 30 bytes": set_raw("raw_key_31_bytes", KEY[:30]),
    "raw ASCII row not a hex string": set_raw("raw_key_ascii_hex_string", b"g" * 64),
    "accept row without a leading zero byte": rekey(KEY[1:] + KEY[:1]),
    "accept row without hex letters": rekey(ALL_DIGITS),
    "accept row with no byte above 7f and no letter first in a byte": rekey(LOW_KEY),
    "accept row that reads the same reversed": rekey(PALINDROME),
    "accept row that reads the same with each byte's digits swapped": rekey(EQUAL_DIGITS),
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
    # The same entry sealed under the main master key: its AAD and fingerprint still match, only the decrypt fails.
    "accept row sealed under another master key": lambda d: accept_row(d).__setitem__("ciphertext_hex", dt(d)["ciphertext_hex"]),
    "accept row plaintext pinned wrong": lambda d: accept_row(d).__setitem__("plaintext_hex", "00"),
}


def main() -> int:
    bad = 0
    rc, out = run(lambda _: None)
    if rc != 0:
        print(f"FAIL baseline fixture does not verify:\n{out}")
        return 1
    print(f"ok  baseline verifies ({'seal' if HAVE_SEAL else 'stdlib'} lane)")

    for name, text in READING_CASES.items():
        if ev.read_hex_key(text) is not None or ev.read_hex_key(text, lenient=True) != KEY:
            print(f"FAIL reading {name!r}: the strict reading must refuse it and the lenient reading must read the key")
            bad += 1
        else:
            print(f"ok  reading {name!r}")

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

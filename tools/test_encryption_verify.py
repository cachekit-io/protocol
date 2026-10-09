#!/usr/bin/env python3
"""Mutation tests for encryption-verify.py's guards: the vectors table, the keyring, the default tenant, master key
input, and the models of wrong implementations each table's notes name.

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
import traceback
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


def run(mutate: Callable[[dict], None]) -> tuple[int | None, str]:
    """The verifier's exit status and output on a mutated copy of the fixture; None as the status if it raised.

    The verifier reports a bad fixture with a FAIL line, never a traceback. A raise is caught here so that it is
    reported against its own case and cannot hide the cases after it; its traceback ends the output.
    """
    doc = copy.deepcopy(DOC)
    mutate(doc)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            rc = ev.verify(doc, require_seal=HAVE_SEAL)
        except Exception:  # noqa: BLE001 -- any raise is a finding, reported by the caller
            print(f"RAISED\n{traceback.format_exc()}")
            return None, out.getvalue()
    return rc, out.getvalue()


def k1(doc: dict) -> dict:
    return next(v for v in doc["keyring"]["vectors"] if v["name"] == "encrypted_with_k1")


def k2(doc: dict) -> dict:
    return next(v for v in doc["keyring"]["vectors"] if v["name"] == "encrypted_with_k2")


def dt(doc: dict) -> dict:
    return next(v for v in doc["default_tenant"]["vectors"] if v["name"] == "default_tenant_interop")


def shape_vector(doc: dict, name: str) -> dict:
    return next(v for v in doc["vectors"] if v["name"] == name)


def reshape(name: str, **fields: object) -> Callable[[dict], None]:
    """A vector with other fields, its AAD rebuilt and, when `cryptography` imports, its ciphertext sealed again under
    its own nonce, so only the guard a case targets can fail it."""

    def mutate(doc: dict) -> None:
        vec = shape_vector(doc, name)
        vec.update(fields)
        aad = ev.aad_v3(doc["tenant_id"], vec["cache_key"], fmt=vec["format"], compressed=vec["compressed"], original_type=vec.get("original_type"))
        vec["aad_hex"] = aad.hex()
        if HAVE_SEAL:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

            key = ev.derive_encryption_key(bytes.fromhex(doc["master_key_hex"]), doc["tenant_id"])
            nonce = bytes.fromhex(vec["ciphertext_hex"][:24])
            vec["ciphertext_hex"] = (nonce + AESGCM(key).encrypt(nonce, bytes.fromhex(vec["plaintext_hex"]), aad)).hex()

    return mutate


def master_fingerprint(doc: dict, key_id: str) -> str:
    entry = next(e for e in doc["keyring"]["entries"] if e["id"] == key_id)
    return ev.key_fingerprint(bytes.fromhex(entry["master_key_hex"]))


def mk(doc: dict, name: str) -> dict:
    return next(r for table in ev.FROZEN_MASTER_KEY_INPUT_VECTORS for r in doc["master_key_input"][table] if r["name"] == name)


def accept_row(doc: dict) -> dict:
    return mk(doc, ev.ACCEPT_ROW)


def first_byte_80_row(doc: dict) -> dict:
    return mk(doc, ev.FIRST_BYTE_80_ROW)


def set_key(name: str, text: str) -> Callable[[dict], None]:
    return lambda d: mk(d, name).__setitem__("master_key_hex", text)


def set_raw(name: str, raw: bytes) -> Callable[[dict], None]:
    return lambda d: mk(d, name).__setitem__("raw_key_hex", raw.hex())


def rekey(key: bytes, name: str = ev.ACCEPT_ROW) -> Callable[[dict], None]:
    """An accept row under another key with its fingerprint recomputed, so only a property the key lacks can fail it.

    The sealed entry is left as it was, so in the seal lane the decrypt fails as well.
    """

    def mutate(doc: dict) -> None:
        mk(doc, name).update(
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
KEY = bytes.fromhex("007f80ffa55ac33c1ee12dd24bb469968778f00f01102332455467768998abba")
H = KEY.hex()
# Keys that each lack one property of KEY. 00..1f: no byte above 7f, and no letter in a byte's first digit.
LOW_KEY = bytes(range(32))
# KEY with bytes 1 and 3 swapped, so byte 1 is ff: a two's-complement decoder's sign byte restores the leading 00.
SIGN_BYTE_KEY = bytes.fromhex("00ff807fa55ac33c1ee12dd24bb469968778f00f01102332455467768998abba")
# KEY with its first byte set to 7f, the highest first byte a two's-complement decoder padded to 32 bytes reads right.
FIRST_BYTE_7F_KEY = bytes.fromhex("7f" + KEY.hex()[2:])
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


# A case is a mutation, or a mutation and the FAIL text of the guard it targets.
Case = Callable[[dict], None] | tuple[Callable[[dict], None], str]

STDLIB_CASES: dict[str, Case] = {
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
    # encryption.md ENC-10 — writer-shape vectors keep their shape over their writer's own container. Each is sealed again,
    # so only the shape guard rejects it.
    "writer-shape vector resealed as compressed False": (
        reshape("standard_serializer_default", compressed=False),
        "must keep the AAD shape (msgpack, True, msgpack)",
    ),
    "writer-shape vector over plain MessagePack under compressed True": (
        lambda d: reshape("standard_serializer_default", plaintext_hex=shape_vector(d, "standard_serializer_integrity_off")["plaintext_hex"])(d),
        "claims compressed True, but its plaintext is no ByteStorage envelope",
    ),
    "writer-shape vector over an envelope under compressed False": (
        lambda d: reshape("standard_serializer_integrity_off", plaintext_hex=shape_vector(d, "standard_serializer_default")["plaintext_hex"])(d),
        "claims compressed False, but its plaintext is not one plain MessagePack document",
    ),
    "writer-shape vector over two documents under compressed False": (
        lambda d: reshape("standard_serializer_integrity_off", plaintext_hex=shape_vector(d, "standard_serializer_integrity_off")["plaintext_hex"] + "00")(d),
        "claims compressed False, but its plaintext is not one plain MessagePack document",
    ),
    # Append-only means a published row never moves either: consumers read rows by position (accept_vectors[0]).
    "accept rows reversed": (
        lambda d: d["master_key_input"]["accept_vectors"].reverse(),
        "frozen master_key_input.accept_vectors rows missing or moved",
    ),
    "first two vectors swapped": (lambda d: d["vectors"].insert(0, d["vectors"].pop(1)), "frozen vectors rows missing or moved"),
    "keyring vectors reversed": (lambda d: d["keyring"]["vectors"].reverse(), "frozen keyring.vectors rows missing or moved"),
    # intent-presets.md rule 5 — the default-tenant block is ground truth for "no tenant configured".
    "default_tenant block deleted": lambda d: d.pop("default_tenant"),
    "default_tenant is not the literal": lambda d: d["default_tenant"].__setitem__("tenant_id", "cross-sdk-test"),
    "default_tenant fingerprint corrupted": lambda d: d["default_tenant"].__setitem__("derived_key_fingerprint_hex", "00" * 16),
    "default_tenant aad tenant component swapped": lambda d: dt(d).__setitem__(
        "aad_hex", ev.aad_v3("cross-sdk-test", dt(d)["cache_key"], fmt="msgpack", compressed=False).hex()
    ),
    "frozen default_tenant vector renamed": lambda d: dt(d).__setitem__("name", "renamed"),
    # intent-presets.md § Master Key Input — keys a hex or raw-bytes entry point must accept or refuse. Each case names
    # the FAIL text of the guard it targets, so a case that another guard catches instead is reported.
    "master_key_input block deleted": (lambda d: d.pop("master_key_input"), "master_key_input rows missing"),
    "unknown vector table": (
        lambda d: d["master_key_input"].__setitem__("legacy_vectors", [{"name": "legacy"}]),
        "unknown vector table",
    ),
    # Fingerprint and AAD rebuilt for the other tenant, so only the literal guard rejects it (stdlib lane; in the seal
    # lane the entry also fails to decrypt).
    "master_key_input tenant is not the literal": (retenant, "tenant_id must be the literal"),
    "accept row fingerprint corrupted": (
        lambda d: accept_row(d).__setitem__("derived_key_fingerprint_hex", "00" * 16),
        "derived-key fingerprint mismatch",
    ),
    "accept row aad tenant component swapped": (
        lambda d: accept_row(d).__setitem__(
            "aad_hex", ev.aad_v3("cross-sdk-test", accept_row(d)["cache_key"], fmt="msgpack", compressed=False).hex()
        ),
        "AAD mismatch",
    ),
    # 33 bytes: a conformant entry point that takes exactly 32 refuses it, and one that takes 32 or more accepts it, so
    # it can be neither an accept row nor a reject row.
    "accept row refused by a conformant length rule": (rekey(KEY + b"\x20"), "refuses it, so the row decides"),
    "reject row accepted by a conformant length rule": (
        set_key("master_key_31_bytes", (KEY + b"\x20").hex()),
        "accepts it, so the row decides",
    ),
    "raw reject row of exactly 32 bytes": (set_raw("raw_key_33_bytes", KEY), "so this row is no reject"),
    # A valid key that one reading of rule 1 refuses and the other accepts: a reject row holding one would decide it.
    "valid key with an uppercase digit as a reject row": (
        set_key("master_key_non_hex_digit", H[:-1] + "A"),
        "accepts it, so the row decides",
    ),
    "valid key with a trailing newline as a reject row": (
        set_key("master_key_odd_65_digits", H + "\n"),
        "accepts it, so the row decides",
    ),
    "non-ASCII character in a row": (set_key("master_key_non_hex_digit", H[:-1] + "\ufeff"), "other than printable ASCII"),
    "raw_key_hex in uppercase": (
        lambda d: mk(d, "raw_key_33_bytes").__setitem__("raw_key_hex", (KEY + b"\x20").hex().upper()),
        "raw_key_hex must be lowercase hex",
    ),
    "row note blank": (lambda d: mk(d, "master_key_16_bytes").__setitem__("note", " "), "note must be a non-empty string"),
    "unknown field on a row": (lambda d: mk(d, "master_key_16_bytes").__setitem__("reject", True), "fields ["),
    "duplicate row name": (
        lambda d: d["master_key_input"]["reject_vectors"].append(copy.deepcopy(mk(d, "master_key_16_bytes"))),
        "duplicate name",
    ),
    # Deleted, not renamed: a renamed row is also a row no wrong entry point lists, which the next case's guard catches.
    "frozen master_key_input row deleted": (
        lambda d: d["master_key_input"]["raw_reject_vectors"].remove(mk(d, "raw_key_31_bytes")),
        "frozen master_key_input.raw_reject_vectors rows missing or moved",
    ),
    "row added with no wrong entry point to show its mistake": (
        lambda d: d["master_key_input"]["reject_vectors"].append(
            {"name": "master_key_20_bytes", "master_key_hex": H[:40], "note": "The accept row's first 20 bytes."}
        ),
        "no wrong entry point shows why",
    ),
    # Each row edited so that a mistake its note names no longer misjudges it; only the wrong-entry-point check
    # rejects these (the accept-row keys also fail to decrypt in the seal lane).
    "65-digit row cut to 63 digits": (set_key("master_key_odd_65_digits", H[:63]), "judges master_key_odd_65_digits correctly"),
    "63-digit row cut to 61 digits": (set_key("master_key_odd_63_digits", H[:61]), "judges master_key_odd_63_digits correctly"),
    "non-hex row also short": (set_key("master_key_non_hex_digit", H[:61] + "g"), "judges master_key_non_hex_digit correctly"),
    "non-hex digit first, where a start-anchored pattern sees it": (
        set_key("master_key_non_hex_digit", "g" + H[1:]),
        "re.match) and a 64-character check, then Buffer.from' judges master_key_non_hex_digit correctly",
    ),
    "trailing row made odd, which an even-length check refuses": (
        set_key("master_key_trailing_non_hex", H + "g"),
        "judges master_key_trailing_non_hex correctly",
    ),
    "plus sign moved inside a pair": (set_key("master_key_plus_sign", "0+" + H[2:]), "judges master_key_plus_sign correctly"),
    "31-byte row cut to 30 bytes": (set_key("master_key_31_bytes", H[:60]), "judges master_key_31_bytes correctly"),
    "24-byte row grown to 25 bytes": (set_key("master_key_24_bytes", H[:50]), "judges master_key_24_bytes correctly"),
    "16-byte row grown to 20 bytes": (
        set_key("master_key_16_bytes", H[:40]),
        "(16 or 32 bytes)' judges master_key_16_bytes correctly",
    ),
    "CRLF row without the CR LF": (
        set_key("master_key_31_bytes_and_crlf", H[:62]),
        "judges master_key_31_bytes_and_crlf correctly",
    ),
    "spaced row with its spaces at the ends, which a strip removes": (
        set_key("master_key_31_bytes_with_spaces", " " + H[:62] + " "),
        "judges master_key_31_bytes_with_spaces correctly",
    ),
    "0x row without the 0x": (
        set_key("master_key_0x_and_31_bytes", H[:62]),
        "0x prefix stripped and the rest decoded' judges master_key_0x_and_31_bytes correctly",
    ),
    "raw 31-byte row cut to 30 bytes": (set_raw("raw_key_31_bytes", KEY[:30]), "judges raw_key_31_bytes correctly"),
    "raw 24-byte row grown to 25 bytes": (set_raw("raw_key_24_bytes", KEY[:25]), "judges raw_key_24_bytes correctly"),
    "raw 16-byte row grown to 17 bytes": (
        set_raw("raw_key_16_bytes", KEY[:17]),
        "(16 or 32 bytes)' judges raw_key_16_bytes correctly",
    ),
    "raw ASCII row not a hex string": (set_raw("raw_key_ascii_hex_string", b"g" * 64), "judges raw_key_ascii_hex_string correctly"),
    "accept row without a leading zero byte": (
        rekey(KEY[1:] + KEY[:1]),
        "drops a leading 00 byte' judges master_key_every_hex_digit correctly",
    ),
    "accept row without hex letters": (
        rekey(ALL_DIGITS),
        "tested only on all-digit keys' judges master_key_every_hex_digit correctly",
    ),
    "accept row with no byte above 7f and no letter first in a byte": (
        rekey(LOW_KEY),
        "refuses a pair above 7f' judges master_key_every_hex_digit correctly",
    ),
    "accept row that reads the same reversed": (rekey(PALINDROME), "(a little-endian integer)' judges master_key_every_hex_digit correctly"),
    "accept row that reads the same with each byte's digits swapped": (
        rekey(EQUAL_DIGITS),
        "digits of each byte swapped' judges master_key_every_hex_digit correctly",
    ),
    "accept row whose second byte a two's-complement sign byte restores": (
        rekey(SIGN_BYTE_KEY),
        'to_signed_bytes_be)" judges master_key_every_hex_digit correctly',
    ),
    "first-byte-80 row whose first byte is 7f": (
        rekey(FIRST_BYTE_7F_KEY, ev.FIRST_BYTE_80_ROW),
        "signed=True))\" judges master_key_first_byte_80 correctly",
    ),
    # PRE-51's pairing needs the accept row and default_tenant_interop under different keys, in different entries. One
    # case per clause of the guard; the AAD is rebuilt, and the guard runs before the seal check, so only that clause
    # rejects each.
    "accept row on default_tenant_interop's cache_key": (
        lambda d: accept_row(d).update(
            cache_key=dt(d)["cache_key"],
            aad_hex=ev.aad_v3(ev.DEFAULT_TENANT_ID, dt(d)["cache_key"], fmt="msgpack", compressed=False).hex(),
        ),
        "shares its master key, cache_key or plaintext",
    ),
    "accept row on default_tenant_interop's plaintext": (
        lambda d: accept_row(d).__setitem__("plaintext_hex", dt(d)["plaintext_hex"]),
        "shares its master key, cache_key or plaintext",
    ),
    "accept row under the main master key": (rekey(bytes.fromhex(DOC["master_key_hex"])), "shares its master key, cache_key or plaintext"),
    # The two accept rows must differ from each other the same way, so a test can plant both and read each under its
    # own key. The first-byte-80 row under the accept row's key also fails the model check; the guard's text is asked.
    "first-byte-80 row on the accept row's cache_key": (
        lambda d: first_byte_80_row(d).update(
            cache_key=accept_row(d)["cache_key"],
            aad_hex=ev.aad_v3(ev.DEFAULT_TENANT_ID, accept_row(d)["cache_key"], fmt="msgpack", compressed=False).hex(),
        ),
        "shares its master key, cache_key or plaintext",
    ),
    "first-byte-80 row on the accept row's plaintext": (
        lambda d: first_byte_80_row(d).__setitem__("plaintext_hex", accept_row(d)["plaintext_hex"]),
        "shares its master key, cache_key or plaintext",
    ),
    "first-byte-80 row under the accept row's key": (rekey(KEY, ev.FIRST_BYTE_80_ROW), "shares its master key, cache_key or plaintext"),
    # A row of sound shape that a model cannot parse reaches the models, which report the raise as a failure.
    "accept row of 63 digits": (
        lambda d: accept_row(d).__setitem__("master_key_hex", H[:63]),
        "raised on master_key_every_hex_digit",
    ),
}

SEAL_CASES: dict[str, Case] = {
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
    # default_tenant_interop's bytes, sealed under the main master key: the row's own fields still match, only the
    # decrypt fails.
    "accept row sealed under another master key": (
        lambda d: accept_row(d).__setitem__("ciphertext_hex", dt(d)["ciphertext_hex"]),
        "decrypt failed",
    ),
    "accept row plaintext pinned wrong": (lambda d: accept_row(d).__setitem__("plaintext_hex", "00"), "plaintext mismatch"),
    # The accept row's bytes, sealed under another master key: the first-byte-80 row's own fields still match.
    "first-byte-80 row sealed under another master key": (
        lambda d: first_byte_80_row(d).__setitem__("ciphertext_hex", accept_row(d)["ciphertext_hex"]),
        "decrypt failed",
    ),
}


# Each model of a mistake, replaced in turn by an entry point that conforms, must turn the verifier red under its own
# label: proof that every model's check is live, not covered by another guard. A model that lists a row its table does
# not freeze must turn it red too.
CONFORMING_MODELS: dict[str, Callable] = {
    "WRONG_HEX_ENTRY_POINTS": lambda t: ev.behind(ev.EXACTLY_32, ev.read_hex_key(t)),
    "WRONG_RAW_ENTRY_POINTS": lambda k: ev.behind(ev.EXACTLY_32, k),
}


def model_cases() -> dict[str, tuple[str, str, Callable, tuple[str, ...], str]]:
    """Case name -> (model table, label, stand-in, rows it lists, text the verifier must print)."""
    cases = {}
    for table, conforming in CONFORMING_MODELS.items():
        for label, (_, targets) in getattr(ev, table).items():
            cases[f"{table}: {label!r} replaced by a conforming entry point"] = (table, label, conforming, targets, repr(label))
        cases[f"{table}: a model listing a row that does not exist"] = (
            table,
            "a model listing a misspelled row",
            conforming,
            ("no_such_row",),
            "which is not a frozen row",
        )
    return cases


def run_model_case(table: str, label: str, stand_in: Callable, targets: tuple[str, ...]) -> tuple[int | None, str]:
    """The verifier's status and output on the committed fixture with one model swapped in, the table restored after."""
    models = getattr(ev, table)
    saved = models.get(label)
    models[label] = (stand_in, targets)
    try:
        return run(lambda _: None)
    finally:
        if saved is None:
            del models[label]
        else:
            models[label] = saved


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
    runs = {name: (lambda case=case: run(case[0] if isinstance(case, tuple) else case)) for name, case in cases.items()}
    expectations = {name: case[1] if isinstance(case, tuple) else None for name, case in cases.items()}
    for name, (table, label, stand_in, targets, expected) in model_cases().items():
        runs[name] = lambda table=table, label=label, stand_in=stand_in, targets=targets: run_model_case(table, label, stand_in, targets)
        expectations[name] = expected
    for name, go in runs.items():
        expected = expectations[name]
        rc, out = go()
        if rc is None:
            print(f"FAIL mutation '{name}' raised instead of failing a guard:\n{out}")
            bad += 1
        elif rc == 0:
            print(f"FAIL mutation '{name}' exited 0:\n{out}")
            bad += 1
        elif expected is not None and expected not in out:
            print(f"FAIL mutation '{name}' went red without the guard it targets ({expected!r}):\n{out}")
            bad += 1
        else:
            print(f"ok  mutation '{name}' goes red")
    if bad:
        print(f"{bad} mutation(s) NOT caught")
        return 1
    print(f"all {len(runs)} mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())

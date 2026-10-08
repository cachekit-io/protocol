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


def ar(doc: dict, name: str = "aad_compressed_false_sealed_true") -> dict:
    return next(r for r in doc["aad_reject_vectors"] if r["name"] == name)


def present(**inputs: object) -> Callable[[dict], None]:
    """An AAD reject row presenting other inputs, its aad_hex rebuilt, so only the one-input rule can fail it."""

    def mutate(doc: dict) -> None:
        row = ar(doc)
        for k, v in inputs.items():
            if v is None:
                row.pop(k, None)
            else:
                row[k] = v
        row["aad_hex"] = ev.aad_v3(
            doc["tenant_id"], row["cache_key"], fmt=row["format"], compressed=row["compressed"], original_type=row.get("original_type")
        ).hex()

    return mutate


def dc(doc: dict, name: str) -> dict:
    return next(r for r in doc["decrypted_container"]["vectors"] if r["name"] == name)


def reseal(name: str, plaintext_hex: str | None = None, **fields: object) -> Callable[[dict], None]:
    """A container row with another plaintext or other AAD inputs, its AAD rebuilt and, when `cryptography` imports, its
    ciphertext sealed again under its own nonce, so only the guard a case targets can fail it."""

    def mutate(doc: dict) -> None:
        row = dc(doc, name)
        row.update(fields)
        if plaintext_hex is not None:
            row["plaintext_hex"] = plaintext_hex
        aad = ev.aad_v3(doc["tenant_id"], row["cache_key"], fmt=row["format"], compressed=row["compressed"], original_type=row.get("original_type"))
        row["aad_hex"] = aad.hex()
        if HAVE_SEAL:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

            key = ev.derive_encryption_key(bytes.fromhex(doc["master_key_hex"]), doc["tenant_id"])
            nonce = bytes.fromhex(row["ciphertext_hex"][:24])
            row["ciphertext_hex"] = (nonce + AESGCM(key).encrypt(nonce, bytes.fromhex(row["plaintext_hex"]), aad)).hex()

    return mutate


def kc(doc: dict, name: str) -> dict:
    return next(r for r in doc["keyring"]["configuration"]["vectors"] if r["name"] == name)


def set_decrypt_only(name: str, change: Callable[[list[str]], list[str]]) -> Callable[[dict], None]:
    return lambda d: kc(d, name).__setitem__("decrypt_only_master_keys_hex", change(kc(d, name)["decrypt_only_master_keys_hex"]))


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

# The value's plain MessagePack, the plaintext of two container rows.
PLAIN = "83a7757365725f69642aa46e616d65a863616368656b6974a6616374697665c3"

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
    # encryption.md ENC-1 — AAD reject rows: a published ciphertext presented under one other AAD input. Each case names
    # the FAIL text of the guard it targets. No case reaches the seal lane's decrypt check alone: a row that keeps to
    # one other input and its sealed vector's ciphertext cannot authenticate, which that check shows with the cipher.
    "aad_reject_vectors deleted": (lambda d: d.pop("aad_reject_vectors"), "aad_reject_vectors missing"),
    "aad reject row presenting its sealed vector's own inputs": (present(compressed=True), "in no AAD input(s)"),
    "aad reject row differing in two inputs": (present(format="orjson"), "in ['format', 'compressed'] AAD input(s)"),
    "aad reject row carrying another vector's ciphertext": (
        lambda d: ar(d).__setitem__("ciphertext_hex", next(v for v in d["vectors"] if v["name"] == "basic_bytes")["ciphertext_hex"]),
        "ciphertext is not compressed_basic's",
    ),
    "aad reject row naming no sealed vector": (lambda d: ar(d).__setitem__("sealed_as", "no_such_vector"), "sealed_as names no vector"),
    "aad reject row whose aad_hex is not rebuilt": (lambda d: ar(d).__setitem__("compressed", True), "AAD mismatch"),
    "aad reject row with compressed as a JSON int": (lambda d: ar(d).__setitem__("compressed", 0), "invalid metadata"),
    "aad reject row with an unknown field": (lambda d: ar(d).__setitem__("plaintext_hex", "00"), "(original_type optional)"),
    "frozen aad reject row deleted": (
        lambda d: d["aad_reject_vectors"].remove(ar(d, "aad_key_with_prefix_sealed_without")),
        "frozen aad_reject_vectors missing",
    ),
    "aad reject row duplicated": (lambda d: d["aad_reject_vectors"].append(copy.deepcopy(ar(d))), "duplicate name"),
    # encryption.md ENC-2 and ENC-3 — containers after decryption. The plaintexts are the rows' own: the envelope, the
    # map's plain MessagePack (PLAIN) and that with a trailing byte.
    "decrypted_container block deleted": (lambda d: d.pop("decrypted_container"), "decrypted_container rows missing"),
    "envelope row holding plain MessagePack instead": (
        lambda d: reseal("container_envelope_to_plain_reader", PLAIN)(d),
        "unwraps a plaintext which parses as a ByteStorage envelope' returns what container_envelope_to_plain_reader's outcome allows",
    ),
    "trailing-byte row without its trailing byte": (
        lambda d: reseal("container_trailing_byte_to_plain_reader", PLAIN)(d),
        "container_trailing_byte_to_plain_reader: a conforming plain_msgpack reader returns a value from it",
    ),
    "plain row holding a valid envelope instead": (
        lambda d: reseal("container_plain_to_envelope_reader", dc(d, "container_envelope_to_plain_reader")["plaintext_hex"])(d),
        "container_plain_to_envelope_reader: a conforming bytestorage_envelope reader returns a value from it",
    ),
    "plain-reader row sealed with compressed True": (
        reseal("container_trailing_byte_to_plain_reader", compressed=True),
        "a plain_msgpack reader builds its AAD with format msgpack, original_type None and compressed False",
    ),
    "bare Arrow row holding the checksummed IPC instead": (
        lambda d: reseal(
            "container_bare_arrow_to_arrow_reader", "0102030405060708" + dc(d, "container_bare_arrow_to_arrow_reader")["plaintext_hex"]
        )(d),
        "container_bare_arrow_to_arrow_reader: a conforming arrow_checksummed reader returns a value from it",
    ),
    "Arrow row sealed without original_type": (
        lambda d: (dc(d, "container_bare_arrow_to_arrow_reader").pop("original_type"), reseal("container_bare_arrow_to_arrow_reader")(d)),
        "a arrow_checksummed reader builds its AAD with format arrow, original_type arrow",
    ),
    "container row naming a reader no SDK has": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("reader", "arrow"),
        "as its frozen name declares",
    ),
    "container row whose aad_hex is not rebuilt": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("cache_key", "test:container:other"),
        "AAD mismatch",
    ),
    "frozen container row deleted": (
        lambda d: d["decrypted_container"]["vectors"].remove(dc(d, "container_plain_to_envelope_reader")),
        "frozen decrypted_container rows missing",
    ),
    "container row with an unknown field": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("tenant_id", "default"),
        "decrypted_container container_plain_to_envelope_reader: fields",
    ),
    "container row added with no wrong reader to show its mistake": (
        lambda d: d["decrypted_container"]["vectors"].append(
            {**copy.deepcopy(dc(d, "container_trailing_byte_to_plain_reader")), "name": "container_another_row"}
        ),
        "no wrong container reader shows why these rows exist: ['container_another_row']",
    ),
    # encryption.md ENC-7 and ENC-9 — keyring configurations an SDK accepts or refuses at load.
    "keyring configuration block deleted": (lambda d: d["keyring"].pop("configuration"), "keyring configuration rows missing"),
    "four-key row cut to three keys": (
        set_decrypt_only("keyring_four_decrypt_only_keys", lambda k: k[:3]),
        "keyring_four_decrypt_only_keys: a conforming load does not reject it",
    ),
    "three-key row grown to four keys": (
        set_decrypt_only("keyring_three_decrypt_only_keys", lambda k: [*k, "33" * 32]),
        "keyring_three_decrypt_only_keys: a conforming load does not accept it",
    ),
    "uppercase row with the repeat in lowercase": (
        set_decrypt_only("keyring_current_key_decrypt_only_uppercase", lambda k: [k[0], k[1].lower()]),
        "judges keyring_current_key_decrypt_only_uppercase correctly",
    ),
    "a key twice in a decrypt-only list": (
        set_decrypt_only("keyring_three_decrypt_only_keys", lambda k: [k[0], k[0], k[2]]),
        "appears twice in the decrypt-only list",
    ),
    "an uppercase decrypt-only key that is not the current key": (
        set_decrypt_only("keyring_three_decrypt_only_keys", lambda k: [k[0], k[1], accept_row(DOC)["master_key_hex"][:-2].upper() + "AB"]),
        "the two readings of rule 1 load it differently",
    ),
    "a decrypt-only key of 31 bytes": (
        set_decrypt_only("keyring_current_key_decrypt_only", lambda k: [k[0][:62], k[1]]),
        "every key must be a valid 32-byte key",
    ),
    "verdict flipped against the frozen name": (
        lambda d: kc(d, "keyring_four_decrypt_only_keys").__setitem__("verdict", "accept"),
        "the one its frozen name declares",
    ),
    "keyring configuration row renamed": (
        lambda d: kc(d, "keyring_current_key_decrypt_only").__setitem__("name", "renamed"),
        "frozen keyring configuration rows missing",
    ),
    "keyring configuration row with an unknown field": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("tenant_id", "default"),
        "keyring configuration keyring_three_decrypt_only_keys: fields",
    ),
    "keyring configuration row added with no wrong loader to show its mistake": (
        lambda d: d["keyring"]["configuration"]["vectors"].append(
            {**copy.deepcopy(kc(d, "keyring_three_decrypt_only_keys")), "name": "keyring_no_decrypt_only_keys", "decrypt_only_master_keys_hex": []}
        ),
        "no wrong keyring loader shows why these rows exist: ['keyring_no_decrypt_only_keys']",
    ),
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
        "frozen master_key_input raw_reject_vectors missing",
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
    for name, case in cases.items():
        mutate, expected = case if isinstance(case, tuple) else (case, None)
        rc, out = run(mutate)
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
    print(f"all {len(cases)} mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Mutation tests for encryption-verify.py's guards: the vectors table, the keyring, the default tenant, master key
input, the AAD reject, post-decryption container and keyring configuration tables, and the models of wrong
implementations each table's notes name.

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


def present(name: str = "aad_compressed_false_sealed_true", **inputs: object) -> Callable[[dict], None]:
    """An AAD reject row presenting other inputs (None removes one), its aad_hex rebuilt, so only a guard on what it
    presents can fail it."""

    def mutate(doc: dict) -> None:
        row = ar(doc, name)
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

# The value's plain MessagePack, the plaintext of two container rows.
PLAIN = "83a7757365725f69642aa46e616d65a863616368656b6974a6616374697665c3"
# interop-mode.json's issue_example_object value, the interop rows' first document.
INTEROP_VALUE = "82a36167651ea46e616d65a5616c696365"

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
        "frozen aad_reject_vectors rows missing or moved",
    ),
    "aad reject row duplicated": (lambda d: d["aad_reject_vectors"].append(copy.deepcopy(ar(d))), "duplicate name"),
    "aad reject row with a blank note": (
        lambda d: ar(d).__setitem__("note", " "),
        "aad_reject aad_compressed_false_sealed_true: note must be a non-empty string",
    ),
    "aad reject row whose note is not a string": (
        lambda d: ar(d).__setitem__("note", 7),
        "aad_reject aad_compressed_false_sealed_true: note must be a non-empty string",
    ),
    "aad reject row whose name is not a string": (
        lambda d: ar(d).__setitem__("name", 7),
        "aad_reject_vectors missing, or a row that is not an object with a string name",
    ),
    "aad reject row with a format outside the registry": (lambda d: ar(d).__setitem__("format", "pickle"), "invalid metadata"),
    "aad reject row presenting another key than its name declares": (
        present("aad_key_with_prefix_sealed_without", cache_key="other:test:vector:1"),
        "and present cache_key 'app:test:vector:1'",
    ),
    "aad reject row presenting an original_type its name does not declare": (
        present("aad_without_original_type_sealed_with", original_type="dataframe"),
        "and present original_type None",
    ),
    # special_cache_key's ciphertext also differs from the row in the cache key alone, so only the frozen sealed_as
    # rejects it.
    "aad reject row repointed at another sealed vector": (
        lambda d: ar(d, "aad_key_with_prefix_sealed_without").update(
            sealed_as="special_cache_key", ciphertext_hex=next(v for v in d["vectors"] if v["name"] == "special_cache_key")["ciphertext_hex"]
        ),
        "must carry basic_bytes's ciphertext",
    ),
    "aad reject rows reordered": (
        lambda d: d["aad_reject_vectors"].insert(0, d["aad_reject_vectors"].pop(1)),
        "frozen aad_reject_vectors rows missing or moved",
    ),
    "aad reject row added with no retry to show its mistake": (
        lambda d: d["aad_reject_vectors"].append({**copy.deepcopy(ar(d)), "name": "aad_another_row"}),
        "no wrong AAD retry shows why these rows exist: ['aad_another_row']",
    ),
    "aad reject row that is not an object": (
        lambda d: d["aad_reject_vectors"].append("not an object"),
        "a row that is not an object with a string name",
    ),
    # encryption.md ENC-2 and ENC-3 — containers after decryption. The plaintexts are the rows' own: the envelope, the
    # map's plain MessagePack (PLAIN), and the interop value (INTEROP_VALUE) with a byte or a header after it.
    "decrypted_container block deleted": (lambda d: d.pop("decrypted_container"), "decrypted_container rows missing"),
    "envelope row holding plain MessagePack instead": (
        lambda d: reseal("container_envelope_to_plain_reader", PLAIN)(d),
        "holds no envelope whose value a conforming reader declines, so not_unwrapped pins nothing",
    ),
    "trailing-byte row without its trailing byte": (
        lambda d: reseal("container_trailing_byte_to_interop_reader", INTEROP_VALUE)(d),
        "container_trailing_byte_to_interop_reader: a conforming interop reader returns a value from it",
    ),
    "plain row holding a valid envelope instead": (
        lambda d: reseal("container_plain_to_envelope_reader", dc(d, "container_envelope_to_plain_reader")["plaintext_hex"])(d),
        "container_plain_to_envelope_reader: a conforming bytestorage_envelope reader returns a value from it",
    ),
    "interop row sealed with compressed True": (
        reseal("container_trailing_byte_to_interop_reader", compressed=True),
        "the interop reader builds its AAD with format msgpack, compressed False and original_type None",
    ),
    "interop row under a key interop-mode.json does not hold": (
        reseal("container_incomplete_tail_to_interop_reader", cache_key="t:op:" + "00" * 32),
        "an interop row's cache_key must be one of interop-mode.json's keys",
    ),
    "container rows reordered": (
        lambda d: d["decrypted_container"]["vectors"].reverse(),
        "frozen decrypted_container.vectors rows missing or moved",
    ),
    "bare Arrow row holding the checksummed IPC instead": (
        lambda d: reseal(
            "container_bare_arrow_to_arrow_reader", "0102030405060708" + dc(d, "container_bare_arrow_to_arrow_reader")["plaintext_hex"]
        )(d),
        "container_bare_arrow_to_arrow_reader: a conforming arrow_checksummed reader returns a value from it",
    ),
    "Arrow row sealed without original_type": (
        lambda d: (dc(d, "container_bare_arrow_to_arrow_reader").pop("original_type"), reseal("container_bare_arrow_to_arrow_reader")(d)),
        "the arrow_checksummed reader builds its AAD with format arrow, compressed False and original_type arrow",
    ),
    "plain-JSON row holding the checksummed JSON instead": (
        lambda d: reseal("container_plain_json_to_orjson_reader", "0102030405060708" + dc(d, "container_plain_json_to_orjson_reader")["plaintext_hex"])(d),
        "container_plain_json_to_orjson_reader: a conforming orjson_checksummed reader returns a value from it",
    ),
    "trailing-byte row with another second document": (
        lambda d: reseal("container_trailing_byte_to_interop_reader", INTEROP_VALUE + "01")(d),
        "container_trailing_byte_to_interop_reader: plaintext differs from the bytes its frozen name pins",
    ),
    "incomplete-tail row with a complete second document": (
        lambda d: reseal("container_incomplete_tail_to_interop_reader", INTEROP_VALUE + "00")(d),
        "refuses only a second complete document' returns what container_incomplete_tail_to_interop_reader's outcome allows",
    ),
    "container row that is not an object": (
        lambda d: d["decrypted_container"]["vectors"].append(["not", "an", "object"]),
        "decrypted_container rows missing, or a row that is not an object",
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
        "frozen decrypted_container.vectors rows missing or moved",
    ),
    "container block note blank": (
        lambda d: d["decrypted_container"].__setitem__("note", " "),
        "FAIL decrypted_container: note must be a non-empty string",
    ),
    "container row duplicated": (
        lambda d: d["decrypted_container"]["vectors"].append(copy.deepcopy(dc(d, "container_plain_to_envelope_reader"))),
        "decrypted_container container_plain_to_envelope_reader: duplicate name",
    ),
    "container row with a blank note": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("note", ""),
        "decrypted_container container_plain_to_envelope_reader: note must be a non-empty string",
    ),
    "container row whose note is not a string": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("note", 7),
        "decrypted_container container_plain_to_envelope_reader: note must be a non-empty string",
    ),
    "container block note that is not a string": (
        lambda d: d["decrypted_container"].__setitem__("note", 7),
        "FAIL decrypted_container: note must be a non-empty string",
    ),
    "container row whose name is not a string": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("name", 7),
        "decrypted_container rows missing, or a row that is not an object with a string name",
    ),
    # Rows added under new names: no frozen entry speaks for them, so only the table's own rules can refuse them.
    "container row added for a reader no SDK has": (
        lambda d: d["decrypted_container"]["vectors"].append(
            {**copy.deepcopy(dc(d, "container_plain_to_envelope_reader")), "name": "container_another_row", "reader": "arrow"}
        ),
        "decrypted_container container_another_row: reader must be one of",
    ),
    "container row added with an outcome the table does not define": (
        lambda d: d["decrypted_container"]["vectors"].append(
            {**copy.deepcopy(dc(d, "container_plain_to_envelope_reader")), "name": "container_another_row", "outcome": "miss"}
        ),
        "decrypted_container container_another_row: reader must be one of",
    ),
    "container row added that an envelope reader unwraps, claiming not_unwrapped": (
        lambda d: (
            d["decrypted_container"]["vectors"].append(
                {**copy.deepcopy(dc(d, "container_envelope_to_plain_reader")), "name": "container_another_row", "reader": "bytestorage_envelope"}
            ),
            reseal("container_another_row", compressed=True)(d),
        ),
        "decrypted_container container_another_row: holds no envelope whose value a conforming reader declines",
    ),
    "container row with an unknown field": (
        lambda d: dc(d, "container_plain_to_envelope_reader").__setitem__("tenant_id", "default"),
        "decrypted_container container_plain_to_envelope_reader: fields",
    ),
    # A row with no frozen entry has no pinned plaintext either, so it must not be told it differs from one.
    "container row added with no wrong reader to show its mistake": (
        lambda d: d["decrypted_container"]["vectors"].append(
            {**copy.deepcopy(dc(d, "container_trailing_byte_to_interop_reader")), "name": "container_another_row"}
        ),
        "no wrong container reader shows why these rows exist: ['container_another_row']",
        "plaintext differs from the bytes its frozen name pins",
    ),
    # encryption.md ENC-7 and ENC-9 — keyring configurations an SDK accepts or refuses at load.
    "keyring configuration block deleted": (lambda d: d["keyring"].pop("configuration"), "keyring configuration rows missing"),
    "four-key row cut to three keys": (
        set_decrypt_only("keyring_four_decrypt_only_keys", lambda k: k[:3]),
        "keyring_four_decrypt_only_keys: a conforming load that refuses uppercase digits, white space and a 0x prefix does not reject it",
    ),
    "three-key row grown to four keys": (
        set_decrypt_only("keyring_three_decrypt_only_keys", lambda k: [*k, "33" * 32]),
        "keyring_three_decrypt_only_keys: a conforming load that refuses uppercase digits, white space and a 0x prefix does not accept it",
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
        "only a repeat of the current key in another case may need the lenient reading",
    ),
    "a decrypt-only key of 31 bytes": (
        set_decrypt_only("keyring_current_key_decrypt_only", lambda k: [k[0][:62], *k[1:]]),
        "every key must be a valid 32-byte key",
    ),
    "verdict flipped against the frozen name": (
        lambda d: kc(d, "keyring_four_decrypt_only_keys").__setitem__("verdict", "accept"),
        "the one its frozen name declares",
    ),
    "keyring configuration row renamed": (
        lambda d: kc(d, "keyring_current_key_decrypt_only").__setitem__("name", "renamed"),
        "frozen keyring.configuration.vectors rows missing or moved",
    ),
    "keyring configuration block note blank": (
        lambda d: d["keyring"]["configuration"].__setitem__("note", " "),
        "FAIL keyring configuration: note must be a non-empty string",
    ),
    "keyring configuration row duplicated": (
        lambda d: d["keyring"]["configuration"]["vectors"].append(copy.deepcopy(kc(d, "keyring_three_decrypt_only_keys"))),
        "keyring configuration keyring_three_decrypt_only_keys: duplicate name",
    ),
    # The next five cases reach one compound guard, which has one message: one case for each of its terms.
    "keyring configuration row with a blank note": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("note", " "),
        "keyring configuration keyring_three_decrypt_only_keys: needs a non-empty note",
    ),
    "keyring configuration row whose note is not a string": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("note", 7),
        "keyring configuration keyring_three_decrypt_only_keys: needs a non-empty note",
    ),
    "keyring configuration row whose current key is not a string": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("current_master_key_hex", 7),
        "keyring configuration keyring_three_decrypt_only_keys: needs a non-empty note",
    ),
    "keyring configuration row whose decrypt-only keys are not a list": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("decrypt_only_master_keys_hex", "11" * 32),
        "keyring configuration keyring_three_decrypt_only_keys: needs a non-empty note",
    ),
    "keyring configuration row with a decrypt-only key that is not a string": (
        set_decrypt_only("keyring_three_decrypt_only_keys", lambda k: [*k[:2], 7]),
        "keyring configuration keyring_three_decrypt_only_keys: needs a non-empty note",
    ),
    "keyring configuration block note that is not a string": (
        lambda d: d["keyring"]["configuration"].__setitem__("note", 7),
        "FAIL keyring configuration: note must be a non-empty string",
    ),
    "keyring configuration row whose name is not a string": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("name", 7),
        "keyring configuration rows missing, or a row that is not an object with a string name",
    ),
    "keyring configuration row added with a verdict the table does not define": (
        lambda d: d["keyring"]["configuration"]["vectors"].append(
            {**copy.deepcopy(kc(d, "keyring_three_decrypt_only_keys")), "name": "keyring_another_row", "verdict": "maybe"}
        ),
        "keyring configuration keyring_another_row: verdict must be accept or reject",
    ),
    "a decrypt-only key that is not hex": (
        set_decrypt_only("keyring_three_decrypt_only_keys", lambda k: [*k[:2], "zz" * 32]),
        "keyring_three_decrypt_only_keys: every key must be a valid 32-byte key",
    ),
    "a current key that needs the lenient reading for its 0x prefix": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__(
            "current_master_key_hex", "0x" + kc(d, "keyring_three_decrypt_only_keys")["current_master_key_hex"]
        ),
        "keyring_three_decrypt_only_keys: only a repeat of the current key in another case may need the lenient reading",
    ),
    "keyring configuration row with an unknown field": (
        lambda d: kc(d, "keyring_three_decrypt_only_keys").__setitem__("tenant_id", "default"),
        "keyring configuration keyring_three_decrypt_only_keys: fields",
    ),
    "keyring configuration rows reordered": (
        lambda d: d["keyring"]["configuration"]["vectors"].reverse(),
        "frozen keyring.configuration.vectors rows missing or moved",
    ),
    "keyring configuration row that is not an object": (
        lambda d: d["keyring"]["configuration"]["vectors"].append(7),
        "keyring configuration rows missing, or a row that is not an object",
    ),
    "keyring configuration row added with no wrong loader to show its mistake": (
        lambda d: d["keyring"]["configuration"]["vectors"].append(
            {**copy.deepcopy(kc(d, "keyring_three_decrypt_only_keys")), "name": "keyring_no_decrypt_only_keys", "decrypt_only_master_keys_hex": []}
        ),
        "no wrong keyring loader shows why these rows exist: ['keyring_no_decrypt_only_keys']",
    ),
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
    "WRONG_AAD_RETRIES": lambda i: [],
    "WRONG_CONTAINER_READERS": lambda d: None,
    "WRONG_KEYRING_LOADS": lambda c, d: ev.keyring_loads(c, d, lenient=False),
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


def run_patched(table: str, key: str, value: object) -> tuple[int | None, str]:
    """The verifier's status and output on the committed fixture with one entry of a module table replaced (or added),
    the table restored after."""
    entries = getattr(ev, table)
    saved = entries.get(key)
    entries[key] = value
    try:
        return run(lambda _: None)
    finally:
        if saved is None:
            del entries[key]
        else:
            entries[key] = saved


def run_model_case(table: str, label: str, stand_in: Callable, targets: tuple[str, ...]) -> tuple[int | None, str]:
    """The verifier's status and output on the committed fixture with one model swapped in."""
    return run_patched(table, label, (stand_in, targets))


def run_with_decrypt(stand_in: Callable) -> tuple[int | None, str]:
    """The verifier's status and output with its AES-GCM decrypt replaced, restored after."""
    saved = ev.decrypt_with_keyring
    ev.decrypt_with_keyring = stand_in
    try:
        return run(lambda _: None)
    finally:
        ev.decrypt_with_keyring = saved


def with_retry(name: str, outcome: str) -> tuple:
    """A row's frozen entry with another retry outcome."""
    return (*ev.FROZEN_AAD_REJECT_VECTORS[name][:4], outcome)


# Code mutations beyond the models, each with the text of the guard it targets: a frozen retry outcome changed, a value
# outcome and an unstated one each recorded as none, and (seal lane only) a decrypt that authenticates anything, which
# only the check that no AAD reject row authenticates catches among the AAD reject guards.
CODE_CASES: dict[str, tuple[Callable[[], tuple[int | None, str]], str]] = {
    "a frozen value retry outcome recorded as none": (
        lambda: run_patched("FROZEN_AAD_REJECT_VECTORS", "aad_without_original_type_sealed_with", with_retry("aad_without_original_type_sealed_with", "none")),
        "a plain_msgpack reader that retried reads 'value' from original_type_numpy's plaintext, not 'none'",
    ),
    "a frozen unstated retry outcome recorded as none": (
        lambda: run_patched("FROZEN_AAD_REJECT_VECTORS", "aad_key_with_prefix_sealed_without", with_retry("aad_key_with_prefix_sealed_without", "none")),
        "a plain_msgpack reader that retried reads 'unstated' from basic_bytes's plaintext, not 'none'",
    ),
}
SEAL_CODE_CASES: dict[str, tuple[Callable[[], tuple[int | None, str]], str]] = {
    "a decrypt that authenticates any AAD": (
        lambda: run_with_decrypt(lambda keys, ciphertext, aad: (0, b"")),
        "decrypts under the AAD it presents",
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
    runs = {name: (lambda case=case: run(case[0] if isinstance(case, tuple) else case)) for name, case in cases.items()}
    expectations = {name: case[1] if isinstance(case, tuple) else None for name, case in cases.items()}
    # An optional third element is a FAIL text the case must not print: a guard that has no business firing on it.
    forbidden = {name: case[2] for name, case in cases.items() if isinstance(case, tuple) and len(case) > 2}
    for name, (table, label, stand_in, targets, expected) in model_cases().items():
        runs[name] = lambda table=table, label=label, stand_in=stand_in, targets=targets: run_model_case(table, label, stand_in, targets)
        expectations[name] = expected
    for name, (go, expected) in (CODE_CASES | (SEAL_CODE_CASES if HAVE_SEAL else {})).items():
        runs[name], expectations[name] = go, expected
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
        elif name in forbidden and forbidden[name] in out:
            print(f"FAIL mutation '{name}' also tripped a guard that should not fire on it ({forbidden[name]!r}):\n{out}")
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

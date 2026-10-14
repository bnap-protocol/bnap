#!/usr/bin/env python3
"""Generate the Wycheproof-style case files in vectors/cases/ from the reference
encoder and the bnap_conf library.

Usage:
  python3 -I conformance/gen_cases.py            write vectors/cases/*.json and schema/
  python3 -I conformance/gen_cases.py --check    fail if any file on disk differs

Every expected result below is stated by hand from the text of draft-00
(plus ERRATA and DECISIONS where they settle a point) and then cross-checked
against bnap_conf: if the library disagrees with the stated expectation the
generator stops, so a case file can never silently encode a library bug.
Output is deterministic: fixed keys, fixed times, BIP-340 with zero
auxiliary randomness, RFC 6979 ECDSA.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from bnap_conf import codec, offer as of, credential as cr, response as rs, manifest as mf  # noqa: E402
from bnap_conf import http as hp, pricing as pr, store as st, client as cl, dpop, registry  # noqa: E402
from bnap_conf.codec import H, tu64, tlv, BnapError  # noqa: E402
from bnap_conf.crypto import schnorr_pub, schnorr_sign, schnorr_verify, key_from_label  # noqa: E402

REPO = HERE.parent
OUT = REPO / "vectors" / "cases"
GENERATOR = "conformance/gen_cases.py"
SOURCE = ("spec/socket-draft-00.md (doc rev 39), spec/ERRATA.md, spec/DECISIONS.md, "
          "registry/generated/registry.json, reference/python/bnap_ref.py")

REG = registry.default()

# ---------------------------------------------------------------- fixed material

OFFER_SK = key_from_label("bnap test offer key")
RECEIPT_SK = key_from_label("bnap test receipt key")
ROOT_SK = key_from_label("bnap test root key")
BACKUP_SK = key_from_label("bnap test backup key")
NOTE_SK = key_from_label("bnap test note key")
MAC_KEY = key_from_label("bnap test mac key")
RETIRED_MAC = key_from_label("bnap conformance retired mac key")
UNKNOWN_MAC = key_from_label("bnap conformance unknown mac key")
STRANGER_SK = key_from_label("bnap conformance stranger key")
NEXT_BACKUP_SK = key_from_label("bnap conformance next backup key")
THIRD_SK = key_from_label("bnap conformance third root key")
OFFER_PK, RECEIPT_PK = schnorr_pub(OFFER_SK), schnorr_pub(RECEIPT_SK)
ROOT_PK, BACKUP_PK = schnorr_pub(ROOT_SK), schnorr_pub(BACKUP_SK)
STRANGER_PK = schnorr_pub(STRANGER_SK)

ORIGIN = "https://api.example"
NOW = 1791700100
EXPIRES = 1791700300
ISSUED = 1791700000
NOT_AFTER = 1792304800
CHAT_BODY = b'{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}'
ACT = hp.action_scope("POST", ORIGIN, "/v1/chat/completions", CHAT_BODY)
ROUTE_CHAT = hp.route_scope(ORIGIN, "chat")
ROUTE_OTHER = hp.route_scope(ORIGIN, "images")
ACT_GET = hp.action_scope("GET", ORIGIN, "/v1/resource")
ACT_GET_OTHER = hp.action_scope("GET", ORIGIN, "/v1/resource?page=2")
PIN_KEYS = [{"kid": OFFER_PK.hex(), "use": "offer", "not_after": NOT_AFTER},
            {"kid": RECEIPT_PK.hex(), "use": "receipt", "not_after": NOT_AFTER}]


def hx(b):
    return b.hex() if b is not None else None


def must(cond, what):
    if not cond:
        raise SystemExit("gen_cases: library disagrees with the stated expectation: " + what)

# ---------------------------------------------------------------- case file model


class Group:
    def __init__(self, cf, gtype, section, description, inputs_schema):
        self.cf = cf
        self.type = gtype
        self.section = section
        self.description = description
        self.inputs_schema = inputs_schema
        self.tests = []

    def add(self, comment, inputs, result, *, error=None, expected=None, flags=(), sections=None,
            acceptable_errors=None, reason=None):
        if result == "invalid" and error is None:
            raise SystemExit(f"{self.cf.area}: invalid case without an error code: {comment}")
        if error is not None and error not in codec.ERRORS:
            raise SystemExit(f"{self.cf.area}: unknown error {error}")
        self.cf.counter += 1
        t = {"tcId": self.cf.counter, "comment": comment, "flags": list(flags),
             "sections": list(sections or [self.section]), "inputs": inputs, "result": result}
        if error is not None:
            t["error"] = error
            t["errorCode"] = codec.code_of(error)
        if acceptable_errors:
            t["acceptableErrors"] = list(acceptable_errors)
        if reason is not None:
            t["reason"] = reason
        if expected is not None:
            t["expected"] = expected
        for f in t["flags"]:
            if f not in self.cf.notes:
                raise SystemExit(f"{self.cf.area}: flag {f} has no note")
        self.tests.append(t)
        return t


class CaseFile:
    def __init__(self, area, title, header, notes):
        self.area = area
        self.title = title
        self.header = header
        self.notes = notes
        self.groups = []
        self.counter = 0

    def group(self, gtype, section, description, inputs_schema):
        g = Group(self, gtype, section, description, inputs_schema)
        self.groups.append(g)
        return g

    def to_json(self):
        return {
            "bnapCases": 1,
            "area": self.area,
            "title": self.title,
            "schema": f"schema/{self.area}.schema.json",
            "generator": GENERATOR,
            "source": SOURCE,
            "numberOfTests": self.counter,
            "header": self.header,
            "notes": self.notes,
            "testGroups": [{"type": g.type, "section": g.section, "description": g.description,
                            "tests": g.tests} for g in self.groups],
        }

    def schema(self):
        test_variants = []
        for g in self.groups:
            test_variants.append({
                "if": {"properties": {"type": {"const": g.type}}, "required": ["type"]},
                "then": {"properties": {"tests": {"type": "array", "items": {
                    "allOf": [{"$ref": "#/$defs/test"},
                              {"properties": {"inputs": _obj_schema(g.inputs_schema)}}]}}}}})
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://github.com/bnap-protocol/bnap/vectors/cases/schema/{self.area}.schema.json",
            "title": f"BNAP conformance cases: {self.title}",
            "type": "object",
            "required": ["bnapCases", "area", "title", "schema", "generator", "source",
                         "numberOfTests", "header", "notes", "testGroups"],
            "additionalProperties": False,
            "properties": {
                "bnapCases": {"const": 1},
                "area": {"const": self.area},
                "title": {"type": "string"},
                "schema": {"const": f"schema/{self.area}.schema.json"},
                "generator": {"type": "string"},
                "source": {"type": "string"},
                "numberOfTests": {"type": "integer"},
                "header": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "object", "additionalProperties": {
                    "type": "object", "required": ["bugType", "description"],
                    "additionalProperties": False,
                    "properties": {"bugType": {"type": "string"}, "description": {"type": "string"}}}},
                "testGroups": {"type": "array", "items": {"allOf": [
                    {"type": "object", "required": ["type", "section", "description", "tests"],
                     "additionalProperties": False,
                     "properties": {"type": {"enum": [g.type for g in self.groups]},
                                    "section": {"type": "string"}, "description": {"type": "string"},
                                    "tests": {"type": "array"}}}] + test_variants}},
            },
            "$defs": {"test": TEST_SCHEMA},
        }


TEST_SCHEMA = {
    "type": "object",
    "required": ["tcId", "comment", "flags", "sections", "inputs", "result"],
    "additionalProperties": False,
    "properties": {
        "tcId": {"type": "integer"},
        "comment": {"type": "string", "minLength": 1},
        "flags": {"type": "array", "items": {"type": "string"}},
        "sections": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "inputs": {"type": "object"},
        "result": {"enum": ["valid", "invalid", "acceptable"]},
        "error": {"enum": list(codec.ERRORS)},
        "errorCode": {"type": "integer"},
        "acceptableErrors": {"type": "array", "items": {"enum": list(codec.ERRORS)}},
        "reason": {"type": "string"},
        "expected": {"type": "object"},
    },
    "if": {"properties": {"result": {"const": "invalid"}}, "required": ["result"]},
    "then": {"required": ["error", "errorCode"]},
}

T_STR = {"type": "string"}
T_INT = {"type": "integer"}
T_BOOL = {"type": "boolean"}
T_ARR = {"type": "array"}
T_OBJ = {"type": "object"}
T_HEX = {"type": "string", "pattern": "^([0-9a-f]{2})*$"}
T_NHEX = {"anyOf": [T_HEX, {"type": "null"}]}
T_NSTR = {"anyOf": [T_STR, {"type": "null"}]}
T_NINT = {"anyOf": [T_INT, {"type": "null"}]}
T_NOBJ = {"anyOf": [T_OBJ, {"type": "null"}]}
T_NARR = {"anyOf": [T_ARR, {"type": "null"}]}


def _obj_schema(fields):
    req = [k for k, v in fields.items() if not k.endswith("?")]
    props = {k.rstrip("?"): v for k, v in fields.items()}
    return {"type": "object", "required": req, "properties": props, "additionalProperties": False}


COMMON_NOTES = {
    "Valid": {"bugType": "BASIC", "description": "A well-formed input every implementation must accept."},
}


def notes(**extra):
    out = dict(COMMON_NOTES)
    for k, (bug, desc) in extra.items():
        out[k] = {"bugType": bug, "description": desc}
    return out

# ---------------------------------------------------------------- offer helpers


def exact_fields(**kw):
    base = dict(scope=ACT_GET, expires=EXPIRES, offer_key=OFFER_PK, nonce=bytes([7]) * 16,
                pay=[of.pay_entry("payment:lightning/charge", 21, "sat")])
    base.update(kw)
    return of.offer_fields(**base)


def route_fields(**kw):
    base = dict(scope=ROUTE_CHAT, route_scope=True, metered=True, expires=EXPIRES,
                info=ORIGIN + "/.well-known/bnap", offer_key=OFFER_PK, nonce=bytes(range(16)),
                pay=[of.pay_entry("bnap:notes", 2100, "sat", rate=500)],
                attest=[of.attest_entry("httpsig:web-bot-auth", "discount", 2000)],
                extra=[(3000000001, b"\x0a\x0a")])
    base.update(kw)
    return of.offer_fields(**base)


def signed(fields, sk=OFFER_SK, mac=MAC_KEY):
    return of.sign_offer(fields, sk, mac)


def replace(fields, t, v):
    out = [(a, b) for a, b in fields if a != t]
    if v is not None:
        out.append((t, v))
    return out


def raw_offer(records):
    """Serialize records in the order given, signature computed over the rest."""
    body = [(t, v) for t, v in records if not codec.is_sig_range(t)]
    S = b"".join(codec.bigsize(t) + codec.bigsize(len(v)) + v for t, v in body)
    sig = schnorr_sign(OFFER_SK, codec.tagged("bnap/offer-sig", S))
    mac = codec.hmac_sha256(MAC_KEY, S)
    return codec.tlv_unsorted(list(records) + [(240, sig), (242, mac)])


def pad_to(fields, size, pad_type=1001, sk=OFFER_SK):
    """Add an unknown odd record so the signed offer is exactly size bytes."""
    n = 0
    while True:
        o = signed(fields + [(pad_type, b"\x00" * n)], sk)
        if len(o) == size:
            return o
        if len(o) > size:
            raise SystemExit("pad_to overshoot")
        n += size - len(o) if n == 0 else 1


def parse_verdict(raw, max_size=4096):
    try:
        o = of.parse_offer(raw, max_size)
        return None, o
    except BnapError as e:
        return e.code, None


VECTORS = json.loads((REPO / "vectors" / "vectors.json").read_text())
V_ROUTE = bytes.fromhex(VECTORS["offer"]["bytes"])
V_EXACT = bytes.fromhex(VECTORS["offer_native"]["without_native"])
V_EXACT_NATIVE = bytes.fromhex(VECTORS["offer_native"]["with_native"])
V_ATTEST = bytes.fromhex(VECTORS["attest_only"]["offer"])

# ---------------------------------------------------------------- bigsize.json


def gen_bigsize():
    cf = CaseFile("bigsize", "BigSize and tu64", [
        "BigSize is the variable-length unsigned integer of BOLT 1 (draft-00 section 2).",
        "tu64 is a big-endian u64 with leading zero bytes removed; zero is the empty string.",
        "Non-minimal encodings of either are MALFORMED. Values are decimal strings so that",
        "64-bit values survive JSON parsers limited to 2^53.",
    ], notes(NonMinimal=("MALFORMED", "A value written in more bytes than its minimal encoding."),
             Truncated=("MALFORMED", "The buffer ends inside the integer."),
             TrailingBytes=("MALFORMED", "Bytes left after exactly one integer was read.")))
    g = cf.group("BigSizeDecode", "2", "Decode a buffer holding exactly one BigSize.",
                 {"hex": T_HEX})
    for n in (0, 252, 253, 65535, 65536, 4294967295, 4294967296, 18446744073709551615):
        b = codec.bigsize(n)
        must(codec.decode_bigsize(b) == n, f"bigsize {n}")
        g.add(f"minimal encoding of {n}", {"hex": hx(b)}, "valid", expected={"value": str(n)},
              flags=["Valid"])
    bad = [("fd00fc", "252 in three bytes", "NonMinimal"), ("fd0000", "0 in three bytes", "NonMinimal"),
           ("fe0000ffff", "65535 in five bytes", "NonMinimal"), ("fe000000fc", "252 in five bytes", "NonMinimal"),
           ("ff00000000ffffffff", "2^32 - 1 in nine bytes", "NonMinimal"),
           ("ff0000000000000000", "0 in nine bytes", "NonMinimal"),
           ("", "empty buffer", "Truncated"), ("fd", "prefix fd with no value", "Truncated"),
           ("fd00", "fd with one byte", "Truncated"), ("fe000100", "fe with three bytes", "Truncated"),
           ("ff00000001000000", "ff with seven bytes", "Truncated"),
           ("0000", "two one-byte values", "TrailingBytes")]
    for h, c, f in bad:
        try:
            codec.decode_bigsize(bytes.fromhex(h))
            must(False, "bigsize accepted " + h)
        except BnapError as e:
            must(e.code == "MALFORMED", h)
        g.add(c, {"hex": h}, "invalid", error="MALFORMED", flags=[f])
    g = cf.group("BigSizeEncode", "14", "Encode; the draft-00 section 14 BigSize vector plus the maximum.",
                 {"value": T_STR})
    for n in (0, 252, 253, 65535, 65536, 4294967296, 18446744073709551615):
        g.add(f"encode {n}", {"value": str(n)}, "valid", expected={"hex": hx(codec.bigsize(n))}, flags=["Valid"])
    g = cf.group("Tu64Decode", "2", "Decode a tu64 value (the whole record value).", {"hex": T_HEX})
    for n in (0, 1, 255, 256, 1791700000, 18446744073709551615):
        g.add(f"minimal tu64 {n}", {"hex": hx(tu64(n))}, "valid", expected={"value": str(n)}, flags=["Valid"])
    for h, c, f in [("00", "zero written as one byte", "NonMinimal"), ("0001", "1 with a leading zero", "NonMinimal"),
                    ("00ff", "255 with a leading zero", "NonMinimal"),
                    ("010000000000000000", "nine bytes", "TrailingBytes")]:
        try:
            codec.parse_tu64(bytes.fromhex(h))
            must(False, "tu64 accepted " + h)
        except BnapError as e:
            must(e.code == "MALFORMED", h)
        g.add(c, {"hex": h}, "invalid", error="MALFORMED", flags=[f])
    g = cf.group("Tu64Encode", "14", "Encode; the draft-00 section 14 tu64 vector.", {"value": T_STR})
    for n in (0, 1, 256, 1791700000):
        g.add(f"encode {n}", {"value": str(n)}, "valid", expected={"hex": hx(tu64(n))}, flags=["Valid"])
    return cf

# ---------------------------------------------------------------- tlv.json


def gen_tlv():
    cf = CaseFile("tlv", "TLV streams, the even/odd rule, entry lists and base64url", [
        "TLV streams are BOLT 1 records with strictly increasing types (draft-00 section 2).",
        "A receiver MUST reject an unknown even type as MALFORMED and MUST ignore an unknown odd",
        "type. Nested streams use only 0-239, the experimental range and GREASE. Objects in the",
        "EvenOddRule group are complete and correctly signed, so the type is the only question.",
    ], notes(Order=("MALFORMED", "Types not strictly increasing."),
             Duplicate=("MALFORMED", "The same type twice."),
             Truncated=("MALFORMED", "A length that runs past the end of the buffer."),
             NonMinimal=("MALFORMED", "A non-minimal BigSize for a type or a length."),
             UnknownEven=("MALFORMED", "An unknown even type."),
             UnknownOdd=("BASIC", "An unknown odd type, which a receiver ignores."),
             Grease=("BASIC", "A GREASE record: odd, 3,000,000,001 to 3,000,000,999."),
             NestedRange=("EDGE", "A nested record outside 0-239, experimental and GREASE. draft-00 says "
                                  "nested streams use only those ranges but names no error for an odd type "
                                  "outside them, so rejecting or ignoring it are both acceptable; bnap_conf rejects."),
             Base64=("MALFORMED", "Not canonical unpadded base64url.")))
    g = cf.group("StreamParse", "2", "Parse a bare TLV stream.", {"hex": T_HEX})
    good = [("", "empty stream"), ("0000", "type 0, empty value"), ("000101020100", "two records"),
            ("fd010003616263", "type 256 written as fd0100"), ("0001ff" + "fd00fd00", "type 253, empty value")]
    for h, c in good:
        recs = codec.parse_stream(bytes.fromhex(h))
        g.add(c, {"hex": h}, "valid", expected={"records": [[r.type, hx(r.value)] for r in recs]}, flags=["Valid"])
    bad = [("02010100 0101".replace(" ", ""), "type 1 after type 2", "Order"),
           ("01010001 0100".replace(" ", ""), "type 1 twice", "Duplicate"),
           ("000501", "length 5, one byte left", "Truncated"),
           ("00", "type with no length", "Truncated"),
           ("fd00fc00", "type 252 in three bytes", "NonMinimal"),
           ("00fd000100", "length 1 in three bytes", "NonMinimal"),
           ("0000fd", "a type prefix with no value", "Truncated")]
    for h, c, f in bad:
        try:
            codec.parse_stream(bytes.fromhex(h))
            must(False, "stream accepted " + h)
        except BnapError as e:
            must(e.code == "MALFORMED", h)
        g.add(c, {"hex": h}, "invalid", error="MALFORMED", flags=[f])

    g = cf.group("EvenOddRule", "2", "Complete objects with one extra record; parse as the named object.",
                 {"object": {"enum": ["offer", "credential", "response", "error"]}, "hex": T_HEX})
    base = exact_fields()
    cases = [
        (1001, "valid", "odd type 1001 (reserved for future socket fields)", ["UnknownOdd"]),
        (1002, "invalid", "even type 1002", ["UnknownEven"]),
        (27, "valid", "odd type 27 in the socket range", ["UnknownOdd"]),
        (28, "invalid", "even type 28 in the socket range", ["UnknownEven"]),
        (241, "valid", "odd type 241 in the signature range", ["UnknownOdd"]),
        (244, "invalid", "even type 244 in the signature range", ["UnknownEven"]),
        (1000000001, "valid", "odd experimental type", ["UnknownOdd"]),
        (1000000000, "invalid", "even experimental type", ["UnknownEven"]),
        (2000000001, "valid", "odd reserved type", ["UnknownOdd"]),
        (3000000001, "valid", "GREASE type 3,000,000,001", ["Grease"]),
        (3000000999, "valid", "GREASE type 3,000,000,999", ["Grease"]),
        (3000000002, "invalid", "even type inside the GREASE range is not GREASE", ["UnknownEven"]),
    ]
    for t, res, c, flags in cases:
        o = signed(base + [(t, b"\x01\x02")])
        code, _ = parse_verdict(o)
        must((code is None) == (res == "valid"), f"offer even/odd {t}")
        g.add("offer: " + c, {"object": "offer", "hex": hx(o)}, res,
              error=None if res == "valid" else "MALFORMED", flags=flags)
    cred_base = dict(offer=V_EXACT, pay=cr.SchemeItem("payment:lightning/charge", b"body", None))
    for t, res, c, flags in [(13, "valid", "odd type 13", ["UnknownOdd"]), (14, "invalid", "even type 14", ["UnknownEven"]),
                             (3000000003, "valid", "GREASE", ["Grease"])]:
        b = cr.build_credential(extra=[(t, b"\x00")], **cred_base)
        try:
            cr.parse_credential(b)
            ok = True
        except BnapError:
            ok = False
        must(ok == (res == "valid"), f"credential even/odd {t}")
        g.add("credential: " + c, {"object": "credential", "hex": hx(b)}, res,
              error=None if res == "valid" else "MALFORMED", flags=flags)
    for t, res, c, flags in [(21, "valid", "odd type 21, covered by the ack", ["UnknownOdd"]),
                             (22, "invalid", "even type 22", ["UnknownEven"])]:
        b = rs.build_response(status=0, charged=0, offer_id=bytes(32), digest=bytes(32), receipt_sk=RECEIPT_SK,
                              settled_at=NOW, extra=[(t, b"\x05")])
        try:
            r = rs.parse_response(b)
            ok = rs.verify_ack(r)
        except BnapError:
            ok = False
        must(ok == (res == "valid"), f"response even/odd {t}")
        g.add("response: " + c, {"object": "response", "hex": hx(b)}, res,
              error=None if res == "valid" else "MALFORMED", flags=flags)
    for t, res, c, flags in [(9, "valid", "odd type 9", ["UnknownOdd"]), (10, "invalid", "even type 10", ["UnknownEven"])]:
        b = codec.build_error("STALE") + codec.tlv([(t, b"\x01")])
        try:
            codec.parse_error(b)
            ok = True
        except BnapError:
            ok = False
        must(ok == (res == "valid"), f"error even/odd {t}")
        g.add("error: " + c, {"object": "error", "hex": hx(b)}, res,
              error=None if res == "valid" else "MALFORMED", flags=flags)

    g = cf.group("NestedEvenOdd", "2", "An offer whose single pay entry carries one extra nested record.",
                 {"hex": T_HEX})
    for t, res, c, flags in [(11, "valid", "odd nested type 11", ["UnknownOdd"]),
                             (12, "invalid", "even nested type 12", ["UnknownEven"]),
                             (1000000001, "valid", "odd experimental nested type", ["UnknownOdd"]),
                             (3000000005, "valid", "GREASE nested type", ["Grease"]),
                             (241, "acceptable", "odd nested type 241, outside the nested ranges", ["NestedRange"]),
                             (1001, "acceptable", "odd nested type 1001, outside the nested ranges", ["NestedRange"]),
                             (240, "invalid", "even nested type 240", ["UnknownEven"])]:
        pe = of.pay_entry("payment:lightning/charge", 21, "sat", extra=[(t, b"\x01")])
        o = signed(exact_fields(pay=[pe]))
        code, _ = parse_verdict(o)
        must((code is None) == (res == "valid"), f"nested {t}")
        g.add(c, {"hex": hx(o)}, res, error="MALFORMED" if res == "invalid" else None,
              acceptable_errors=["MALFORMED"] if res == "acceptable" else None, flags=flags)

    g = cf.group("EntryList", "2", "Parse an entry list: lp(stream) repeated.", {"hex": T_HEX})
    el = codec.entry_list([codec.tlv([(0, b"a")]), codec.tlv([(0, b"b"), (2, b"c")])])
    g.add("two entries", {"hex": hx(el)}, "valid",
          expected={"entries": [hx(e) for e in codec.parse_entry_list(el)]}, flags=["Valid"])
    g.add("empty list", {"hex": ""}, "valid", expected={"entries": []}, flags=["Valid"])
    for h, c in [(hx(el)[:-2], "last entry truncated"), ("05000161", "length prefix past the end")]:
        try:
            codec.parse_entry_list(bytes.fromhex(h))
            must(False, "entry list accepted")
        except BnapError:
            pass
        g.add(c, {"hex": h}, "invalid", error="MALFORMED", flags=["Truncated"])

    g = cf.group("Base64url", "10.2", "Decode a header value: base64url without padding (RFC 4648 section 5).",
                 {"text": T_STR})
    for raw in (b"", b"\x00", b"\x00\x01", b"\xfb\xff", bytes(range(10))):
        g.add(f"{len(raw)} bytes", {"text": codec.b64u(raw)}, "valid", expected={"hex": hx(raw)}, flags=["Valid"])
    g.add("draft-00 10.3 REQUIRED error", {"text": "AAEBAgEQ"}, "valid",
          expected={"hex": "000101020110"}, flags=["Valid"])
    for t, c in [("AA==", "padding"), ("+/8", "standard alphabet"), ("AB", "non-zero trailing bits"),
                 ("A", "one character"), ("AA AA", "embedded space")]:
        try:
            codec.b64u_decode(t)
            must(False, "b64u accepted " + t)
        except BnapError:
            pass
        g.add(c, {"text": t}, "invalid", error="MALFORMED", flags=["Base64"])
    return cf

# ---------------------------------------------------------------- offer.json


def flip_last_bit(raw, rtype):
    """Flip the low bit of the last value byte of record rtype."""
    recs = codec.parse_stream(raw)
    out = []
    for r in recs:
        v = r.value
        if r.type == rtype and v:
            v = v[:-1] + bytes([v[-1] ^ 1])
        out.append((r.type, v))
    return codec.tlv(out)


def gen_offer():
    cf = CaseFile("offer", "The Offer", [
        "Offers are TLV streams signed by an online offer key (draft-00 section 4).",
        "Offers are signed with SHA-256(\"bnap test offer key\"), as in vectors.json, and carry a MAC",
        "under SHA-256(\"bnap test mac key\") unless the case says otherwise. Times are Unix seconds;",
        "every expiry check allows 60 seconds of skew. A client cannot check the MAC.",
    ], notes(Structure=("MALFORMED", "A record missing, of the wrong length or with a bad value."),
             Version=("VERSION", "An unsupported socket version."),
             Size=("TOO_LARGE", "Over the size limit."),
             ClassRule=("MALFORMED", "An offer no gate may build: a binding-class, metering or quota rule "
                                     "of 4.3, 7, 12 or DECISIONS row 25 is broken. No socket code names this; "
                                     "the cases use MALFORMED, the code a validator reports."),
             Signature=("BAD_OFFER", "offer_sig does not verify, or the key is not trusted."),
             Mac=("BAD_OFFER", "The MAC does not verify under any current or retained key."),
             Expired=("STALE", "Expired, or issued in the future, beyond the 60 s skew."),
             Skew=("EDGE", "Exactly at the edge of the 60 s skew allowance."),
             Scope=("WRONG_SCOPE", "The offer names another action or route."),
             NotOffered=("NOT_OFFERED", "The credential uses a scheme the offer does not list."),
             Order=("EDGE", "Two faults at once: the 4.4 order decides the code."),
             Tofu=("EDGE", "No pinned manifest: the client trusts on first use."),
             Advance=("EDGE", "An offer published in advance: no MAC, issued_at, a key the gate holds."),
             UnknownScheme=("BASIC", "An entry whose scheme the client does not know, which it ignores."),
             UnknownOdd=("BASIC", "An unknown odd record, ignored by the receiver."),
             Native=("BASIC", "Native entries and OfferID invariance.")))
    io = {"offer": T_HEX, "max_offer": T_INT}

    g = cf.group("OfferParse", "4.1", "Parse an offer and apply every record rule of 4.1.", io)

    def add_parse(comment, raw, result, error=None, flags=(), max_size=4096, sections=None):
        code, o = parse_verdict(raw, max_size)
        must(code == error, f"offer parse {comment}: got {code}")
        exp = {"offer_id": hx(o.offer_id), "pay": [e.scheme for e in o.pay],
               "attest": [[a.scheme, a.effect_name] for a in o.attest],
               "route_scope": o.route_scope, "metered": o.metered, "ignored": o.ignored} if o else None
        g.add(comment, {"offer": hx(raw), "max_offer": max_size}, result, error=error, expected=exp,
              flags=flags or (["Valid"] if result == "valid" else []), sections=sections)

    add_parse("draft-00 section 14 route offer", V_ROUTE, "valid")
    add_parse("draft-00 section 14 exact offer without native", V_EXACT, "valid")
    add_parse("draft-00 section 14 exact offer with native", V_EXACT_NATIVE, "valid", flags=["Native"])
    add_parse("draft-00 section 14 attestation-only offer (waive, no pay)", V_ATTEST, "valid")
    base = exact_fields()
    add_parse("version 2", signed(replace(base, 0, tu64(2))), "invalid", "VERSION", ["Version"])
    add_parse("version written with a leading zero byte", signed(replace(base, 0, b"\x00\x01")), "invalid",
              "MALFORMED", ["Structure"])
    add_parse("version record missing", signed(replace(base, 0, None)), "invalid", "MALFORMED", ["Structure"])
    for t, name in ((2, "scope"), (10, "expires"), (14, "offer_key"), (16, "nonce")):
        add_parse(f"{name} missing", signed(replace(base, t, None)), "invalid", "MALFORMED", ["Structure"])
    add_parse("offer_sig missing", codec.tlv([(t, v) for t, v in
                                               ((r.type, r.value) for r in codec.parse_stream(signed(base)))
                                               if t != 240]), "invalid", "MALFORMED", ["Structure"])
    for t, n, name in ((2, 31, "scope"), (14, 33, "offer_key"), (16, 15, "nonce")):
        add_parse(f"{name} of {n} bytes", signed(replace(base, t, bytes(n))), "invalid", "MALFORMED", ["Structure"])
    add_parse("offer_sig of 63 bytes", codec.tlv([(r.type, r.value[:63] if r.type == 240 else r.value)
                                                   for r in codec.parse_stream(signed(base))]),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("mac of 31 bytes", codec.tlv([(r.type, r.value[:31] if r.type == 242 else r.value)
                                             for r in codec.parse_stream(signed(base))]),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("route_scope flag with a value", signed(replace(route_fields(), 4, b"\x01")),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("metered flag with a value", signed(replace(route_fields(), 8, b"\x01")), "invalid", "MALFORMED",
              ["Structure"])
    add_parse("expires with a leading zero byte", signed(replace(base, 10, b"\x00" + tu64(EXPIRES))), "invalid",
              "MALFORMED", ["Structure"])
    add_parse("headers record, two lower-case names", signed(exact_fields(headers=["accept", "anthropic-version"])),
              "valid")
    add_parse("headers record with an upper-case name", signed(replace(base, 6, b"Accept")), "invalid",
              "MALFORMED", ["Structure"])
    add_parse("headers record with a space after the comma", signed(replace(base, 6, b"accept, x-a")), "invalid",
              "MALFORMED", ["Structure"])
    add_parse("info that is not UTF-8", signed(replace(base, 12, b"\xff\xfe")), "invalid", "MALFORMED",
              ["Structure"])
    add_parse("no pay and no waive", signed(exact_fields(pay=[], attest=[of.attest_entry("httpauth:DPoP", "discount", 5000)])),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("no pay, one waive", signed(exact_fields(pay=[], attest=[of.attest_entry("httpauth:DPoP", "waive")])),
              "valid")
    for drop, name in ((0, "scheme"), (2, "amount"), (4, "unit")):
        pe = codec.tlv([(t, v) for t, v in [(0, b"payment:lightning/charge"), (2, tu64(21)), (4, b"sat")] if t != drop])
        add_parse(f"pay entry without {name}", signed(exact_fields(pay=[pe])), "invalid", "MALFORMED", ["Structure"])
    add_parse("pay entry amount with a leading zero byte",
              signed(exact_fields(pay=[codec.tlv([(0, b"payment:lightning/charge"), (2, b"\x00\x15"), (4, b"sat")])])),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("the same scheme twice in pay",
              signed(exact_fields(pay=[of.pay_entry("payment:lightning/charge", 21), of.pay_entry("payment:lightning/charge", 22)])),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("quote_expires after expires",
              signed(exact_fields(pay=[of.pay_entry("payment:lightning/charge", 21, quote_expires=EXPIRES + 1)])),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("quote_expires equal to expires",
              signed(exact_fields(pay=[of.pay_entry("payment:lightning/charge", 21, quote_expires=EXPIRES)])), "valid")
    add_parse("metered offer whose entry has no rate",
              signed(route_fields(pay=[of.pay_entry("bnap:notes", 2100, "sat")])), "invalid", "MALFORMED",
              ["Structure"], sections=["4.1", "7"])
    add_parse("empty unit", signed(exact_fields(pay=[of.pay_entry("payment:lightning/charge", 21, "")])), "invalid",
              "MALFORMED", ["Structure"])
    for eff, val, ep, res, c in [(4, None, None, "invalid", "effect 4"),
                                 (2, 0, None, "invalid", "discount of 0 basis points"),
                                 (2, 10001, None, "invalid", "discount of 10,001 basis points"),
                                 (2, None, None, "invalid", "discount without a value"),
                                 (2, 10000, None, "valid", "discount of 10,000 basis points"),
                                 (2, 1, None, "valid", "discount of 1 basis point"),
                                 (3, 0, 60, "invalid", "quota of 0 actions"),
                                 (3, 5, 0, "invalid", "quota with an epoch of 0"),
                                 (3, 5, None, "invalid", "quota without an epoch"),
                                 (3, 1, 1, "valid", "quota of 1 action per second")]:
        ae = codec.tlv([(t, v) for t, v in [(0, b"httpauth:DPoP"), (2, tu64(eff)),
                                            (4, tu64(val) if val is not None else None),
                                            (6, tu64(ep) if ep is not None else None)] if v is not None])
        add_parse("attest entry: " + c, signed(exact_fields(attest=[ae])), res,
                  None if res == "valid" else "MALFORMED", [] if res == "valid" else ["Structure"])
    add_parse("attest entry without an effect", signed(exact_fields(attest=[codec.tlv([(0, b"httpauth:DPoP")])])),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("the same scheme twice in attest",
              signed(exact_fields(attest=[of.attest_entry("httpauth:DPoP", "waive"), of.attest_entry("httpauth:DPoP", "discount", 10)])),
              "invalid", "MALFORMED", ["Structure"])
    nat = of.native_entry(1, "bolt11", b"invoice placeholder")
    add_parse("native pay_index past the end of pay", signed(exact_fields(native=[nat])), "invalid", "MALFORMED",
              ["Structure"])
    add_parse("native record in a route-scope offer",
              signed(route_fields(native=[of.native_entry(0, "bolt11", b"x")])), "invalid", "MALFORMED",
              ["Structure"], sections=["4.3", "12"])
    add_parse("native entry without a kind",
              signed(exact_fields(native=[codec.tlv([(0, b""), (4, b"x")])])), "invalid", "MALFORMED", ["Structure"])
    add_parse("pay entry list truncated", signed(replace(base, 18, codec.entry_list([of.pay_entry("payment:lightning/charge", 21)])[:-1])),
              "invalid", "MALFORMED", ["Structure"])
    add_parse("unknown odd type 27, covered by the OfferID", signed(base + [(27, b"\x01")]), "valid", flags=["UnknownOdd"])
    o4096 = pad_to(base, 4096)
    o4097 = pad_to(base, 4097)
    add_parse("exactly 4,096 bytes", o4096, "valid", sections=["2"])
    add_parse("4,097 bytes", o4097, "invalid", "TOO_LARGE", ["Size"], sections=["2"])
    add_parse("4,097 bytes with max_offer raised to 8,192 by the manifest", o4097, "valid", max_size=8192,
              sections=["2", "9.1"])
    add_parse("4,097 bytes that are also malformed: size is checked first",
              o4097[:-1] + b"\xff", "invalid", "TOO_LARGE", ["Size", "Order"], sections=["2", "4.4"])

    g = cf.group("OfferRules", "4.3", "Offers no gate may build; the registry gives every binding class.",
                 {"offer": T_HEX})

    def add_rule(comment, raw, valid, sections, flags=None):
        o = of.parse_offer(raw)
        v = of.offer_rule_violations(o, REG)
        must(bool(v) != valid, f"rule {comment}: {v}")
        g.add(comment, {"offer": hx(raw)}, "valid" if valid else "invalid",
              error=None if valid else "MALFORMED", reason=v[0] if v else None,
              flags=flags or (["Valid"] if valid else ["ClassRule"]), sections=sections)

    add_rule("route-scope offer with class S and A schemes (section 14)", V_ROUTE, True, ["4.3"])
    add_rule("route-scope offer listing class O httpauth:L402",
             signed(route_fields(metered=False, pay=[of.pay_entry("httpauth:L402", 2100)])), False, ["4.3", "12"])
    add_rule("route-scope offer listing class none httpauth:Bearer as an attestation",
             signed(route_fields(attest=[of.attest_entry("httpauth:Bearer", "required")])), False, ["4.3", "12"])
    add_rule("route-scope offer listing an unknown scheme, which clients ignore",
             signed(route_fields(attest=[of.attest_entry("vnd.example.unknown", "discount", 100)])), True, ["4.3", "4.4"],
             ["UnknownScheme"])
    add_rule("native for class O payment:lightning/charge (section 14)", V_EXACT_NATIVE, True, ["4.1"], ["Native"])
    add_rule("native for class S bnap:notes",
             signed(exact_fields(pay=[of.pay_entry("bnap:notes", 21)], native=[of.native_entry(0, "bolt11", b"x")])),
             False, ["4.1"])
    for eff in ("discount", "waive", "quota"):
        ae = of.attest_entry("httpauth:Bearer", eff, 2000 if eff == "discount" else (5 if eff == "quota" else None),
                             60 if eff == "quota" else None)
        add_rule(f"bearer attestation httpauth:Bearer (class none) trying to {eff}",
                 signed(exact_fields(attest=[ae])), False, ["7"])
    add_rule("bearer attestation httpauth:Bearer as required only",
             signed(exact_fields(attest=[of.attest_entry("httpauth:Bearer", "required")])), True, ["7"])
    add_rule("class O pp:0x0002 discount", signed(exact_fields(attest=[of.attest_entry("pp:0x0002", "discount", 1000)])),
             True, ["7"])
    add_rule("class none value scheme cashu:nut22 at price 0",
             signed(exact_fields(pay=[of.pay_entry("cashu:nut22", 0)])), True, ["7"])
    add_rule("class none value scheme cashu:nut22 at price 1 (DECISIONS row 25)",
             signed(exact_fields(pay=[of.pay_entry("cashu:nut22", 1)])), False, ["7"])
    add_rule("metered offer with httpauth:L402, which has neither refund = atomic nor upto",
             signed(exact_fields(metered=True, pay=[of.pay_entry("httpauth:L402", 2100, rate=500)])), False, ["7"])
    add_rule("metered offer with bnap:notes, refund = atomic", V_ROUTE, True, ["7"])
    add_rule("quota for pp:0x0002, whose registry entry has no quota_id",
             signed(exact_fields(attest=[of.attest_entry("pp:0x0002", "quota", 5, 60)])), False, ["6.2"])
    add_rule("quota for httpauth:DPoP, quota_id the key thumbprint",
             signed(exact_fields(attest=[of.attest_entry("httpauth:DPoP", "quota", 5, 60)])), True, ["6.2"])

    g = cf.group("OfferIdAndSignature", "4.2", "Recompute the OfferID and check offer_sig.", {"offer": T_HEX})
    for raw, c in ((V_EXACT, "exact offer without native"), (V_EXACT_NATIVE, "the same offer with a native record")):
        o = of.parse_offer(raw)
        must(of.verify_offer_sig(o), "vector sig")
        g.add(c + ": same OfferID, different offer_sig", {"offer": hx(raw)}, "valid",
              expected={"offer_id": hx(o.offer_id), "offer_sig": hx(o.offer_sig), "offer_sig_valid": True},
              flags=["Native"], sections=["4.2", "14"])
    o = of.parse_offer(V_ROUTE)
    g.add("route offer: the GREASE record after mac is inside OfferID and offer_sig", {"offer": hx(V_ROUTE)}, "valid",
          expected={"offer_id": hx(o.offer_id), "offer_sig": hx(o.offer_sig), "offer_sig_valid": True},
          flags=["Valid"], sections=["4.2", "14"])
    with241 = signed(base + [(241, b"\x01")])
    o241 = of.parse_offer(with241)
    flipped241 = flip_last_bit(with241, 241)
    of241 = of.parse_offer(flipped241)
    must(of.verify_offer_sig(of241) and of241.offer_id == o241.offer_id, "241 not covered")
    g.add("unknown odd type 241 is in the signature range: flipping it changes neither OfferID nor offer_sig",
          {"offer": hx(flipped241)}, "valid",
          expected={"offer_id": hx(of241.offer_id), "offer_sig": hx(of241.offer_sig), "offer_sig_valid": True},
          flags=["UnknownOdd"], sections=["2", "4.2", "12"])

    gc = cf.group("ClientOfferCheck", "4.4", "The client checks of 4.4 for an offer received with a 402.",
                  {"offer": T_HEX, "now": T_INT, "origin": T_STR, "pin_keys": T_NARR, "scope": T_NHEX,
                   "route_scope": T_NHEX})
    gg = cf.group("GateOfferCheck", "4.4", "The gate checks of 4.4, steps 1 to 6 in order.",
                  {"offer?": T_NHEX, "offer_id?": T_NHEX, "now": T_INT, "mac_keys": T_ARR, "listed_offer_keys": T_ARR,
                   "cache": T_OBJ, "action_scope": T_HEX, "route_scope": T_NHEX, "pay_scheme": T_NSTR,
                   "attest_schemes": T_ARR, "max_offer": T_INT})

    def client(comment, raw, result, error=None, *, now=NOW, pin=PIN_KEYS, scope=ACT_GET, rscope=None,
               flags=(), sections=None):
        chk = of.client_check_offer(raw, now=now, origin=ORIGIN, pin_keys=pin, scope=scope, route_scope=rscope,
                                    registry=REG)
        must(chk.code == error, f"client {comment}: got {chk.code} {chk.reason}")
        gc.add(comment, {"offer": hx(raw), "now": now, "origin": ORIGIN, "pin_keys": pin, "scope": hx(scope),
                         "route_scope": hx(rscope)}, result, error=error, reason=chk.reason,
               flags=flags or (["Valid"] if result == "valid" else []), sections=sections)

    def gate(comment, result, error=None, *, raw=None, oid=None, now=NOW, mac_keys=(MAC_KEY,), listed=(OFFER_PK,),
             cache=None, act=ACT_GET, rscope=None, pay="payment:lightning/charge", attest=(), max_offer=4096,
             flags=(), sections=None):
        state = of.GateOfferState(mac_keys, listed, cache or {}, max_offer)
        try:
            of.gate_check_offer(state, now=now, action_scope=act, route_scope=rscope, offer_raw=raw, offer_id=oid,
                                pay_scheme=pay, attest_schemes=attest)
            code = None
        except BnapError as e:
            code = e.code
        must(code == error, f"gate {comment}: got {code}")
        inputs = {"now": now, "mac_keys": [hx(k) for k in mac_keys], "listed_offer_keys": [hx(k) for k in listed],
                  "cache": {k.hex(): hx(v) for k, v in (cache or {}).items()}, "action_scope": hx(act),
                  "route_scope": hx(rscope), "pay_scheme": pay, "attest_schemes": list(attest), "max_offer": max_offer}
        if raw is not None:
            inputs["offer"] = hx(raw)
        else:
            inputs["offer_id"] = hx(oid)
        gg.add(comment, inputs, result, error=error,
               flags=flags or (["Valid"] if result == "valid" else []), sections=sections)

    ex = signed(base)
    client("exact offer for the request about to be sent", ex, "valid")
    client("route offer for the manifest route the client expects", V_ROUTE, "valid", scope=ACT, rscope=ROUTE_CHAT)
    client("no pinned manifest: trust on first use", ex, "valid", pin=None, flags=["Tofu"])
    client("expires 60 s ago: inside the skew", ex, "valid", now=EXPIRES + 60, flags=["Skew"])
    client("expires 61 s ago", ex, "invalid", "STALE", now=EXPIRES + 61, flags=["Expired"])
    client("issued_at 60 s in the future: inside the skew", signed(exact_fields(issued_at=NOW + 60)), "valid",
           flags=["Skew"])
    client("issued_at 61 s in the future", signed(exact_fields(issued_at=NOW + 61)), "invalid", "STALE",
           flags=["Expired"])
    client("offer_key not in the pinned manifest", signed(exact_fields(offer_key=STRANGER_PK), STRANGER_SK), "invalid", "BAD_OFFER", flags=["Signature"],
           sections=["4.4", "9.3"])
    client("offer_key pinned with use receipt only", ex, "invalid", "BAD_OFFER",
           pin=[{"kid": OFFER_PK.hex(), "use": "receipt", "not_after": NOT_AFTER}], flags=["Signature"],
           sections=["4.4", "9.3"])
    client("offer_key pinned but its not_after has passed", ex, "invalid", "BAD_OFFER",
           pin=[{"kid": OFFER_PK.hex(), "use": "offer", "not_after": NOW - 1}], flags=["Signature"],
           sections=["4.4", "9.3"])
    for t, name in ((2, "scope"), (10, "expires"), (14, "offer_key"), (16, "nonce"), (18, "pay")):
        fl = flip_last_bit(ex, t)
        code, _ = parse_verdict(fl)
        want = code or "BAD_OFFER"
        sc = ACT_GET if t != 2 else codec.parse_stream(fl)[1].value
        client(f"a flipped bit in {name}", fl, "invalid", want, scope=sc, flags=["Signature"], sections=["4.4", "14"])
    client("a flipped bit in offer_sig", flip_last_bit(ex, 240), "invalid", "BAD_OFFER", flags=["Signature"],
           sections=["4.4", "14"])
    client("a flipped bit in mac: a client cannot check the MAC", flip_last_bit(ex, 242), "valid", flags=["Mac"],
           sections=["4.4"])
    client("info on another origin", signed(exact_fields(info="https://evil.example/.well-known/bnap")),
           "invalid", "BAD_OFFER", flags=["Signature"])
    client("info as an origin-relative path", signed(exact_fields(info="/.well-known/bnap")), "valid")
    client("info on the same origin with the default port written out",
           signed(exact_fields(info="https://api.example:443/.well-known/bnap")), "valid")
    client("exact offer for another request", ex, "invalid", "WRONG_SCOPE", scope=ACT_GET_OTHER, flags=["Scope"])
    client("route offer for another route", V_ROUTE, "invalid", "WRONG_SCOPE", scope=ACT, rscope=ROUTE_OTHER,
           flags=["Scope"])
    client("an entry with an unknown scheme is ignored, the offer stays usable",
           signed(exact_fields(pay=[of.pay_entry("vnd.example.unknown", 5), of.pay_entry("payment:lightning/charge", 21)])),
           "valid", flags=["UnknownScheme"])
    adv = of.sign_offer(exact_fields(issued_at=NOW - 10), OFFER_SK, None)
    client("published in advance: no mac, issued_at present", adv, "valid", flags=["Advance"])
    client("no mac and no issued_at", of.sign_offer(base, OFFER_SK, None), "invalid", "BAD_OFFER",
           flags=["Signature"], sections=["4.1", "4.4"])
    client("bearer attestation trying to discount: no gate may build this offer",
           signed(exact_fields(attest=[of.attest_entry("httpauth:Bearer", "discount", 2000)])), "invalid", "MALFORMED",
           flags=["ClassRule"], sections=["4.4", "7"])
    client("version 2", signed(replace(base, 0, tu64(2))), "invalid", "VERSION", flags=["Version"])

    gate("exact offer for this request", "valid", raw=ex)
    gate("MAC under a retained key", "valid", raw=signed(base, mac=RETIRED_MAC), mac_keys=(MAC_KEY, RETIRED_MAC),
         sections=["4.2", "4.4"])
    gate("MAC under a key the gate never had", "invalid", "BAD_OFFER", raw=signed(base, mac=UNKNOWN_MAC),
         mac_keys=(MAC_KEY, RETIRED_MAC), flags=["Mac"])
    for t, name in ((0, "version"), (2, "scope"), (10, "expires"), (14, "offer_key"), (16, "nonce"), (18, "pay")):
        fl = flip_last_bit(ex, t)
        code, o = parse_verdict(fl)
        want = code or "BAD_OFFER"
        act = ACT_GET if t != 2 else o.scope
        gate(f"a flipped bit in {name}", "invalid", want, raw=fl, act=act,
             flags=["Mac"] if want == "BAD_OFFER" else ["Version" if want == "VERSION" else "Structure"],
             sections=["4.4", "14"])
    fl = flip_last_bit(V_ROUTE, 3000000001)
    gate("a flipped bit in the GREASE record of the route offer", "invalid", "BAD_OFFER", raw=fl, act=ACT,
         rscope=ROUTE_CHAT, pay="bnap:notes", flags=["Mac"], sections=["4.2", "14"])
    gate("a flipped bit in offer_sig: the MAC still passes", "valid", raw=flip_last_bit(ex, 240), flags=["Mac"])
    gate("a flipped bit in mac", "invalid", "BAD_OFFER", raw=flip_last_bit(ex, 242), flags=["Mac"])
    gate("published in advance under a key the gate holds and lists", "valid", raw=adv, flags=["Advance"])
    gate("published in advance under a key the offer names but the gate does not hold", "invalid", "BAD_OFFER",
         raw=of.sign_offer(exact_fields(offer_key=STRANGER_PK, issued_at=NOW - 10), STRANGER_SK, None),
         flags=["Advance", "Signature"], sections=["4.4", "12"])
    gate("published in advance without issued_at", "invalid", "BAD_OFFER", raw=of.sign_offer(base, OFFER_SK, None),
         flags=["Advance"])
    gate("published in advance with a broken offer_sig", "invalid", "BAD_OFFER",
         raw=flip_last_bit(adv, 240), flags=["Advance", "Signature"])
    gate("expires 60 s ago: inside the skew", "valid", raw=ex, now=EXPIRES + 60, flags=["Skew"], sections=["2", "4.4"])
    gate("expires 61 s ago", "invalid", "STALE", raw=ex, now=EXPIRES + 61, flags=["Expired"], sections=["2", "4.4"])
    q = signed(exact_fields(pay=[of.pay_entry("payment:lightning/charge", 21, quote_expires=NOW - 100),
                                 of.pay_entry("httpauth:L402", 21)]))
    gate("the chosen entry's quote_expires passed", "invalid", "STALE", raw=q, flags=["Expired"])
    gate("another entry's quote_expires passed, the chosen one is fine", "valid", raw=q, pay="httpauth:L402")
    gate("issued_at 61 s in the future", "invalid", "STALE", raw=signed(exact_fields(issued_at=NOW + 61)),
         flags=["Expired"])
    gate("exact offer sent with another request", "invalid", "WRONG_SCOPE", raw=ex, act=ACT_GET_OTHER, flags=["Scope"])
    gate("route offer for route chat on a request to route images", "invalid", "WRONG_SCOPE", raw=V_ROUTE, act=ACT,
         rscope=ROUTE_OTHER, pay="bnap:notes", flags=["Scope"], sections=["4.3", "4.4"])
    gate("route offer on its own route", "valid", raw=V_ROUTE, act=ACT, rscope=ROUTE_CHAT, pay="bnap:notes",
         attest=("httpsig:web-bot-auth",), sections=["4.3", "4.4"])
    gate("pay scheme not in the offer", "invalid", "NOT_OFFERED", raw=ex, pay="httpauth:L402", flags=["NotOffered"])
    gate("attestation scheme not in the offer", "invalid", "NOT_OFFERED", raw=ex, attest=("httpauth:DPoP",),
         flags=["NotOffered"])
    rid = of.parse_offer(V_ROUTE).offer_id
    gate("offer by reference, cached", "valid", oid=rid, cache={rid: V_ROUTE}, act=ACT, rscope=ROUTE_CHAT,
         pay="bnap:notes", sections=["5.1", "4.4"])
    gate("offer by reference, unknown OfferID", "invalid", "BAD_OFFER", oid=H(b"unknown offer"), cache={rid: V_ROUTE},
         act=ACT, rscope=ROUTE_CHAT, pay="bnap:notes", flags=["Signature"], sections=["5.1"])
    gate("4,097-byte offer", "invalid", "TOO_LARGE", raw=o4097, flags=["Size"], sections=["2", "4.4"])
    gate("order: oversize and malformed gives TOO_LARGE", "invalid", "TOO_LARGE", raw=o4097[:-1] + b"\xff",
         flags=["Order", "Size"])
    gate("order: malformed and a bad MAC gives MALFORMED", "invalid", "MALFORMED",
         raw=signed(base + [(28, b"\x00")], mac=UNKNOWN_MAC), flags=["Order", "Structure"])
    gate("order: version 2 and a bad MAC gives VERSION", "invalid", "VERSION",
         raw=signed(replace(base, 0, tu64(2)), mac=UNKNOWN_MAC), flags=["Order", "Version"])
    gate("order: a bad MAC and expired gives BAD_OFFER", "invalid", "BAD_OFFER", raw=signed(base, mac=UNKNOWN_MAC),
         now=EXPIRES + 1000, flags=["Order", "Mac"])
    gate("order: expired and the wrong scope gives STALE", "invalid", "STALE", raw=ex, now=EXPIRES + 1000,
         act=ACT_GET_OTHER, flags=["Order", "Expired"])
    gate("order: the wrong scope and a scheme not offered gives WRONG_SCOPE", "invalid", "WRONG_SCOPE", raw=ex,
         act=ACT_GET_OTHER, pay="httpauth:L402", flags=["Order", "Scope"])
    return cf

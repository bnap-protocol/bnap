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

# Rejections that have no section 8.2 code: a client refusing an object, or a
# manifest the 9.3 rules refuse. They carry no errorCode; "reason" says why.
CLIENT_LABELS = {
    "CLIENT_REJECT": "a client refuses the object or the action; no socket error code applies",
    "MANIFEST_REJECT": "a client refuses the manifest under the 9.1 and 9.3 rules",
}

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
        if error is not None and error not in codec.ERRORS and error not in CLIENT_LABELS:
            raise SystemExit(f"{self.cf.area}: unknown error {error}")
        self.cf.counter += 1
        t = {"tcId": self.cf.counter, "comment": comment, "flags": list(flags),
             "sections": list(sections or [self.section]), "inputs": inputs, "result": result}
        if error is not None:
            t["error"] = error
            if error in codec.ERRORS:
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
        "error": {"enum": list(codec.ERRORS) + list(CLIENT_LABELS)},
        "errorCode": {"type": "integer"},
        "acceptableErrors": {"type": "array", "items": {"enum": list(codec.ERRORS)}},
        "reason": {"type": "string"},
        "expected": {"type": "object"},
    },
    "if": {"properties": {"result": {"const": "invalid"}}, "required": ["result"]},
    "then": {"required": ["error"]},
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
    est = max(0, size - len(signed(fields + [(pad_type, b"")], sk)))
    for n in range(est, -1, -1):
        o = signed(fields + [(pad_type, b"\x00" * n)], sk)
        if len(o) == size:
            return o
    raise SystemExit("pad_to: no padding gives exactly %d bytes" % size)


def exact_size(build, size):
    """build(n) -> bytes growing with n; find n with len(build(n)) == size."""
    est = max(0, size - len(build(0)))
    for n in range(est, -1, -1):
        b = build(n)
        if len(b) == size:
            return b, n
    raise SystemExit("exact_size: no n gives %d bytes" % size)


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
            code, why = None, None
        except BnapError as e:
            code, why = e.code, e.reason
        must(code == error, f"gate {comment}: got {code}")
        inputs = {"now": now, "mac_keys": [hx(k) for k in mac_keys], "listed_offer_keys": [hx(k) for k in listed],
                  "cache": {k.hex(): hx(v) for k, v in (cache or {}).items()}, "action_scope": hx(act),
                  "route_scope": hx(rscope), "pay_scheme": pay, "attest_schemes": list(attest), "max_offer": max_offer}
        if raw is not None:
            inputs["offer"] = hx(raw)
        else:
            inputs["offer_id"] = hx(oid)
        gg.add(comment, inputs, result, error=error, reason=why,
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

# ---------------------------------------------------------------- credential.json

WBA_BODY = b"sig1=:...placeholder web bot auth signature over the Context...:"
NOTE_Y = H(b"note secret 1")
NOTES_BODY = tlv([(0, NOTE_Y), (2, b"proofs+outputs placeholder")])
BINDING = H(b"tls-exporter placeholder")
DPOP_BODY = b"DPoP proof placeholder with claim bnap_ctx"


def vector_credential(**over):
    """Rebuild the draft-00 section 14 credential; over replaces parts after signing."""
    oid = of.parse_offer(V_ROUTE).offer_id
    ctx = cr.context(oid, ACT, "bnap:notes", ["httpsig:web-bot-auth"], b"")
    dg = cr.digest(ctx, BINDING, NOTES_BODY, [WBA_BODY])
    witness = schnorr_sign(NOTE_SK, dg)
    parts = dict(offer=V_ROUTE, pay=cr.SchemeItem("bnap:notes", NOTES_BODY, witness),
                 attest=[cr.SchemeItem("httpsig:web-bot-auth", WBA_BODY, None)], binding=BINDING)
    parts.update(over)
    return cr.build_credential(**parts)


def gen_credential():
    cf = CaseFile("credential", "The Credential, its envelope and the identifiers", [
        "Credentials are TLV streams (draft-00 section 5). Context, Digest and ReplayKey follow",
        "5.2 and 6.1, with attestations in the credential's sorted order. Scheme bodies are",
        "placeholders, as in vectors.json. The witness key of the class S cases is",
        "SHA-256(\"bnap test note key\"): it signs the Digest, as the bnap:notes registry entry says.",
    ], notes(Structure=("MALFORMED", "A 5.1 rule is broken."),
             Version=("VERSION", "An unsupported socket version."),
             Size=("TOO_LARGE", "Over the size limit; the HTTP cap is DECISIONS row 30."),
             UnknownOdd=("BASIC", "An unknown odd record outside ext, which MUST NOT affect processing."),
             EmptyForms=("BASIC", "The \"or empty\" forms of section 2: absent and empty hash the same."),
             Binding=("BASIC", "The binding is in the Digest, not in the Context or the ReplayKey."),
             PathAttack=("BAD_CREDENTIAL", "A path attacker changed the credential; the class S witness "
                                           "over the Digest no longer verifies."),
             SharedRail=("BASIC", "One payment named by two schemes has one RailId."),
             TwoValue=("MALFORMED", "More than one value credential in one request."),
             Ambiguous=("EDGE", "draft-00 does not settle this; either answer is acceptable.")))

    g = cf.group("CredentialParse", "5.1", "Parse a credential and apply the 5.1 rules. With carrier http, "
                 "the cap is 9,216 bytes (DECISIONS row 30); otherwise max_credential.",
                 {"credential": T_HEX, "max_credential": T_INT, "carrier": {"enum": ["http", "none"]}})

    def add(comment, raw, result, error=None, flags=(), max_c=16384, carrier="none", sections=None):
        limit = min(max_c, cr.HTTP_MAX_CREDENTIAL) if carrier == "http" else max_c
        try:
            c = cr.parse_credential(raw, limit, REG)
            code = None
        except BnapError as e:
            code, c = e.code, None
        must(code == error, f"credential {comment}: got {code}")
        exp = None
        if c is not None:
            exp = {"pay_scheme": c.pay.scheme if c.pay else None, "attest_schemes": c.attest_schemes,
                   "binding": hx(c.binding), "offer_form": "inline" if c.offer is not None else "reference",
                   "ignored": c.ignored}
        g.add(comment, {"credential": hx(raw), "max_credential": max_c, "carrier": carrier}, result, error=error,
              expected=exp, flags=flags or (["Valid"] if result == "valid" else []), sections=sections)

    vc = vector_credential()
    must(len(vc) == VECTORS["credential"]["bytes_len"], "vector credential length")
    add("draft-00 section 14 credential, 581 bytes", vc, "valid")
    rid = of.parse_offer(V_ROUTE).offer_id
    add("the same credential naming its offer by OfferID", vector_credential(offer=None, offer_id=rid), "valid")
    add("both offer and offer_id", vector_credential(offer_id=rid), "invalid", "MALFORMED", ["Structure"])
    add("neither offer nor offer_id", vector_credential(offer=None), "invalid", "MALFORMED", ["Structure"])
    add("neither pay nor attest", cr.build_credential(offer=V_ROUTE), "invalid", "MALFORMED", ["Structure"])
    a1 = cr.SchemeItem("httpauth:DPoP", b"a", None).encode()
    a2 = cr.SchemeItem("httpsig:web-bot-auth", b"b", None).encode()
    add("attest list out of order", cr.build_credential(offer=V_ROUTE, attest=[a2, a1]), "invalid", "MALFORMED",
        ["Structure"])
    add("attest list in order", cr.build_credential(offer=V_ROUTE, attest=[a1, a2]), "valid")
    add("the same attestation scheme twice", cr.build_credential(offer=V_ROUTE, attest=[a1, a1]), "invalid",
        "MALFORMED", ["Structure"])
    add("binding with no class S scheme (DPoP is class A)",
        cr.build_credential(offer=V_ATTEST, attest=[cr.SchemeItem("httpauth:DPoP", DPOP_BODY, None)], binding=BINDING),
        "invalid", "MALFORMED", ["Structure"], sections=["5.1", "5.3"])
    add("binding of 31 bytes", vector_credential(binding=BINDING[:31]), "invalid", "MALFORMED", ["Structure"])
    add("offer_id of 31 bytes", vector_credential(offer=None, offer_id=rid[:31]), "invalid", "MALFORMED",
        ["Structure"])
    add("version 2", cr.build_credential(offer=V_ROUTE, pay=cr.SchemeItem("bnap:notes", b"x", None), version=2),
        "invalid", "VERSION", ["Version"])
    add("version record missing", vc[3:], "invalid", "MALFORMED", ["Structure"])
    add("unknown even type 14", vector_credential(extra=[(14, b"\x00")]), "invalid", "MALFORMED", ["Structure"],
        sections=["2"])
    add("unknown odd type 13 outside ext", vector_credential(extra=[(13, b"\x00")]), "valid", flags=["UnknownOdd"],
        sections=["2"])
    add("GREASE record", vector_credential(extra=[(3000000007, b"\x2a")]), "valid", flags=["UnknownOdd"],
        sections=["2"])
    add("pay item without a scheme", cr.build_credential(offer=V_ROUTE, pay=codec.tlv([(2, b"x")])), "invalid",
        "MALFORMED", ["Structure"])
    add("pay item with an unknown even nested type",
        cr.build_credential(offer=V_ROUTE, pay=codec.tlv([(0, b"bnap:notes"), (2, b"x"), (6, b"y")])),
        "invalid", "MALFORMED", ["Structure"])
    add("ext that is not a TLV stream", vector_credential(ext=b"\x05\x01"), "invalid", "MALFORMED", ["Structure"])
    add("ext with an unknown even extension", vector_credential(ext=codec.tlv([(2, b"x")])), "invalid", "MALFORMED",
        ["Structure"])
    add("ext with an unknown odd extension", vector_credential(ext=codec.tlv([(1, b"x")])), "valid")
    def cbuild(n):
        return cr.build_credential(offer=V_ROUTE, pay=cr.SchemeItem("bnap:notes", bytes(n), None))

    c16384, _ = exact_size(cbuild, 16384)
    c16385, _ = exact_size(cbuild, 16385)
    c9216, _ = exact_size(cbuild, 9216)
    c9217, _ = exact_size(cbuild, 9217)
    add("exactly 16,384 bytes", c16384, "valid", sections=["2"])
    add("16,385 bytes", c16385, "invalid", "TOO_LARGE", ["Size"], sections=["2"])
    add("9,216 bytes on HTTP", c9216, "valid", carrier="http", sections=["10.2"])
    add("9,217 bytes on HTTP: over the carrier cap of DECISIONS row 30", c9217, "invalid", "TOO_LARGE", ["Size"],
        carrier="http", sections=["10.2", "2"])

    g = cf.group("Envelope", "5.2", "Compute Context, Digest and ReplayKey from their inputs.",
                 {"offer_id": T_HEX, "action_scope": T_HEX, "pay_scheme": T_NSTR, "attest_schemes": T_ARR,
                  "ext": T_NHEX, "binding": T_NHEX, "pay_body": T_NHEX, "attest_bodies": T_ARR, "ids": T_ARR})

    def env(comment, *, oid, act, pay, attests, ext, binding, pay_body, bodies, ids, flags=("Valid",),
            sections=None, expect=None):
        ctx = cr.context(oid, act, pay, attests, ext)
        dg = cr.digest(ctx, binding, pay_body, bodies)
        rk = cr.replay_key(ctx, pay_body, bodies, ids)
        if expect:
            for k, v in expect.items():
                must(hx({"context": ctx, "digest": dg, "replay_key": rk}[k]) == v, f"envelope {comment} {k}")
        g.add(comment, {"offer_id": hx(oid), "action_scope": hx(act), "pay_scheme": pay, "attest_schemes": attests,
                        "ext": hx(ext), "binding": hx(binding), "pay_body": hx(pay_body),
                        "attest_bodies": [hx(b) for b in bodies], "ids": [hx(i) for i in ids]}, "valid",
              expected={"context": hx(ctx), "digest": hx(dg), "replay_key": hx(rk)}, flags=flags, sections=sections)
        return ctx, dg, rk

    u_note = cr.use_id("bnap:notes", NOTE_Y)
    u_wba = cr.use_id("httpsig:web-bot-auth", H(b"bot key thumbprint"))
    must([hx(u_note), hx(u_wba)] == VECTORS["credential"]["use_ids"], "use ids")
    vcv = VECTORS["credential"]
    env("draft-00 section 14: notes and Web Bot Auth", oid=rid, act=ACT, pay="bnap:notes",
        attests=["httpsig:web-bot-auth"], ext=b"", binding=BINDING, pay_body=NOTES_BODY, bodies=[WBA_BODY],
        ids=[u_note, u_wba], sections=["5.2", "6.1", "14"],
        expect={"context": vcv["context"], "digest": vcv["digest"], "replay_key": vcv["replay_key"]})
    env("a replay with a changed binding: same Context and ReplayKey, new Digest", oid=rid, act=ACT,
        pay="bnap:notes", attests=["httpsig:web-bot-auth"], ext=b"", binding=H(b"other connection"),
        pay_body=NOTES_BODY, bodies=[WBA_BODY], ids=[u_wba, u_note], flags=["Binding"],
        sections=["5.3", "6.1", "14"],
        expect={"digest": vcv["digest_other_binding"], "replay_key": vcv["replay_key"]})
    va = VECTORS["attest_only"]
    u_dpop = cr.use_id("httpauth:DPoP", H(b"client key thumbprint"))
    env("draft-00 section 14: attestation only, every \"or empty\" form", oid=bytes.fromhex(va["offer_id"]),
        act=ACT, pay=None, attests=["httpauth:DPoP"], ext=None, binding=None, pay_body=None, bodies=[DPOP_BODY],
        ids=[u_dpop], flags=["EmptyForms"], sections=["5.2", "2", "14"],
        expect={"context": va["context"], "digest": va["digest"], "replay_key": va["replay_key"]})
    env("ext present but empty hashes as absent", oid=bytes.fromhex(va["offer_id"]), act=ACT, pay=None,
        attests=["httpauth:DPoP"], ext=b"", binding=b"", pay_body=b"", bodies=[DPOP_BODY], ids=[u_dpop],
        flags=["EmptyForms"], sections=["2"], expect={"context": va["context"], "replay_key": va["replay_key"]})
    env("ext with one extension changes the Context", oid=rid, act=ACT, pay="bnap:notes",
        attests=["httpsig:web-bot-auth"], ext=codec.tlv([(1, b"x")]), binding=BINDING, pay_body=NOTES_BODY,
        bodies=[WBA_BODY], ids=[u_note, u_wba])
    env("pay only, n = 0", oid=rid, act=ACT, pay="bnap:notes", attests=[], ext=None, binding=BINDING,
        pay_body=NOTES_BODY, bodies=[], ids=[u_note])
    env("two attestations, sorted bytewise", oid=rid, act=ACT, pay="bnap:notes",
        attests=["httpauth:DPoP", "httpsig:web-bot-auth"], ext=None, binding=BINDING, pay_body=NOTES_BODY,
        bodies=[DPOP_BODY, WBA_BODY], ids=[u_note, u_dpop, u_wba])
    _, _, rk1 = env("two clients, same request, reusable attestations: client 1", oid=bytes.fromhex(va["offer_id"]),
                    act=ACT, pay=None, attests=["httpauth:DPoP"], ext=None, binding=None, pay_body=None,
                    bodies=[b"DPoP proof of client 1"], ids=[cr.use_id("httpauth:DPoP", H(b"client 1 key"))],
                    sections=["6.1", "15"])
    _, _, rk2 = env("two clients, same request, reusable attestations: client 2 gets another ReplayKey",
                    oid=bytes.fromhex(va["offer_id"]), act=ACT, pay=None, attests=["httpauth:DPoP"], ext=None,
                    binding=None, pay_body=None, bodies=[b"DPoP proof of client 2"],
                    ids=[cr.use_id("httpauth:DPoP", H(b"client 2 key"))], sections=["6.1", "15"])
    must(rk1 != rk2, "two clients share a ReplayKey")

    g = cf.group("UseId", "6.1", "UseId = H_bnap/use(lp(scheme ID) || local ID).", {"scheme": T_STR, "local": T_HEX})
    for scheme, local, c in (("bnap:notes", NOTE_Y, "draft-00 section 14 note Y"),
                             ("httpsig:web-bot-auth", H(b"bot key thumbprint"), "draft-00 section 14 bot key"),
                             ("httpauth:L402", H(b"preimage"), "L402 payment hash"),
                             ("payment:lightning/charge", H(b"preimage"), "MPP payment hash: same bytes, other scheme")):
        g.add(c, {"scheme": scheme, "local": hx(local)}, "valid", expected={"use_id": hx(cr.use_id(scheme, local))},
              flags=["Valid"])
    g = cf.group("RailId", "6.1", "RailId = H_bnap/rail(lp(rail kind) || canonical payment bytes).",
                 {"kind": T_STR, "fields": T_OBJ})
    ph = H(b"preimage")
    must(hx(cr.rail_id("ln", ph)) == VECTORS["rail_id"]["rail_id"], "rail id vector")
    rails = [("ln", {"payment_hash": hx(ph)}, cr.canonical_ln(ph), "draft-00 section 14 Lightning payment"),
             ("onchain", {"txid": hx(H(b"tx")), "vout": 1}, cr.canonical_onchain(H(b"tx"), 1), "on-chain output 1"),
             ("evm", {"chain_id": "eip155:8453", "token": hx(bytes(range(20))), "payer": hx(bytes(range(20, 40))),
                      "nonce": hx(H(b"nonce"))},
              cr.canonical_evm("eip155:8453", bytes(range(20)), bytes(range(20, 40)), H(b"nonce")), "EVM transfer"),
             ("card", {"processor": "example-processor", "payment_id": "pi_123"},
              cr.canonical_card("example-processor", "pi_123"), "card payment")]
    for kind, fields, canon, c in rails:
        g.add(c, {"kind": kind, "fields": fields}, "valid",
              expected={"canonical": hx(canon), "rail_id": hx(cr.rail_id(kind, canon))}, flags=["Valid"])
    g.add("one Lightning payment named by L402 and by MPP: one RailId", {"kind": "ln", "fields": {"payment_hash": hx(ph)}},
          "valid", expected={"canonical": hx(ph), "rail_id": hx(cr.rail_id("ln", ph)),
                             "use_ids": [hx(cr.use_id("httpauth:L402", ph)), hx(cr.use_id("payment:lightning/charge", ph))]},
          flags=["SharedRail"], sections=["6.1"])
    g = cf.group("CounterKeys", "6.2", "Rate and quota counter keys.",
                 {"kind": {"enum": ["rate", "quota"]}, "use_id": T_HEX, "limit": T_INT, "epoch": T_INT, "now": T_INT})
    for kind, lim, ep, now in (("rate", 10, 60, NOW), ("rate", 10, 60, NOW + 60), ("quota", 100, 86400, NOW),
                               ("quota", 100, 86400, NOW + 1)):
        fn = cr.rate_key if kind == "rate" else cr.quota_key
        g.add(f"{kind} key, limit {lim}, epoch {ep}, now {now}",
              {"kind": kind, "use_id": hx(u_dpop), "limit": lim, "epoch": ep, "now": now}, "valid",
              expected={"key": hx(fn(u_dpop, lim, ep, now)), "epoch_index": now // ep}, flags=["Valid"])
    g = cf.group("NativeEnvelope", "5.4", "Synthetic Context and Digest for a native credential.",
                 {"offer_id": T_HEX, "action_scope": T_HEX, "scheme": T_STR, "native_bytes": T_HEX})
    vn = VECTORS["native"]
    nid = bytes.fromhex(VECTORS["offer_native"]["offer_id"])
    for scheme, nb, c in (("payment:lightning/charge", b"MPP credential placeholder", "draft-00 section 14 MPP native"),
                          ("httpauth:L402", b"macaroon:preimage placeholder", "L402 native token")):
        ctx = cr.native_context(nid, ACT, scheme)
        dg = cr.native_digest(ctx, nb)
        if scheme == vn["scheme"]:
            must(hx(ctx) == vn["context"] and hx(dg) == vn["digest"], "native vector")
        g.add(c, {"offer_id": hx(nid), "action_scope": hx(ACT), "scheme": scheme, "native_bytes": hx(nb)}, "valid",
              expected={"context": hx(ctx), "digest": hx(dg)}, flags=["Valid"], sections=["5.4", "14"])

    g = cf.group("WitnessOverDigest", "5.2", "Parse the credential, rebuild Context and Digest for action_scope, "
                 "and verify the pay witness under witness_key. cache maps OfferIDs to offers.",
                 {"credential": T_HEX, "action_scope": T_HEX, "witness_key": T_HEX, "cache": T_OBJ})

    def wit(comment, raw, result, flags, sections=None, act=ACT):
        c = cr.parse_credential(raw, registry=REG)
        oid = of.offer_id_of(c.offer) if c.offer is not None else c.offer_id_ref
        _, dg = cr.credential_envelope(c, oid, act)
        ok = schnorr_verify(schnorr_pub(NOTE_SK), dg, c.pay.witness)
        must(ok == (result == "valid"), f"witness {comment}")
        g.add(comment, {"credential": hx(raw), "action_scope": hx(act), "witness_key": hx(schnorr_pub(NOTE_SK)),
                        "cache": {hx(rid): hx(V_ROUTE)}}, result,
              error=None if result == "valid" else "BAD_CREDENTIAL", flags=flags, sections=sections)

    wit("the section 14 credential as sent", vc, "valid", ["Valid"])
    wit("the offer replaced by its OfferID: the Digest is unchanged", vector_credential(offer=None, offer_id=rid),
        "valid", ["Valid"], ["5.1", "5.2"])
    wit("an unknown odd record added outside ext: ignored", vector_credential(extra=[(13, b"x")]), "valid",
        ["UnknownOdd"], ["2", "12"])
    wit("attestation stripped on the path", vector_credential(attest=[]), "invalid", ["PathAttack"], ["5.2", "12"])
    wit("ext altered on the path", vector_credential(ext=codec.tlv([(1, b"x")])), "invalid", ["PathAttack"],
        ["5.2", "12"])
    wit("pay body altered on the path", vector_credential(
        pay=cr.SchemeItem("bnap:notes", NOTES_BODY + b"\x00", cr.parse_credential(vc).pay.witness)), "invalid",
        ["PathAttack"], ["5.1", "5.2"])
    wit("the credential sent with another request on the same route", vc, "invalid", ["PathAttack"], ["4.3", "5.2"],
        act=hp.action_scope("POST", ORIGIN, "/v1/chat/completions", CHAT_BODY + b" "))

    g = cf.group("ValueCredentialCount", "5.4", "Count the value credentials in one request.",
                 {"bnap_pay": T_BOOL, "bnap_attest_only": T_BOOL, "native": T_ARR})
    for bp, ba, nat, res, c in ((True, False, [], "valid", "one BNAP credential with pay"),
                                (False, False, ["httpauth:L402"], "valid", "one native L402 token"),
                                (True, False, ["httpauth:L402"], "invalid", "a BNAP pay and a native L402 token"),
                                (False, False, ["httpauth:L402", "payment:lightning/charge"], "invalid",
                                 "two native value credentials"),
                                (False, True, ["httpauth:L402"], "acceptable",
                                 "a BNAP attestation-only credential next to a native L402 token")):
        g.add(c, {"bnap_pay": bp, "bnap_attest_only": ba, "native": nat}, res,
              error="MALFORMED" if res == "invalid" else None,
              acceptable_errors=["MALFORMED"] if res == "acceptable" else None,
              flags=["TwoValue"] if res == "invalid" else (["Ambiguous"] if res == "acceptable" else ["Valid"]))
    return cf

# ---------------------------------------------------------------- response.json


def vector_response(**over):
    oid = of.parse_offer(V_ROUTE).offer_id
    args = dict(status=0, charged=340, unit="sat", offer_id=oid, digest=bytes.fromhex(VECTORS["credential"]["digest"]),
                metered_units=850, scheme_result=b"change signatures placeholder", receipt_sk=RECEIPT_SK,
                settled_at=1791700042)
    args.update(over)
    return rs.build_response(**args)


def drop_and_resign(raw, t):
    recs = [(r.type, r.value) for r in codec.parse_stream(raw) if r.type not in (t, 240)]
    body = b"".join(codec.bigsize(a) + codec.bigsize(len(b)) + b for a, b in recs)
    ack = schnorr_sign(RECEIPT_SK, codec.tagged("bnap/ack", body))
    return codec.tlv(recs + ([] if t == 240 else [(240, ack)]))


def gen_response():
    cf = CaseFile("response", "The Response, the receipt rules and errors", [
        "Responses are signed by the receipt key SHA-256(\"bnap test receipt key\") (draft-00 8.1).",
        "ClientReceiptCheck applies 9.3 \"on a receipt\" and binds the receipt to the request the",
        "client sent: its Digest, its OfferID and, where the offer allows, the charge.",
    ], notes(Structure=("MALFORMED", "A required record missing or a bad value."),
             Version=("VERSION", "An unsupported socket version."),
             Size=("TOO_LARGE", "Over 8,192 bytes."),
             Ack=("CLIENT_REJECT", "The ack does not verify: a record changed after signing."),
             Key=("CLIENT_REJECT", "The receipt key is not pinned for use receipt at settled_at."),
             Clock=("CLIENT_REJECT", "settled_at more than 60 s from the client's clock, without replayed."),
             Binding=("CLIENT_REJECT", "The receipt answers another request or charges something else."),
             UnknownOdd=("BASIC", "An unknown odd record."),
             Replayed=("BASIC", "A replayed receipt keeps the original settled_at.")))
    g = cf.group("ResponseParse", "8.1", "Parse a Response and check the ack.", {"response": T_HEX, "max_response": T_INT})

    def add(comment, raw, result, error=None, flags=(), max_r=8192, ack_ok=True):
        try:
            r = rs.parse_response(raw, max_r)
            code = None
        except BnapError as e:
            code, r = e.code, None
        must(code == error, f"response {comment}: {code}")
        exp = None
        if r is not None:
            must(rs.verify_ack(r) == ack_ok, f"ack {comment}")
            exp = {"status": r.status_name, "replayed": r.replayed, "charged": r.charged, "unit": r.unit,
                   "metered_units": r.metered_units, "settled_at": r.settled_at, "ack_valid": rs.verify_ack(r)}
        g.add(comment, {"response": hx(raw), "max_response": max_r}, result, error=error, expected=exp,
              flags=flags or (["Valid"] if result == "valid" else []))

    vr = vector_response()
    must(hx(vr) == VECTORS["response"]["bytes"], "vector response")
    add("draft-00 section 14 Response", vr, "valid")
    for t, name in ((2, "status"), (6, "charged"), (10, "offer_id"), (12, "digest"), (18, "receipt_key"),
                    (20, "settled_at"), (240, "ack")):
        add(f"{name} missing", drop_and_resign(vr, t), "invalid", "MALFORMED", ["Structure"])
    add("status 2", rs.build_response(status=2, charged=0, offer_id=bytes(32), digest=bytes(32),
                                      receipt_sk=RECEIPT_SK, settled_at=NOW),
        "invalid", "MALFORMED", ["Structure"])
    add("replayed flag with a value", codec.tlv(sorted([(r.type, r.value) for r in codec.parse_stream(vr)] + [(4, b"\x01")])),
        "invalid", "MALFORMED", ["Structure"])
    v2 = codec.tlv([(r.type, tu64(2) if r.type == 0 else r.value) for r in codec.parse_stream(vr)])
    add("version 2", v2, "invalid", "VERSION", ["Version"])
    add("digest of 31 bytes", vector_response(digest=bytes(31)), "invalid", "MALFORMED", ["Structure"])
    r8192, _ = exact_size(lambda n: vector_response(scheme_result=bytes(n)), 8192)
    r8193, _ = exact_size(lambda n: vector_response(scheme_result=bytes(n)), 8193)
    add("exactly 8,192 bytes", r8192, "valid")
    add("8,193 bytes", r8193, "invalid", "TOO_LARGE", ["Size"])
    add("unknown odd type 21, signed", vector_response(extra=[(21, b"x")]), "valid", flags=["UnknownOdd"])

    g = cf.group("ClientReceiptCheck", "9.3", "The client's receipt rules.",
                 {"response": T_HEX, "now": T_INT, "pin_keys": T_NARR, "digest": T_NHEX, "offer_id": T_NHEX,
                  "has_pay": T_BOOL, "metered": T_BOOL, "expected_charge": T_NINT})
    oid = of.parse_offer(V_ROUTE).offer_id
    dg = bytes.fromhex(VECTORS["credential"]["digest"])

    def rc(comment, raw, result, flags, *, now=1791700050, pin=PIN_KEYS, digest=dg, offer_id=oid, has_pay=True,
           metered=True, charge=340, sections=None):
        chk = rs.client_check_receipt(raw, now=now, pin_keys=pin, digest=digest, offer_id=offer_id,
                                      has_pay=has_pay, metered=metered, expected_charge=charge)
        must(chk.ok == (result == "valid"), f"receipt {comment}: {chk.reason}")
        err = None
        if result == "invalid":
            err = chk.reason.split(":")[0] if chk.reason.split(":")[0] in codec.ERRORS else "CLIENT_REJECT"
        g.add(comment, {"response": hx(raw), "now": now, "pin_keys": pin, "digest": hx(digest),
                        "offer_id": hx(offer_id), "has_pay": has_pay, "metered": metered, "expected_charge": charge},
              result, error=err, reason=chk.reason, flags=flags, sections=sections)

    rc("the section 14 Response, 8 s after settlement", vr, "valid", ["Valid"])
    rc("settled_at 60 s ago", vr, "valid", ["Valid"], now=1791700102)
    rc("settled_at 61 s ago, not replayed", vr, "invalid", ["Clock"], now=1791700103)
    rc("settled_at a day ago, replayed", vector_response(replayed=True), "valid", ["Replayed"], now=1791786442,
       sections=["8.1", "9.3", "6.4"])
    rc("receipt_key not pinned", vector_response(receipt_sk=STRANGER_SK), "invalid", ["Key"])
    rc("receipt_key pinned with use offer", vr, "invalid", ["Key"],
       pin=[{"kid": RECEIPT_PK.hex(), "use": "offer", "not_after": NOT_AFTER}])
    rc("receipt_key not_after before settled_at", vr, "invalid", ["Key"],
       pin=[{"kid": RECEIPT_PK.hex(), "use": "receipt", "not_after": 1791700041}])
    rc("receipt_key not_after equal to settled_at", vr, "valid", ["Valid"],
       pin=[{"kid": RECEIPT_PK.hex(), "use": "receipt", "not_after": 1791700042}])
    rc("the Digest of another request", vr, "invalid", ["Binding"], digest=H(b"other"), sections=["8.1"])
    rc("the OfferID of another offer", vr, "invalid", ["Binding"], offer_id=H(b"other"), sections=["8.1"])
    rc("unit missing although the credential has pay", vector_response(unit=None), "invalid", ["Binding"],
       sections=["8.1"])
    rc("metered_units missing in a metered offer", vector_response(metered_units=None), "invalid", ["Binding"],
       sections=["8.1"])
    rc("a charge other than the one the client computed", vector_response(charged=341), "invalid", ["Binding"],
       sections=["7", "8.1"])
    for r in codec.parse_stream(vr):
        if r.value and r.type != 0:
            fl = codec.tlv([(x.type, (x.value[:-1] + bytes([x.value[-1] ^ 1])) if x.type == r.type else x.value)
                            for x in codec.parse_stream(vr)])
            try:
                rr = rs.parse_response(fl)
                kind = "ack" if not rs.verify_ack(rr) else "ok"
            except BnapError:
                kind = "parse"
            if kind == "ok":
                continue
            rc(f"a flipped bit in record {r.type}", fl, "invalid", ["Ack"] if kind == "ack" else ["Ack"],
               sections=["8.1", "12", "14"])
    rc("unknown odd type 21 added after signing", codec.tlv(sorted([(x.type, x.value) for x in codec.parse_stream(vr)]
                                                                    + [(21, b"x")])), "invalid", ["Ack"],
       sections=["8.1", "12"])
    rc("odd type 241 added after signing: the signature range is not covered",
       codec.tlv(sorted([(x.type, x.value) for x in codec.parse_stream(vr)] + [(241, b"x")])), "valid",
       ["UnknownOdd"], sections=["2", "8.1"])

    g = cf.group("ErrorParse", "8.2", "Parse an Error TLV.", {"hex": T_HEX})
    for name in codec.ERRORS:
        b = codec.build_error(name, retry_after=5 if name in codec.NEEDS_RETRY_AFTER else None)
        e = codec.parse_error(b)
        g.add(f"{name}", {"hex": hx(b)}, "valid", flags=["Valid"],
              expected={"code": e.code, "name": e.name, "scheme_code": None, "detail": None,
                        "retry_after": e.retry_after})
    b = codec.b64u_decode("AAEBAgEQ")
    g.add("draft-00 10.3 BNAP-Error AAEBAgEQ", {"hex": hx(b)}, "valid", flags=["Valid"], sections=["8.2", "10.3"],
          expected={"code": 16, "name": "REQUIRED", "scheme_code": None, "detail": None, "retry_after": None})
    b = codec.build_error("BAD_CREDENTIAL", scheme_code="bnap:notes/OUTPUT_REUSED", detail="output reused")
    g.add("BAD_CREDENTIAL with a scheme code and detail", {"hex": hx(b)}, "valid", flags=["Valid"],
          expected={"code": 10, "name": "BAD_CREDENTIAL", "scheme_code": "bnap:notes/OUTPUT_REUSED",
                    "detail": "output reused", "retry_after": None})
    b = codec.tlv([(0, tu64(1)), (2, tu64(1001))])
    g.add("code 1001, assigned by the registry", {"hex": hx(b)}, "valid", flags=["Valid"],
          expected={"code": 1001, "name": "code-1001", "scheme_code": None, "detail": None, "retry_after": None})
    for raw, c, err, fl in ((codec.tlv([(0, tu64(1)), (2, tu64(5)), (6, b"d" * 256)]), "detail of 256 bytes", None, "Valid"),
                            (codec.tlv([(0, tu64(1)), (2, tu64(5)), (6, b"d" * 257)]), "detail of 257 bytes", "MALFORMED", "Structure"),
                            (codec.tlv([(0, tu64(1))]), "code missing", "MALFORMED", "Structure"),
                            (codec.tlv([(0, tu64(2)), (2, tu64(5))]), "version 2", "VERSION", "Version"),
                            (codec.tlv([(0, tu64(1)), (2, tu64(5)), (10, b"")]), "unknown even type 10", "MALFORMED", "Structure"),
                            (codec.tlv([(0, tu64(1)), (2, tu64(5)), (6, b"\xff")]), "detail not UTF-8", "MALFORMED", "Structure")):
        try:
            codec.parse_error(raw)
            code = None
        except BnapError as e:
            code = e.code
        must(code == err, f"error parse {c}")
        g.add(c, {"hex": hx(raw)}, "valid" if err is None else "invalid", error=err, flags=[fl])
    g = cf.group("ErrorHttpStatus", "8.2", "The HTTP status, fresh offer and retry_after of each code.",
                 {"name": T_STR})
    for name, (code, status) in codec.ERRORS.items():
        g.add(name, {"name": name}, "valid", flags=["Valid"],
              expected={"code": code, "http_status": status, "fresh_offer": name in codec.FRESH_OFFER,
                        "retry_after": name in codec.NEEDS_RETRY_AFTER})
    return cf

# ---------------------------------------------------------------- manifest.json


def vector_manifest_obj(**over):
    m = {"bnap": 1, "origin": ORIGIN, "seq": 1, "issued": ISSUED, "max_age": 604800,
         "root": ROOT_PK.hex(), "backup": BACKUP_PK.hex(), "required": True,
         "keys": [{"kid": OFFER_PK.hex(), "use": "offer", "not_after": NOT_AFTER},
                  {"kid": RECEIPT_PK.hex(), "use": "receipt", "not_after": NOT_AFTER}],
         "limits": {"replay_window": 86400, "pending_timeout": 300, "max_offer": 4096,
                    "max_credential": 16384, "max_response": 8192},
         "carriers": ["http"],
         "routes": [{"id": "chat", "match": "POST /v1/chat/completions", "scope": "route", "metered": True,
                     "meter": "tokens", "price": {"sat": 2100}, "headers": [],
                     "pay": ["bnap:notes", "httpauth:L402"],
                     "attest": [{"scheme": "httpsig:web-bot-auth", "effect": "discount", "value": 2000}]}]}
    m.update(over)
    return m


def signed_manifest(obj, sk=ROOT_SK):
    return mf.jcs(mf.sign_manifest(obj, sk))


def gen_manifest():
    cf = CaseFile("manifest", "The manifest, JCS and pinning", [
        "The manifest is JSON at /.well-known/bnap, signed by its root key over",
        "H_bnap/manifest(JCS(manifest without sig)) (draft-00 9.1). Manifests are given as the exact",
        "bytes in hex. JCS assumes I-JSON (RFC 7493), so duplicate member names, non-integer numbers,",
        "integers beyond 2^53, null and lone surrogates are refused: two parsers must never read two",
        "documents out of one signed byte string. Root key SHA-256(\"bnap test root key\"), backup",
        "SHA-256(\"bnap test backup key\"), as in vectors.json.",
    ], notes(Document=("MANIFEST_REJECT", "A 9.1 document rule is broken."),
             Signature=("MANIFEST_REJECT", "sig does not verify under root."),
             Time=("MANIFEST_REJECT", "issued, max_age and the client's clock disagree beyond 60 s."),
             Skew=("EDGE", "At the edge of the 60 s skew."),
             DuplicateMember=("MANIFEST_REJECT", "Two members with one name: a parser differential on signed JSON."),
             IJson=("MANIFEST_REJECT", "A value I-JSON and 9.1 do not allow."),
             Rollback=("MANIFEST_REJECT", "A lower seq, or the same seq with other bytes."),
             Rotation=("BASIC", "A root rotation signed by the pinned backup."),
             Stolen=("MANIFEST_REJECT", "The current root tries to replace the backup."),
             DoubleRotation=("MANIFEST_REJECT", "A client that missed one rotation sees a second."),
             Lapse=("EDGE", "The pin lapsed, so the client trusts on first use again."),
             Native=("CLIENT_REJECT", "A native challenge the 9.3 rules forbid paying."),
             Fetch=("CLIENT_REJECT", "A fetch the 9.3 rules forbid.")))
    g = cf.group("ManifestDocument", "9.1", "Parse strictly, check the 9.1 rules, the root signature and the "
                 "issued window at now.", {"manifest": T_HEX, "origin": T_STR, "now": T_INT})
    now = ISSUED + 100

    def doc(comment, raw, result, flags=(), origin=ORIGIN, at=now, sections=None):
        try:
            obj = mf.parse_json_strict(raw)
            probs = mf.document_problems(obj, origin=origin, now=at)
        except mf.ManifestReject as e:
            probs = [(e.reason, e.detail)]
        must((not probs) == (result == "valid"), f"manifest {comment}: {probs}")
        exp = {"signing_input": hx(mf.signing_input(obj))} if not probs else None
        g.add(comment, {"manifest": hx(raw), "origin": origin, "now": at}, result,
              error=None if result == "valid" else "MANIFEST_REJECT", reason=probs[0][0] if probs else None,
              expected=exp, flags=flags or (["Valid"] if result == "valid" else []), sections=sections)

    base = vector_manifest_obj()
    vm = signed_manifest(base)
    must(mf.jcs({k: v for k, v in mf.parse_json_strict(vm).items() if k != "sig"}).decode() == VECTORS["manifest"]["jcs"],
         "manifest jcs vector")
    must(mf.parse_json_strict(vm)["sig"] == VECTORS["manifest"]["sig"], "manifest sig vector")
    doc("draft-00 section 14 manifest, JCS bytes", vm, "valid")
    pretty = json.dumps(mf.sign_manifest(base, ROOT_SK), indent=2).encode()
    doc("the same manifest pretty-printed: the signature is over JCS, not the bytes", pretty, "valid")
    obj = mf.parse_json_strict(vm)
    obj["seq"] = 2
    doc("seq changed after signing", mf.jcs(obj), "invalid", ["Signature"])
    doc("bnap 2", signed_manifest(vector_manifest_obj(bnap=2)), "invalid", ["Document"])
    doc("origin of another site", vm, "invalid", ["Document"], origin="https://other.example")
    for o, c in (("https://API.example", "upper-case host"), ("https://api.example:443", "default port written out"),
                 ("https://api.example/", "trailing slash")):
        doc(f"origin with a {c}", signed_manifest(vector_manifest_obj(origin=o)), "invalid", ["Document"],
            origin=o)
    doc("max_age of 2,592,000 s", signed_manifest(vector_manifest_obj(max_age=2592000)), "valid", sections=["9.1"])
    doc("max_age of 2,592,001 s", signed_manifest(vector_manifest_obj(max_age=2592001)), "invalid", ["Document"])
    doc("issued 60 s in the future", vm, "valid", ["Skew"], at=ISSUED - 60, sections=["9.3"])
    doc("issued 61 s in the future", vm, "invalid", ["Time"], at=ISSUED - 61, sections=["9.3"])
    doc("issued + max_age + 60", vm, "valid", ["Skew"], at=ISSUED + 604800 + 60, sections=["9.3"])
    doc("issued + max_age + 61", vm, "invalid", ["Time"], at=ISSUED + 604800 + 61, sections=["9.3"])
    t = vm.decode()
    dup_root = t.replace('"root":"', '"root":"' + STRANGER_PK.hex() + '","root":"', 1).encode()
    doc("two root members, the second the signing root", dup_root, "invalid", ["DuplicateMember"])
    dup_root2 = t.replace('"routes":', '"root":"' + STRANGER_PK.hex() + '","routes":', 1).encode()
    doc("two root members, the first the signing root", dup_root2, "invalid", ["DuplicateMember"])
    doc("a duplicate written with an escape: \\u0072oot", t.replace('"routes":', '"\\u0072oot":"' + ROOT_PK.hex()
                                                                    + '","routes":', 1).encode(),
        "invalid", ["DuplicateMember"])
    doc("pay twice inside routes[0]", t.replace('"pay":[', '"pay":["httpauth:L402"],"pay":[', 1).encode(), "invalid",
        ["DuplicateMember"])
    doc("seq written as 1.0", t.replace('"seq":1', '"seq":1.0', 1).encode(), "invalid", ["IJson"])
    doc("issued written with an exponent", t.replace('"issued":1791700000', '"issued":1.7917e9', 1).encode(),
        "invalid", ["IJson"])
    doc("seq of 2^53", signed_manifest(vector_manifest_obj(seq=1 << 53)), "valid", sections=["9.1"])
    doc("seq of 2^53 + 1", t.replace('"seq":1', '"seq":9007199254740993', 1).encode(), "invalid", ["IJson"])
    doc("required set to null", t.replace('"required":true', '"required":null', 1).encode(), "invalid", ["IJson"])
    doc("a lone surrogate in a string", t.replace('"meter":"tokens"', '"meter":"\\ud800"', 1).encode(), "invalid",
        ["IJson"])
    doc("a byte order mark", b"\xef\xbb\xbf" + vm, "invalid", ["IJson"])
    doc("bytes that are not UTF-8", vm.replace(b'"tokens"', b'"tok\xffns"', 1), "invalid", ["IJson"])
    doc("a non-ASCII meter name, signed over its JCS form",
        signed_manifest(vector_manifest_obj(routes=[dict(base["routes"][0], meter="tökens")])), "valid")
    for k, v, c in (("effect", "percent", "an attest effect named percent"),):
        r = dict(base["routes"][0])
        r["attest"] = [{"scheme": "httpsig:web-bot-auth", "effect": v, "value": 2000}]
        doc(c, signed_manifest(vector_manifest_obj(routes=[r])), "invalid", ["Document"])
    for field, v, c in (("scope", "global", "route scope global"), ("match", "POST/v1", "match without a space"),
                        ("headers", ["Accept"], "an upper-case listed header")):
        doc(c, signed_manifest(vector_manifest_obj(routes=[dict(base["routes"][0], **{field: v})])), "invalid",
            ["Document"])
    doc("a key entry with use sign", signed_manifest(vector_manifest_obj(keys=[{"kid": OFFER_PK.hex(), "use": "sign",
                                                                                "not_after": NOT_AFTER}])),
        "invalid", ["Document"])
    noback = vector_manifest_obj()
    del noback["backup"]
    doc("backup missing", signed_manifest(noback), "invalid", ["Document"])

    g = cf.group("JCS", "9.1", "RFC 8785 serialization of a parsed JSON value.", {"json": T_STR})
    for src, c in (('{"b":1,"a":{"d":true,"c":false}}', "nested member order"),
                   ('{"a":"\\u00e9"}', "an escaped non-ASCII character becomes literal UTF-8"),
                   ('{"a":"\\u001f\\n\\t\\"\\\\/"}', "control characters, quote, backslash and solidus"),
                   ('{"a":" "}', "U+2028 stays literal"),
                   ('{"a":[3,1,2],"b":[]}', "arrays keep their order"),
                   ('{ "z" : 0 , "y" : -1 }', "whitespace removed, integers as written"),
                   ('{}', "empty object")):
        out = mf.jcs(mf.parse_json_strict(src.encode()))
        g.add(c, {"json": src}, "valid", expected={"jcs": out.decode(), "jcs_hex": hx(out)}, flags=["Valid"])

    g = cf.group("Pinning", "9.3", "Apply fetch(origin) of 9.3 with an existing pin (or none).",
                 {"pin": T_NOBJ, "manifest": T_HEX, "origin": T_STR, "now": T_INT})

    def pin_of(raw, at):
        return mf.fetch_accept(raw, origin=ORIGIN, now=at)

    def pin_case(comment, pin, raw, at, result, flags, sections=None):
        try:
            p = mf.fetch_accept(raw, origin=ORIGIN, now=at, pin=pin)
            reason = None
        except mf.ManifestReject as e:
            p, reason = None, e.reason
        must((p is not None) == (result == "valid"), f"pin {comment}: {reason}")
        exp = None
        if p is not None:
            exp = {"root": p.root, "backup": p.backup, "seq": p.seq, "hash": hx(p.hash), "required": p.required,
                   "until": p.until}
        g.add(comment, {"pin": pin.to_json() if pin else None, "manifest": hx(raw), "origin": ORIGIN, "now": at},
              result, error=None if p else "MANIFEST_REJECT", reason=reason, expected=exp, flags=flags,
              sections=sections)

    m1 = vm
    p1 = pin_of(m1, now)
    m2 = signed_manifest(vector_manifest_obj(seq=2))
    p2 = pin_of(m2, now)
    next_pk = schnorr_pub(NEXT_BACKUP_SK)
    third_pk = schnorr_pub(THIRD_SK)
    rot = signed_manifest(vector_manifest_obj(seq=3, root=BACKUP_PK.hex(), backup=next_pk.hex()), BACKUP_SK)
    stolen = signed_manifest(vector_manifest_obj(seq=3, backup=third_pk.hex()))
    double = signed_manifest(vector_manifest_obj(seq=4, root=next_pk.hex(), backup=third_pk.hex()), NEXT_BACKUP_SK)
    late_issued = ISSUED + 700000
    double_late = signed_manifest(vector_manifest_obj(seq=4, issued=late_issued, root=next_pk.hex(),
                                                      backup=third_pk.hex()), NEXT_BACKUP_SK)
    pin_case("first contact: trust on first use", None, m1, now, "valid", ["Valid"])
    pin_case("refetch, the same bytes", p1, m1, now + 400, "valid", ["Valid"])
    pin_case("refetch, a higher seq", p1, m2, now + 400, "valid", ["Valid"])
    pin_case("rollback to a lower seq", p2, m1, now + 400, "invalid", ["Rollback"], ["9.3", "15"])
    pin_case("the same seq with other bytes", p1, json.dumps(mf.sign_manifest(base, ROOT_SK), indent=1).encode(),
             now + 400, "invalid", ["Rollback"], ["9.3", "15"])
    pin_case("rotation: signed by the pinned backup, which it names as root", p1, rot, now + 400, "valid",
             ["Rotation"], ["9.2", "9.3"])
    pin_case("the current root replaces the backup", p1, stolen, now + 400, "invalid", ["Stolen"], ["9.2", "9.3"])
    pin_case("a second rotation seen by a client that missed the first", p1, double, now + 400, "invalid",
             ["DoubleRotation"], ["9.2", "9.3", "14"])
    pin_case("a manifest naming the backup as root but signed by the old root", p1,
             mf.jcs(dict(mf.sign_manifest(vector_manifest_obj(seq=3, root=BACKUP_PK.hex(), backup=next_pk.hex()),
                                          ROOT_SK))), now + 400, "invalid", ["Signature"], ["9.2"])
    pin_case("the pin lapsed: any valid manifest is trusted on first use again", p1, double_late, late_issued + 10,
             "valid", ["Lapse"], ["9.2", "9.3"])
    edge = signed_manifest(vector_manifest_obj(max_age=2592000))
    pin_case("pin until is capped at now + 30 days", None, edge, ISSUED - 60, "valid", ["Skew"], ["9.3"])

    g = cf.group("NativeChallenge", "9.3", "May the client pay this native artifact? via_header: it came in a "
                 "native header field rather than from a BNAP offer's native record.",
                 {"pin": T_NOBJ, "now": T_INT, "native": T_HEX, "via_header": T_BOOL, "offers": T_ARR,
                  "scope": T_HEX})
    nat_bytes = of.parse_offer(V_EXACT_NATIVE).native[0].data
    pin_open = mf.Pin(ROOT_PK.hex(), BACKUP_PK.hex(), 1, H(b"x"), False, PIN_KEYS, NOT_AFTER)
    pin_req = mf.Pin(ROOT_PK.hex(), BACKUP_PK.hex(), 1, H(b"x"), True, PIN_KEYS, NOT_AFTER)
    for pin, native, via, scope, res, c, at in (
            (None, b"some other invoice", True, ACT, "valid", "no pin: any native challenge", NOW),
            (pin_open, nat_bytes, True, ACT, "valid", "pin, bytes equal a native entry of a passing offer", NOW),
            (pin_open, b"some other invoice", True, ACT, "invalid", "pin, bytes in no passing offer", NOW),
            (pin_open, nat_bytes, True, ACT_GET_OTHER, "invalid", "pin, the offer carrying it fails 4.4 (scope)", NOW),
            (pin_req, nat_bytes, True, ACT, "invalid", "bnap-required pin: never through a native header", NOW),
            (pin_req, nat_bytes, False, ACT, "valid", "bnap-required pin: through the BNAP offer", NOW),
            (pin_req, nat_bytes, True, ACT, "valid", "bnap-required pin that lapsed", NOT_AFTER + 1)):
        passing = [chk.offer for _, chk in cl.usable_offers([V_EXACT_NATIVE], now=at, origin=ORIGIN, pin=pin,
                                                             scope=scope, route_scope=None, registry=REG)]
        ok, reason = cl.decide_native(native, passing, pin, at, via)
        must(ok == (res == "valid"), f"native {c}: {reason}")
        g.add(c, {"pin": pin.to_json() if pin else None, "now": at, "native": hx(native), "via_header": via,
                  "offers": [hx(V_EXACT_NATIVE)], "scope": hx(scope)}, res,
              error=None if ok else "CLIENT_REJECT", reason=reason, flags=["Valid"] if ok else ["Native"])

    g = cf.group("FetchRules", "9.3", "May the client fetch the manifest now?",
                 {"url": T_STR, "last_fetch": T_NINT, "now": T_INT})
    for url, last, at, res, c in (("https://api.example/.well-known/bnap", None, NOW, "valid", "first fetch over HTTPS"),
                                  ("http://api.example/.well-known/bnap", None, NOW, "invalid", "plain HTTP"),
                                  ("https://api.example/.well-known/bnap", NOW - 299, NOW, "invalid", "299 s after the last fetch"),
                                  ("https://api.example/.well-known/bnap", NOW - 300, NOW, "valid", "300 s after the last fetch")):
        ok, why = mf.may_fetch(url, last, at)
        must(ok == (res == "valid"), "fetch " + c)
        g.add(c, {"url": url, "last_fetch": last, "now": at}, res, error=None if res == "valid" else "CLIENT_REJECT",
              reason=why, flags=["Valid"] if res == "valid" else ["Fetch"])
    return cf

# ---------------------------------------------------------------- http-scope.json


def gen_http_scope():
    cf = CaseFile("http-scope", "HTTP scopes and route matching", [
        "action scope = H_bnap/scope/http(lp(method) || lp(target) || lp(content hash, or empty) ||",
        "BigSize(h) || lp(name) || lp(value) ...); target = manifest origin + request-target as received",
        "(draft-00 10.1). Several cases differ from a neighbour in one byte of input, and their",
        "scopes differ: no normalization of any kind.",
    ], notes(NoNormalization=("BASIC", "The input differs from a neighbour only in a form normalization "
                                       "would hide; the scope differs."),
             HeaderCombine=("EDGE", "Repeated fields are combined as RFC 9110 5.3 describes. draft-00 does "
                                    "not fix the separator bytes; these cases use a comma and one space."),
             Ambiguous=("EDGE", "draft-00 does not settle whether /v1/* matches /v1 itself.")))
    g = cf.group("ActionScope", "10.1", "Compute the HTTP action scope. request_headers are the fields as "
                 "sent; listed are the route's header names in route order.",
                 {"method": T_STR, "origin": T_STR, "request_target": T_STR, "content": T_NHEX, "listed": T_ARR,
                  "request_headers": T_ARR})

    def act(comment, method, target, content=None, listed=(), req=(), origin=ORIGIN, flags=("Valid",), expect=None):
        hs = hp.listed_headers(list(listed), list(req))
        s = hp.action_scope(method, origin, target, content, hs)
        if expect:
            must(hx(s) == expect, "scope " + comment)
        g.add(comment, {"method": method, "origin": origin, "request_target": target, "content": hx(content),
                        "listed": list(listed), "request_headers": [list(x) for x in req]}, "valid",
              expected={"action_scope": hx(s), "headers": [list(x) for x in hs]}, flags=list(flags))

    act("draft-00 section 14: POST /v1/chat/completions with the 10.3 body", "POST", "/v1/chat/completions",
        CHAT_BODY, expect=VECTORS["http_scope"]["action_scope"])
    act("the same with method post: methods are case-sensitive", "post", "/v1/chat/completions", CHAT_BODY,
        flags=["NoNormalization"])
    act("GET with no content", "GET", "/v1/resource")
    act("GET with zero-length content: the same as no content", "GET", "/v1/resource", b"")
    act("query a=1&b=2", "GET", "/v1/resource?a=1&b=2")
    act("query b=2&a=1", "GET", "/v1/resource?b=2&a=1", flags=["NoNormalization"])
    act("path /v1/~user", "GET", "/v1/~user")
    act("path /v1/%7Euser", "GET", "/v1/%7Euser", flags=["NoNormalization"])
    act("path /v1/%7euser", "GET", "/v1/%7euser", flags=["NoNormalization"])
    act("trailing slash", "GET", "/v1/resource/", flags=["NoNormalization"])
    act("origin with a port", "GET", "/v1/resource", origin="https://api.example:8443")
    act("content as sent after content coding", "POST", "/v1/chat/completions", bytes.fromhex("1f8b0800000000000003"))
    act("two listed headers, both present", "POST", "/v1/chat/completions", CHAT_BODY,
        listed=["accept", "anthropic-version"],
        req=[("Accept", "application/json"), ("anthropic-version", "2023-06-01")])
    act("a listed header that is absent has an empty value", "POST", "/v1/chat/completions", CHAT_BODY,
        listed=["accept", "anthropic-version"], req=[("Accept", "application/json")])
    act("a repeated listed field, combined", "POST", "/v1/chat/completions", CHAT_BODY, listed=["accept"],
        req=[("Accept", "text/html"), ("accept", "application/json")], flags=["HeaderCombine"])
    act("an unlisted header does not enter the scope", "POST", "/v1/chat/completions", CHAT_BODY,
        req=[("X-Other", "1")], expect=VECTORS["http_scope"]["action_scope"])
    g = cf.group("RouteScope", "10.1", "Compute the HTTP route scope.", {"origin": T_STR, "route_id": T_STR})
    for o, r, c in ((ORIGIN, "chat", "draft-00 section 14"), (ORIGIN, "images", "another route"),
                    ("https://api.example:8443", "chat", "another origin")):
        s = hp.route_scope(o, r)
        if c.startswith("draft"):
            must(hx(s) == VECTORS["http_scope"]["route_scope"], "route scope vector")
        g.add(c, {"origin": o, "route_id": r}, "valid", expected={"route_scope": hx(s)}, flags=["Valid"])
    g = cf.group("RouteMatch", "9.1", "Does the request match the route's match string?",
                 {"match": T_STR, "method": T_STR, "request_target": T_STR})
    for m, meth, tgt, res, c in (("POST /v1/chat/completions", "POST", "/v1/chat/completions", True, "exact path"),
                                 ("POST /v1/chat/completions", "POST", "/v1/chat/completions?stream=1", True, "query ignored"),
                                 ("POST /v1/chat/completions", "GET", "/v1/chat/completions", False, "other method"),
                                 ("POST /v1/chat/completions", "post", "/v1/chat/completions", False, "method case"),
                                 ("POST /v1/chat/completions", "POST", "/v1/chat/completions/", False, "trailing slash"),
                                 ("GET /v1/*", "GET", "/v1/a", True, "one level below /*"),
                                 ("GET /v1/*", "GET", "/v1/a/b", True, "two levels below /*"),
                                 ("GET /v1/*", "GET", "/v1/", True, "the directory itself with a slash"),
                                 ("GET /v1/*", "GET", "/v1x/a", False, "a sibling prefix"),
                                 ("GET /v1/*", "GET", "/v1", None, "the directory without a slash")):
        got = hp.route_matches(m, meth, tgt)
        if res is not None:
            must(got == res, "match " + c)
        g.add(c, {"match": m, "method": meth, "request_target": tgt}, "valid" if res is not None else "acceptable",
              expected={"matches": got} if res is not None else None,
              flags=["Valid"] if res is not None else ["Ambiguous"])
    g = cf.group("ManifestOrigin", "10.1", "The target uses the manifest origin, never the authority the gate "
                 "sees, so the scope survives a TLS-terminating front.",
                 {"manifest_origin": T_STR, "seen_authority": T_STR, "method": T_STR, "request_target": T_STR})
    for seen in ("api.example", "10.0.0.7:8080"):
        g.add(f"seen as {seen}", {"manifest_origin": ORIGIN, "seen_authority": seen, "method": "GET",
                                   "request_target": "/v1/resource"}, "valid",
              expected={"action_scope": hx(ACT_GET)}, flags=["Valid"])
    return cf

# ---------------------------------------------------------------- pricing.json


def A(effect, verified=True, value=None, epoch=None, room=True, scheme=None, cls="A"):
    d = {"scheme": scheme or {"required": "httpauth:DPoP", "waive": "httpauth:DPoP", "discount": "httpsig:web-bot-auth",
                              "quota": "httpauth:DPoP"}[effect],
         "effect": effect, "verified": verified, "class": cls}
    if value is not None:
        d["value"] = value
    if epoch is not None:
        d["epoch"] = epoch
    if effect == "quota":
        d["room"] = room
    return d


def gen_pricing():
    cf = CaseFile("pricing", "Pricing, admission and metering", [
        "price() and admit of draft-00 section 7, in offer order. Each attestation lists whether it",
        "verified and, for a quota, whether its counter has room. Admission for a credential without",
        "pay prices from any positive base (see the NoPayBase note): only a waive, a 10,000 bp discount",
        "or a quota with room bring it to 0. Class None value schemes are admissible only at price 0",
        "(DECISIONS row 25).",
    ], notes(Multiply=("BASIC", "Discounts multiply and each step rounds the amount taken off down."),
             OrderMatters=("EDGE", "Rounding makes the result depend on order: the offer's order rules."),
             Quota=("BASIC", "A quota applies only while p > 0, the first verified one with room."),
             Policy=("POLICY", "A required attestation did not verify."),
             Underpaid=("UNDERPAID", "Value below the effective price."),
             NoPayBase=("EDGE", "draft-00 7 writes price(entry.amount, or 0 if the credential has no pay), which "
                                "makes its own 'p > 0 and no pay' check unreachable and would admit any "
                                "attestation-only credential for free. These cases price a credential without "
                                "pay from a positive base; a waive, a 10,000 bp discount or a quota with room "
                                "admit it, nothing else does. Reported as an erratum candidate."),
             Overpayment=("BASIC", "Value above the price is admitted; a scheme that can return change does."),
             Metering=("BASIC", "charged = min(price(ceil(units x rate / 1000)), price(amount)), exactly."),
             ClassRule=("MALFORMED", "An offer no gate may build.")))
    g = cf.group("Price", "7", "price(base) over the attestations in offer order.", {"base": T_INT, "attests": T_ARR})

    def price(comment, base, attests, want, flags=("Valid",), quota=None):
        r = pr.price(base, attests)
        must(r.price == want and r.quota_index == quota, f"price {comment}: {r.price} {r.quota_index}")
        g.add(comment, {"base": base, "attests": attests}, "valid",
              expected={"price": r.price, "quota_index": r.quota_index}, flags=list(flags))

    price("no attestations", 2100, [], 2100)
    price("a verified waive", 2100, [A("waive")], 0)
    price("a waive that did not verify", 2100, [A("waive", False)], 2100)
    price("one 20% discount (draft-00 10.3)", 2100, [A("discount", value=2000)], 1680)
    price("two 20% discounts multiply: 36% off, never 40%", 2100,
          [A("discount", value=2000), A("discount", value=2000, scheme="nip:98")], 1344, ["Multiply"])
    base, order = None, None
    for b in range(1, 400):
        x = pr.price(b, [A("discount", value=3333), A("discount", value=5001, scheme="nip:98")]).price
        y = pr.price(b, [A("discount", value=5001, scheme="nip:98"), A("discount", value=3333)]).price
        if x != y:
            base, order = b, (x, y)
            break
    must(base is not None, "order example")
    price(f"base {base}: 3,333 bp then 5,001 bp", base,
          [A("discount", value=3333), A("discount", value=5001, scheme="nip:98")], order[0], ["OrderMatters"])
    price(f"base {base}: 5,001 bp then 3,333 bp", base,
          [A("discount", value=5001, scheme="nip:98"), A("discount", value=3333)], order[1], ["OrderMatters"])
    price("a 10,000 bp discount", 2100, [A("discount", value=10000)], 0)
    price("rounding: 999 with 3,333 bp takes off 332", 999, [A("discount", value=3333)], 667, ["Multiply"])
    price("a discount that did not verify has no effect", 2100, [A("discount", False, value=2000)], 2100)
    price("a quota with room", 2100, [A("quota", value=5, epoch=60)], 0, ["Quota"], quota=0)
    price("a full quota", 2100, [A("quota", value=5, epoch=60, room=False)], 2100, ["Quota"])
    price("a quota after a waive is not used", 2100, [A("waive"), A("quota", value=5, epoch=60, scheme="nip:98")], 0,
          ["Quota"])
    price("first quota full, second with room: the second is used", 2100,
          [A("quota", value=5, epoch=60, room=False), A("quota", value=5, epoch=60, scheme="nip:98")], 0, ["Quota"],
          quota=1)
    price("a quota that did not verify is skipped", 2100,
          [A("quota", False, value=5, epoch=60), A("quota", value=5, epoch=60, scheme="nip:98")], 0, ["Quota"], quota=1)
    price("a discount then a quota: the quota still zeroes", 2100,
          [A("discount", value=2000), A("quota", value=5, epoch=60)], 0, ["Quota"], quota=1)

    g = cf.group("Admit", "7", "admit: amount is the chosen pay entry's amount, null without pay; value is the "
                 "scheme's verified value.", {"amount": T_NINT, "value": T_NINT, "attests": T_ARR})

    def admit(comment, amount, value, attests, want, flags=("Valid",), sections=None):
        r = pr.admit(attests, amount=amount, value=value)
        must((r.code if not r.ok else "ok") == want, f"admit {comment}: {r}")
        g.add(comment, {"amount": amount, "value": value, "attests": attests}, "valid" if r.ok else "invalid",
              error=r.code, expected={"price": r.price, "quota_index": r.quota_index} if r.ok else None,
              flags=list(flags), sections=sections)

    admit("required attestation verified, value covers the price", 21, 21, [A("required")], "ok")
    admit("required attestation missing", 21, 21, [A("required", False)], "POLICY", ["Policy"])
    admit("required attestation missing beats a verified waive", 21, None,
          [A("required", False), A("waive", scheme="nip:98")], "POLICY", ["Policy"])
    admit("no pay, a verified waive (the section 14 attestation-only case)", None, None, [A("waive")], "ok")
    admit("no pay, the waive did not verify", None, None, [A("waive", False)], "UNDERPAID", ["NoPayBase", "Underpaid"])
    admit("no pay, a 20% discount only", None, None, [A("discount", value=2000)], "UNDERPAID",
          ["NoPayBase", "Underpaid"])
    admit("no pay, a 10,000 bp discount", None, None, [A("discount", value=10000)], "ok", ["NoPayBase"])
    admit("no pay, a quota with room", None, None, [A("quota", value=5, epoch=60)], "ok", ["NoPayBase", "Quota"])
    admit("no pay, a full quota", None, None, [A("quota", value=5, epoch=60, room=False)], "UNDERPAID",
          ["NoPayBase", "Underpaid"])
    admit("value one below the price", 21, 20, [], "UNDERPAID", ["Underpaid"])
    admit("value equal to the price", 21, 21, [], "ok")
    admit("value above the price", 21, 30, [], "ok", ["Overpayment"])
    admit("draft-00 10.3: 2,100 ceiling, 20% off, notes worth 1,680", 2100, 1680, [A("discount", value=2000)], "ok",
          sections=["7", "10.3"])
    admit("draft-00 10.3 with notes worth 1,679", 2100, 1679, [A("discount", value=2000)], "UNDERPAID", ["Underpaid"],
          sections=["7", "10.3"])

    g = cf.group("Metered", "7", "The metered charge at settlement. quota_index is the admission decision.",
                 {"units": T_STR, "rate": T_INT, "amount": T_INT, "attests": T_ARR, "quota_index": T_NINT})

    def meter(comment, units, rate, amount, attests, want, quota=None, flags=("Metering",)):
        got = pr.metered_charge(units, rate, amount, attests, quota)
        must(got == want, f"meter {comment}: {got}")
        g.add(comment, {"units": str(units), "rate": rate, "amount": amount, "attests": attests, "quota_index": quota},
              "valid", expected={"charged": got}, flags=list(flags))

    meter("draft-00 10.3: 850 tokens at 500 per 1,000, 20% off", 850, 500, 2100, [A("discount", value=2000)], 340)
    meter("no units", 0, 500, 2100, [], 0)
    meter("one unit at 500 per 1,000 rounds up to 1", 1, 500, 2100, [], 1)
    meter("units beyond the ceiling are charged the ceiling", 10000, 500, 2100, [A("discount", value=2000)], 1680)
    meter("a product beyond 2^64 still yields the ceiling", 1 << 64, 1 << 20, 2100, [], 2100)
    meter("a waive at admission: nothing charged", 850, 500, 2100, [A("waive")], 0)
    meter("the quota chosen at admission is reused, not consumed again", 850, 500, 2100, [A("quota", value=5, epoch=60)],
          0, quota=0)
    meter("a quota that was full at admission stays unused", 850, 500, 2100,
          [A("quota", value=5, epoch=60, room=True)], 425, quota=None)

    g = cf.group("BuildRules", "7", "Offer-building rules for the entries of one offer.",
                 {"entries": T_ARR, "metered": T_BOOL})
    for entries, metered, res, c in (
            ([{"role": "pay", "scheme": "cashu:nut22", "class": "none", "amount": 0}], False, "valid",
             "class None value scheme at price 0"),
            ([{"role": "pay", "scheme": "cashu:nut22", "class": "none", "amount": 21}], False, "invalid",
             "class None value scheme at price 21"),
            ([{"role": "attest", "scheme": "httpauth:Bearer", "class": "none", "effect": "discount"}], False, "invalid",
             "bearer attestation trying to discount"),
            ([{"role": "attest", "scheme": "httpauth:Bearer", "class": "none", "effect": "waive"}], False, "invalid",
             "bearer attestation trying to waive"),
            ([{"role": "attest", "scheme": "httpauth:Bearer", "class": "none", "effect": "quota"}], False, "invalid",
             "bearer attestation trying to carry a quota"),
            ([{"role": "attest", "scheme": "pp:0x0002", "class": "O", "effect": "discount"}], False, "valid",
             "class O discount"),
            ([{"role": "attest", "scheme": "httpauth:DPoP", "class": "A", "effect": "waive"}], False, "valid",
             "class A waive")):
        v = pr.class_rule_violations(entries)
        must(bool(v) == (res == "invalid"), "build " + c)
        g.add(c, {"entries": entries, "metered": metered}, res, error="MALFORMED" if v else None,
              reason=v[0] if v else None, flags=["ClassRule"] if v else ["Valid"])
    for scheme, res in (("httpauth:L402", "invalid"), ("bnap:notes", "valid")):
        ok = REG.meterable(scheme)
        must(ok == (res == "valid"), "meterable " + scheme)
        g.add(f"metered entry for {scheme} (refund {REG.refund(scheme)}, upto {str(REG.upto(scheme)).lower()})",
              {"entries": [{"role": "pay", "scheme": scheme, "class": REG.binding(scheme), "amount": 2100,
                            "refund": REG.refund(scheme), "upto": REG.upto(scheme)}], "metered": True}, res,
              error=None if ok else "MALFORMED", reason=None if ok else "metered-not-refundable",
              flags=["Valid"] if ok else ["ClassRule"])
    return cf

# ---------------------------------------------------------------- outcomes.json


def run_trace(steps, replay_window=86400, pending_timeout=300):
    return st.apply_trace(steps, replay_window, pending_timeout)


def gen_outcomes():
    cf = CaseFile("outcomes", "Commit, replay, settle and timeout as state-machine traces", [
        "Each case is a trace of operations on one use store (draft-00 6.3 and 6.4). A conformant",
        "store returns, for every step, what that step's expect says. commit returns New, Replay",
        "(with the recorded status), SPENT, RATE_LIMITED or UNAVAILABLE; gate names what the gate",
        "then does. IDs are labels unless the case computes them from the socket formulas. A case",
        "is invalid when its last commit is refused, with that refusal as its error.",
    ], notes(Replay=("BASIC", "The same credential for the same request finds its outcome."),
             Spent=("SPENT", "A single use ID already committed under another ReplayKey."),
             Abort=("BASIC", "An aborted commit consumes nothing."),
             Rate=("RATE_LIMITED", "A counter is full."),
             Once=("BASIC", "The status changes exactly once, from PENDING, and never flips on replay."),
             Timeout=("BASIC", "PENDING past pending_timeout becomes FAILED, with counters given back."),
             Purge=("BASIC", "After replay_window the outcome may go; single uses stay."),
             Unavailable=("UNAVAILABLE", "The store cannot be reached: fail closed."),
             SharedRail=("SPENT", "One payment presented through two schemes admits one action."),
             ReceiptOnly=("BASIC", "The carrier kept no response: the receipt alone, with the recorded scheme_result."),
             Window=("POLICY", "A credential with no single-use ID whose offer outlives its outcome record. "
                               "draft-00 names no code for this refusal; POLICY is used, others are acceptable.")))
    g = cf.group("Trace", "6.3", "Run the steps in order on one store.",
                 {"replay_window": T_INT, "pending_timeout": T_INT, "steps": T_ARR})

    def trace(comment, steps, want_last, flags, sections=None, rw=86400, pt=300, checks=None):
        out = run_trace(steps, rw, pt)
        if checks:
            for i, k, v in checks:
                must(out[i].get(k) == v, f"trace {comment} step {i} {k}: {out[i]}")
        commits = [(st_, o) for st_, o in zip(steps, out) if st_["op"] == "commit"]
        last = commits[-1][1]["result"] if commits else "New"
        must(last == want_last, f"trace {comment}: last commit {last}")
        err = last if last in ("SPENT", "RATE_LIMITED", "UNAVAILABLE") else None
        sts = []
        for st_, o in zip(steps, out):
            d = dict(st_)
            d["expect"] = o
            sts.append(d)
        g.add(comment, {"replay_window": rw, "pending_timeout": pt, "steps": sts},
              "invalid" if err else "valid", error=err, flags=flags, sections=sections)

    T = 1791700100
    trace("commit, settle OK, then three replays: the same status every time, replayed set",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "OK", "response": "kept"},
           {"op": "commit", "at": T + 2, "rk": "rk1", "singles": ["u1"]},
           {"op": "commit", "at": T + 3, "rk": "rk1", "singles": ["u1"]},
           {"op": "commit", "at": T + 4, "rk": "rk1", "singles": ["u1"]}],
          "Replay", ["Replay", "Once"], ["6.3", "6.4"], checks=[(2, "status", "OK"), (4, "status", "OK")])
    trace("the same single use ID under another ReplayKey",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "OK"},
           {"op": "commit", "at": T + 2, "rk": "rk2", "singles": ["u1"]}], "SPENT", ["Spent"])
    trace("an aborted commit consumes nothing",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "commit", "at": T + 1, "rk": "rk2", "singles": ["u1", "u2"]},
           {"op": "commit", "at": T + 2, "rk": "rk3", "singles": ["u2"]}], "New", ["Abort"],
          checks=[(1, "result", "SPENT")])
    trace("a full rate counter refuses and consumes the commit's single uses neither",
          [{"op": "commit", "at": T, "rk": "rk1", "counters": [["c1", 1]]},
           {"op": "commit", "at": T + 1, "rk": "rk2", "singles": ["u5"], "counters": [["c1", 1]]},
           {"op": "commit", "at": T + 2, "rk": "rk3", "singles": ["u5"]}], "New", ["Rate", "Abort"],
          checks=[(1, "result", "RATE_LIMITED")])
    trace("a counter full at commit although it had room at pricing",
          [{"op": "commit", "at": T, "rk": "rkA", "singles": ["uA"], "counters": [["q1", 1]]},
           {"op": "commit", "at": T, "rk": "rkB", "singles": ["uB"], "counters": [["q1", 1]]}], "RATE_LIMITED",
          ["Rate"], ["7", "6.3"])
    trace("a replay while the first is in flight returns PENDING",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "commit", "at": T + 1, "rk": "rk1", "singles": ["u1"]}], "Replay", ["Replay"], ["6.4"],
          checks=[(1, "status", "PENDING"), (1, "gate", "PENDING")])
    trace("settle succeeds once; a second settle with another status changes nothing",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "OK"},
           {"op": "settle", "at": T + 2, "rk": "rk1", "status": "FAILED"},
           {"op": "get", "at": T + 3, "rk": "rk1"}], "New", ["Once"], ["6.4"],
          checks=[(1, "settled", True), (2, "settled", False), (3, "status", "OK")])
    trace("FAILED gives the counters back and leaves single uses spent",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"], "counters": [["c1", 1]]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "FAILED"},
           {"op": "counter", "key": "c1"},
           {"op": "commit", "at": T + 2, "rk": "rk3", "counters": [["c1", 1]]},
           {"op": "commit", "at": T + 3, "rk": "rk2", "singles": ["u1"]}], "SPENT", ["Once", "Spent"], ["6.4"],
          checks=[(2, "value", 0), (3, "result", "New")])
    trace("a FAILED outcome replays as FAILED, every time",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "FAILED", "response": "kept"},
           {"op": "commit", "at": T + 2, "rk": "rk1", "singles": ["u1"]},
           {"op": "commit", "at": T + 3, "rk": "rk1", "singles": ["u1"]}], "Replay", ["Replay", "Once"], ["6.4"],
          checks=[(2, "status", "FAILED"), (3, "status", "FAILED")])
    trace("PENDING past pending_timeout becomes FAILED; a late settle changes nothing",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"], "counters": [["c1", 3]]},
           {"op": "get", "at": T + 301, "rk": "rk1"},
           {"op": "settle", "at": T + 302, "rk": "rk1", "status": "OK"},
           {"op": "counter", "key": "c1"},
           {"op": "commit", "at": T + 303, "rk": "rk1", "singles": ["u1"]}], "Replay", ["Timeout", "Once"], ["6.4"],
          checks=[(1, "status", "FAILED"), (2, "settled", False), (3, "value", 0), (4, "status", "FAILED")])
    trace("after replay_window the outcome may be deleted, the single use stays: a replay is SPENT",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "OK"},
           {"op": "purge", "at": T + 86401},
           {"op": "commit", "at": T + 86402, "rk": "rk1", "singles": ["u1"]}], "SPENT", ["Purge", "Spent"], ["6.4"])
    trace("the store cannot be reached: UNAVAILABLE, the action never runs",
          [{"op": "store", "available": False},
           {"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]}], "UNAVAILABLE", ["Unavailable"], ["6.3", "12"])
    trace("a replay of an OK outcome whose response was not kept: the receipt alone",
          [{"op": "commit", "at": T, "rk": "rk1", "singles": ["u1"]},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "OK", "scheme_result": "change-1"},
           {"op": "commit", "at": T + 2, "rk": "rk1", "singles": ["u1"]}], "Replay", ["ReceiptOnly"], ["6.4", "14"],
          checks=[(2, "gate", "replay-receipt-only"), (2, "scheme_result", "change-1")])
    ph = H(b"preimage")
    va = VECTORS["attest_only"]
    ctx = bytes.fromhex(va["context"])
    rail = hx(cr.rail_id("ln", ph))
    u_l402, u_mpp = hx(cr.use_id("httpauth:L402", ph)), hx(cr.use_id("payment:lightning/charge", ph))
    rk_l = hx(cr.replay_key(ctx, b"l402 token", [], [cr.use_id("httpauth:L402", ph), cr.rail_id("ln", ph)]))
    rk_m = hx(cr.replay_key(ctx, b"mpp credential", [], [cr.use_id("payment:lightning/charge", ph), cr.rail_id("ln", ph)]))
    trace("one Lightning payment presented through L402 and then MPP admits one action (IDs computed)",
          [{"op": "commit", "at": T, "rk": rk_l, "singles": sorted([u_l402, rail])},
           {"op": "settle", "at": T + 1, "rk": rk_l, "status": "OK"},
           {"op": "commit", "at": T + 2, "rk": rk_m, "singles": sorted([u_mpp, rail])}], "SPENT", ["SharedRail"],
          ["6.1", "6.3", "14"])
    u1, u2 = cr.use_id("httpauth:DPoP", H(b"client 1 key")), cr.use_id("httpauth:DPoP", H(b"client 2 key"))
    r1 = hx(cr.replay_key(ctx, b"", [b"DPoP proof of client 1"], [u1]))
    r2 = hx(cr.replay_key(ctx, b"", [b"DPoP proof of client 2"], [u2]))
    trace("two clients, same request, reusable attestations: two ReplayKeys, two actions (IDs computed)",
          [{"op": "commit", "at": T, "rk": r1},
           {"op": "settle", "at": T + 1, "rk": r1, "status": "OK", "response": "kept"},
           {"op": "commit", "at": T + 2, "rk": r2}], "New", ["Replay"], ["6.1", "15"])
    rkv = VECTORS["credential"]["replay_key"]
    trace("a replay on a new connection (another binding) has the same ReplayKey (section 14)",
          [{"op": "commit", "at": T, "rk": rkv, "singles": [VECTORS["credential"]["use_ids"][0]]},
           {"op": "settle", "at": T + 1, "rk": rkv, "status": "OK", "response": "kept"},
           {"op": "commit", "at": T + 2, "rk": rkv, "singles": [VECTORS["credential"]["use_ids"][0]]}], "Replay",
          ["Replay"], ["5.3", "6.4", "14"])
    trace("reusable only: after the outcome is purged the same credential would run again",
          [{"op": "commit", "at": T, "rk": "rk1"},
           {"op": "settle", "at": T + 1, "rk": "rk1", "status": "OK"},
           {"op": "purge", "at": T + 86401},
           {"op": "commit", "at": T + 86402, "rk": "rk1"}], "New", ["Purge"], ["6.1"])

    g = cf.group("ReusableAdmissionWindow", "6.1", "May the gate admit a credential that yields no single-use ID? "
                 "Only if expires + 60 <= now + replay_window.",
                 {"expires": T_INT, "now": T_INT, "replay_window": T_INT})
    for exp_, now, rw, c in ((T + 300, T, 86400, "a five-minute offer, a day of outcomes"),
                             (T + 86340, T, 86400, "expires + 60 equals now + replay_window"),
                             (T + 86341, T, 86400, "one second too long"),
                             (T + 300, T, 300, "replay_window shorter than the offer lifetime plus 60")):
        ok = exp_ + 60 <= now + rw
        g.add(c, {"expires": exp_, "now": now, "replay_window": rw}, "valid" if ok else "invalid",
              error=None if ok else "POLICY", acceptable_errors=None if ok else ["STALE", "BAD_OFFER"],
              flags=["Valid"] if ok else ["Window"])
    return cf

# ---------------------------------------------------------------- writer

GENERATORS = [gen_bigsize, gen_tlv, gen_offer, gen_credential, gen_response, gen_manifest, gen_http_scope,
              gen_pricing, gen_outcomes]


def render():
    files = {}
    for gen in GENERATORS:
        cf = gen()
        files[f"{cf.area}.json"] = json.dumps(cf.to_json(), indent=1, ensure_ascii=True) + "\n"
        files[f"schema/{cf.area}.schema.json"] = json.dumps(cf.schema(), indent=1, ensure_ascii=True) + "\n"
    return files


def main(argv):
    check = "--check" in argv
    files = render()
    bad = []
    for name, text in sorted(files.items()):
        path = OUT / name
        if check:
            if not path.is_file() or path.read_text() != text:
                bad.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    if check:
        extra = sorted(str(p.relative_to(OUT)) for p in OUT.rglob("*.json")
                       if str(p.relative_to(OUT)) not in files)
        if bad or extra:
            sys.stderr.write("gen_cases: stale or missing: " + ", ".join(bad + extra) + "\n")
            return 1
        print(f"gen_cases: {len(files)} files up to date")
        return 0
    total = sum(json.loads(t)["numberOfTests"] for n, t in files.items() if not n.startswith("schema/"))
    print(f"gen_cases: wrote {len(files)} files, {total} tests, to {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

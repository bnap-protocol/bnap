"""Consume every case in vectors/cases/ the way an implementation would.

Each group type has an evaluator that reads only the case inputs and calls
bnap_conf; the test passes when the verdict (valid, invalid with its error,
or anything for acceptable) and every expected value agree with the file.
The files are also checked against their schemas and for reproducibility.
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest

CONF = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONF))

from bnap_conf import codec, offer as of, credential as cr, response as rs, manifest as mf  # noqa: E402
from bnap_conf import http as hp, pricing as pr, store as st, client as cl, registry  # noqa: E402
from bnap_conf.codec import BnapError  # noqa: E402
from bnap_conf.crypto import schnorr_verify  # noqa: E402
from bnap_conf._ref import REPO_ROOT  # noqa: E402

CASES = REPO_ROOT / "vectors" / "cases"
REG = registry.default()
AREAS = ["bigsize", "tlv", "offer", "credential", "response", "manifest", "http-scope", "pricing", "outcomes"]


def b(h):
    return bytes.fromhex(h) if h is not None else None


class Verdict:
    """valid with values, or invalid with an error label (socket code or client label)."""

    def __init__(self, ok, error=None, values=None):
        self.ok = ok
        self.error = error
        self.values = values or {}


def V(values=None):
    return Verdict(True, values=values)


def X(error):
    return Verdict(False, error)


def guard(fn):
    try:
        return fn()
    except BnapError as e:
        return X(e.code)

# ---------------------------------------------------------------- evaluators


def ev_bigsize_decode(i):
    return guard(lambda: V({"value": str(codec.decode_bigsize(b(i["hex"])))}))


def ev_bigsize_encode(i):
    return V({"hex": codec.bigsize(int(i["value"])).hex()})


def ev_tu64_decode(i):
    return guard(lambda: V({"value": str(codec.parse_tu64(b(i["hex"])))}))


def ev_tu64_encode(i):
    return V({"hex": codec.tu64(int(i["value"])).hex()})


def ev_stream(i):
    return guard(lambda: V({"records": [[r.type, r.value.hex()] for r in codec.parse_stream(b(i["hex"]))]}))


def ev_even_odd(i):
    raw = b(i["hex"])

    def go():
        kind = i["object"]
        if kind == "offer":
            of.parse_offer(raw)
        elif kind == "credential":
            cr.parse_credential(raw)
        elif kind == "response":
            if not rs.verify_ack(rs.parse_response(raw)):
                return X("CLIENT_REJECT")
        else:
            codec.parse_error(raw)
        return V()
    return guard(go)


def ev_nested(i):
    return guard(lambda: (of.parse_offer(b(i["hex"])), V())[1])


def ev_entry_list(i):
    return guard(lambda: V({"entries": [e.hex() for e in codec.parse_entry_list(b(i["hex"]))]}))


def ev_b64(i):
    return guard(lambda: V({"hex": codec.b64u_decode(i["text"]).hex()}))


def ev_offer_parse(i):
    def go():
        o = of.parse_offer(b(i["offer"]), i["max_offer"])
        return V({"offer_id": o.offer_id.hex(), "pay": [e.scheme for e in o.pay],
                  "attest": [[a.scheme, a.effect_name] for a in o.attest], "route_scope": o.route_scope,
                  "metered": o.metered, "ignored": o.ignored})
    return guard(go)


def ev_offer_rules(i):
    v = of.offer_rule_violations(of.parse_offer(b(i["offer"])), REG)
    return X("MALFORMED") if v else V()


def ev_offer_id(i):
    o = of.parse_offer(b(i["offer"]))
    return V({"offer_id": o.offer_id.hex(), "offer_sig": o.offer_sig.hex(), "offer_sig_valid": of.verify_offer_sig(o)})


def ev_client_offer(i):
    chk = of.client_check_offer(b(i["offer"]), now=i["now"], origin=i["origin"], pin_keys=i["pin_keys"],
                                scope=b(i["scope"]), route_scope=b(i["route_scope"]), registry=REG)
    return V() if chk.ok else X(chk.code)


def ev_gate_offer(i):
    state = of.GateOfferState([b(k) for k in i["mac_keys"]], [b(k) for k in i["listed_offer_keys"]],
                              {b(k): b(v) for k, v in i["cache"].items()}, i["max_offer"])
    return guard(lambda: (of.gate_check_offer(state, now=i["now"], action_scope=b(i["action_scope"]),
                                              route_scope=b(i["route_scope"]), offer_raw=b(i.get("offer")),
                                              offer_id=b(i.get("offer_id")), pay_scheme=i["pay_scheme"],
                                              attest_schemes=i["attest_schemes"]), V())[1])


def ev_cred_parse(i):
    limit = min(i["max_credential"], cr.HTTP_MAX_CREDENTIAL) if i["carrier"] == "http" else i["max_credential"]

    def go():
        c = cr.parse_credential(b(i["credential"]), limit, REG)
        return V({"pay_scheme": c.pay.scheme if c.pay else None, "attest_schemes": c.attest_schemes,
                  "binding": c.binding.hex() if c.binding else None,
                  "offer_form": "inline" if c.offer is not None else "reference", "ignored": c.ignored})
    return guard(go)


def ev_envelope(i):
    ctx = cr.context(b(i["offer_id"]), b(i["action_scope"]), i["pay_scheme"], i["attest_schemes"], b(i["ext"]))
    bodies = [b(x) for x in i["attest_bodies"]]
    return V({"context": ctx.hex(), "digest": cr.digest(ctx, b(i["binding"]), b(i["pay_body"]), bodies).hex(),
              "replay_key": cr.replay_key(ctx, b(i["pay_body"]), bodies, [b(x) for x in i["ids"]]).hex()})


def ev_use_id(i):
    return V({"use_id": cr.use_id(i["scheme"], b(i["local"])).hex()})


def ev_rail_id(i):
    f = i["fields"]
    k = i["kind"]
    canon = {"ln": lambda: cr.canonical_ln(b(f["payment_hash"])),
             "onchain": lambda: cr.canonical_onchain(b(f["txid"]), f["vout"]),
             "evm": lambda: cr.canonical_evm(f["chain_id"], b(f["token"]), b(f["payer"]), b(f["nonce"])),
             "card": lambda: cr.canonical_card(f["processor"], f["payment_id"])}[k]()
    out = {"canonical": canon.hex(), "rail_id": cr.rail_id(k, canon).hex()}
    if k == "ln":
        out["use_ids"] = [cr.use_id("httpauth:L402", canon).hex(), cr.use_id("payment:lightning/charge", canon).hex()]
    return V(out)


def ev_counter(i):
    fn = cr.rate_key if i["kind"] == "rate" else cr.quota_key
    return V({"key": fn(b(i["use_id"]), i["limit"], i["epoch"], i["now"]).hex(), "epoch_index": i["now"] // i["epoch"]})


def ev_native(i):
    ctx = cr.native_context(b(i["offer_id"]), b(i["action_scope"]), i["scheme"])
    return V({"context": ctx.hex(), "digest": cr.native_digest(ctx, b(i["native_bytes"])).hex()})


def ev_witness(i):
    c = cr.parse_credential(b(i["credential"]), registry=REG)
    cache = {b(k): b(v) for k, v in i["cache"].items()}
    raw = c.offer if c.offer is not None else cache[c.offer_id_ref]
    _, dg = cr.credential_envelope(c, of.offer_id_of(raw), b(i["action_scope"]))
    return V() if schnorr_verify(b(i["witness_key"]), dg, c.pay.witness) else X("BAD_CREDENTIAL")


def ev_value_count(i):
    n = (1 if i["bnap_pay"] else 0) + len(i["native"])
    return X("MALFORMED") if n > 1 else V()


def ev_resp_parse(i):
    def go():
        r = rs.parse_response(b(i["response"]), i["max_response"])
        return V({"status": r.status_name, "replayed": r.replayed, "charged": r.charged, "unit": r.unit,
                  "metered_units": r.metered_units, "settled_at": r.settled_at, "ack_valid": rs.verify_ack(r)})
    return guard(go)


def ev_receipt(i):
    chk = rs.client_check_receipt(b(i["response"]), now=i["now"], pin_keys=i["pin_keys"], digest=b(i["digest"]),
                                  offer_id=b(i["offer_id"]), has_pay=i["has_pay"], metered=i["metered"],
                                  expected_charge=i["expected_charge"])
    if chk.ok:
        return V()
    head = chk.reason.split(":")[0]
    return X(head if head in codec.ERRORS else "CLIENT_REJECT")


def ev_error_parse(i):
    def go():
        e = codec.parse_error(b(i["hex"]))
        return V({"code": e.code, "name": e.name, "scheme_code": e.scheme_code, "detail": e.detail,
                  "retry_after": e.retry_after})
    return guard(go)


def ev_error_status(i):
    n = i["name"]
    return V({"code": codec.code_of(n), "http_status": codec.http_status_of(n), "fresh_offer": n in codec.FRESH_OFFER,
              "retry_after": n in codec.NEEDS_RETRY_AFTER})


def ev_manifest_doc(i):
    try:
        obj = mf.parse_json_strict(b(i["manifest"]))
    except mf.ManifestReject:
        return X("MANIFEST_REJECT")
    if mf.document_problems(obj, origin=i["origin"], now=i["now"]):
        return X("MANIFEST_REJECT")
    return V({"signing_input": mf.signing_input(obj).hex()})


def ev_jcs(i):
    out = mf.jcs(mf.parse_json_strict(i["json"].encode()))
    return V({"jcs": out.decode(), "jcs_hex": out.hex()})


def ev_pinning(i):
    pin = mf.Pin.from_json(i["pin"]) if i["pin"] else None
    try:
        p = mf.fetch_accept(b(i["manifest"]), origin=i["origin"], now=i["now"], pin=pin)
    except mf.ManifestReject:
        return X("MANIFEST_REJECT")
    return V({"root": p.root, "backup": p.backup, "seq": p.seq, "hash": p.hash.hex(), "required": p.required,
              "until": p.until})


def ev_native_challenge(i):
    pin = mf.Pin.from_json(i["pin"]) if i["pin"] else None
    passing = [chk.offer for _, chk in cl.usable_offers([b(x) for x in i["offers"]], now=i["now"],
                                                         origin="https://api.example", pin=pin, scope=b(i["scope"]),
                                                         route_scope=None, registry=REG)]
    ok, _ = cl.decide_native(b(i["native"]), passing, pin, i["now"], i["via_header"])
    return V() if ok else X("CLIENT_REJECT")


def ev_fetch(i):
    ok, _ = mf.may_fetch(i["url"], i["last_fetch"], i["now"])
    return V() if ok else X("CLIENT_REJECT")


def ev_action_scope(i):
    hs = hp.listed_headers(i["listed"], [tuple(x) for x in i["request_headers"]])
    s = hp.action_scope(i["method"], i["origin"], i["request_target"], b(i["content"]), hs)
    return V({"action_scope": s.hex(), "headers": [list(x) for x in hs]})


def ev_route_scope(i):
    return V({"route_scope": hp.route_scope(i["origin"], i["route_id"]).hex()})


def ev_route_match(i):
    return V({"matches": hp.route_matches(i["match"], i["method"], i["request_target"])})


def ev_manifest_origin(i):
    return V({"action_scope": hp.action_scope(i["method"], i["manifest_origin"], i["request_target"]).hex()})


def ev_price(i):
    r = pr.price(i["base"], i["attests"])
    return V({"price": r.price, "quota_index": r.quota_index})


def ev_admit(i):
    a = pr.admit(i["attests"], amount=i["amount"], value=i["value"])
    return V({"price": a.price, "quota_index": a.quota_index}) if a.ok else X(a.code)


def ev_metered(i):
    return V({"charged": pr.metered_charge(int(i["units"]), i["rate"], i["amount"], i["attests"], i["quota_index"])})


def ev_build_rules(i):
    v = pr.class_rule_violations(i["entries"])
    if i["metered"]:
        v += ["metered-not-refundable" for e in i["entries"]
              if e["role"] == "pay" and e.get("refund") != "atomic" and not e.get("upto")]
    return X("MALFORMED") if v else V()


def ev_trace(i):
    out = st.apply_trace(i["steps"], i["replay_window"], i["pending_timeout"])
    for step, got in zip(i["steps"], out):
        if step["expect"] != got:
            return Verdict(False, "TRACE_MISMATCH", {"step": step, "got": got})
    last = [g for s, g in zip(i["steps"], out) if s["op"] == "commit"][-1]["result"]
    return X(last) if last in ("SPENT", "RATE_LIMITED", "UNAVAILABLE") else V()


def ev_window(i):
    return V() if i["expires"] + 60 <= i["now"] + i["replay_window"] else X("POLICY")


EVALUATORS = {
    "BigSizeDecode": ev_bigsize_decode, "BigSizeEncode": ev_bigsize_encode, "Tu64Decode": ev_tu64_decode,
    "Tu64Encode": ev_tu64_encode, "StreamParse": ev_stream, "EvenOddRule": ev_even_odd, "NestedEvenOdd": ev_nested,
    "EntryList": ev_entry_list, "Base64url": ev_b64, "OfferParse": ev_offer_parse, "OfferRules": ev_offer_rules,
    "OfferIdAndSignature": ev_offer_id, "ClientOfferCheck": ev_client_offer, "GateOfferCheck": ev_gate_offer,
    "CredentialParse": ev_cred_parse, "Envelope": ev_envelope, "UseId": ev_use_id, "RailId": ev_rail_id,
    "CounterKeys": ev_counter, "NativeEnvelope": ev_native, "WitnessOverDigest": ev_witness,
    "ValueCredentialCount": ev_value_count, "ResponseParse": ev_resp_parse, "ClientReceiptCheck": ev_receipt,
    "ErrorParse": ev_error_parse, "ErrorHttpStatus": ev_error_status, "ManifestDocument": ev_manifest_doc,
    "JCS": ev_jcs, "Pinning": ev_pinning, "NativeChallenge": ev_native_challenge, "FetchRules": ev_fetch,
    "ActionScope": ev_action_scope, "RouteScope": ev_route_scope, "RouteMatch": ev_route_match,
    "ManifestOrigin": ev_manifest_origin, "Price": ev_price, "Admit": ev_admit, "Metered": ev_metered,
    "BuildRules": ev_build_rules, "Trace": ev_trace, "ReusableAdmissionWindow": ev_window,
}


def load_validator():
    spec = importlib.util.spec_from_file_location("registry_validate", REPO_ROOT / "registry" / "validate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SchemaValidator


class CaseFilesTest(unittest.TestCase):
    def test_every_case(self):
        total = 0
        for area in AREAS:
            data = json.loads((CASES / f"{area}.json").read_text())
            for g in data["testGroups"]:
                ev = EVALUATORS[g["type"]]
                for t in g["tests"]:
                    total += 1
                    with self.subTest(area=area, tcId=t["tcId"], comment=t["comment"]):
                        got = ev(t["inputs"])
                        if t["result"] == "acceptable":
                            continue
                        if t["result"] == "valid":
                            self.assertTrue(got.ok, f"rejected with {got.error} {got.values}")
                            for k, v in (t.get("expected") or {}).items():
                                self.assertEqual(got.values.get(k), v, k)
                        else:
                            self.assertFalse(got.ok, "accepted")
                            allowed = {t["error"]} | set(t.get("acceptableErrors", []))
                            self.assertIn(got.error, allowed)
        self.assertGreater(total, 500)

    def test_schema_and_shape(self):
        SV = load_validator()
        for area in AREAS:
            data = json.loads((CASES / f"{area}.json").read_text())
            schema = json.loads((CASES / data["schema"]).read_text())
            self.assertEqual(SV(schema).errors(data, schema, ""), [], area)
            ids = [t["tcId"] for g in data["testGroups"] for t in g["tests"]]
            self.assertEqual(ids, list(range(1, len(ids) + 1)), area)
            self.assertEqual(data["numberOfTests"], len(ids), area)
            for g in data["testGroups"]:
                for t in g["tests"]:
                    for f in t["flags"]:
                        self.assertIn(f, data["notes"], f"{area} {t['tcId']}")

    def test_required_negative_cases_exist(self):
        """The negative cases the build task and draft-00 section 14 name."""
        text = {a: (CASES / f"{a}.json").read_text() for a in AREAS}
        needles = {
            "bigsize": ["252 in three bytes"],
            "tlv": ["type 1 after type 2", "even type 1002", "odd type 1001", "GREASE"],
            "offer": ["4,097 bytes", "version 2", "a flipped bit in", "expires 61 s ago",
                      "offer_key not in the pinned manifest", "published in advance under a key the offer names",
                      "native record in a route-scope offer", "listing class O", "bearer attestation",
                      "exact offer sent with another request"],
            "credential": ["attestation stripped", "ext altered", "attest list out of order",
                           "binding with no class S", "two native value credentials",
                           "a BNAP pay and a native L402 token", "one Lightning payment named by L402 and by MPP",
                           "a replay with a changed binding", "two clients, same request"],
            "manifest": ["two root members", "rollback", "second rotation"],
            "pricing": ["two 20% discounts", "class None value scheme at price 0", "bearer attestation trying to discount",
                        "draft-00 10.3: 850 tokens"],
            "outcomes": ["the same single use ID under another ReplayKey", "PENDING", "response was not kept",
                         "one Lightning payment presented through L402 and then MPP"],
        }
        for area, ns in needles.items():
            for n in ns:
                self.assertIn(n, text[area], f"{area}: {n}")

    def test_generator_reproducible(self):
        spec = importlib.util.spec_from_file_location("gen_cases", CONF / "gen_cases.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        first = gen.render()
        second = gen.render()
        self.assertEqual(first, second)
        for name, text in first.items():
            self.assertEqual((CASES / name).read_text(), text, name)

    def test_generator_rejects_unknown_arguments(self):
        # A mistyped --check must fail with a usage error, not regenerate the files.
        spec = importlib.util.spec_from_file_location("gen_cases", CONF / "gen_cases.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        before = {p: p.stat().st_mtime_ns for p in CASES.rglob("*.json")}
        for argv, code in ((["--chek"], 2), (["--check", "extra"], 2), (["--help"], 0)):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    gen.main(argv)
                self.assertEqual(cm.exception.code, code)
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in CASES.rglob("*.json")})


if __name__ == "__main__":
    unittest.main()

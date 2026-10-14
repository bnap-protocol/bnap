"""A stand-in for lnd's lncli, for testing conformance/payers/lncli-payer.sh without a node.

  decodepayreq INVOICE                      prints {"payment_hash", "num_satoshis", "num_msat", "features"}
                                            as lnd would, from bnap_conf's strict decode
  payinvoice --force --json [--max_parts N] [--fee_limit N] INVOICE
                                            asks the mock gate in FAKE_LNCLI_GATE to settle the invoice and
                                            prints {"status": "SUCCEEDED", "payment_preimage", "fee_msat"}

Every call is appended to the file FAKE_LNCLI_LOG. FAKE_LNCLI_MSAT, FAKE_LNCLI_HASH and
FAKE_LNCLI_FEATURES (JSON) make decodepayreq read another amount, payment hash or feature map than
bnap_conf does, as a disagreeing decoder would. FAKE_LNCLI_FEE_MSAT is the fee payinvoice reports
(default 0).
"""
import json
import os
import pathlib
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from bnap_conf import http as hp, lightning as ln  # noqa: E402


def main(argv):
    with open(os.environ["FAKE_LNCLI_LOG"], "a") as f:
        f.write(" ".join(argv) + "\n")
    cmd, inv = argv[0], argv[-1]
    if cmd == "decodepayreq":
        try:
            d = ln.decode_bolt11(inv)
        except ValueError as e:
            sys.stderr.write(f"[lncli] invalid payment request: {e}\n")
            return 1
        msat = os.environ.get("FAKE_LNCLI_MSAT", str(d.amount_msat or 0))
        names = {30: "amp", 31: "amp", 16: "multi-path-payments", 17: "multi-path-payments"}
        features = {str(b): {"name": names.get(b, "unknown"), "is_required": b % 2 == 0, "is_known": b in names}
                    for b in range(d.features.bit_length()) if d.features >> b & 1}
        if "FAKE_LNCLI_FEATURES" in os.environ:
            features = json.loads(os.environ["FAKE_LNCLI_FEATURES"])
        print(json.dumps({"destination": d.payee.hex(), "payment_hash": os.environ.get(
            "FAKE_LNCLI_HASH", d.payment_hash.hex()), "num_satoshis": str(int(msat) // 1000), "num_msat": msat,
            "features": features}))
        return 0
    if cmd == "payinvoice":
        r = hp.http_request(os.environ["FAKE_LNCLI_GATE"], "GET", "/__mock/pay?invoice=" + urllib.parse.quote(inv))
        if r.status != 200:
            sys.stderr.write(f"[lncli] payment failed: {r.status}\n")
            return 1
        print(json.dumps({"status": "SUCCEEDED", "payment_preimage": r.body.decode().strip(),
                          "fee_msat": os.environ.get("FAKE_LNCLI_FEE_MSAT", "0")}))
        return 0
    sys.stderr.write(f"[lncli] unknown command {cmd}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

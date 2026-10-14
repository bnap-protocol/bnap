#!/bin/sh
# A payer for run.py --payer that pays with lnd's lncli, after checking the invoice itself.
# Code is MIT OR Apache-2.0, (c) BNAP contributors.
#
#   python3 -I conformance/run.py ... --payer 'cmd:conformance/payers/lncli-payer.sh' --max-spend-sat 100
#
# run.py appends the BOLT 11 invoice as the last argument and also sets:
#   BNAP_INVOICE              the same invoice
#   BNAP_EXPECT_AMOUNT_SAT    the amount run.py decoded and checked against its spend cap, in sat
#   BNAP_EXPECT_PAYMENT_HASH  the payment hash run.py decoded, in hex
# run.py caps spending against its own decode, so this wrapper decodes the invoice with lnd
# (lncli decodepayreq) and refuses to pay unless lnd reads exactly that amount, a whole number of
# satoshis, and that payment hash. lncli decodepayreq also refuses an invoice for another network.
# On success it prints the 32-byte preimage in hex, as run.py expects.
#
# Settings (environment):
#   LNCLI             the lncli command with its flags, for example "lncli --network=regtest"
#                     (default: lncli)
#   BNAP_FEE_LIMIT_SAT  routing fee limit passed to lncli payinvoice --fee_limit (default: 10)
#   PYTHON            the Python 3 used to read lncli's JSON (default: python3)
set -eu

die() {
    echo "lncli-payer: $*" >&2
    exit 1
}

[ "$#" -ge 1 ] || die "no invoice argument"
eval "inv=\${$#}"
[ "${BNAP_INVOICE:-}" = "$inv" ] || die "the invoice argument and BNAP_INVOICE differ"
want_sat=${BNAP_EXPECT_AMOUNT_SAT:-}
want_hash=${BNAP_EXPECT_PAYMENT_HASH:-}
[ -n "$want_sat" ] || die "BNAP_EXPECT_AMOUNT_SAT is not set (run.py sets it)"
[ -n "$want_hash" ] || die "BNAP_EXPECT_PAYMENT_HASH is not set (run.py sets it)"
LNCLI=${LNCLI:-lncli}
PY=${PYTHON:-python3}

# Read one field of a JSON object on stdin; fail when it is missing.
field() {
    "$PY" -I -c 'import json, sys
v = json.load(sys.stdin).get(sys.argv[1])
if v is None:
    sys.exit("missing " + sys.argv[1])
print(v)' "$1"
}

decoded=$($LNCLI decodepayreq "$inv") || die "lncli decodepayreq refused the invoice"
got_hash=$(printf '%s' "$decoded" | field payment_hash) || die "decodepayreq gave no payment_hash"
got_msat=$(printf '%s' "$decoded" | field num_msat) || die "decodepayreq gave no num_msat"
case "$got_msat" in
    ''|*[!0-9]*) die "decodepayreq num_msat is not a decimal: $got_msat" ;;
esac
case "$want_sat" in
    ''|*[!0-9]*) die "BNAP_EXPECT_AMOUNT_SAT is not a decimal: $want_sat" ;;
esac
[ "$got_hash" = "$want_hash" ] || die "lnd reads payment hash $got_hash, run.py expects $want_hash: not paying"
[ "$got_msat" = "${want_sat}000" ] || die "lnd reads $got_msat msat, run.py expects ${want_sat} sat: not paying"

paid=$($LNCLI payinvoice --force --json --fee_limit "${BNAP_FEE_LIMIT_SAT:-10}" "$inv") \
    || die "lncli payinvoice failed"
status=$(printf '%s' "$paid" | field status) || die "payinvoice gave no status"
[ "$status" = "SUCCEEDED" ] || die "payment status $status"
printf '%s' "$paid" | field payment_preimage

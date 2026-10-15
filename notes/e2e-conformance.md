# Integration notes: e2e conformance, the native entry shapes

Branch `node/e2e-conformance` of bnap, paired with branch `node/e2e` of
caparra (its `notes/e2e.md` has the full report). It changes the
conformance runner only where the runner read the native entries in a way
draft-00 does not support. No spec text changes.

## The disagreement

The runner (N11) and the gate's scheme plugs (caparra N7) read draft-00 4.1
"`data`: the artifact's bytes" differently for the two Lightning schemes:

| Pay entry | N11 runner expected | N7 plugs sent |
| --- | --- | --- |
| `httpauth:L402` | an `l402-macaroon` entry with the binary macaroon and a `bolt11` entry with the invoice | one `l402-macaroon` entry holding the whole `WWW-Authenticate: L402 ...` challenge |
| `payment:lightning/charge` | an `mpp-challenge` entry holding the challenge's parameters as canonical JSON (suite profile `bnap-conf-mpp-1`), the OfferID as the prefix of the `id` | an `mpp-challenge` entry holding the `Payment` challenge exactly as sent in `WWW-Authenticate`, the OfferID in `opaque`, bound by the HMAC `id` of draft-httpauth-payment-01 |

## Decision (literal draft-00 4.1 and the registry's native kinds)

A native entry carries one artifact; its `kind` is a label the scheme's
registry entry lists and `data` is that artifact's own bytes.

- **L402.** The registry lists two kinds, `l402-macaroon` ("a first-party
  caveat `bnap_offer`") and `bolt11` ("the invoice description hash is the
  OfferID"). The macaroon and the invoice are the artifacts; the
  `WWW-Authenticate` challenge is a carrier rendering of both, not an
  artifact of either kind. So the runner was right and the plugs were wrong:
  caparra now sends two entries per L402 pay entry, the binary V2 macaroon
  and the invoice string, and builds the challenge from them.
- **MPP.** The registry's kind is `mpp-challenge`: the artifact is the
  challenge itself, and its bytes are the challenge as the server issues it,
  the `Payment` auth-params of draft-httpauth-payment-01. A JSON re-encoding
  of its parameters is not the artifact's bytes, and an `id` with the
  OfferID as a prefix is not the draft's HMAC-bound id. So the plugs were
  right and the runner was wrong: the runner now reads the entry as one
  `Payment` challenge (profile `bnap-conf-mpp-2`), takes the OfferID from
  `opaque` (`b64u(JCS {"bnap_offer": hex(OfferID)})`, covered by the HMAC
  id), and reads the invoice at `methodDetails.invoice` of the request (the
  lightning charge method) or at `invoice`. The credential shape is
  unchanged: `b64u(JCS {"challenge": parameters, "payload": {"preimage"}})`.
  No separate `bolt11` entry is required for MPP: the invoice is inside the
  challenge, whose bytes the client compares (9.3).

## What changed here

| File | Change |
| --- | --- |
| `conformance/bnap_conf/lightning.py` | MPP profile `bnap-conf-mpp-2`: `mpp_challenge_params` (the entry is one `Payment` challenge, byte for byte), `mpp_offer_id` from `opaque`, `mpp_opaque`, `mpp_challenge_header`, `mpp_request_invoice` reads `methodDetails.invoice` first |
| `conformance/run.py` | `OFR-NATIVE-EMBED` and `PAY-MPP` / `PAY-TWO-SCHEMES` parse the entry as a challenge; `OFR-NATIVE-MATCH` compares the `Payment` challenge's raw bytes with the entry |
| `conformance/mock_gate.py` | Sends the new MPP shape: the challenge in the entry, OfferID in `opaque`, an HMAC id over the bound parameters, the lightning charge request; no `bolt11` entry for MPP |

Checks: `python3 -I -m unittest discover -s conformance/tests` (66 tests,
OK), `mock_gate.py selftest --max-wait 0` (OK, every fault caught),
`gen_cases.py --check` and `coverage_check.py` unchanged and green.

## ERRATA candidate

Draft-00 4.1 should say that `data` is the artifact's own encoding, one
entry per artifact, and that a carrier challenge built from several
artifacts (L402) is not itself an artifact. The MPP adapter spec should fix
how the challenge carries the OfferID (`opaque` under the HMAC id).

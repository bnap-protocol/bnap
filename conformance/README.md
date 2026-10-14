# BNAP conformance suite

Code is MIT OR Apache-2.0, (c) BNAP contributors.

A conformance suite for [socket draft-00](../spec/socket-draft-00.md), built only from the spec, [ERRATA](../spec/ERRATA.md), [DECISIONS](../spec/DECISIONS.md), the [registry export](../registry/generated/registry.json) and the [reference encoder](../reference/python/bnap_ref.py). Standard library only, Python 3.11 or later; run everything with `python3 -I` from the repository root.

| Path | What it is |
| --- | --- |
| [bnap_conf/](bnap_conf/) | A client library that extends the reference encoder: strict TLV, Offer checks, Credential and envelope, Response and ack, manifest with strict I-JSON, JCS and pinning, HTTP scopes, pricing, the use store, client choice rules |
| [gen_cases.py](gen_cases.py) | Writes [vectors/cases/](../vectors/cases/): 535 Wycheproof-style cases in nine areas, with schemas |
| [run.py](run.py) | The black-box runner: `--target`, `--profile`, `--payer`, `--report` |
| [mock_gate.py](mock_gate.py) | A minimal gate with injectable faults, to prove the runner bites |
| [payers/lncli-payer.sh](payers/lncli-payer.sh) | A `--payer` wrapper for lnd: it decodes the invoice with `lncli decodepayreq` and pays only the amount and payment hash run.py expects |
| [COVERAGE.md](COVERAGE.md) | Every BCP 14 sentence of draft-00 mapped to cases; checked by [coverage_check.py](coverage_check.py) |
| [tests/](tests/) | Unit tests: library against vectors.json, every case through an independent evaluator, the mutation self-check |

```sh
python3 -I -m unittest discover -s conformance/tests          # all tests, about a minute and a half
python3 -I conformance/gen_cases.py --check                    # cases on disk are reproducible
python3 -I conformance/coverage_check.py                       # COVERAGE.md is complete
python3 -I conformance/mock_gate.py selftest --max-wait 0      # clean mock green, each fault caught (about a minute)
python3 -I conformance/run.py --list                           # every runner case

python3 -I conformance/run.py --target https://gate.example --profile server --report out/
python3 -I conformance/run.py --target https://gate.example --profile gateway \
    --role echo=echo --role sse=sse --role slow=slow --role fail=fail --role short=short --role cache=cache \
    --payer 'cmd:./pay-invoice.sh' --max-spend-sat 100 --report out/
```

`--profile client` is read-only (manifest and offers). `server` adds every credential path that needs no money; `gateway` adds what a gate in front of an application owes it. With `--payer cmd:<command>`, the command gets the BOLT 11 invoice as its last argument and must print the preimage in hex. The runner decodes the invoice strictly (exact network prefix, a valid amount and multiplier, exactly one payment hash, no trailing data, a signature that recovers a public key), pays only the exact amount of the offer's pay entry, refuses AMP invoices, and caps the total with `--max-spend-sat`, routing fees included: each payment reserves `--fee-limit-sat` (default 10) on top of its amount. Because the payer parses the invoice on its own, the runner also sets `BNAP_EXPECT_AMOUNT_SAT` and `BNAP_EXPECT_PAYMENT_HASH`: a wrapper MUST decode the invoice itself and refuse to pay when either differs. It sets `BNAP_REMAINING_SAT` and `BNAP_FEE_LIMIT_SAT` too: a wrapper MUST cap its routing fee at the limit and refuse unless amount + limit fits in what is left. A payer that prints `fee_msat=<N>` before the preimage has that fee counted; otherwise the whole limit stays counted. [payers/lncli-payer.sh](payers/lncli-payer.sh) does all of this (single part, `--fee_limit`, AMP refused). Reports: `report.json`, `junit.xml` and `report.html` in the `--report` directory.

Exit status: 0 when every MUST case of the profile ran and passed; 1 when a MUST case failed or any case errored; 3 when nothing failed but a MUST case was skipped, for example for want of a payer, a role or a DPoP waive on the target, or was left out by `--only`. The verdict is then "incomplete: N MUST cases not run" or "incomplete: N MUST cases not selected", and `report.json` (`must_skipped`, `must_not_selected`) and `report.html` list them. `--allow-skips` turns 3 into 0 and keeps the lists; 2 is a usage error.

Attestation-only flows use DPoP keys the runner makes, in the profile `bnap-conf-dpop-1` ([bnap_conf/dpop.py](bnap_conf/dpop.py)); a target must accept that profile (empty access token, or one from `--dpop-token-cmd`) for those cases to run. Integration notes, assumptions and gaps: [notes/n11-conformance.md](../notes/n11-conformance.md).

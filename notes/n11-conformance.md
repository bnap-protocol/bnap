# Integration notes: node N11, the conformance suite

Branch `node/n11` of the spec repository, based on `develop` at `4abe3d5`. This node owns `conformance/` and `vectors/cases/`; nothing else in the tree changed. It was built from `spec/socket-draft-00.md`, `spec/ERRATA.md`, `spec/DECISIONS.md`, `registry/generated/registry.json` and `reference/python/bnap_ref.py` only. No code of the implementation under test was read.

## What was built

| Path | Content |
| --- | --- |
| `conformance/bnap_conf/` | Client library on top of the reference encoder (imported by path, so every primitive is shared): strict codecs (BigSize, tu64, TLV, entry lists, type ranges, even/odd, base64url, Error TLV), Offer parse, registry rules, OfferID, offer_sig, client checks and gate checks of 4.4 in order, Credential parse and build, Context, Digest, ReplayKey, UseId, RailId, counter keys, native envelope, Response and ack with the client's receipt rules, manifest with strict I-JSON (duplicate members rejected at every depth), JCS, root signature, document rules and the 9.3 pin and fetch rules, HTTP scopes, route matching, challenge and SSE parsing, a raw HTTP client, pricing and metering, the use store as a state machine, client choice rules (bnap-required, native challenges), and the DPoP, L402, BOLT 11 and MPP test profiles. BIP-340 and P-256 use Jacobian arithmetic, cross-checked against the reference (identical bytes), BIP-340 vector 0 and RFC 6979 A.2.5 |
| `conformance/gen_cases.py` | Writes `vectors/cases/*.json` and `vectors/cases/schema/*.schema.json`. Each expectation is stated by hand and cross-checked against the library; a disagreement stops the generator |
| `vectors/cases/` | 535 cases in 9 files and 42 group types, Wycheproof style, plus a JSON Schema per file and a README |
| `conformance/run.py` | The black-box runner (87 cases, 80 MUST, 7 SHOULD), sections named after draft-00, JSON, JUnit XML and HTML reports |
| `conformance/mock_gate.py` | A minimal in-process gate built from the library, with five injectable faults, a fake payer and the `selftest` command |
| `conformance/COVERAGE.md`, `conformance/coverage_check.py` | Every BCP 14 sentence of draft-00 mapped to vector groups and runner cases; the checker re-extracts the sentences and fails on any gap |
| `conformance/tests/` | 44 unit tests: library against `vectors.json`, every case through an independent evaluator, schemas, reproducibility, the mutation self-check, payer flows, profiles, exit codes, coverage |

## Usage

From the repository root, with Python 3.11 or later:

```sh
python3 -I -m unittest discover -s conformance/tests          # 44 tests, about two minutes
python3 -I conformance/gen_cases.py [--check]                  # write, or verify, vectors/cases
python3 -I conformance/coverage_check.py [--list]              # COVERAGE.md complete; --list prints the sentences
python3 -I conformance/mock_gate.py selftest [--max-wait 0] [--with-payer] [--report DIR]
python3 -I conformance/mock_gate.py serve --port 8402 [--fault F]
python3 -I conformance/run.py --list
python3 -I conformance/run.py --target https://gate.example --profile client|server|gateway \
    [--payer none|cmd:<command>] [--report out/] [--role NAME=ROUTE_ID]... \
    [--dpop-token-cmd CMD] [--max-wait 120] [--max-spend-sat 100] [--only ID,...]
```

- **Profiles.** `client` is read-only: the manifest and every route's 402 (31 cases), no credential sent. `server` adds every credential path that needs no money (85 cases). `gateway` adds the two cases that need the application behind the gate (`GW-TARGET` with `--role echo=...`, `GW-SSE` with `--role sse=...`).
- **Roles** name routes with special application behaviour: `slow` (an action of a second or more, for PENDING), `fail` (the application fails, for FAILED replays), `short` (offers that expire within `--max-wait - 61` seconds, for STALE and the 60 s skew), `echo`, `sse`. Without a role the case skips with the reason.
- **Payer.** `--payer cmd:<command>`: the runner runs the command through the shell with the invoice appended (shell-quoted, after the invoice has been decoded as BOLT 11) and in `BNAP_INVOICE`, checks the printed preimage against the payment hash, and refuses invoices beyond `--max-spend-sat` per action or in total.
- **Exit status** 0 when no MUST case failed or errored, 1 otherwise, 2 on usage errors. SHOULD failures are reported but do not fail the run.
- **Plain HTTP** needs `--allow-http` (test gates only); `MAN-HTTPS` then skips. `--insecure` skips certificate checks and is reported the same way.

### Running against a gate

1. The gate must serve the manifest at `/.well-known/bnap` with every route a client may use.
2. For the attestation flows, at least one route must offer `httpauth:DPoP` with effect `waive` and accept the suite's DPoP profile (below) with an empty access token, or with the token `--dpop-token-cmd` prints for the runner's key thumbprint. Without such a route the attestation section skips.
3. For STALE, give a route whose offers live about a second (`--role short=...`), or the runner waits up to `--max-wait` for the shortest offer it sees.
4. The value flows need `--payer` and an exact-scope offer with `httpauth:L402` natives (`l402-macaroon` and `bolt11`). `PAY-TWO-SCHEMES` additionally needs a `payment:lightning/charge` entry whose MPP challenge names the same invoice; otherwise it skips.

## The mutation self-check

`mock_gate.py selftest` runs the runner against the clean mock and once per fault, in parallel:

```
clean                 all pass                  pass
strip-attest          ATT-CONTEXT-BOUND         caught (also: ATT-BODY-ONLY, ATT-REQUIRED)
status-flip           REPLAY-STATUS-STABLE      caught (also: REPLAY-FAILED)
no-replay             REPLAY-RECORDED           caught (also: ATT-EMPTY-FORMS, ATT-PENDING, ATT-UNKNOWN-ODD, REPLAY-BY-ID, REPLAY-FAILED)
wrong-scope-accepted  ERR-WRONG-SCOPE-EXACT     caught
bad-ack               RCPT-ACK                  caught (also: GW-SSE, RCPT-FIELDS, REPLAY-RECORDED)
selftest: OK
```

| Fault | What the mock then does | Case that must fail |
| --- | --- | --- |
| `strip-attest` | The DPoP adapter ignores the Context claim | `ATT-CONTEXT-BOUND` |
| `status-flip` | A replay reports the opposite status | `REPLAY-STATUS-STABLE` |
| `no-replay` | The store forgets outcomes, so a replay runs again | `REPLAY-RECORDED` |
| `wrong-scope-accepted` | Exact-scope offers are accepted for any request | `ERR-WRONG-SCOPE-EXACT` |
| `bad-ack` | Every Response ack is corrupted | `RCPT-ACK` |

The clean run in the unit tests uses the full `--max-wait`, so `ATT-STALE` (expiry plus the 60 s skew) really runs; with the fake payer (`--with-payer`, or `PayerAndProfiles` in the tests) `PAY-L402`, `PAY-OFFER-BINDING`, `PAY-TWO-SCHEMES`, `PAY-MPP` and `PAY-NATIVE` pass too. Against the clean mock the only skips are `MAN-HTTPS` (plain HTTP), `PAY-METERED` and `NOTES-VALUE` (both need a notes wallet), and the payer cases when no payer is given.

## Coverage

`coverage_check.py` extracts 48 normative sentences (40 MUST, 8 SHOULD); COVERAGE.md also has 47 further rows for the 4.4 check lists, the normative algorithms in code blocks, the ten negative vectors section 14 promises and the DECISIONS rows the suite applies.

| | Sentences |
| --- | --- |
| Covered | 29 |
| Partial (what is not reached is said in the row) | 8: R-4.4-03, R-5.1-05, R-5.3-01, R-5.3-02, R-6.3-01, R-9.2-02, R-12-03, R-12-04 |
| Client duty, checked through vectors | 3: R-7-02, R-10.1-02, R-10.2-03 |
| Untestable black-box, with the reason | 8: R-2-01, R-6.1-01, R-6.1-03, R-6.4-01, R-6.4-02, R-8.2-01, R-9.2-03, R-12-02 |
| Reached by a vector group | 33 |
| Reached by a runner case | 40 |
| Reached by neither | 2 (R-2-01 signer randomness, R-12-02 synchronous durability) |

Cases per file (valid / invalid / acceptable): bigsize 41 (25/16/0), tlv 53 (27/24/2), offer 139 (43/96/0), credential 61 (37/23/1), response 80 (44/36/0), manifest 62 (26/36/0), http-scope 31 (30/0/1), pricing 47 (35/12/0), outcomes 21 (13/8/0). Every negative case the build task names is present (`test_required_negative_cases_exist`).

## Assumptions the suite makes

These fill gaps in the spec. If the implementation under test chose differently, either it or the suite moves; each is a candidate for an adapter spec or an owner decision.

1. **DPoP adapter profile `bnap-conf-dpop-1`** (`bnap_conf/dpop.py`). The registry says the claim name is for the adapter spec, which does not exist. Body = TLV {0: access token, 2: compact JWS}; ES256, `typ dpop+jwt`, `jwk` in the header; claims `jti`, `htm`, `htu` (manifest origin plus path, no query), `iat`, `bnap_ctx` = b64u(Context) and `ath` when a token is present; local ID = the raw 32-byte RFC 7638 thumbprint. Two consequences any DPoP adapter must respect: it must not refuse a seen `jti` (a replay sends the same body and must reach the outcome record), and it must not apply an `iat` window that cuts off replays inside the offer's lifetime.
2. **MPP profile `bnap-conf-mpp-1`** (`bnap_conf/lightning.py`): native entry data is the challenge as canonical JSON; the credential is b64u(JSON {"challenge", "payload": {"preimage"}}); the challenge id is b64u(OfferID || 16-byte tag). Not checked against the text of draft-httpauth-payment-01.
3. **L402**: libmacaroons v2 binary macaroons, base64 in headers, identifier = version 0 || payment hash || token ID, first-party caveat `bnap_offer=<hex OfferID>`, token `macaroon:preimage` (the registry's description).
4. **Client labels.** Refusals with no section 8.2 code are `CLIENT_REJECT` and `MANIFEST_REJECT` in the cases; offers no gate may build (class rules) are labelled MALFORMED.
5. **Repeated header fields** are combined with ", " for the action scope.
6. **Credential without pay** is priced from a positive base (erratum candidate 1).
7. **Binding before the scheme.** `ERR-BINDING` fails a gate that lets the scheme reject a class S credential before it checks the binding.

## Erratum candidates for the spec owner

1. **Section 7, admit.** "p = price(entry.amount, or 0 if the credential has no pay)" makes "if p > 0 and no pay -> UNDERPAID" unreachable and, read literally, admits any attestation-only credential for free. Whether a price reaches 0 does not depend on which positive base it starts from, so the suite prices from a positive base: only a waive, a 10,000 bp discount or a quota with room admit a credential without pay. Owner decision.
2. **Section 10.1.** The separator used to combine repeated listed fields is not fixed; clients and gates must agree byte for byte. Suggest ", ".
3. **Section 9.1.** Whether `GET /v1/*` matches `/v1` itself is open (`http-scope.json` marks it acceptable).
4. **Section 2.** Nested streams "use only 0-239, the experimental range and GREASE", but no error is named for an odd nested type outside those ranges (cases mark it acceptable; bnap_conf rejects).
5. **Section 5.4.** "More than one value credential" leaves open whether a BNAP attestation-only credential may accompany a native value credential, and how the gate would combine them (case marked acceptable).
6. **Section 6.1.** No error code is named for refusing a credential with no single-use ID whose offer outlives its outcome record (cases use POLICY, STALE and BAD_OFFER acceptable).
7. **Section 4.4.** An offer without `mac` and without `issued_at`: MALFORMED at step 2 (a required record is missing) or BAD_OFFER at step 3, where the text puts the rule? The suite uses BAD_OFFER.
8. **Section 5.3.** The order of the binding check relative to scheme verification is not fixed (see assumption 7).
9. **Sections 6.4 and 4.4.** Because the offer checks run before the replay lookup, a replay after the offer expired is STALE, so "replaying a credential is also how a client fetches a receipt it missed" works only while the offer is valid. Worth one sentence.
10. **DECISIONS row 13** says the per-unit rate "travels in the pay entry parameters"; draft-00 and the vectors carry it in the dedicated `rate` record (type 10), not `params` (type 8). The suite follows draft-00.
11. **Section 5.3.** "Its routes MUST NOT require one": the manifest has no member that requires a binding, so it is unclear what a route requiring one looks like.

## Gaps

- **bnap:notes value flows** are stubbed: `spec/schemes/bnap-notes-draft-00.md` is not on develop (it exists only on `node/n13`), so `NOTES-VALUE` and the metered charge flow (`PAY-METERED`) skip with that reason. When the file lands, `bnap_conf/notes.py` is where the wallet goes.
- **TLS binding, positive path.** Python's `ssl` module exposes no `tls-exporter` value, so the runner only sends bindings that cannot match. A correct binding is never presented.
- **Trailers.** `http.client` drops HTTP trailers, so receipts sent as a `BNAP-Receipt` trailer are not read; event streams are.
- **Other attestations** (Web Bot Auth, Privacy Pass, NIP-98, World ID) are not exercised: the runner can make only DPoP keys.
- **Durability, crashes, rate limits and load, rotations over 30 days**: untestable black-box (see COVERAGE.md).
- **Real Lightning.** The value flows were verified only against the mock and its fake payer, never against a real node or wallet.
- **CI.** No workflow job was added (`.github/` belongs to N12). Suggested job: `python3 -I conformance/gen_cases.py --check`, `python3 -I conformance/coverage_check.py` and `python3 -I -m unittest discover -s conformance/tests` on Python 3.11 and 3.x.

## Stop-condition evidence

| Condition | Command | Result |
| --- | --- | --- |
| Unit tests green | `python3 -I -m unittest discover -s conformance/tests` | `Ran 44 tests ... OK` (Python 3.15; the fast subset also on 3.12; every file parses under the 3.9 grammar, so no 3.12-only f-strings) |
| Generator reproducible | `gen_cases.py` twice, SHA-256 of all 18 files | identical both times (`b9e25bb1...02698ed5`); `--check` up to date |
| Runner vs clean mock green | `mock_gate.py selftest` | `clean all pass` (the unit test also runs ATT-STALE with the full wait) |
| Each fault detected | `mock_gate.py selftest` | five of five caught by their case |
| COVERAGE.md complete | `coverage_check.py` | 48 normative sentences, every one mapped; 47 further rows checked |
| Leak guard | `sh ops/leak-guard.sh` | clean |

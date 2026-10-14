# Integration notes: node N11, the conformance suite

Branch `node/n11` of the spec repository, based on `develop` at `4abe3d5`, with `develop` at `e90fd8c` merged in (repair round 3). This node owns `conformance/` and `vectors/cases/`; nothing else in the tree changed. It was built from `spec/socket-draft-00.md`, `spec/ERRATA.md`, `spec/DECISIONS.md`, `registry/generated/registry.json` and `reference/python/bnap_ref.py` only. No code of the implementation under test was read.

## What was built

| Path | Content |
| --- | --- |
| `conformance/bnap_conf/` | Client library on top of the reference encoder (imported by path, so every primitive is shared): strict codecs (BigSize, tu64, TLV, entry lists, type ranges, even/odd, base64url, Error TLV), Offer parse, registry rules, OfferID, offer_sig, client checks and gate checks of 4.4 in order, Credential parse and build, Context, Digest, ReplayKey, UseId, RailId, counter keys, native envelope, Response and ack with the client's receipt rules, manifest with strict I-JSON (duplicate members rejected at every depth), JCS, root signature, document rules and the 9.3 pin and fetch rules, HTTP scopes, route matching, challenge and SSE parsing, a raw HTTP client, pricing and metering, the use store as a state machine, client choice rules (bnap-required, native challenges), and the DPoP, L402, BOLT 11 and MPP test profiles. BIP-340 and P-256 use Jacobian arithmetic, cross-checked against the reference (identical bytes), BIP-340 vector 0 and RFC 6979 A.2.5 |
| `conformance/gen_cases.py` | Writes `vectors/cases/*.json` and `vectors/cases/schema/*.schema.json`. Each expectation is stated by hand and cross-checked against the library; a disagreement stops the generator |
| `vectors/cases/` | 535 cases in 9 files and 42 group types, Wycheproof style, plus a JSON Schema per file and a README |
| `conformance/run.py` | The black-box runner (96 cases, 89 MUST, 7 SHOULD), sections named after draft-00, JSON, JUnit XML and HTML reports, and a verdict that stays "incomplete" while any MUST case of the profile did not run, skipped or left out by `--only` |
| `conformance/mock_gate.py` | A minimal in-process gate built from the library, with nineteen injectable faults plus a `no-dpop` setting, a fake payer and the `selftest` command |
| `conformance/COVERAGE.md`, `conformance/coverage_check.py` | Every BCP 14 sentence of draft-00 mapped to vector groups and runner cases; the checker re-extracts the sentences and fails on any gap |
| `conformance/tests/` | 50 unit tests: library against `vectors.json`, every case through an independent evaluator, schemas, reproducibility, generator arguments, the mutation self-check, payer flows, profiles, exit codes, `--only` verdicts, coverage and its counts |

## Usage

From the repository root, with Python 3.11 or later:

```sh
python3 -I -m unittest discover -s conformance/tests          # 50 tests, about a minute and a half
python3 -I conformance/gen_cases.py [--check]                  # write, or verify, vectors/cases; other arguments exit 2
python3 -I conformance/coverage_check.py [--list]              # COVERAGE.md complete; --list prints the sentences
python3 -I conformance/mock_gate.py selftest [--max-wait 0] [--with-payer] [--report DIR]
python3 -I conformance/mock_gate.py serve --port 8402 [--fault F]
python3 -I conformance/run.py --list
python3 -I conformance/run.py --target https://gate.example --profile client|server|gateway \
    [--payer none|cmd:<command>] [--report out/] [--role NAME=ROUTE_ID]... \
    [--dpop-token-cmd CMD] [--max-wait 120] [--max-spend-sat 100] [--fee-limit-sat 10] [--only ID,...] [--allow-skips]
```

- **Profiles.** `client` is read-only: the manifest and every route's 402 (32 cases), no credential sent. `server` adds every credential path that needs no money (94 cases). `gateway` adds the two cases that need the application behind the gate (`GW-TARGET` with `--role echo=...`, `GW-SSE` with `--role sse=...`).
- **Roles** name routes with special application behaviour: `slow` (an action of a second or more, for PENDING), `fail` (the application fails, for FAILED replays), `short` (offers that expire within `--max-wait - 61` seconds, for STALE and the 60 s skew), `echo`, `sse`. Without a role the case skips with the reason.
- **Payer.** `--payer cmd:<command>`: the runner runs the command through the shell with the invoice appended (shell-quoted, after the invoice has been decoded as BOLT 11) and in `BNAP_INVOICE`, checks the printed preimage against the payment hash, and refuses invoices whose amount plus the per-payment routing fee limit (`--fee-limit-sat`, default 10) is over what `--max-spend-sat` leaves; AMP invoices are refused. The payer gets `BNAP_EXPECT_AMOUNT_SAT`, `BNAP_EXPECT_PAYMENT_HASH`, `BNAP_REMAINING_SAT` and `BNAP_FEE_LIMIT_SAT`, and may print `fee_msat=<N>` before the preimage; the runner counts amount + fee (otherwise amount + the whole limit). `conformance/payers/lncli-payer.sh` checks lnd's decode, the budget and AMP, pays in one part with `--fee_limit`, and reports the fee lnd paid.
- **Exit status** 0 when every MUST case of the profile ran and passed; 1 when a MUST case failed or any case errored; 3 when nothing failed but a MUST case was skipped or left out by `--only` (the verdict is then "incomplete: N MUST cases not run" and/or "N MUST cases not selected", and `report.json` `must_skipped` and `must_not_selected` and `report.html` list the IDs); 2 on usage errors. `--allow-skips` turns 3 into 0 and keeps the lists. SHOULD failures are reported but do not fail the run. A run with `--only` is therefore never "conformant" unless it selects every MUST case of the profile.
- **Plain HTTP** needs `--allow-http` (test gates only); `MAN-HTTPS` then skips. `--insecure` skips certificate checks and is reported the same way.

### Running against a gate

1. The gate must serve the manifest at `/.well-known/bnap` with every route a client may use.
2. For the attestation flows, at least one route must offer `httpauth:DPoP` with effect `waive` and accept the suite's DPoP profile (below) with an empty access token, or with the token `--dpop-token-cmd` prints for the runner's key thumbprint. Without such a route the attestation section skips, and the run is incomplete (exit 3), never conformant.
3. For STALE, give a route whose offers live about a second (`--role short=...`), or the runner waits up to `--max-wait` for the shortest offer it sees.
4. The value flows need `--payer` and an exact-scope offer with `httpauth:L402` natives (`l402-macaroon` and `bolt11`). `PAY-TWO-SCHEMES` additionally needs a `payment:lightning/charge` entry whose MPP challenge names the same invoice; otherwise it skips.
5. `RCPT-EVERY-COMMIT` first sends one admissible DPoP-only credential to every route that offers a DPoP waive, roles or not, so a route whose application fails is reached without `--role fail`. Each such route's application therefore runs once more.
6. `USE-REUSABLE-WINDOW` reads `limits.replay_window`. To test the refusal half, give a route whose offer outlives it (expires + 60 > now + replay_window), with a DPoP waive; the mock's `window` route does that.
7. `SCOPE-MANIFEST-ORIGIN` sends a Host field that spells the target's authority another way: the host name in upper case, `localhost` for a loopback address, or the default port written out (a non-loopback address on an explicit port has no other spelling, and the case skips). If a front routes by Host and does not answer that spelling with a BNAP 402, the case skips with the response it got.

## The mutation self-check

`mock_gate.py selftest` runs the runner against the clean mock, once per fault, once more for `no-receipt-on-failed` with no roles, and twice with the `no-dpop` setting, in parallel (`selftest`; the clean run below had no payer, so the payer cases count among those not run):

```
clean                          all pass                  pass; verdict incomplete: 8 MUST cases not run
strip-attest                   ATT-CONTEXT-BOUND         caught (also: ATT-BODY-ONLY, ATT-EXT-BOUND, ATT-REQUIRED)
status-flip                    REPLAY-STATUS-STABLE      caught (also: REPLAY-FAILED)
no-replay                      REPLAY-RECORDED           caught (also: ATT-EMPTY-FORMS, ATT-NESTED-ODD, ATT-PENDING, ATT-UNKNOWN-ODD, REPLAY-BY-ID, REPLAY-FAILED)
wrong-scope-accepted           ERR-WRONG-SCOPE-EXACT     caught
bad-ack                        RCPT-ACK                  caught (also: GW-SSE, RCPT-FIELDS, REPLAY-RECORDED)
quote-expires-over             OFR-PARSE                 caught (also: OFR-NATIVE-MATCH)
native-in-route                OFR-ROUTE-CLASSES         caught (also: OFR-PARSE)
ext-ignored                    ATT-EXT-BOUND             caught
reusable-window                USE-REUSABLE-WINDOW       caught
late-expiry                    ERR-EXPIRY-BEFORE-PLUG    caught
nonce-reuse                    OFR-NONCE-ONE-MINT        caught (also: OFR-NONCE-FRESH)
no-receipt-on-failed           RCPT-EVERY-COMMIT         caught (also: REPLAY-FAILED)
nested-odd-rejected            ATT-NESTED-ODD            caught
nested-odd-in-rk               ATT-NESTED-ODD            caught
nested-even-ignored            ERR-NESTED-EVEN           caught
ext-even-ignored               ERR-EXT-EVEN              caught
offer-size-unchecked           ERR-OFFER-TOO-LARGE       caught
htu-from-host                  SCOPE-MANIFEST-ORIGIN     caught
scope-from-host                SCOPE-MANIFEST-ORIGIN     caught
no-receipt-on-failed/no-roles  RCPT-EVERY-COMMIT         caught
no-dpop+no-replay              verdict incomplete        caught: incomplete: 34 MUST cases not run, exit 3
no-dpop+status-flip+bad-ack    verdict incomplete        caught: incomplete: 34 MUST cases not run, exit 3
selftest: OK
```

A fault row counts as caught only when its case fails and the run exits 1. A `no-dpop` row counts only when nothing failed, the verdict is incomplete, the exit status is 3 and the replay and receipt cases are among those listed as not run.

| Fault | What the mock then does | Case that must fail |
| --- | --- | --- |
| `strip-attest` | The DPoP adapter ignores the Context claim | `ATT-CONTEXT-BOUND` |
| `status-flip` | A replay reports the opposite status | `REPLAY-STATUS-STABLE` |
| `no-replay` | The store forgets outcomes, so a replay runs again | `REPLAY-RECORDED` |
| `wrong-scope-accepted` | Exact-scope offers are accepted for any request | `ERR-WRONG-SCOPE-EXACT` |
| `bad-ack` | Every Response ack is corrupted | `RCPT-ACK` |
| `quote-expires-over` | Exact-scope pay entries carry `quote_expires` after `expires` | `OFR-PARSE` |
| `native-in-route` | Route-scope offers carry a native record | `OFR-ROUTE-CLASSES` |
| `ext-ignored` | The 5.2 Context leaves `ext` out | `ATT-EXT-BOUND` |
| `reusable-window` | `replay_window` 120 s and the 6.1 admission check removed | `USE-REUSABLE-WINDOW` |
| `late-expiry` | Scheme plugs run before the expiry check; STALE comes afterwards | `ERR-EXPIRY-BEFORE-PLUG` |
| `nonce-reuse` | One fixed nonce per route, a new invoice on every 402 | `OFR-NONCE-ONE-MINT` |
| `no-receipt-on-failed` | Responses to FAILED outcomes carry no BNAP-Receipt | `RCPT-EVERY-COMMIT`, also without `--role` |
| `nested-odd-rejected` | A scheme item with an unknown odd record is MALFORMED | `ATT-NESTED-ODD` |
| `nested-odd-in-rk` | Unknown odd records inside scheme items enter the ReplayKey | `ATT-NESTED-ODD` |
| `nested-even-ignored` | Unknown even records inside scheme items are dropped, not refused | `ERR-NESTED-EVEN` |
| `ext-even-ignored` | The gate does not parse `ext`, so an even extension passes | `ERR-EXT-EVEN` |
| `offer-size-unchecked` | An inline offer is not checked against `max_offer` (the gate answers BAD_OFFER) | `ERR-OFFER-TOO-LARGE` |
| `htu-from-host` | The DPoP adapter builds `htu` from the raw Host field | `SCOPE-MANIFEST-ORIGIN` |
| `scope-from-host` | The action scope is built from the Host field instead of the manifest origin | `SCOPE-MANIFEST-ORIGIN` |
| `no-dpop` (setting) | No route offers an `httpauth:DPoP` waive | none: the verdict must be incomplete, exit 3 |

The clean run in the unit tests uses the full `--max-wait`, so `ATT-STALE` and `ERR-EXPIRY-BEFORE-PLUG` (expiry plus the 60 s skew) really run; the `late-expiry` run always keeps the full wait, even under `selftest --max-wait 0`. With the fake payer (`--with-payer`, or `PayerAndProfiles` in the tests) `PAY-L402`, `PAY-OFFER-BINDING`, `PAY-TWO-SCHEMES`, `PAY-MPP` and `PAY-NATIVE` pass too. Against the clean mock no case fails; the verdict is still "incomplete" because `MAN-HTTPS` (plain HTTP), `PAY-METERED` and `NOTES-VALUE` (both need a notes wallet) cannot run there, plus the payer cases when no payer is given. That is the intended reading of a run that did not reach every MUST.

## Coverage

`coverage_check.py` extracts 48 normative sentences (40 MUST, 8 SHOULD); COVERAGE.md also has 47 further rows for the 4.4 check lists, the normative algorithms in code blocks, the ten negative vectors section 14 promises and the DECISIONS rows the suite applies.

| | Sentences |
| --- | --- |
| Covered | 29 |
| Partial (what is not reached is said in the row) | 10: R-4.4-02, R-4.4-03, R-5.1-05, R-5.3-01, R-5.3-02, R-6.1-03, R-6.3-01, R-9.2-02, R-12-03, R-12-04 |
| Client duty, checked through vectors | 3: R-7-02, R-10.1-02, R-10.2-03 |
| Untestable black-box, with the reason | 6: R-2-01, R-6.4-01, R-6.4-02, R-8.2-01, R-9.2-03, R-12-02 |
| Reached by a vector group | 33 |
| Reached by a runner case | 41 |
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

- **bnap:notes value flows** are stubbed: `spec/schemes/bnap-notes-draft-00.md` has landed on develop (N13 merge `40c12d3`, merged into `node/n11`), but the suite's notes wallet client is not built yet, so `NOTES-VALUE`, the metered charge flow (`PAY-METERED`) and the draft-00 6.1 RailId commit at mint skip with that reason (COVERAGE rows R-6.1-03, A-7m and D-31 are partial). `bnap_conf/notes.py` is where the wallet goes.
- **TLS binding, positive path.** Python's `ssl` module exposes no `tls-exporter` value, so the runner only sends bindings that cannot match. A correct binding is never presented.
- **Trailers.** `http.client` drops HTTP trailers, so receipts sent as a `BNAP-Receipt` trailer are not read; event streams are.
- **Other attestations** (Web Bot Auth, Privacy Pass, NIP-98, World ID) are not exercised: the runner can make only DPoP keys.
- **Durability, crashes, rate limits and load, rotations over 30 days**: untestable black-box (see COVERAGE.md).
- **Order among the 4.4 offer checks.** The runner shows that parse, authenticity, expiry and scope each come before any plug, but sends no pair of offer faults that would show version before authenticity or expiry before scope; only the vectors (`offer.json#GateOfferCheck`) fix that order.
- **Per-address mint limits** (DECISIONS row 24, section 12): one mint per offer nonce is checked; limits per client address need load from many addresses.
- **Nested records in pay items.** The runner puts unknown odd records only inside attest items: an admissible pay item needs a payer. Unknown even records go into both.
- **Host spellings.** `SCOPE-MANIFEST-ORIGIN` skips for a non-loopback IP address on an explicit port (it has no other spelling), and for a front that routes by Host and refuses the variant.
- **Real Lightning.** The value flows were verified only against the mock and its fake payer, never against a real node or wallet.
- **CI.** No workflow job was added (`.github/` belongs to N12). Suggested job: `python3 -I conformance/gen_cases.py --check`, `python3 -I conformance/coverage_check.py` and `python3 -I -m unittest discover -s conformance/tests` on Python 3.11 and 3.x.

## Repair round 1

Seven review findings, each fixed with a mock fault that proves the fix bites (table above):

| Finding | Fix |
| --- | --- |
| Skipped MUST cases still gave "conformant", exit 0 (no DPoP waive, no payer: 31 MUST cases skipped) | Verdict "incomplete: N MUST cases not run", exit 3, skipped IDs in `report.json` and `report.html`; `--allow-skips` for exit 0 |
| No case sent a non-empty ext (A-5.2) | `ATT-EXT-BOUND`: an odd extension in ext, Context over H(ext), receipt digest checked; an altered ext must be refused |
| R-6.1-01 marked untestable, though a violation shows at admission | `USE-REUSABLE-WINDOW`: every admission without a single-use ID audited against `limits.replay_window`; offers that outlive the record must be refused |
| Expiry before plugs was never exercised (R-4.4-02) | `ERR-EXPIRY-BEFORE-PLUG`: garbage value body under an expired offer must be STALE, not BAD_CREDENTIAL; R-4.4-02 now partial |
| D-24 (one invoice per nonce, a MUST) mapped to the SHOULD case `OFR-NONCE-FRESH` | `OFR-NONCE-ONE-MINT` (MUST): offers sharing a nonce carry byte-identical natives; D-24 and R-12-04 corrected |
| `OFR-PARSE` checked size only; the native-in-route check of `OFR-ROUTE-CLASSES` was dead code | Parse failures fail `OFR-PARSE`; `OFR-ROUTE-CLASSES` reads route_scope and native records from the raw bytes of offers that did not parse |
| `RCPT-EVERY-COMMIT` ignored responses of HTTP 400 and above, FAILED outcomes included | Every credentialed response without BNAP-Error must carry a receipt; the case first commits once on every DPoP-waive route, so `--role fail` is not needed |

Also in this round: the mock gate no longer calls `socket.getfqdn()` on bind (a reverse DNS lookup that cost about 35 s per mock start where DNS is blocked), which brought the unit suite from about 127 s to about 98 s, and the mock gained a `window` route whose route offer outlives its `replay_window` of 7,200 s.

## Repair round 2

Seven review findings. Each of the first four came with a fault that passed every case; each is now a mock fault caught by its case (table above).

| Finding | Fix |
| --- | --- |
| No unknown record was ever put inside a scheme item, so R-2-03, R-2-04 and R-2-05 were "covered" only at the top level | `ATT-NESTED-ODD`: a DPoP attest item with an odd type 5 is admitted under the runner's Digest, and the same credential without it replays. `ERR-NESTED-EVEN`: an even type 6 in an attest item and in a pay item is MALFORMED. Faults `nested-odd-rejected`, `nested-odd-in-rk`, `nested-even-ignored` |
| No even extension inside ext was sent (fault: the gate does not parse ext) | `ERR-EXT-EVEN`: a valid DPoP credential whose ext holds even type 2 is MALFORMED. Fault `ext-even-ignored` |
| The 4.4 size check was never run on an inline Offer | `ERR-OFFER-TOO-LARGE`: the probe offer padded with an experimental odd record to `max_offer` + 1 bytes, inline in a credential under min(max_credential, 9,216), must be TOO_LARGE (413). Fault `offer-size-unchecked` |
| The Host field always equalled the manifest authority, so htu or the scope built from Host went unseen | `SCOPE-MANIFEST-ORIGIN`: the 402 offer scope and the admitted receipt's Digest must follow the manifest origin when Host spells the authority another way. `http_request` now sends a caller's Host instead of its own. Faults `htu-from-host`, `scope-from-host` |
| `--only` could print "conformant for this profile" and exit 0 for two cases | A run that leaves out MUST cases of the profile is "incomplete: N MUST cases not selected", exit 3 unless `--allow-skips`; `report.json` lists them in `must_not_selected` (with the `--only` value) and `report.html` in its own section |
| `gen_cases.py` ignored unknown arguments, so `--chek` rewrote the files | argparse with only `--check`; anything else exits 2 and writes nothing |
| `coverage_check.py` printed 10 untestable rows where there are 7 | Statuses are read from the start of the cell and counted separately; every status must start with covered, partial, client duty or untestable black-box, and a row naming no test must be untestable with a reason |

COVERAGE.md rows R-2-03, R-2-04, R-2-05, R-2-07, R-4.4-02a, R-5.1-04, A-5.1 and A-10.1 now name the new cases and say which part of the rule each reaches. The runner still sends no odd record inside a pay item (an admissible pay item needs a payer); `tlv.json#NestedEvenOdd` covers the nested rule.

## Stop-condition evidence

| Condition | Command | Result |
| --- | --- | --- |
| Unit tests green | `python3 -I -m unittest discover -s conformance/tests` | `Ran 50 tests in 90.9s OK` (Python 3.15) |
| Generator reproducible | `gen_cases.py` twice, then SHA-256 over the sorted per-file SHA-256 list of `vectors/cases` | identical both times (`72ced574...1d2b94e7`); `--check` up to date. Unchanged in repair rounds 1 and 2 |
| Runner vs clean mock green | `mock_gate.py selftest`, and `run.py --profile gateway` with every role and the fake payer against `mock_gate.py serve` | selftest `clean all pass`; the served run: 91 pass, 0 fail, 0 errors, verdict incomplete only for `MAN-HTTPS`, `PAY-METERED`, `NOTES-VALUE` and, at `--max-wait 0`, `ATT-STALE` and `ERR-EXPIRY-BEFORE-PLUG` (the unit test runs the clean mock with the full wait, where both pass) |
| Each fault detected | `mock_gate.py selftest` | nineteen of nineteen caught by their case with exit 1, `no-receipt-on-failed` also without roles, and both `no-dpop` runs incomplete with exit 3 |
| `--only` not conformant | `run.py --profile gateway --only OFR-402,MAN-SIG` against the served clean mock | `verdict: incomplete: 87 MUST cases not selected`, exit 3; `report.json` `must_not_selected` lists 87 |
| COVERAGE.md complete | `coverage_check.py` | 48 normative sentences, every one mapped (33 named by vectors, 41 by runner cases); status: 29 covered, 9 partial, 3 client duty, 7 untestable black-box; 47 further rows checked |
| Leak guard | `sh ops/leak-guard.sh` | clean (95 tracked files) |

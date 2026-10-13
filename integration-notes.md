# Integration notes: node N13 (standards drafts and the notes-scheme rewrite)

Branch `node/n13` of the `bnap` repository. Files this node owns:

- `spec/schemes/bnap-notes-draft-00.md` (priority 1, done)
- `ietf/` (priority 2, done; CI-ready, not built locally)
- `nuts/` and `docs/payment-method-cashu.md` (priority 3, done)

Nothing else in the repository was edited.

## 1. bnap:notes draft-00: the contract downstream nodes build against

The document is normative for the `bnap-scheme-notes` crate, the wallet (`caparra-wallet`), the issuer endpoints in the gate, and the notes test vectors. Section numbers below are of `spec/schemes/bnap-notes-draft-00.md`.

### Wire objects

| Object | Where it lives | Section |
| --- | --- | --- |
| Body | Credential `pay` record, nested type 2. TLV: 0 `inputs` (entry list), 2 `outputs` (entry list), 4 `fund` (UTF-8 quote ID, 1 to 64 bytes) | 3.1 |
| Input entry | 0 `keyset` (33-byte full keyset ID), 2 `amount` (tu64 power of two), 4 `key` (32-byte x-only K), 6 `C` (33-byte point). Inputs sorted by `key`, strictly ascending | 3.2 |
| Output entry | 0 `keyset` (33 bytes, an active keyset), 2 `amount` (tu64 power of two), 4 `blinded` (33-byte B') | 3.3 |
| Witness | Credential `pay` record, nested type 4. TLV: 0 `input_sigs` (64 bytes per input, input order), 2 `fund_sig` (64 bytes). All BIP-340 over the socket Digest | 3.4 |
| Pay entry params | Offer pay entry record 8. TLV: 0 `issuer` URL, 2 `keysets` (entry list: 0 id, 2 input_fee_ppk, 4 active flag), 4 `max_inputs`, 6 `max_outputs` (default 16 each), 8 `max_fund`, 10 `fund_quote` | 5.1, 5.2 |
| fund_quote | 0 quote ID, 2 BOLT11 request, 4 amount, 6 expiry, 8 33-byte NUT-20 pubkey | 5.3 |
| scheme_result | Response record 16. TLV: 0 `signatures` (entry list: 0 index tu64, 2 C' point, 4 DLEQ e, 6 DLEQ s). Omitted when the change is 0 | 7.3 |

Bodies and witnesses are strict: any unknown record, even or odd, any empty record and any non-canonical encoding is `bnap:notes/NON_CANONICAL` (3.5). Params follow the even/odd rule (5.1).

### What `verify` returns (6.4)

- local IDs: the 33-byte compressed `Y = hash_to_curve(hex(K))` of each input, use model `single`;
- rail references: none, except kind `ln` with the invoice payment hash when the body holds `fund`;
- value: `I + F - fee`, fee = `(sum of input_fee_ppk + 999) div 1000`, checked u64 arithmetic (6.3).

Outputs and quote IDs are not use IDs. `verify` has no side effects and runs the seven checks of 6.2 in order. It reads no use state at all: it checks that a fund quote is paid, never whether it has issued (the RailId commit is the single-use check), and it never consults the signed-output table. That keeps every replay of a committed credential on the socket's replay path. There is no `OUTPUT_REUSED` check any more; the code `bnap:notes/OUTPUT_REUSED` is reserved and never sent.

### Settlement (section 7)

- change = `value - charged`; charged is 0 on FAILED, so FAILED refunds the whole value (fees kept).
- The outputs must form a complete power-of-two ladder covering the value (6.3, checked at verify as `BAD_OUTPUTS`).
- `select(outputs, change)`: greedy by amount descending, then index ascending. Proven exact on complete ladders (brute force over 942 ladders, 55,542 targets, zero failures).
- DLEQ with NUT-12's deterministic nonce is a MUST, so settle is byte-deterministic.
- The signed-output table (NUT-09) must be durable no later than the outcome write. It is keyed by `(B', source)`, where the 32-byte source is `H(pay body)` of the credential that settled the output, or `rk_mint`, and it keeps every record. A `B'` signed before is signed again and gets its own record, never a settle failure. Records with the same keyset, amount and `B'` hold the same `C'` and DLEQ proof (NUT-12's nonce depends on `a`, `A`, `B'`, `C'` only), so NUT-09 answers with any record whose keyset, amount and `B'` match.
- NUT-04 minting (8.5) still refuses outputs signed before, but checks inside its transaction and only after recognizing a retry of the same mint request (`used[RailId] = rk_mint`).
- Timeout refunds are computed lazily when the client replays the credential (7.5). The gate must support "outcome FAILED, no scheme_result yet" and fill it with one conditional write.
- **Admission cutoff** (5.4, P9). Draft-00 4.4 answers STALE before the commit can find a replay, so a replay after the offer's deadline never reaches `outcome[rk]`. A notes gate therefore commits a new notes credential only until `cutoff = min(expires, quote_expires) - pending_timeout - 60 s`, checked inside the commit transaction after the replay lookup: an existing outcome is still served, a new commit past the cutoff aborts with STALE and consumes nothing. The socket `commit` needs an optional `admit_until` argument for this (owner of `bnap-plug` / the store crates). The gate MUST NOT list `bnap:notes` in an offer whose cutoff is less than 60 s after issuance; with `pending_timeout` 300 s, notes offers live at least 7 minutes (10 or more recommended), and the next route offer is issued before the current one's cutoff. Wallets replay unanswered credentials at once, at each `retry_after`, and when `pending_timeout` has passed, always before the deadline.

### Issuer and store requirements that cross crate boundaries

- **NUT-04 minting commits the RailId** (8.5) in the gate's use store, keyed `rk_mint = H_"bnap:notes/mint"(lp(quote ID) ‖ BigSize(k) ‖ lp(output₁) ‖ …)`, in one transaction with the signed-output records, with no outcome record and no PENDING state. The `UseStore` trait needs a single-ID insert-or-compare for this (the socket `commit` is not the right shape). Owner of `bnap-plug` / the store crates: please expose one.
- **NUT-23 quote state is derived from the use store** (8.6): issued exactly when the RailId is committed.
- **NUT-07** answers from the use store; **NUT-09** from the signed-output table (12.2).
- **Key isolation** (4.2): refuse NUT-03 swaps and NUT-05 melts of BNAP-keyset inputs.
- **Funding inside the 402** (section 8): the `BNAP-Fund` request field (RFC 9651 Dictionary: `amount` Integer, `pubkey` String of 66 hex characters). At most one quote per offer nonce, per-address rate limit, never without the field, `fund_quote` only in exact-scope offers.
- **Swap route**: manifest route id `notes-swap`, price `{"sat": 0}`, answered by the gate itself (section 11).

### Wallet requirements (section 15, 12)

NUT-13 derivation for version-01 keysets with type `0x02` for the note key and `0x01` for the blinding factor; 64-bit counter, top 16 bits = device slot; never reuse a counter; record the highest counter per keyset and slot in the backup at least every 100 values; restore in batches of 100, stop after three empty batches but never before the recorded counter.

### Test vectors

Section 18 lists what the notes vectors must contain. The socket vectors' notes body is a placeholder and is not a valid notes body under this draft; they need no change, because they test socket hashing only.

## 2. ietf/: draft-bnap-socket

| File | What it is |
| --- | --- |
| `ietf/draft-bnap-socket.md` | kramdown-rfc source, `docname: draft-bnap-socket-latest`, generated; do not edit by hand |
| `ietf/tools/from-draft00.py` | Generator: `cd ietf && python3 -I tools/from-draft00.py ../spec/socket-draft-00.md > draft-bnap-socket.md` |
| `ietf/Makefile`, `.gitignore`, `.editorconfig`, `.github/workflows/{ghpages,publish,archive,update}.yml` | martinthomson/i-d-template files, current template versions (checkout@v6, cache@v5, upload-artifact@v6) |
| `ietf/ci/bnap-monorepo.yml` | A workflow that builds the draft from inside the bnap repository |
| `ietf/README.md`, `CONTRIBUTING.md`, `LICENSE.md` | Template-style docs: derivation, split-out plan, IETF contribution terms |

How the derivation keeps the normative text: same section order, so draft-00's section numbers stay valid; sections 1, 12 and 13 renamed Introduction, Security Considerations, IANA Considerations; the BCP 14 sentence replaced by `{::boilerplate bcp14-tagged}`; non-ASCII symbols written as ASCII (`||`, `ceil()`, `floor()`, `_1`, `^64`); the twelve code blocks re-wrapped to at most 72 columns, each pinned by the first 8 hex digits of the SHA-256 of its draft-00 original, so a draft-00 change stops the generator instead of leaving a stale copy; code comments, which draft-00 sets off by spacing alone, marked with `#` (repair round 1: wrapped comments had read as statements, and the L402 placeholder had lost its caveat name `bnap_offer`); "RFC NNNN" turned into citations and other documents cited at first mention; the 10.3 HTTP example folded as RFC 8792 describes. Added: abstract, a note to readers, a security paragraph, IANA templates (HTTP authentication scheme `BNAP`, the four `BNAP-*` fields, the well-known URI `bnap`, and the BNAP registry group with RFC 8126 policies), references, acknowledgments. Checked: both hex blocks equal `vectors.json` byte for byte, no non-ASCII character is left, every declared reference is cited and every citation is declared, the YAML front matter and all workflow files parse.

**Not built locally.** `xml2rfc` and `kramdown-rfc` are not installed on this machine, and installing them (pipx, gem) was not done in this session: it downloads packages, which needs the owner's go-ahead, and disk is tight. The build is left to CI.

**For the orchestrator or N12 (who own the repository root):** GitHub runs workflows only from the root `.github/workflows/`, and i-d-template expects the draft at the repository root. Either copy `ietf/ci/bnap-monorepo.yml` to `.github/workflows/ietf-draft.yml` (it diffs the generated source against draft-00, then builds text and HTML and uploads them), or split the directory into its own repository (`git subtree split --prefix=ietf`) as `bnap-protocol/draft-bnap-socket`, where the template workflows run unchanged. The front matter's `venue` already points at that repository name.

**Before a Datatracker submission (owner):** the author is an organization only, and the Datatracker wants a person; the name `draft-bnap-socket` lacks the `draft-<author>-` part individual drafts usually carry.

## 3. nuts/ and docs/

| File | What it is |
| --- | --- |
| `nuts/xx-key-secret-proofs.md` | NUT-XX key-secret proofs: secret = hex(K), witness = one BIP-340 signature by K over a context digest; key-secret keysets and key isolation; `swap`, `melt` and external contexts; theft-resistant NUT-22 tokens; NUT-13 type `0x02`; test vectors |
| `nuts/tools/key_secret_vectors.py` | Regenerates those vectors (`python3 -I nuts/tools/key_secret_vectors.py reference/python`); checks `hash_to_curve` against the three NUT-00 vectors first, and they match |
| `nuts/xx-http-402-self-issued-mint.md` | NUT-XX HTTP 402 with a self-issued mint: a NUT-24 profile; `X-Cashu` keeps a NUT-18/NUT-26 request (own mint only, `i` = OfferID hex) next to the BNAP offer; payment in `BNAP-Credential`; change and receipt in `BNAP-Receipt`; funding in the 402; alignment table |
| `nuts/README.md` | Submission plan: one issue first (NUT numbers, NUT-13 type `0x02`, NUT-24 and NUT-22 feedback), then one pull request per NUT, merged only with two independent implementations |
| `docs/payment-method-cashu.md` | Registration of `cashu` in the HTTP Payment Methods registry of draft-httpauth-payment-01: the template plus the six items its Section 9.1 requires; BNAP use as `payment:cashu/charge` |

All three markdown files in `nuts/` pass Prettier 3.9.9 (run from the local npx cache, nothing downloaded). `docs/` follows the repository's compact table style instead.

Downstream: the key-secret swap digest (`Cashu_KeySecret_Swap_v1`) and auth digest (`Cashu_KeySecret_Auth_v1`) are new tags only the NUT uses; `bnap:notes` itself uses only the external context (the socket Digest).

## 4. Decisions made

All 30 provisional decisions are listed in Appendix B of the notes document (P1 to P30), numbered in section order, one row for every "(provisional)" marker in the text. Repair round 1 renumbered them; the old numbers are gone. The ones with the widest effect:

- P2: unknown records in a notes body are rejected even when odd (draft-00 5.1 canonical bodies).
- P9: admission cutoff, so that every committed notes credential can still be replayed when its timeout refund is due (ERRATA row 50).
- P11: `verify` reads no use state; the v0.4 `OUTPUT_REUSED` check is dropped and the code reserved (ERRATA row 49).
- P12: one output ladder replaces v0.4's separate change and refund lists, because the charge of a metered call is known only at settlement.
- P15: outputs are not use IDs; the RailId alone guards fund quotes.
- P24: NUT-04 minting of BNAP keysets requires a NUT-20 key and commits the RailId.
- P26: NUT-13 derivation type `0x02` for note keys is unassigned upstream.

## 5. ERRATA rows (for the orchestrator to merge into spec/ERRATA.md)

This node does not own `spec/ERRATA.md`. Proposed rows, numbered from 35:

| # | where | draft-00 says | other source says | resolution | owner decision needed (yes/no) |
| --- | --- | --- | --- | --- | --- |
| 35 | Empty records in scheme bodies: draft-00 2, 5.1 | An absent record and an empty one "MUST mean the same"; a scheme MUST reject alternative encodings | (internal) | Read together: the notes scheme has no record whose value can be empty, so it rejects empty records as non-canonical (notes 3.5) | no |
| 36 | Even/odd rule inside scheme bytes: draft-00 2, 4.1, 5.1 | The even/odd rule applies to socket streams; scheme `params` and bodies are opaque | (silent) | Notes params follow the even/odd rule (signed, extensible); notes bodies reject every unknown record, GREASE included | yes |
| 37 | Failed rail confirmation: draft-00 6.1 | The rail confirms a payment and returns canonical bytes | (silent on the error) | Unpaid: BAD\_CREDENTIAL with the scheme's code (`bnap:notes/QUOTE_UNPAID`); unreachable: UNAVAILABLE | yes |
| 38 | charged on FAILED: draft-00 6.4, 8.1 | `charged` is "0 when nothing was charged"; FAILED refunds "as its registered refund property allows" | (silent) | A FAILED outcome charges 0; an atomic-refund scheme returns the whole value | no |
| 39 | Timeout refund: draft-00 6.4 | A timed-out outcome "moves to FAILED, with the refund that implies"; settle is deterministic so a replay can recompute it | (silent on when) | The refund's `scheme_result` is computed and stored when the client replays the credential | yes |
| 40 | Funding request field: draft-00 13 | IANA list: `BNAP-Credential`, `BNAP-Receipt`, `BNAP-Error`, `BNAP-Context` | v0.4 and notes draft-00: `BNAP-Fund` | Register `BNAP-Fund` with the HTTP carrier, or let the notes scheme request it | yes |
| 41 | Caching exact offers without natives: draft-00 5.1 | Gates cache route offers and exact offers with natives; nothing else | Notes: exact offers with a `fund_quote` | Gates MAY cache them; clients otherwise send them inline | yes |
| 42 | Binding discovery: draft-00 5.3, 9.1 | A gate behind a TLS-terminating front rejects bound credentials | (silent on how a client knows) | A manifest member (for example `limits.binding`) would let clients know; notes wallets retry unbound after BINDING meanwhile | yes |
| 43 | HTTP status of a FAILED outcome: draft-00 8.2, 10.2 | Error codes have statuses; a FAILED outcome is a Response, not an error | v0.4: 502 | Unspecified; the HTTP carrier should say | yes |
| 44 | Registry example vs vectors: draft-00 11, 14 | `local_id` is a 33-byte point | Vectors use a 32-byte stand-in for Y and a bare 64-byte witness | Placeholders, as draft-00 14 says; the notes vectors (notes draft 18) will use real values | no |
| 45 | NUT-13 derivation type: notes 12.1 | (draft-00 silent) | v0.4: type `0x02` "to be requested from the Cashu maintainers" | Use `0x02` provisionally; request it upstream before freezing vectors | yes |
| 46 | Tab references in draft-00: draft-00 1, 12, 15 | "the first tab" | (I-D form) | The I-D cites the overview as a reference instead; the repository text keeps "the first tab" (ERRATA 28) | no |
| 47 | HTTP field and auth-scheme registration status: draft-00 13 | "To IANA directly" | (I-D form) | The I-D asks for provisional field registrations and a well-known URI with status provisional, change controller IETF | no |
| 48 | ACT and suites: notes 19; overview catalogue | v0.4: suites 1 to 3 are tags inside the notes scheme | Overview catalogue lists ACT as its own scheme | Suites become scheme IDs; notes has no suite tag | yes |
| 49 | Verify on replays: draft-00 6.3, 6.4, 8.2 | A replay is recognized at commit, after the scheme has verified the credential again. 8.2 gives `bnap:notes/OUTPUT_REUSED` as its example scheme code | v0.4: a blinded output signed before is rejected with `OUTPUT_REUSED` | A scheme's `verify` MUST NOT reject an artifact because it, or anything in it, was used before; otherwise a replay of a committed credential fails before commit and the client loses the PENDING answer, the stored response, a missed receipt and the timeout refund. The socket text should say so. Notes verify reads no use state: not the use store, not quote issuance, not the signed-output table (notes 6.2). The v0.4 output check is dropped, because a front-runner that got one of a committed credential's `B'` signed first (a cheap price-0 swap) would otherwise turn every replay of it into BAD\_CREDENTIAL; `bnap:notes/OUTPUT_REUSED` is reserved, so 8.2's example still names a registered code (notes P10, P11) | yes |
| 50 | Replay after offer expiry: draft-00 4.4, 6.3, 6.4, 12 | 4.4 step 4 answers STALE before commit, where 6.4 finds the replay; 6.4 promises the stored response "inside `replay_window`", makes replay the way to fetch a missed receipt, and leaves the timeout refund to a replay; 12 says exact-scope offers live minutes | DECISIONS 21: `pending_timeout` 300 s, `replay_window` 86,400 s; notes 7.5 relies on replays for the timeout refund and missed change | Literal reading: a replay after the offer's deadline is STALE, so `replay_window` is in effect the offer lifetime, and a credential committed close to its deadline can never collect its timeout refund. Proposed draft-00 erratum: when an offer passes authenticity but fails expiry, the gate still runs the scope and NOT\_OFFERED checks, verification and the binding check, computes the ReplayKey, and serves the replay if `outcome[rk]` exists, answering STALE otherwise and committing nothing; gates resolve `offer_id` for replays after expiry, or clients send the offer inline (it does not change the Context or the ReplayKey); schemes keep artifacts verifiable for `replay_window` past the deadline (for notes: `final_expiry` later than `expires` plus `replay_window`). Until then notes adds an admission cutoff, applied after the replay lookup (notes 5.4, 7.5, P9) | yes |

## 6. Known gaps

- The notes test vectors themselves (section 18) are not produced here; a reference-code owner must generate them.
- The NUT-13 derivation layout in 12.1 was taken from the current NUT-13 text and must be checked against its test vectors before the notes vectors are frozen.
- BOLT12 funding (NUT-25) is only mentioned, not specified for redemption inside a credential.
- Withdrawal (BNAP-W) is out of scope, as in v0.4.
- The I-D has not been rendered by xml2rfc yet; the first CI run may report warnings (for example typographic quotes from kramdown's smart quotes in table cells that had to leave code spans).
- The NUT drafts use relative links (`00.md`) that resolve only inside cashubtc/nuts.
- `UseStore` needs a single-ID insert-or-compare for NUT-04 minting (section 1 above); without it the issuer cannot follow notes 8.5.

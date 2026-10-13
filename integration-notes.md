# Integration notes: node N13 (standards drafts and the notes-scheme rewrite)

Branch `node/n13` of the `bnap` repository. Files this node owns:

- `spec/schemes/bnap-notes-draft-00.md` (priority 1, done)
- `ietf/` (priority 2)
- `nuts/` and `docs/payment-method-cashu.md` (priority 3)

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

Outputs and quote IDs are not use IDs. `verify` has no side effects and runs the checks of 6.2 in order.

### Settlement (section 7)

- change = `value - charged`; charged is 0 on FAILED, so FAILED refunds the whole value (fees kept).
- The outputs must form a complete power-of-two ladder covering the value (6.3, checked at verify as `BAD_OUTPUTS`).
- `select(outputs, change)`: greedy by amount descending, then index ascending. Proven exact on complete ladders (brute force over 942 ladders, 55,542 targets, zero failures).
- DLEQ with NUT-12's deterministic nonce is a MUST, so settle is byte-deterministic.
- The signed-output table (NUT-09) must be durable no later than the outcome write. Each record carries a 32-byte source: `H(pay body)` of the credential that settled it, or `rk_mint`. Verify's `OUTPUT_REUSED` check skips records whose source equals `H(this body)`, so a replay of the same credential still reaches the socket's replay path. A `B'` signed meanwhile is signed again, never a settle failure.
- Timeout refunds are computed lazily when the client replays the credential (7.5). The gate must support "outcome FAILED, no scheme_result yet" and fill it with one conditional write.

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

## 2. Decisions made

All 26 provisional decisions are listed in Appendix B of the notes document (P1 to P26). The ones with the widest effect:

- P1: one output ladder replaces v0.4's separate change and refund lists, because the charge of a metered call is known only at settlement.
- P3: unknown records in a notes body are rejected even when odd (draft-00 5.1 canonical bodies).
- P11: outputs are not use IDs; the RailId alone guards fund quotes.
- P19: NUT-04 minting of BNAP keysets requires a NUT-20 key and commits the RailId.
- P21: NUT-13 derivation type `0x02` for note keys is unassigned upstream.

## 3. ERRATA rows (for the orchestrator to merge into spec/ERRATA.md)

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

## 4. Known gaps

- The notes test vectors themselves (section 18) are not produced here; a reference-code owner must generate them.
- The NUT-13 derivation layout in 12.1 was taken from the current NUT-13 text and must be checked against its test vectors before the notes vectors are frozen.
- BOLT12 funding (NUT-25) is only mentioned, not specified for redemption inside a credential.
- Withdrawal (BNAP-W) is out of scope, as in v0.4.

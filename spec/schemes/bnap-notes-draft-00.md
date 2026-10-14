<!--
  Written for this repository (not exported from the source doc).
  Spec text licensed CC-BY-4.0, (c) BNAP contributors.
  Restates spec/schemes/bnap-notes.md (v0.4 profile) and the bnap:notes section of
  spec/overview-v0.5.md in the terms of spec/socket-draft-00.md, as DECISIONS.md row 31 requires.
-->

# bnap:notes, scheme draft-00

2026-10-13 · BNAP contributors

## 1. Status and scope

**Status.** Working draft 00 of the `bnap:notes` credential scheme. It restates the v0.4 Cashu profile ([bnap-notes.md](bnap-notes.md)) and the `bnap:notes` section of the v0.5.1 overview ([overview-v0.5.md](../overview-v0.5.md)) as a plug for the socket of [socket-draft-00.md](../socket-draft-00.md) ("draft-00" below). Where those texts and draft-00 differ, draft-00 wins; section 19 lists every such difference, and also the places where draft-00's own text, read literally, contradicts itself or leaves its encoding open (19.2). Every choice this document had to make that none of its sources settles is marked "(provisional)" and collected in Appendix B for owner review.

**Scope.** This document defines everything the socket leaves to the scheme: the body and witness bytes (section 3, the section the draft-00 registry example points to), the Note format, the pay entry parameters, verification, the change and refund outputs, funding inside a 402, input fees, keyset rotation, swaps, seed recovery, the scheme's error codes, its registry entry and its test-vector requirements. It does not restate the socket: the Offer, the Credential envelope, the Context, Digest and ReplayKey, the use store, pricing, the Response and its receipt are as draft-00 defines them, and this document only says what the scheme puts into them and takes out of them.

**What the scheme is, in one paragraph.** The operator runs its own Cashu-style issuer for its own origin. A client buys credit over Lightning with Cashu's mint flow (NUT-23, NUT-04, NUT-20), or inside the 402 that asked it to pay, and holds the credit as Notes: Cashu proofs whose secret is the hex of a public key K. To pay for an action it puts notes and blinded change outputs in the body of a socket Credential and signs the socket's Digest with each K. The gate checks the notes offline, commits each note's `Y` as a single-use ID, and at settlement signs exactly `value - charged` worth of the client's blinded outputs as change. Wallets recover from a seed through NUT-13, NUT-09 and NUT-07.

## 2. Conventions

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

### 2.1 Notation

Every notation of draft-00 section 2 applies: `H`, `H_tag`, `‖`, BigSize, `tu64`, `lp`, TLV stream, entry list, flag, Key, Signature, `b64u` and empty. One error code changes. Draft-00's BigSize and `tu64` rows make a non-minimal encoding MALFORMED (2), the socket's code for its own streams. The notes body and witness are opaque bytes to the socket (draft-00 section 2, "One encoding"), parsed only by the scheme, and draft-00 5.1 makes the scheme reject alternative encodings of a body; 3.5 applies the same rules to the witness. A non-minimal BigSize or `tu64` inside them, like every other encoding error there, is therefore a scheme rejection, BAD\_CREDENTIAL (10) with `bnap:notes/NON_CANONICAL` (3.5, 13.1), and never MALFORMED (provisional). The socket's own streams, the pay record around the body and witness included, keep MALFORMED. In addition:

| Notation | Meaning |
| --- | --- |
| Point | A secp256k1 point in SEC1 compressed form: 33 bytes, first byte `02` or `03`. The point at infinity has no encoding and is never valid |
| `G`, `n` | The secp256k1 generator and group order |
| `hash_to_curve(x)` | The NUT-00 map from a byte string to a point |
| `hex(x)` | Lowercase hexadecimal, two characters per byte |
| Keyset ID | The NUT-02 keyset ID of version `01`: 33 bytes, the byte `01` followed by a SHA-256 digest. v0.4 calls it the version-2 ID |
| `a`, `A` | The private and public key of one keyset for one amount, `A = a·G` |
| NUT-xx | The Cashu specification of that number in the `cashubtc/nuts` repository |

### 2.2 Terms

| Term | Meaning |
| --- | --- |
| Issuer | The operator's Cashu-style mint. It signs notes for its own origin only, and is the only party that accepts them |
| BNAP keyset | A Cashu keyset (NUT-01, NUT-02) whose keys sign notes and nothing else |
| Note | A Cashu proof `{id, amount, secret, C}` whose secret is `hex(K)` (section 4) |
| Note key | The private key `k_n` of a note and its x-only public key `K` |
| `Y` | `hash_to_curve(secret)`, the note's single-use ID |
| Value | What `verify` reports: the sats the credential brings, after input fees (6.3) |
| Change | `value - charged` at settlement, returned as signed outputs (section 7) |
| Fund quote | A NUT-23 BOLT11 mint quote locked to a client key (NUT-20) and redeemed inside a credential (section 8) |

### 2.3 Hash tags

This document defines one tagged hash, `H_"bnap:notes/mint"` (8.5). Its tag starts with the scheme ID, so it can never equal a socket tag, which all start with `bnap/`.

## 3. Body and witness

A notes credential is the `pay` record of a socket Credential (draft-00 5.1) with scheme `bnap:notes`, a `body` (record 2) and a `witness` (record 4). Both are TLV streams. The body carries everything the gate verifies except signatures over the Digest; the witness carries those signatures (draft-00 5.1). The Digest covers `H(body)`; nothing covers the witness, which is why it only holds signatures over the Digest.

### 3.1 Body records

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | inputs | Entry list of input entries (3.2), sorted by `key`, strictly ascending bytewise | When the credential spends notes |
| 2 | outputs | Entry list of output entries (3.3), in the client's order | When `value` > 0 (6.3) |
| 4 | fund | UTF-8 quote ID of a paid NUT-23 BOLT11 mint quote, 1 to 64 bytes | When the credential redeems a fund quote (8.4) |

A body MUST hold `inputs`, `fund`, or both.

### 3.2 Input entries

An input entry is one note, as a nested stream:

| Type | Name | Value |
| --- | --- | --- |
| 0 | keyset | 33 bytes: the full keyset ID. Required |
| 2 | amount | tu64: a power of two, at least 1, in sat. Required |
| 4 | key | Key: `K`, 32 bytes. The note's secret is `hex(K)`. Required |
| 6 | C | Point: the note's unblinded signature. Required |

The body carries `K`, not the secret, because the secret is a fixed function of `K` (4.1); the gate rebuilds the secret and `Y` itself. Inputs never carry a DLEQ proof or a blinding factor (4.2).

### 3.3 Output entries

An output entry is one Cashu blinded message, as a nested stream:

| Type | Name | Value |
| --- | --- | --- |
| 0 | keyset | 33 bytes: the full ID of a keyset the offer lists as active (5.2). Required |
| 2 | amount | tu64: a power of two, at least 1, in sat. Required |
| 4 | blinded | Point: `B'`, the NUT-00 blinded message. Required |

Outputs serve both as change and as refund (section 7). A client SHOULD list them in ascending amount order (provisional), which the canonical ladder of 6.3 already is.

### 3.4 Witness records

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | input\_sigs | `64 × m` bytes, where m is the number of inputs: the Signature by each input's `K` over the Digest, in input order | When the body holds `inputs` |
| 2 | fund\_sig | Signature over the Digest by the private key of the fund quote's NUT-20 `pubkey` | When the body holds `fund` |

Each signature is a BIP-340 signature over the 32-byte Digest of draft-00 5.2. `fund_sig` verifies under the x-only form of the quote's 33-byte compressed `pubkey`, that is its last 32 bytes. One signature is made per key; signatures are never aggregated (4.2).

### 3.5 Canonical form

Draft-00 5.1 requires a scheme to reject a body that contains any byte it does not verify. The body and the witness MUST therefore be rejected with BAD\_CREDENTIAL and `bnap:notes/NON_CANONICAL` (section 13), not with socket MALFORMED (2.1), when any of these holds:

- a framing error: a truncated record or entry, a non-minimal BigSize or tu64, types not strictly increasing, or bytes left over;
- an input or output entry that lacks a record 3.2 or 3.3 marks Required, such as an input without `C`, or an entry that is the empty stream (the single byte `00` in the entry list, a zero length);
- a record type not listed in 3.1 to 3.4, even or odd. The even/odd rule of draft-00 section 2 governs socket streams; inside a notes body or witness every unknown record is rejected, GREASE included (provisional reading: a client puts its GREASE in the socket streams, never in a scheme body);
- a record of the wrong length, or with an empty value. No notes record is a flag, and every tu64 in a body is at least 1, so an empty value is never valid here;
- a Point that is not a valid compressed point on secp256k1, or a `key` that is not a valid x-only key (its value is at least p, or no point has that x coordinate);
- inputs not in strictly ascending order of `key`, which also rules out the same `K` twice;
- two outputs with the same `blinded` point;
- a witness whose records do not match the body: `input_sigs` present without `inputs`, absent with them, or not exactly 64 bytes per input; `fund_sig` present without `fund`, or absent with it.

A body or witness that passes these checks has exactly one encoding. The `scheme_result` of 7.3 follows the same rules, except for the one empty value that 7.3 defines.

### 3.6 Sizes

The pay entry parameters cap the counts (5.1): `max_inputs` and `max_outputs`, each 16 by default (provisional). An input entry takes about 110 bytes on the wire, its length prefix included, and an output entry about 75. At the defaults, the largest credential has 16 inputs and the 16-output ladder, whose total of 65,535 sat caps its value (6.3). Take 16 inputs on a keyset with no input fee, such as keyset B of 18.1: one each of 1, 2, 4, …, 16,384 sat and a second note of 16,384 sat, so I = 32,767 + 16,384 = 49,151, eight amounts of one byte (1 to 128) and eight of two bytes (256 to 16,384). With a 36-byte quote ID for a quote of F sat, 1 ≤ F ≤ 16,384, the value is 49,151 + F, from 49,152 to 65,535, so its bit length is 16 and the 16-output ladder covers it. That body is 2,974 bytes and its witness 1,094, and a credential that names its offer by `offer_id` and carries a binding and a GREASE record with an 8-byte value (14 bytes in all) is 4,177 bytes, 5,570 base64url characters. It fits the HTTP carrier's credential cap of 9,216 bytes (DECISIONS row 30) even with a 4,096-byte offer inline instead of `offer_id`, which makes it 4,177 − 34 + 4,100 = 8,243 bytes; clients SHOULD still send `offer_id` where draft-00 5.1 allows it.

The 1,680 sat of the draft-00 10.3 example is the price after its 20% Web Bot Auth discount, 2,100 − ⌊2,100 × 2,000 / 10,000⌋ = 1,680, so a credential that pays it also carries a Web Bot Auth attestation that verifies; without one the price is 2,100 sat (draft-00 7). The sizes that follow count that attestation's `attest` record as 91 bytes, its size with the 64-byte attest body of the draft-00 section 14 vectors: 22 bytes for the scheme ID record, 66 for the body record, a 1-byte entry prefix and a 2-byte record header. A real Web Bot Auth body changes each size by its own length minus 64. Notes are powers of two, so 1,680 sat take four inputs (1,024 + 512 + 128 + 16) on a keyset with no input fee, such as keyset B, and the 11-output ladder: that credential, built as above but with no quote and with the attest record, is 1,719 bytes. A wallet holding one 2,048-sat note on such a keyset instead sends one input and the 12-output ladder, 1,271 bytes. On keyset A of 18.1, at 100 ppk, the same four notes are worth 1,680 − (400 + 999) div 1000 = 1,679 sat, one short of the discounted price (UNDERPAID), and the 2,048-sat note is worth 2,048 − (100 + 999) div 1000 = 2,047 sat and takes the 11-output ladder, 1,196 bytes. These three credentials stay under the 2 KiB of draft-00 section 2; the largest credential above, at 4,177 bytes, does not. `nuts/tools/notes_sizes.py` rebuilds every credential of this section and checks each size.

## 4. Notes: the Cashu profile

### 4.1 Note format

A Note is a Cashu proof whose secret is the hexadecimal encoding of a public key `K`, so only the holder of `K`'s private key can spend it. Everything else about the note is Cashu as the NUTs specify it.

```
k_n, r  = NUT-13 derivation (section 12): seed, keyset ID, counter, derivation types 0x02 and 0x01
K       = x-only public key of k_n (BIP-340), 32 bytes
secret  = hex(K), 64 ASCII characters
Y       = hash_to_curve(UTF-8 bytes of secret)              NUT-00
B'      = Y + r·G                                            sent as an output
C'      = a·B', with a NUT-12 DLEQ proof (e, s)              returned by the issuer
C       = C' - r·A                                           the unblinded signature
Note    = {id: keyset ID, amount, secret, C}                 a valid NUT-00 proof
witness = Signature by k_n over the socket Digest            one per note, per spend
```

A wallet MAY store notes as ordinary Cashu proofs, for example in a NUT-00 V4 token, but a note is not transferable: spending it also needs `k_n`.

### 4.2 Rules beyond Cashu

- **Spends need the key.** An issuer MUST accept its notes only with a valid witness by each note's `K`: inside a `bnap:notes` credential, or in the witnessed melt of a withdrawal extension (section 16). It never accepts them through a NUT-03 swap or a plain NUT-05 melt: without the witness rule, `hex(K)` reads to Cashu as an unlocked secret.
- **Key isolation.** BNAP keysets MUST NOT be served by a mint that accepts plain swaps or melts for them. The issuer MUST refuse every NUT-03 request whose inputs belong to a BNAP keyset, and every NUT-05 request whose inputs do, unless it implements a withdrawal extension (section 16) and the melt carries a notes witness for every input. An issuer without such an extension SHOULD mark NUT-05 as disabled in its NUT-06 info. A BNAP key never appears in any other keyset. NUT-04 minting (8.5), NUT-07 state checks and NUT-09 restore are served as section 12 says.
- **Keyset IDs.** Bodies, parameters and derivation all use the full 33-byte keyset ID. The 8-byte short ID never appears in a notes body (provisional; v0.4 allowed it on the wire).
- **Unit.** Every BNAP keyset has unit `sat`, and the notes pay entry has unit `sat`.
- **Final expiry.** Every BNAP keyset MUST publish a `final_expiry` (NUT-02) (provisional; without one, draft-00 6.2 would keep its spend records forever).
- **No signature aggregation.** One BIP-340 signature per `K`. Batch verification is fine. Buying a note never proves knowledge of `k_n`, so a summed key could steal another holder's note.
- **Denominations.** Amounts are powers of two. A wallet uses each `K` once, at one origin.
- **Outputs.** Every `B'` is a valid point other than infinity. A credential is never rejected because one of its `B'` was signed before: settlement signs it again (7.4), and only the client that reused it can lose value. Verification reads no use state at all (6.2), so a replay of a committed credential always reaches the socket's replay path (draft-00 6.4). NUT-04 minting refuses a `B'` signed before, as NUT-04 does (8.5).
- **DLEQ.** The issuer returns a NUT-12 DLEQ proof with every blind signature, made with NUT-12's deterministic nonce, which this scheme makes a MUST (7.4). Clients never send a DLEQ proof or a blinding factor to the issuer, because either would link a spend to the purchase.

## 5. Offer parameters

### 5.1 The pay entry

A `bnap:notes` pay entry (draft-00 4.1) has unit `sat`. Its `params` record (pay entry type 8) is a TLV stream:

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | issuer | UTF-8: the absolute `https` URL of the issuer's Cashu API base, on the origin the offer came from | Required |
| 2 | keysets | Entry list of keyset entries (5.2), sorted by `id`, strictly ascending | Required, at least one entry marked `active` |
| 4 | max\_inputs | tu64, at least 1; 16 when absent | Optional |
| 6 | max\_outputs | tu64, at least 1; 16 when absent | Optional |
| 8 | max\_fund | tu64, in sat: the gate accepts funding requests (8.1) on this route up to this amount | When the route offers funding inside the 402 |
| 10 | fund\_quote | Nested stream (5.3): a quote made for this client | Exact-scope offers only |

The parameters are bytes inside a signed offer, so `offer_sig` and the MAC cover them (draft-00 4.2) and they follow the even/odd rule of draft-00 section 2: a client ignores an unknown odd record and treats the pay entry as unusable if it meets an unknown even one (provisional; draft-00 leaves the encoding of `params` to the scheme). A client also treats the pay entry as unusable if `params`, a keyset entry or the `fund_quote` lacks a record this section marks Required. A gate never builds a record outside this table.

### 5.2 Keyset entries

| Type | Name | Value |
| --- | --- | --- |
| 0 | id | 33 bytes: the keyset ID. Required |
| 2 | input\_fee\_ppk | tu64: the keyset's NUT-02 `input_fee_ppk`; 0 when absent |
| 4 | active | Flag: the keyset signs outputs |

`keysets` lists the BNAP keysets this offer accepts for inputs. Each is not revoked, and its `final_expiry` is later than the offer's `expires` plus 60 seconds. Entries marked `active` are the keysets the gate signs outputs on. `input_fee_ppk` MUST equal the fee the keyset publishes through NUT-02; it is in the offer so that a client holding only the offer can compute its value exactly (draft-00 7: the offer is the quote).

A client takes keyset IDs, fees and the `active` flag from the offer, and the keys themselves from the issuer's NUT-01 and NUT-02 endpoints at `issuer`. It MUST recompute each keyset ID from the keys it fetched (NUT-02) and MUST NOT use a keyset whose recomputed ID differs from the offer's.

### 5.3 The fund quote

| Type | Name | Value |
| --- | --- | --- |
| 0 | quote | UTF-8 quote ID, 1 to 64 bytes. Required |
| 2 | request | UTF-8: the quote's BOLT11 invoice. Required |
| 4 | amount | tu64, in sat: the quote amount. Required |
| 6 | expiry | tu64: the Unix time until which the invoice can be paid. Required |
| 8 | pubkey | 33 bytes: the compressed NUT-20 key the client sent (8.1). Required |

These are the NUT-23 quote fields a client needs, so it can pay from the 402 without another round trip. Inside the offer, `offer_sig` authenticates them.

### 5.4 Offer rules

- `bnap:notes` is binding class S, so it MAY appear in route-scope and in exact-scope offers (draft-00 4.3), and its refund is atomic, so it MAY appear in metered offers (draft-00 7).
- `fund_quote` MUST appear only in exact-scope offers, because a route-scope offer is the same for every client (draft-00 5.1) (provisional).
- A gate MAY send such an exact-scope notes offer, made for one request to carry a `fund_quote` (8.2), on a route that the manifest lists with `"scope": "route"`, next to that route's route-scope offer (provisional). Draft-00 4.3 allows a class S scheme in an exact-scope offer. This document reads the rule of draft-00 9.1, that such a route "gets route-scope offers for its class S and A schemes", as the route's default offer set, not as a ban on a per-request exact-scope offer (19.2).
- A gate MUST NOT put a `fund_quote` in an offer for a route whose `require` sets `link-payment` to `unlinkable`, because a credential that redeems it is linkable to the payment (section 14) (provisional). On such a route it also puts no `max_fund` in the notes pay entry, and admits no credential that redeems a quote, whichever offer the quote came from (8.4) (provisional).
- A gate MAY cache an exact-scope offer that carries a `fund_quote` as it caches offers with natives, so that the client can send `offer_id`; when it does not, the client sends the offer inline (provisional; draft-00 5.1 names only offers with natives).
- The notes pay entry carries no native record: `bnap:notes` defines no native artifact.
- **Replay horizon.** Draft-00 4.4 checks expiry before the commit looks for a replay (draft-00 6.3, 6.4), so a replay sent after the offer has expired is STALE even when its outcome exists. Without a limit on late admissions, a credential committed shortly before expiry could never collect its timeout refund (7.5) or a missed change. The **deadline** of a notes entry is the earlier of the offer's `expires` and the entry's `quote_expires`; its **admission cutoff** is that deadline minus `pending_timeout` minus 60 seconds. A gate that lists `bnap:notes` (provisional):
  - MUST NOT commit a new notes credential after the cutoff. It applies the cutoff inside the commit transaction, after the replay lookup of draft-00 6.3: a credential whose outcome exists is still served as a replay, and a new one gets STALE and consumes nothing;
  - MUST NOT list `bnap:notes` in an offer whose cutoff is less than 60 seconds after the offer is issued, and SHOULD leave several minutes. With the default `pending_timeout` of 300 seconds, an exact-scope offer that lists `bnap:notes` therefore lives at least 7 minutes, and SHOULD live 10 minutes or more, which is still the "minutes" of draft-00 12;
  - SHOULD issue the next route-scope offer before the current one reaches its cutoff, so that clients always hold an offer that admits.

  Every committed notes credential then reaches its `pending_timeout` at least 60 seconds before its deadline, and a client that replays as 7.5 says collects its refund. A socket-level cure, a gate that serves the replay of an authentic but expired offer instead of answering STALE, is proposed as a draft-00 erratum; with it, the cutoff could go.

## 6. Verification

### 6.1 What verify gets

The gate calls the scheme's `verify` only after the offer checks of draft-00 4.4, and passes it the pay body and witness, the Digest the gate computed (draft-00 5.2), the chosen pay entry (amount, unit and parameters), the current time, read access to the issuer's keyset and quote tables, and the signer's check of unblinded notes. `verify` has no side effects: it writes nothing to any store.

### 6.2 Checks

The scheme runs these checks in this order, cheapest first. The first failure ends verification with socket code BAD\_CREDENTIAL (10) and the `scheme_code` shown (section 13).

1. **Form.** The body and witness pass 3.5 (`NON_CANONICAL`). The body holds `inputs` or `fund` (`EMPTY`). There are at most `max_inputs` inputs and at most `max_outputs` outputs (`LIMIT`).
2. **Keysets.** Every input's keyset is listed in the offer's `keysets`, is known to the issuer, is not revoked, and `now` is before its `final_expiry` plus 60 seconds: draft-00 section 2 allows 60 seconds of clock skew on every expiry check, this one included. Every output's keyset is listed with `active` and is not revoked (`UNKNOWN_KEYSET`). The offer can only narrow what the issuer's live table allows: a keyset revoked after the offer was made is refused.
3. **Amounts.** Every amount is a power of two for which its keyset has a key (`BAD_AMOUNT`).
4. **Fund.** If the body holds `fund`, the quote exists, has method `bolt11` and unit `sat`, carries a NUT-20 `pubkey`, and is paid in full (`QUOTE_UNPAID`). Verification does not ask whether the quote has issued: the RailId commit decides that atomically (8.4, 8.5), so a quote used before gives SPENT at commit, and a replay of the same credential still reaches the socket's replay path (provisional). That replay verifies only while the quote record and the rail's confirmation of its payment still exist, which 8.6 guarantees until the replay can no longer arrive.
5. **Value and outputs.** The value of 6.3 is defined, and the outputs form a complete ladder that covers it (`BAD_AMOUNT` or `BAD_OUTPUTS`).
6. **Witness.** The i-th signature of `input_sigs` verifies under the i-th input's `K` over the Digest, and `fund_sig` verifies under the quote's `pubkey` (`BAD_SIGNATURE`).
7. **Notes.** For every input, `C = a·hash_to_curve(hex(K))` for the key `a` of its keyset and amount, checked by the signer (`BAD_SIGNATURE`).

The scheme does not compare the value with the price: the socket does that after pricing and answers UNDERPAID (draft-00 7).

**No use state.** Verification never asks whether anything in the credential was used before: not the use store, not whether the fund quote has issued (step 4), and not the signed-output table. The socket decides use at commit (draft-00 6.3), after verification, and recognizes a replay there. A check of earlier use inside `verify` would fail a replay of a committed credential before commit, and the client would lose the stored response, a missed receipt and the timeout refund (draft-00 6.4, 7.5). v0.4's check that no output was signed before is therefore dropped (provisional): a `B'` signed before is signed again at settlement (7.4).

### 6.3 Value and the output ladder

```
I     = sum of the input amounts
F     = the fund quote's amount, or 0 without fund
fee   = (sum over the inputs of their keyset's input_fee_ppk + 999) div 1000     NUT-02; the fund pays no fee
value = I + F - fee
```

All arithmetic is checked unsigned 64-bit. An overflow, or `fee > I + F`, is `BAD_AMOUNT`.

**Ladder rule.** Sort the output amounts in ascending order, `a₁ ≤ a₂ ≤ … ≤ aₖ`. The outputs form a **complete ladder** when every `aᵢ ≤ 1 + (a₁ + … + aᵢ₋₁)`, which for powers of two means every amount from 0 to their total is the sum of some of them. The outputs MUST form a complete ladder whose total is at least `value`; otherwise the result is `BAD_OUTPUTS`. When `value` is 0 the body MAY omit `outputs`. Because any change from 0 to `value` can then be formed exactly, the gate never keeps change the client meant to get back, and a FAILED outcome always refunds the whole value (section 7) (provisional; v0.4 used separate exact change and refund lists, which a charge known only at settlement cannot use).

**Canonical ladder.** A client SHOULD send exactly one output of each amount 1, 2, 4, …, 2^(b-1), in that order, where b is the bit length of `value`, so that every wallet sends the same outputs for the same value (provisional). For the draft-00 10.3 example, a value of 1,680 sat gives b = 11 and the outputs 1 to 1,024, 2,047 sat in total. At the default `max_outputs` of 16, one credential carries a value of at most 65,535 sat.

### 6.4 What verify returns

- **Local IDs:** the `Y` of each input, as a 33-byte compressed point, under the use model `single`. The gate turns each into `UseId = H_"bnap/use"(lp("bnap:notes") ‖ Y)` (draft-00 6.1).
- **Rail references:** none for notes. A body with `fund` adds one: rail kind `ln` and the payment hash of the quote's invoice. The operator's rail confirms the payment and returns the canonical bytes, the 32-byte payment hash, from which the gate computes the RailId and commits it with the UseIds (draft-00 6.1, 6.3). If the rail reports the payment unpaid, the result is BAD\_CREDENTIAL with `bnap:notes/QUOTE_UNPAID`, and if the rail cannot be reached, UNAVAILABLE (provisional; draft-00 does not name the code for a failed rail confirmation).
- **Value:** `value` of 6.3, in sat.

Outputs and quote IDs yield no local ID (provisional). The RailId already makes a fund quote single-use across credentials and NUT-04 minting (8.5), and signing a `B'` twice harms only the client who reused it (7.4).

## 7. Settlement: change and refund

### 7.1 The change cap

When the scheme's `settle` runs, the socket has fixed `charged` (draft-00 6.4, 7): the effective price for a non-metered offer, `min(price(⌈units × rate / 1000⌉), price(amount))` for a metered one, and 0 for a FAILED outcome (provisional reading: draft-00 8.1 sets `charged` to 0 "when nothing was charged", and a FAILED action charges nothing). A FAILED Response to a metered offer reports `metered_units` 0, the count for which the metering formula of draft-00 7 also gives `charged` 0: ⌈0 × rate / 1000⌉ = 0 and price(0) = 0 (provisional; draft-00 8.1 requires `metered_units` in every Response to a metered offer but does not say what a FAILED action counts, and the byte-exact Response vectors of 18.2 item 6 need one value). Admission required `value ≥ price(amount)`, and `charged` never exceeds `price(amount)`, so

```
change = value - charged,        0 ≤ change ≤ value ≤ total of the outputs
```

The scheme signs outputs worth exactly `change`. The operator-trusted signer enforces the same cap on its own and refuses to sign more than `value - charged` (the `CappedSigner` of the v0.5.1 overview). Input fees are kept in both outcomes.

### 7.2 Selecting the outputs

```
select(outputs, change):
  r = change; S = {}
  for i in the output indices, by amount descending, then by index ascending:
      if amount(i) ≤ r:  S = S ∪ {i};  r = r - amount(i)
  return S                            r is 0 here, by the ladder rule of 6.3
```

On a complete power-of-two ladder this greedy rule always reaches exactly `change`. OK and FAILED outcomes use the same rule; a FAILED outcome, with `charged` 0, returns the whole value. In the draft-00 10.3 example the value is 1,680 sat and the charge 340 sat, so the change is 1,340 sat and the scheme signs the outputs of 1,024, 256, 32, 16, 8 and 4 sat.

### 7.3 Scheme result

The scheme's `scheme_result` (Response record 16, draft-00 8.1) is a TLV stream:

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | signatures | Entry list of signature entries, one per signed output, in ascending `index` order | When change > 0 |

A signature entry:

| Type | Name | Value |
| --- | --- | --- |
| 0 | index | tu64: the zero-based index of the output in the body. Required, for index 0 too, whose value is empty |
| 2 | C\_ | Point: `C' = a·B'` for that output's keyset and amount. Required |
| 4 | e | 32 bytes: the NUT-12 DLEQ challenge. Required |
| 6 | s | 32 bytes: the NUT-12 DLEQ response. Required |

When the change is 0 the scheme returns empty bytes and the Response omits record 16 (provisional). The Response's ack signs the whole `scheme_result` (draft-00 8.1), so a wrong change is attributable.

**Encoding.** The gate writes `scheme_result` canonically, under the rules 3.5 sets for a body, so that the same settlement always gives the same bytes (7.4) and every client parses them one way. One value in it can be empty: `tu64` writes 0 as the empty string (draft-00 section 2), so the entry for the first output has an `index` record with an empty value. A Required record is always written, empty or not, and an optional record whose value is empty is left out, as record 16 is above. A gate therefore MUST write the `index` of output 0 as a present record with an empty value, the two bytes `00 00`, and MUST NOT leave it out; draft-00's own vectors write the Required `status` record of an OK Response the same way, as `02 00`. The stream of a signature entry is then 105 bytes for index 0, starting `00 00 02 21`, and 106 bytes for an index from 1 to 255, starting `00 01`, the index byte, `02 21`; with its length prefix an entry is 106 or 107 bytes. Draft-00 section 2 also says an absent record and an empty one MUST mean the same, so a client MUST read a signature entry without an `index` record as index 0, and MUST NOT reject the Response for that alone; a gate that leaves the record out still breaks this section, and its signed Response shows it (provisional).

The client knows `value` from its own body and the offer, and `charged` from the Response, so it recomputes `select` itself. It MUST check that the signed indices equal its own result, MUST verify every DLEQ proof against the keyset key `A` for that amount (NUT-12), and only then unblinds `C = C' - r·A`. A mismatch is the operator's fault, and the signed Response is the evidence.

### 7.4 Deterministic signing and the signed-output table

Draft-00 6.4 requires `settle` to be deterministic. A blind signature `a·B'` already is. The issuer MUST make every DLEQ proof with NUT-12's deterministic nonce, which NUT-12 itself only recommends; with it, the same verified credential, outcome and charge always give byte-identical `scheme_result`.

The issuer records every signed output, with its keyset, amount, `B'`, `C'`, DLEQ proof and source, in a signed-output table that it keeps until 60 seconds after the output keyset's final expiry (section 10), as NUT-09 requires. The source is 32 bytes: `H(body)` of the credential body whose settlement signed the output, or `rk_mint` for a NUT-04 mint (8.5). The table is keyed by `(B', source)` and keeps every record: a `B'` signed under two sources has two records (provisional). These records MUST be durable no later than the outcome write of draft-00 6.4, and therefore before the Response is sent.

If a `B'` was signed before, under another credential or mint request, `settle` still signs it, does not fail, and adds its own record (provisional). Records for the same keyset, amount and `B'` carry the same `C'` and the same DLEQ proof, because `C' = a·B'` and NUT-12's deterministic nonce is derived from `a`, `A`, `B'` and `C'` only. A NUT-09 restore therefore answers with any record whose keyset, amount and `B'` match the request. The two signatures share one `Y`, so at most one of them can ever be spent: the client that reused the output loses value, and the operator loses nothing. A third party that copies someone else's `B'` gains nothing either (section 17).

### 7.5 Replays and timeouts

Replays are the socket's (draft-00 6.4): a replay returns the stored `scheme_result`, and the scheme MUST NOT sign anything beyond it. When an outcome is still PENDING after `pending_timeout`, the socket moves it to FAILED with charge 0. The refund needs the client's outputs, which the outcome record does not keep, so it is computed when the client replays the credential: the gate finds the FAILED outcome without a `scheme_result`, calls `settle` for FAILED with charge 0, stores the result once with a conditional write, and returns it (provisional reading of draft-00 6.4, which relies on `settle` being deterministic but does not say when the timeout refund is computed). A client whose request timed out therefore replays it to collect its refund.

**When to replay.** A client whose request has no final answer, or whose response or receipt went missing, replays the credential at once, again at each `retry_after` of a PENDING answer, and in any case as soon as `pending_timeout` has passed since it sent the credential. The admission cutoff of 5.4 leaves at least 60 seconds between that timeout and the offer's deadline for this replay (provisional). After the deadline, draft-00 as written answers even a replay with STALE (5.4), so a refund, change or receipt not collected by then is lost to the client.

## 8. Funding inside the 402

Buying credit is Cashu's Lightning mint flow, used verbatim: a NUT-23 BOLT11 quote locked to a client key (NUT-20), paid, then minted with NUT-04. BOLT11 is mandatory, because the issuer is always online and every payer stack accepts it. BOLT12 through NUT-25 is optional and is minted through NUT-25 only; a body's `fund` redeems BOLT11 quotes only (provisional). This section adds one shortcut: a first-time client can get the quote inside the 402 and redeem it inside the paid request, so it funds and acts in one round trip.

### 8.1 Asking for a quote

On the HTTP carrier, a client asks for funding by sending the request field `BNAP-Fund` with the request that will get the 402 (provisional; draft-00 section 13 does not list this field, so it needs registering):

```
BNAP-Fund: amount=2100, pubkey="02c4…"
```

The field is an RFC 9651 Dictionary. `amount` is an Integer, the most the client will pay, in sat. `pubkey` is a String of 66 lowercase hex characters, a compressed secp256k1 key the client made fresh for this quote. Other members are ignored. Other carriers define no such member yet; their clients buy credit through NUT-23 and NUT-04 directly (8.5).

### 8.2 Making the quote

A gate that receives `BNAP-Fund` on a route whose notes pay entry carries `max_fund`:

- MAY ignore it, and then sends its offers without a `fund_quote`;
- otherwise creates a NUT-23 BOLT11 quote for `min(amount, max_fund)` sat, locked to `pubkey` (NUT-20), with a quote ID of at most 64 bytes, and puts it in the `fund_quote` of an exact-scope offer for this request (5.3, 5.4), also on a route listed with `"scope": "route"` (5.4). It MAY also send its route-scope offer, without the quote, in the same 402;
- MUST create at most one quote per offer nonce and MUST rate-limit quote creation per client address (provisional, following DECISIONS row 24 for native challenges), and SHOULD bound the open, unpaid quotes per address;
- MUST NOT create a quote for a request without `BNAP-Fund`. A scraper gets an offer, never an invoice;
- SHOULD set the quote's `expiry` no later than the admission cutoff of the offer that carries it (5.4), so that a client that pays in time can still use that offer (provisional). A quote paid later is not lost: it is redeemed with any other notes offer that admits a funded credential, or minted (8.4, 8.5);
- MAY decline amounts below a minimum top-up of its choosing, in which case it sends no quote. v0.4 suggested `max(4 × price, 21)` sat, because the operator's inbound liquidity, not routing, is the real cost of a small payment.

### 8.3 Paying the quote

Before paying, a client MUST check that the offer passes draft-00 4.4, that `pubkey` is the key it sent, that `amount` is at most what it asked for and equals the amount of the BOLT11 invoice in `request`, and that the invoice has not expired. It MUST save the quote ID, the quote key and the offer before it pays, so that a request that fails can still mint the paid quote through NUT-04 (8.5). It then pays the invoice through any Lightning pay source, such as an NWC connection.

### 8.4 Redeeming the quote in a credential

The client puts the quote ID in the body's `fund` and signs the Digest with the quote key as `fund_sig`. The quote may be redeemed with any offer that lists `bnap:notes`, not only the one that carried it, and alongside notes or alone, except under an offer for a route whose `require` sets `link-payment` to `unlinkable`. Such a credential is linkable to its payment (section 14), so on such a route the gate MUST reject a notes credential whose `verify` returns a rail reference, which it does exactly when the body holds `fund` (6.4), with POLICY (8), after verification and before commit (provisional). Nothing is consumed and the quote stays mintable through NUT-04, as for any failure before commit. It adds its amount to the value with no input fee (6.3). Verification checks the quote (6.2, step 4) and returns its payment as a rail reference (6.4), and the socket commits the RailId in the same transaction as the notes' UseIds (draft-00 6.3).

If the request fails before commit, nothing is consumed and the quote stays mintable through NUT-04. After commit the quote counts as issued, whatever the outcome: on OK the change comes back as notes, and on FAILED the whole value, the quote's amount included, comes back as notes (7.2).

A credential that redeems a quote links that one action to the Lightning payment. Notes received as change are unlinkable. A client that needs every action unlinkable buys credit through NUT-04 first and spends only notes. A route that requires `link-payment = unlinkable` holds every client to this: its gate offers no quote there (5.4) and admits no funded credential.

### 8.5 Minting through NUT-04

The issuer serves NUT-04 BOLT11 minting (`POST /v1/mint/bolt11`) for BNAP keysets, the ISSUE of v0.4. A quote for a BNAP keyset MUST carry a NUT-20 `pubkey`, and the mint request MUST carry a valid NUT-20 signature (provisional; NUT-20 makes both optional). Outputs follow NUT-04: they sum to the quote amount, are on active BNAP keysets, are powers of two, and no `B'` was signed before.

Draft-00 6.1 requires that "a scheme that mints credit from a payment … MUST have the gate commit that payment's RailId when it mints". The issuer therefore uses the gate's use store, the same one the socket commits to, as follows (provisional):

```
rk_mint = H_"bnap:notes/mint"( lp(quote ID) ‖ BigSize(k) ‖ lp(output₁) ‖ … ‖ lp(outputₖ) )
          outputᵢ = the output entry of 3.3 built from the i-th blinded message of the mint request

mint(quote, outputs):
  confirm through the rail that the quote's invoice is paid      otherwise the NUT-04 "not paid" error
  sigs = blind signatures and DLEQ proofs for outputs            deterministic, as in 7.4
  in one serializable transaction:
      if used[RailId] = rk_mint:        return sigs               a retry of the same mint request
      if used[RailId] exists:           abort                     NUT-04 error for an issued quote
      if any output's B' has a record:  abort                     NUT-04 error for an output signed before
      used[RailId] = rk_mint; record sigs with source rk_mint
  return sigs
```

A mint commit has no outcome record and no PENDING state, because signing comes before the transaction and the transaction is the whole operation. A retry with the same quote and outputs is recognized before the output check, and gets the same signatures, as NUT-19 cached responses would give, because signing is deterministic. An abort consumes nothing: the quote stays mintable, and a client whose outputs were refused derives fresh ones and signs a new NUT-20 request. The issuer keeps the RailId record at least as long as the quote record, and the quote record at least as long as the RailId record (8.6).

### 8.6 Quote state

The use store is the authority on whether a quote has issued: a quote is issued exactly when its RailId is committed, by a credential or by a mint. The issuer's NUT-23 quote check MUST then report `amount_issued` equal to `amount`, and the deprecated `state` as `ISSUED`.

**Retention.** Every verification of a credential that redeems a quote, replays included, reads the quote record (6.2, step 4) and asks the rail to confirm the quote's payment (6.4). A replay of a committed funded credential therefore reaches the socket's replay path (draft-00 6.4) only while both still answer; if either is gone, the replay fails with `QUOTE_UNPAID` before commit, and the client loses the stored response, a missed receipt and the timeout refund (draft-00 6.4, 7.5). Therefore (provisional):

- the issuer MUST keep each quote record, with its amount, `pubkey`, payment hash and paid state, for as long as the quote's RailId record, so that the two are deleted together (8.5);
- when a credential commits the RailId, the issuer MUST keep both at least until 60 seconds after the deadline (5.4) of that credential's notes entry, the last moment a replay of it can pass the expiry check of draft-00 4.4. A gate can store that time with the RailId when it commits, or keep every redeemed quote for the longest lifetime of any notes offer it issues, plus 60 seconds, after the commit;
- the rail MUST be able to confirm the payment for as long. A rail plug whose Lightning node prunes settled invoices answers from the paid state that the quote record holds.

A quote minted through NUT-04 needs no such time, because a mint has no replay beyond the NUT-04 retry (8.5). If the draft-00 erratum of 5.4 lets replays through after the deadline, the bound becomes `replay_window` after the commit.

## 9. Input fees

Input fees follow NUT-02: each input contributes its keyset's `input_fee_ppk`, and the fee is the sum rounded up to whole sats (6.3). The offer repeats each keyset's fee (5.2). The fund quote pays no fee. Fees are kept on OK and on FAILED. Fees exist so that free swaps cannot bloat the store, so an operator that offers a swap route at price 0 (section 11) SHOULD set a nonzero `input_fee_ppk` on its keysets.

## 10. Keysets and rotation

- **Lifecycle.** A keyset is published, with its keys served but not active, at least 30 days before it signs anything. It then signs outputs for about 3 months, then accepts inputs only, and reaches its `final_expiry` about 15 months after it started signing. Once `final_expiry` plus the 60 seconds of skew has passed (6.2, step 2), it is never accepted again.
- **Standby.** The operator always keeps at least one published keyset that is not yet active, so that a compromised keyset can be replaced at once.
- **Revocation.** A compromised keyset leaves the `keysets` of every new offer and the issuer's live table at once, and inputs and outputs on it are refused from then on (`UNKNOWN_KEYSET`). The operator cannot tell honest notes on that keyset from forged ones, so their holders lose them; this is an accepted residual risk (section 17).
- **Retention.** A note still verifies for 60 seconds after its keyset's `final_expiry`, because draft-00 section 2 allows that skew on every expiry check (6.2, step 2). Its single-use record therefore stays in the use store until `final_expiry` plus 60 seconds, which is how long draft-00 6.2 requires: a record deleted at `final_expiry` itself would let a note that still verifies be spent a second time. Signed-output records stay until the output keyset's `final_expiry` plus 60 seconds (NUT-09). After that the issuer MAY delete both, as NUT-02 allows. Quote records and their RailId records are kept as 8.6 says.
- **Offers and expiry.** An offer lists only keysets whose `final_expiry` is later than its `expires` plus 60 seconds (5.2). The issuer MUST keep signing on a keyset for as long as an unexpired offer lists it as `active`, unless the keyset is revoked.
- **Consistent keys.** Clients compare the full key list of each keyset from a second vantage point, such as another network path or a published mirror, and SHOULD NOT accept change on a keyset whose keys differ between them; this catches keys made to tag one user. The 30-day publication rule gives them time to do so.
- **Wallets.** A wallet SHOULD swap notes on a keyset that is within 30 days of its `final_expiry` into an active keyset (section 11). An operator announces retirement or shutdown at least 30 days ahead through the keyset's `final_expiry`.

## 11. Swaps

A swap re-denominates notes, or moves them to an active keyset. It is an ordinary BNAP request on a route priced at 0; the body and witness are as for any other credential, and the whole value comes back as change through the outputs (section 7). The operator SHOULD list such a route in its manifest with id `notes-swap`, for example `{"id": "notes-swap", "match": "POST /bnap/notes/swap", "scope": "route", "price": {"sat": 0}, "pay": ["bnap:notes"]}`, and the gate answers it itself, with status 200, no content and `BNAP-Receipt` (provisional). A wallet finds the route in the manifest by its id. The swap's scope is the carrier's ordinary action scope (draft-00 10.1); v0.4's `H_"bnap/scope/swap"(origin)` and its info-endpoint swap URL are gone. A plain NUT-03 swap is never accepted (4.2).

## 12. Seed recovery

### 12.1 Derivation

A wallet holds one BIP-39 seed. Note keys and blinding factors come from the NUT-13 derivation for keysets with version-01 IDs:

```
d(type)  = HMAC-SHA256(seed, "Cashu_KDF_HMAC_SHA256" ‖ keyset ID ‖ counter as 8 bytes big-endian ‖ type)
k_n      = int(d(0x02)) mod n          the note key; derivation type 0x02 (provisional)
r        = int(d(0x01)) mod n          the blinding factor, as NUT-13 defines it
```

NUT-13 assigns types `0x00` (secret) and `0x01` (blinding factor). Type `0x02` for the note key is not assigned yet and is to be requested from the Cashu maintainers; until then this document uses it as written (provisional). Type `0x00` is not used, because a note's secret is `hex(K)`. If `k_n` or `r` is 0, the wallet skips that counter value. Before the test vectors of section 18 are frozen, this layout MUST be checked against the NUT-13 test vectors.

**Counters.** Counters are per keyset. The top 16 bits of the 64-bit counter name a device or agent slot, and the low 48 bits count within it, so two devices that share a seed never derive the same key (provisional; v0.4 split the counter the same way without fixing its width). Every output consumes one counter value. A wallet MUST NOT reuse a counter value once the `B'` derived from it has been sent in any credential or mint request, signed or not, because the same `B'` in two requests links them.

### 12.2 Restore

The issuer MUST serve NUT-09 restore and NUT-07 state checks for BNAP keysets:

- **NUT-09** answers from the signed-output table (7.4, 8.5).
- **NUT-07** answers from the gate's use store: a `Y` whose UseId is committed is `PENDING` while its outcome is PENDING and `SPENT` otherwise, even after the outcome record is deleted, and every other `Y` is `UNSPENT`.

To restore, a wallet takes the sites and slots recorded in its backup and, for each keyset of each issuer (inactive keysets inside their final expiry included), regenerates outputs in batches of 100 counter values, asks the issuer to restore them, and stops after three consecutive batches come back empty (NUT-13). It unblinds what comes back and checks each note's `Y` with NUT-07.

**Gaps.** Unsigned outputs leave gaps in the counter sequence: a credential whose change is 0 leaves its whole ladder unsigned, up to `max_outputs` values. A long run of such credentials would hide later notes from the three-empty-batches rule. A wallet MUST therefore record, in its backup, the highest counter value it has used per keyset and slot, at least every time that value has advanced by 100 since the last record, and a restore MUST scan at least up to the recorded value before applying the gap rule (provisional).

**Backup.** The wallet's site list, with each origin's issuer URL, keysets, slots and counters, is backed up encrypted, as Cashu wallets back up their mint lists. The encryption is the wallet's choice.

## 13. Errors

### 13.1 Scheme codes

Every scheme error is sent with socket code BAD\_CREDENTIAL (10, HTTP 402) and one of these `scheme_code` values (draft-00 8.2):

| scheme\_code | Meaning | Client action |
| --- | --- | --- |
| `bnap:notes/NON_CANONICAL` | The body or witness breaks 3.5, for example with a non-minimal BigSize or `tu64`, which inside them is this code and not socket MALFORMED (2.1) | Fix the encoder |
| `bnap:notes/EMPTY` | The body has neither inputs nor fund | Add notes or a fund quote |
| `bnap:notes/LIMIT` | More inputs or outputs than `max_inputs` or `max_outputs` | Swap into fewer notes first |
| `bnap:notes/UNKNOWN_KEYSET` | An input keyset is not in the offer, unknown, revoked or past its final expiry, or an output keyset is not active | Refresh the offer and keysets; swap old notes |
| `bnap:notes/BAD_AMOUNT` | An amount is not a power of two with a key, the arithmetic overflows, or the fees exceed inputs plus fund | Fix the amounts |
| `bnap:notes/BAD_OUTPUTS` | The outputs are not a complete ladder covering the value | Send the canonical ladder (6.3) |
| `bnap:notes/BAD_SIGNATURE` | A note, an input signature or the fund signature failed | Drop the bad input, or check the wallet's keys |
| `bnap:notes/QUOTE_UNPAID` | The fund quote is unknown, unpaid, not BOLT11 in sat, or has no NUT-20 key, or the rail does not confirm its payment. A quote already issued gives socket SPENT (12) at commit instead | Pay it, wait for the payment, or drop it |

A rail that cannot be reached gives UNAVAILABLE (15), never admission (draft-00 12).

`bnap:notes/OUTPUT_REUSED`, which v0.4 defined and draft-00 8.2 uses as its example of a scheme code, is reserved and never sent: verification does not reject a reused output (6.2), and settlement signs it again (7.4) (provisional).

### 13.2 The v0.4 codes in draft-00

| v0.4 code | Now |
| --- | --- |
| `VERSION` | Socket VERSION (1) |
| `MALFORMED` | Socket MALFORMED (2) for the socket streams; `bnap:notes/NON_CANONICAL` or `bnap:notes/EMPTY` for the body and witness, non-minimal integers included (2.1) |
| `TOO_LARGE` | Socket TOO\_LARGE (3) for sizes; `bnap:notes/LIMIT` for counts |
| `UNKNOWN_KEYSET` | `bnap:notes/UNKNOWN_KEYSET` |
| `UNIT_MISMATCH` | `bnap:notes/UNKNOWN_KEYSET`: only `sat` keysets are ever listed (provisional) |
| `BAD_CHALLENGE` | Socket BAD\_OFFER (4) |
| `STALE` | Socket STALE (5) |
| `WRONG_SCOPE` | Socket WRONG\_SCOPE (6); a binding mismatch is BINDING (11) |
| `WRONG_AMOUNT` | Socket UNDERPAID (9) when the value is below the price; `bnap:notes/BAD_OUTPUTS` when the outputs do not fit |
| `BAD_SIGNATURE` | `bnap:notes/BAD_SIGNATURE` |
| `OUTPUT_REUSED` | Not sent; `bnap:notes/OUTPUT_REUSED` is reserved (13.1) |
| `SPENT` | Socket SPENT (12) |
| `QUOTE_UNPAID` | `bnap:notes/QUOTE_UNPAID` |
| `PENDING` | Socket PENDING (13) |
| `RATE_LIMITED` | Socket RATE\_LIMITED (14) |

v0.4 said error responses SHOULD carry an operator signature. Draft-00 errors are never signed (draft-00 8.2), and that rule is dropped.

## 14. Registry entry and property vector

The registry entry, in the form of draft-00 section 11:

```toml
[scheme."bnap:notes"]
role        = "value"
spec        = "https://github.com/bnap-protocol/bnap/blob/main/spec/schemes/bnap-notes-draft-00.md"
binding     = "S"
use         = "single"
local_id    = "Y of each input: hash_to_curve(hex(K)), 33-byte compressed point"
quota_id    = ""
rail_refs   = "none for notes; kind ln, the invoice payment hash, for a redeemed fund quote and at minting"
body        = "TLV, section 3 of the scheme spec"
witness     = "TLV, section 3.4: one BIP-340 signature per input, plus one by the fund quote's NUT-20 key, all over the Digest"
native      = []
units       = ["sat"]
refund      = "atomic"
upto        = false
properties  = { theft = "key-witnessed", link-payment = "unlinkable", link-actions = "unlinkable",
                issuer = "self-issued", verify = "offline", finality = "final-on-verification",
                custody = "operator-iou", pq = "no", maturity = "experimental" }
conformance = ""
```

Two fields differ from the `bnap:notes` example in draft-00 section 11, which gives `rail_refs = "none at spend; the funding payment at minting, confirmed by the rail"` and `witness = "one BIP-340 signature per input, over the Digest"`. That example does not cover funding inside a credential (section 8). A credential that redeems a fund quote relies on the quote's Lightning payment, and draft-00 6.1 says a scheme MUST return a rail reference for every payment its credential relies on, so `rail_refs` names the `ln` reference at spend as well as at minting (6.4). The quote's NUT-20 signature is a signature over the Digest, which draft-00 5.1 puts in the witness, so `witness` names `fund_sig` too (3.4). Draft-00 6.1 and 5.1 govern, and the draft-00 example should read as this entry does (19.2).

Draft-00 section 11 lists an entry only once it has a public specification, test vectors, passing conformance results and expert review. This document is the specification; `conformance` stays empty, and the entry stays unlisted, until the conformance suite has produced results for it.

The property vector, weakest to strongest as the overview orders each property:

| Property | Value | Note |
| --- | --- | --- |
| use | single | Each `Y` admits one action |
| binding | S | The witness signs the Digest: offer, chosen schemes, extensions, bodies and TLS binding |
| theft | key-witnessed | A note copied from a log or a proxy is useless without `k_n` |
| link-payment | unlinkable | Notes are unlinkable from the purchase that funded them. A credential that redeems a fund quote is linkable to that payment, so a gate never admits one on a route that requires `link-payment = unlinkable` (8.4). The first action after a purchase can still be correlated by timing |
| link-actions | unlinkable | Blinding; one `K` per note; the canonical ladder (6.3) |
| issuer | self-issued | The gate accepts only its own keysets |
| verify | offline | A signer check and signature checks; the rail is asked only for a fund quote |
| finality | final-on-verification | |
| custody | operator-iou | Credit is the operator's promise; wallets keep balances small (section 15) |
| refund | atomic | Change and refunds come back in the Response (section 7) |
| pq | no | Forgery is not post-quantum; blinding keeps past spends private |
| maturity | experimental | Until the NUTs of `nuts/` are accepted |

These are the scheme's own values. The gate combines them with the rail and verifier entries into the effective vector of each pay entry (draft-00 section 11): notes funded through a card or another reversible rail are reversible and linkable to the payer.

## 15. Wallet requirements

A notes wallet MUST:

- enforce spending caps per origin and per task in code, never in a model's prompt;
- make a fresh NUT-20 key for every quote, run the checks of 8.3 before paying, and never pay more than it asked for in `BNAP-Fund`;
- save the quote, its key and the offer before paying (8.3);
- keep per-site balances small, because credit is the operator's IOU; 5,000 sat per site is the RECOMMENDED default cap;
- use each note key once, at one origin, and never reuse a counter value (12.1);
- send outputs that form a complete ladder covering the value (6.3);
- check the selected outputs and every DLEQ proof before accepting change (7.3);
- record its counters in its backup as 12.2 requires;
- keep every Response it paid for (draft-00 8.1);
- replay a credential that has no final answer, or whose receipt went missing, at once, at each `retry_after` and as soon as `pending_timeout` has passed, and in any case before its offer's deadline (7.5).

A notes wallet SHOULD send the canonical ladder (6.3), send `offer_id` instead of the offer where it can (draft-00 5.1), and swap notes before their keyset's final expiry (section 10). It SHOULD include a `binding` whenever it can read its connection's `tls-exporter` value. A BINDING error means the gate cannot check the binding or the connection is intercepted; the wallet MAY retry without a binding only if it accepts that the response is then only as confidential as the credential (draft-00 6.4). v0.4 said agents and native clients MUST bind. Draft-00 5.3 makes a gate behind a TLS-terminating front reject every bound credential, so a wallet that always binds could never pay such a gate, and draft-00 does not say how a client learns whether a gate can check a binding (provisional).

## 16. Withdrawal

Withdrawal (v0.4's BNAP-W) is not part of this document. An issuer that offers no withdrawal extension MUST refuse NUT-05 melts of BNAP notes (4.2). An operator that enables one MUST, as v0.4 required, write spend records synchronously to durable, replicated storage before answering, cap withdrawals per epoch and per request, pay out only through a melt that carries a notes witness for every input (4.2), and keep the issuer key in a separate signer process. Paying out to arbitrary invoices moves an operator from merchant toward money transmitter, so withdrawal needs legal review in each jurisdiction.

## 17. Security and privacy considerations

The socket's considerations (draft-00 section 12) apply. These are the scheme's own:

| Threat | Closed by |
| --- | --- |
| Double spend | Each `Y` committed as a single UseId, atomically and durably, before the action runs (draft-00 6.3) |
| Note theft from logs, proxies or CDNs | A witness by `K` over the Digest |
| Change or refund stolen by a proxy | The Digest covers the body, outputs and quote included; the outputs are blinded |
| A fund quote redeemed twice | One RailId per payment, single, shared by credentials and NUT-04 minting (8.5) |
| A quote swapped by a proxy | `offer_sig` covers the quote; the wallet checks its key and amount (8.3) |
| Theft with a summed key | One signature per `K`, no aggregation |
| Redeeming a note through a plain Cashu swap or melt | Key isolation (4.2) |
| Mixed units or overflow | `sat` only, checked arithmetic (6.3) |
| Bloating the store with free swaps | Per-keyset input fees (section 9) |
| Admission minted by someone else | The gate accepts only its own keysets (6.2, step 2) |
| The issuer links a spend to a purchase | Blinding; no DLEQ proof or blinding factor is ever presented (4.2) |
| Keys made to tag one user | Keysets published 30 days ahead and compared from a second vantage point (section 10) |
| Wallet fingerprinting | Powers of two, the canonical ladder, one `K` per note |
| Linking two actions through a reused output | Counters are never reused (12.1) |
| Lost device | Seed recovery through NUT-13, NUT-09 and NUT-07 (section 12) |
| A linkable funded credential admitted on a route that requires unlinkable payment | No quote and no `max_fund` in that route's offers (5.4), and POLICY for every credential that redeems a quote there, whichever offer the quote came from (8.4) |
| Invoice minting as denial of service | Funding only on `BNAP-Fund`, capped, one quote per offer nonce, rate-limited per address (8.2) |
| Change withheld or miscounted | The deterministic selection (7.2), checked by the client against the signed Response |
| A timeout refund or missed change lost because the offer expired | The admission cutoff (5.4) and prompt replays (7.5) |
| A replay of a funded credential failing because the quote record or the rail's record of its payment was pruned | Both kept at least 60 seconds past the deadline of the entry that committed the quote (8.6) |
| A replay or crash paying change twice | The socket's single settle write and stored `scheme_result` (draft-00 6.4); deterministic signing (7.4) |

**Output front-running.** Someone who sees a credential in transit or in a log can copy its `B'` values into a credential of its own, for example a price-0 swap (section 11) whose change is one of the victim's outputs, and have it settle first, even while the victim's action is still running. This gains it nothing and costs the victim nothing. The front-runner cannot unblind what it gets back, so the output it spent its own value on is lost to it. The victim's credential is unaffected at every stage, because verification never consults the signed-output table (6.2): before commit it is admitted as usual; after commit, a replay still reaches the socket's replay path, so a PENDING answer, the stored response, a missed receipt and a timeout refund all stay available (draft-00 6.4, 7.5); and its settlement signs each of its `B'` under its own keyset and amount (7.4), which only the victim can unblind. Had verification rejected outputs signed before, as v0.4 did, the same copy would have turned every replay of a committed credential into BAD\_CREDENTIAL, and the victim would have lost its change or its whole refund.

**Accepted residual risks:**

- **Linkable funding.** A credential that redeems a fund quote is linkable to its payment, and the first action after any purchase can be correlated by timing.
- **Small operators** can still link visitors by address, TLS fingerprint and timing. Notes are unlinkable; their holders are not anonymous.
- **Operator credit.** An operator that disappears takes unspent credit with it. Wallets keep balances small.
- **Store loss.** Without withdrawal, notes spent since the last durable copy of the use store can be spent again until their keyset expires, which costs free actions, never bitcoin.
- **Key compromise.** A stolen issuer key forges notes, so the keyset is revoked and replaced at once (section 10), and honest notes on it are lost. Keys live in a separate signer process.
- **Not post-quantum.** A quantum attacker could forge notes; blinding keeps past spends private.
- **Late replays.** Under draft-00 as written, a replay after its offer's deadline is STALE (5.4), so a client that does not replay in time loses its refund or change. The admission cutoff gives every client at least 60 seconds after the timeout.
- **Restore leaks a wallet.** NUT-09 and NUT-07 requests show the issuer a set of outputs and notes that belong together, as in any Cashu wallet.

## 18. Test vector requirements

The `bnap:notes` vectors MUST be published, generated by a reference encoder and reproducible from the prose, before the registry entry is listed (section 14). Like the socket vectors (draft-00 section 14), they derive secret keys as SHA-256 of fixed strings, use 32 zero bytes of BIP-340 auxiliary randomness, and give every intermediate value.

### 18.1 The notes route offer

The route offer of draft-00 section 14 cannot carry a notes credential. Its `bnap:notes` pay entry is scheme, amount, unit and rate only, with no `params` record, so it names no `issuer` and no `keysets`, which 5.1 requires. No input can pass step 2 of 6.2 (`UNKNOWN_KEYSET`), so no valid notes credential exists for that offer. Its `expires` is also 300 seconds after the vectors' reference time of 1791700000 (the manifest's `issued`), which leaves it no admission window under 5.4 with the default `pending_timeout` of 300 seconds. The socket vectors in `vectors/vectors.json` use that offer with a placeholder notes body and a bare 64-byte witness: they test the socket's hashing, not this scheme, and are not valid notes credentials under this document.

The notes vectors therefore use their own offer, the **notes route offer**. It is the draft-00 route offer, signed with the same offer key and MAC key, with the same nonce, attest entry, GREASE record and every other record unchanged, except that:

- `expires` is 1791703600, one hour after the reference time, so its admission cutoff (5.4) is 1791703240;
- the `bnap:notes` pay entry carries a `params` record (5.1) of 106 bytes: `issuer` `https://api.example/cashu` and the keyset entries of keysets A and B below, in that order, with no limits, no `max_fund` and no `fund_quote`.

Both keysets have unit `sat` and one key for each amount m = 2^i, 0 ≤ i ≤ 15. The private key `a` for amount m of keyset L is SHA-256 of the ASCII string `bnap notes test keyset L m`, with m in decimal, for example `bnap notes test keyset A 1024`, read as a big-endian integer, and its public key is `A = a·G`. A keyset ID is NUT-02's version-01 ID: the byte `01` followed by SHA-256 of a UTF-8 string made of `m:hex(A)`, with `A` as a Point, for each amount in ascending order, joined by `,`, then `|unit:sat`, then `|input_fee_ppk:` and the fee unless the fee is 0, then `|final_expiry:` and the final expiry, numbers in decimal.

| Keyset | `input_fee_ppk` | `final_expiry` | `active` | Keyset ID |
| --- | --- | --- | --- | --- |
| A | 100 | 1830000000 | yes | `011decbc482233faf1b58395ddb55c465e3bf6d8fa1c5a5b17219f7d5883b112a7` |
| B | 0 | 1800000000 | no | `014423cf221427bb65863007387bbc9b74963e47b24c3ec3a25ddd673e9ed6e898` |

| Vector | Value |
| --- | --- |
| Offer | 413 bytes, below |
| OfferID | `666b28f7f1d68d92e9c180f0d11fe743730d3932ab5bc566d68f53b17b0cbd95` |
| `offer_sig` | `108b3bf0…eb9f5fec` |
| `mac` | `e77e4e3ef6ce609745c194c160d1814295ad7e4d6d5a56178d68cf40b4a5dd4c` |
| Context: the action scope of draft-00 section 14, `bnap:notes`, `httpsig:web-bot-auth`, empty ext | `29c131cbf11af082d603f2246516d288565da10bc3703cc556b87575f43cbdf3` |

```
0001010220862d641e67813f6e78b20a81aa929519e66a978e69e8a4d3e27280990697f3a0040008000a046acb3a30
0c2468747470733a2f2f6170692e6578616d706c652f2e77656c6c2d6b6e6f776e2f626e61700e20b28dad5f717c51
44bdb0aa6db94bb6c79afa9b8bd9bc84825a2c1baafe64add91010000102030405060708090a0b0c0d0e0f12868500
0a626e61703a6e6f746573020208340403736174086a001968747470733a2f2f6170692e6578616d706c652f636173
6875024d280021011decbc482233faf1b58395ddb55c465e3bf6d8fa1c5a5b17219f7d5883b112a702016404002300
21014423cf221427bb65863007387bbc9b74963e47b24c3ec3a25ddd673e9ed6e8980a0201f4141e1d001468747470
7369673a7765622d626f742d61757468020102040207d0f040108b3bf0b2354e7363ba171b73ad57dfb594f6281ee8
5067dbb6d74eb1bbe558fd03765abf702d22562f8399ee60fdb4d54bcdf1c05bf3f26776cd79eb9f5fecf220e77e4e
3ef6ce609745c194c160d1814295ad7e4d6d5a56178d68cf40b4a5dd4cfeb2d05e01020a0a
```

**The fee offer.** One negative vector of 18.2 item 9, fees above the inputs, cannot be built on the notes route offer. On keysets A and B each input adds at most 100 to the fee sum, so k inputs pay at most (100k + 999) div 1000 ≤ k sat, and every input is worth at least 1 sat, so the fee never exceeds I, let alone I + F. That vector uses the **fee offer** instead: the notes route offer with a third entry in `keysets`, keyset C, and every other record unchanged. Keyset C is built by the rule above with the label `C`, `input_fee_ppk` 2000 and `final_expiry` 1830000000, and is not active, so outputs stay on keyset A. Its entry sorts after those of A and B and adds 40 bytes, so the fee offer's `params` record is 146 bytes and the offer 453 bytes.

| Vector | Value |
| --- | --- |
| Keyset C ID | `01fd899e9c7a7f4940273d43ec1dcd3bafc9fe4fe80ba292b9f021ab09b5aecf46` |
| Fee offer OfferID | `b958c89e56ef83bb05dd98e88b0a4746f79ebac53c09c53f306e74635be1f2aa` |
| Fee offer Context, as for the notes route offer | `a6f07b0ed275845d2d088e724cd9a7fc9cd7093df6e6456c613f40ca788bab11` |

`nuts/tools/notes_offer_vector.py` prints these values, the bytes of both offers and every keyset key from the reference encoder. Before it prints anything it checks that the same records, without `params` and with the draft-00 `expires`, give the draft-00 OfferID, that the notes route offer has the OfferID above, and that its keyset ID code reproduces a published version-01 ID.

### 18.2 Required vectors

The vectors MUST include:

1. **Note math:** a seed, keyset ID and counter giving `k_n` (type `0x02`), `K`, the secret, `Y`, `r` (type `0x01`) and `B'`; a keyset key `a`; `C'` with its deterministic NUT-12 DLEQ proof; and `C`. The `hash_to_curve` and DLEQ steps MUST agree with the NUT-00 and NUT-12 vectors.
2. **Offer parameters:** the `params` bytes of the notes route offer (18.1), a route-scope pay entry with two keysets, one active and with a fee; and of an exact-scope pay entry with a `fund_quote`.
3. **Two notes credentials** for the notes route offer (18.1), each with the action scope, Web Bot Auth attest body and binding of draft-00 section 14. That attest body is a placeholder, not a Web Bot Auth signature (draft-00 section 14: "Scheme bodies are placeholders"), and a real `httpsig:web-bot-auth` verifier would not verify it. The notes vectors therefore run with a **stub attestation verifier** in its place (provisional): it reports exactly that body as verified, with the local ID SHA-256(`bot key thumbprint`), so that its UseId is the one of draft-00 section 14, and reports any other body as not verified. The body's bytes still enter the Context, the Digest and the ReplayKey as draft-00 5.2 and 6.3 say. Under the stub the discount applies, and `price(amount)` = 2,100 − ⌊2,100 × 2,000 / 10,000⌋ = 2,100 − 420 = 1,680 sat. Without it the attestation has no effect (draft-00 7), `price(amount)` is 2,100, and both credentials below, worth 2,047 and 1,680 sat, are UNDERPAID. No document defines a real `httpsig:web-bot-auth` body yet; once one does, the vectors can carry a real signature by a test key derived from a fixed string, which changes the bytes, the Digest and the ReplayKey but none of the amounts. For each: the body and witness bytes, the Digest, the UseIds, the ReplayKey and the whole Credential. Both send the canonical ladder (6.3) on keyset A, the only active keyset.
   - **Credential 3a** has two inputs: a 1,024-sat note on keyset A and a 1,024-sat note on keyset B. I = 2,048, fee = (100 + 0 + 999) div 1000 = 1, value = 2,047 ≥ 1,680. The value's bit length is 11, so the outputs are 1, 2, 4, …, 1,024 sat at indices 0 to 10, 2,047 sat in total.
   - **Credential 3b** has a value equal to `price(amount)`: four notes on keyset B, 1,024 + 512 + 128 + 16 = 1,680 sat, fee 0, value 1,680, with the same 11 outputs (bit length 11, total 2,047). No two-input credential can have this value: on keyset B alone the two notes would have to sum to 1,680, and with any input on keyset A the fee is 1 and they would have to sum to 1,681, but a sum of two powers of two has at most two bits set, and 1,680 (`11010010000`) has four, 1,681 five.
4. **A funded credential** for the notes route offer: a body with one input and a `fund`, the `fund_sig`, the RailId of the quote's payment hash, and the value.
5. **Value and fees:** inputs on keysets with nonzero `input_fee_ppk`, showing the rounding of 6.3.
6. **Settlement:** for each of these outcomes, the `charged` and `metered_units`, the selected indices, the `scheme_result` bytes, and a Response carrying them, naming the notes route offer's OfferID. All three run under the stub verifier of item 3: the charges of 340 and 1,680 sat below are discounted prices, and a gate whose verifier rejects the placeholder body never reaches settlement, because it answers both credentials UNDERPAID at admission.
   - **Credential 3a, OK, metered:** 850 tokens. ⌈850 × 500 / 1000⌉ = 425, price 425 − ⌊425 × 2,000 / 10,000⌋ = 425 − 85 = 340, `charged` = min(340, 1,680) = 340. Change 2,047 − 340 = 1,707 = 1,024 + 512 + 128 + 32 + 8 + 2 + 1, so `select` (7.2) signs indices 0, 1, 3, 5, 7, 9 and 10. The `scheme_result` is 752 bytes: one 106-byte entry for index 0 and six 107-byte entries, behind a 4-byte record header (7.3).
   - **Credential 3a, FAILED:** `charged` 0 and `metered_units` 0, as 7.1 sets for a FAILED outcome (P35); draft-00 8.1 requires the record in a metered offer but does not say what a FAILED action counts. Change 2,047, so all 11 indices, 0 to 10, are signed. The `scheme_result` is 1,180 bytes: 106 + 10 × 107 = 1,176 bytes of entries behind a 4-byte header.
   - **Credential 3b, OK with charge equal to the value:** 4,200 tokens. ⌈4,200 × 500 / 1000⌉ = 2,100, price 2,100 − 420 = 1,680, `charged` = min(1,680, 1,680) = 1,680 = value. Change 0, so no output is signed, `select` returns the empty set, and the Response has no record 16 (7.3).

   Both signed sets contain index 0, so the vectors fix its encoding (7.3).
7. **Minting:** `rk_mint` for a quote and two outputs (8.5).
8. **A reused output:** a credential one of whose `B'` already has a signed-output record under another source. It verifies, and its settlement signs that `B'` again, with the same `C'` and DLEQ proof when keyset and amount match, and adds a second record (6.2, 7.4).
9. **Negative vectors**, each with the expected `scheme_code`: inputs out of order; a repeated `K`; two outputs with one `B'`; an unknown odd record in the body; a record with an empty value; an input entry without its `C` record and an output entry that is the empty stream `00`, each `NON_CANONICAL` (3.5); a short keyset ID; a non-power-of-two amount; an incomplete ladder; a ladder whose total is below the value; fees above the inputs, under the fee offer of 18.1: one 1-sat input on keyset C and no outputs, so I = 1, F = 0 and fee = (2,000 + 999) div 1000 = 2 > I + F = 1 (`BAD_AMOUNT`, step 5 of 6.2); `input_sigs` of the wrong length; `fund` without `fund_sig`; a witness signature over another Digest; a note whose `C` does not verify; an output keyset that is not active. Every vector of this item but the fee vector uses the notes route offer.

## 19. Differences from the sources

### 19.1 Changes from the v0.4 scheme

Draft-00 wins over the v0.4 text and the overview in each of these places:

| v0.4 or overview | This document | Why |
| --- | --- | --- |
| SPEND is a CBOR object | The notes body and witness are TLV streams inside the socket Credential (section 3) | Draft-00 5.1; DECISIONS row 31 |
| Own Digest, `H_"bnap/spend"(SigningBody)`, and SigningBody table | The socket Digest, which covers `H(body)` (draft-00 5.2) | The socket owns the Digest |
| Witness inside each input | All signatures in the witness record, apart from the body | Draft-00 5.1: the Digest covers bodies, never witnesses |
| `fund = {quote, signature}` | `fund` in the body, `fund_sig` in the witness | Same reason |
| CHALLENGE TLV with `amount`, `unit`, `keysets`, `info`, `op_key_id`, `fund_quote` | The socket Offer; `keysets`, `issuer`, limits and `fund_quote` are notes pay entry parameters (section 5) | Draft-00 section 4; the overview moves `fund_quote` into the notes offer |
| Self-issued challenges built by the client | Gone. Draft-00 4.4 accepts offers without `mac` only when published in advance under a key the gate holds | Draft-00 4.4 |
| Own ack over `Digest ‖ status ‖ amount ‖ signatures` | The socket Response and its ack (draft-00 8.1); the signatures travel in `scheme_result` (7.3) | The socket owns receipts |
| Replay lookup by Y with 16-byte Digest tags | The socket's ReplayKey and outcome record (draft-00 6.3, 6.4) | The socket owns replay |
| Amount rule: inputs + quote - fees - outputs = amount, exactly | `value ≥ price` (checked by the socket) and change of exactly `value - charged` at settlement | Draft-00 7: the charge is known only at settlement in metered offers |
| Separate `outputs` (change) and `refund_outputs` | One list of outputs forming a complete ladder that covers the value; a deterministic subset is signed (6.3, 7.2) (provisional) | A charge fixed at settlement needs change of any size |
| A blinded output signed before is rejected with `OUTPUT_REUSED` | Not checked by verification; a `B'` signed before is signed again at settlement, and the code is reserved (6.2, 7.4, 13.1) (provisional) | Draft-00 6.4: a replay of a committed credential must reach the replay path, which a use check in `verify` would block |
| Short keyset ID allowed on the wire | Full 33-byte keyset ID only (provisional) | One encoding; no ambiguous short IDs |
| A suite tag on every input; suites 1 to 3 reserved | No suite tag. A different construction gets its own scheme ID, as ACT does in the overview's catalogue (provisional) | Draft-00 identifies schemes by ID |
| `Authorization: BNAP` or `BNAP-Authorization`; `Authentication-Info` | `BNAP-Credential` and `BNAP-Receipt` (draft-00 10.2) | Draft-00 10.2 |
| HTTP scope over a normalized URI and Content-Digest | The HTTP carrier's action scope (draft-00 10.1) | Draft-00 10.1 |
| Agents and native clients MUST bind to the TLS exporter | A wallet SHOULD bind whenever it can read its connection's `tls-exporter` value, and MAY retry without a binding after a BINDING error (section 15) (provisional) | Draft-00 5.3: a gate behind a TLS-terminating front MUST reject bound credentials, so a client that always binds could not pay it |
| Swap scope `H_"bnap/scope/swap"(origin)` at the info endpoint's swap URL | A price-0 manifest route (section 11) (provisional) | Draft-00 has no scheme-defined scopes |
| A `bnap` section in the NUT-06 info endpoint with prices, limits, `max_fund`, `replay_window_s`, `op_keys`, `self_issued`, `swap` | The manifest (draft-00 9.1) for keys, limits and routes; offer parameters for the notes limits and `max_fund` | Draft-00 section 9 |
| Error codes of the SPEND, error responses SHOULD be signed | Socket codes plus `bnap:notes/…` scheme codes; errors are unsigned (section 13) | Draft-00 8.2 |
| FAILED returns HTTP 502 | Not defined here: draft-00 does not give an HTTP status for a FAILED outcome, and the carrier, not the scheme, would | Draft-00 10.2 |
| Spend store: 16-byte prefix of Y with a 16-byte Digest tag | The socket's use store with full UseIds, plus the scheme's signed-output table (7.4) | Draft-00 6.3 |
| Restore stops after `3 × max_outputs` unsigned counters | NUT-13's three empty batches of 100, plus a recorded counter in the backup (12.2) (provisional) | NUT-13; ladders can leave long gaps |
| DLEQ nonce must be deterministic (BNAP's own rule) | NUT-12's deterministic nonce, made a MUST (7.4) | NUT-12 now defines one |

### 19.2 Readings of draft-00's own text

In these places draft-00, read literally, contradicts itself or leaves its own encoding rules open, and this document follows the rule named in the last column. Each is proposed as a draft-00 erratum.

| Draft-00 says | This document | Why |
| --- | --- | --- |
| Section 2: `tu64` writes 0 as the empty string, and an absent record and a present one with an empty value MUST mean the same. The canonical rule of 5.1 covers bodies, not a scheme's `scheme_result` | The `index` of output 0 is a present record with an empty value, `00 00`; a client reads an entry without `index` as index 0 (7.3) (provisional) | Without one form, two gates send different bytes for the same settlement, although the ack signs them (draft-00 8.1), settlement must be deterministic (draft-00 6.4) and the vectors of 18.2 item 6 are byte-exact. Draft-00's own vectors write the Required `status` 0 as a present empty record |
| Section 2: a non-minimal BigSize or `tu64` is MALFORMED (2, HTTP 400) | Inside the notes body and witness it is BAD\_CREDENTIAL (10, HTTP 402) with `bnap:notes/NON_CANONICAL`; MALFORMED stays for the socket streams (2.1, 3.5, 13.1) (provisional) | The body and witness are opaque to the socket (draft-00 section 2), only the scheme parses them, and draft-00 5.1 makes rejecting alternative encodings of a body the scheme's job. BAD\_CREDENTIAL is the code for a scheme's rejection (draft-00 8.2), and its `scheme_code` tells the client which encoder to fix |
| Section 11, the `bnap:notes` registry example: `rail_refs = "none at spend; the funding payment at minting, confirmed by the rail"`, `witness = "one BIP-340 signature per input, over the Digest"` | `rail_refs` names kind `ln`, the invoice payment hash, at spend for a redeemed fund quote as well as at minting; `witness` adds the fund quote's NUT-20 signature (section 14) | Draft-00 6.1: a scheme MUST return a rail reference for every payment its credential relies on, and a funded credential relies on the quote's payment. Draft-00 5.1: signatures over the Digest go in the witness. The example predates funding inside a credential |
| Section 9.1: a route listed with `"scope": "route"` "gets route-scope offers for its class S and A schemes, and exact-scope offers for the rest"; 10.3 gives the `chat` route route-scope notes offers | On such a route, a gate MAY also send a per-request exact-scope `bnap:notes` offer that carries a `fund_quote`, next to the route-scope offer (5.4, 8.2, Appendix A) (provisional) | Draft-00 4.3 allows class S schemes in exact-scope offers. A fund quote is made for one client, so it cannot sit in a route-scope offer, which is the same for every client (draft-00 5.1). Read as the default offer set, 9.1 keeps the route-scope offer for every request; read as a ban, it would rule out funding inside the 402 on every route-scope route, the `chat` route of 10.3 included |

## Appendix A. HTTP example (informative)

A first-time agent funds and calls the metered route of draft-00 10.3 in one round trip after its first request. Byte strings are elided.

```http
POST /v1/chat/completions HTTP/1.1
Host: api.example
Content-Type: application/json
BNAP-Fund: amount=2100, pubkey="02c4…"

{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}

HTTP/1.1 402 Payment Required
WWW-Authenticate: BNAP offer="…"      route scope: bnap:notes up to 2,100 sat, 500 sat per 1,000 tokens
WWW-Authenticate: BNAP offer="…"      exact scope, metered, expires in 10 minutes: bnap:notes up to
                                       2,100 sat at 500 sat per 1,000 tokens, with fund_quote {quote,
                                       request = "lnbc21u1…", amount 2100, expiry, pubkey 02c4…}
BNAP-Error: AAEBAgEQ                   (REQUIRED)

(the agent checks the quote's key and amount, saves quote, key and offer, and pays through NWC)

POST /v1/chat/completions HTTP/1.1
Host: api.example
Content-Type: application/json
BNAP-Credential: …                     exact offer inline; pay = bnap:notes, body {fund = quote ID,
                                       outputs = ladder 1 … 2048}, witness {fund_sig}; binding

HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: private, no-store

data: {"choices":[{"delta":{"content":"Hello"}}]}
…
event: bnap-receipt
data: …                                OK, 850 tokens; charged 425 sat; scheme_result signs 1,675 sat of change
```

The manifest lists `chat` with `"scope": "route"`, so the route-scope offer is the route's default; the exact offer is the per-request offer that 5.4 lets such a route add to carry the quote (provisional reading of draft-00 9.1, 19.2). The exact offer lives 10 minutes. With the default `pending_timeout` of 300 s, it admits new credentials for its first 4 minutes (5.4), and the quote's invoice expires at that cutoff (8.2); a client that sends later gets STALE, consumes nothing, and redeems the paid quote with the route offer. With no attestation, the 850 tokens cost ⌈850 × 500 / 1000⌉ = 425 sat. The value is the quote's 2,100 sat, so the change is 1,675 sat, signed as the ladder outputs of 1,024, 512, 128, 8, 2 and 1 sat. Every later call spends those notes against the cached route offer, sending `offer_id`.

## Appendix B. Provisional decisions

Each of these is marked "(provisional)" where it is made, and each is open to owner review. P1 to P31 are numbered in the order of the sections that make them. From P32 on, a number is never reassigned: each later decision takes the next free number, wherever it is made, so that references to earlier numbers stay valid. The rows of 19.1 that say "(provisional)" restate P4, P11, P12, P26, P28 and P30, except the one for P31, which 19.1 makes; the rows of 19.2 that say "(provisional)" restate P32, P33 and P34.

| # | Where | Decision |
| --- | --- | --- |
| P1 | 3.3 | Clients SHOULD list outputs in ascending amount order |
| P2 | 3.5 | Unknown records inside a notes body or witness are rejected even when odd; GREASE belongs in socket streams |
| P3 | 3.6, 5.1 | `max_inputs` and `max_outputs` default to 16 |
| P4 | 4.2 | Full 33-byte keyset IDs only, never the short ID |
| P5 | 4.2 | Every BNAP keyset publishes a `final_expiry` |
| P6 | 5.1 | Notes parameters follow the even/odd rule |
| P7 | 5.4 | `fund_quote` only in exact-scope offers, and never on routes requiring `link-payment = unlinkable` |
| P8 | 5.4 | Gates may cache exact-scope offers that carry a `fund_quote` |
| P9 | 5.4, 7.5, 8.2, 15 | Admission cutoff: no new notes commit later than the deadline minus `pending_timeout` minus 60 s, checked after the replay lookup; offers that list notes admit for at least 60 s; fund quotes expire by the cutoff; wallets replay before the deadline |
| P10 | 6.2 | Verification does not check whether a fund quote has issued; the RailId commit does, so replays of funded credentials work |
| P11 | 6.2, 13.1 | Verification reads no use state; v0.4's check that no output was signed before is dropped, and `bnap:notes/OUTPUT_REUSED` is reserved |
| P12 | 6.3, 7.2 | One output list, a complete power-of-two ladder covering the value, replaces v0.4's separate change and refund lists; settlement signs a greedy subset worth exactly `value - charged` |
| P13 | 6.3 | Wallets SHOULD send the canonical ladder 1, 2, …, 2^(b-1) |
| P14 | 6.4 | A rail that does not confirm a fund payment gives BAD\_CREDENTIAL with `QUOTE_UNPAID` |
| P15 | 6.4 | Outputs and quote IDs yield no local ID; the RailId guards the quote |
| P16 | 7.1 | A FAILED outcome has `charged` 0 and refunds the whole value |
| P17 | 7.3 | No `scheme_result` when the change is 0 |
| P18 | 7.4 | The signed-output table is keyed by `(B', source)`, the source being `H(body)` or `rk_mint`, and keeps every record |
| P19 | 7.4 | Settlement signs a `B'` that was signed before instead of failing, and adds its own record |
| P20 | 7.5 | The refund of a timed-out outcome is computed when the client replays the credential |
| P21 | 8 | A body's `fund` redeems BOLT11 (NUT-23) quotes only; BOLT12 credit is minted through NUT-25 |
| P22 | 8.1 | The `BNAP-Fund` request field, an RFC 9651 Dictionary, needs registering |
| P23 | 8.2 | One quote per offer nonce and a per-address rate limit are MUST, as DECISIONS row 24 sets for natives |
| P24 | 8.5 | BNAP quotes require a NUT-20 key; NUT-04 minting commits the RailId under `rk_mint` in one transaction |
| P25 | 8.6 | A quote record lives as long as its RailId record, and both, with the rail's confirmation of the payment, last at least until 60 s after the deadline of the entry under which a credential committed the RailId, so replays of funded credentials still verify |
| P26 | 11 | Swaps use a price-0 manifest route with id `notes-swap`, answered by the gate |
| P27 | 12.1 | Derivation type `0x02` for note keys; the counter's top 16 bits name the slot |
| P28 | 12.2 | Wallets record their counters in the backup; restore scans at least that far |
| P29 | 13.2 | `UNIT_MISMATCH` folds into `UNKNOWN_KEYSET` |
| P30 | 15 | Wallets SHOULD bind whenever they can read `tls-exporter`, where v0.4 said agents and native clients MUST; a wallet may retry without a binding after a BINDING error |
| P31 | 19.1 | Suites 1 to 3 become their own scheme IDs |
| P32 | 7.3 | Required records of `scheme_result` are written even when empty, so the `index` of output 0 is a present empty record; optional empty records are left out; a client reads an absent `index` as 0 |
| P33 | 2.1 | A non-minimal BigSize or `tu64` inside a notes body or witness is BAD\_CREDENTIAL with `bnap:notes/NON_CANONICAL`, not the socket MALFORMED that draft-00 section 2 names |
| P34 | 5.4, 8.2 | On a route listed with `"scope": "route"`, a gate MAY also send a per-request exact-scope notes offer that carries a `fund_quote`; draft-00 9.1 is read as the route's default offer set |
| P35 | 7.1 | A FAILED Response to a metered offer reports `metered_units` 0, which draft-00 8.1 leaves open; the Response vectors of 18.2 item 6 use it |
| P36 | 5.4, 8.4 | On a route whose `require` sets `link-payment = unlinkable`, the notes pay entry carries no `max_fund`, and the gate rejects a credential that redeems a fund quote with POLICY after verification and before commit |
| P37 | 18.2 | The notes vectors replace the `httpsig:web-bot-auth` verifier with a stub that reports the placeholder attest body of draft-00 section 14 verified, with the local ID SHA-256(`bot key thumbprint`), so that the 20% discount applies; a real verifier rejects that body, and both credentials of item 3 are then UNDERPAID |

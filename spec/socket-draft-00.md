<!--
  Source doc: WJztndZC9mY1jogSMesi8n (Claude Docs)
  Tab: "Socket spec draft-00" (tab e8fc6cea-06b9, body node 354bdfd9-f24c)
  Doc rev exported: 39
  Export date: 2026-10-13
  Spec text licensed CC-BY-4.0, (c) BNAP contributors
  Transcribed verbatim to GitHub-flavoured Markdown from the doc's own markdown export.
  Chips: the date chip is a plain date, the mention is "Dominic".
-->

# BNAP socket — draft-00

2026-10-11 · Dominic

## 1. Status and scope

**Status.** Working draft 00 of the BNAP socket, the part every deployment shares. It turns the design in the first tab (v0.5.1) into byte layouts, algorithms and test vectors. It is meant to become the repository's normative text and, later, an IETF individual draft. Where this draft and the first tab differ, this draft wins and the difference is listed in section 15.

**Scope.** This draft defines the Offer, the Credential, use IDs and the use store, pricing with attestations, the Response and its receipt, errors, the manifest, and the HTTP carrier. It does not define any credential scheme: `bnap:notes`, L402, MPP and the rest are plugs with their own registry entries, and they plug into the slots defined here. Nothing in this draft depends on Cashu, on Lightning or on any one model or framework.

## 2. Conventions

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

| Notation | Meaning |
| --- | --- |
| `H(x)` | SHA-256 of `x` |
| `H_tag(x)` | BIP-340 tagged hash: `H(H(tag) ‖ H(tag) ‖ x)`, with `tag` as UTF-8. Every hash the socket defines is tagged, and no two uses share a tag |
| `‖` | Byte concatenation |
| BigSize | The variable-length unsigned integer of Lightning BOLT 1. Non-minimal encodings are MALFORMED |
| `tu64` | An unsigned 64-bit integer, big-endian, with leading zero bytes removed; zero is the empty string. Non-minimal encodings are MALFORMED |
| `lp(x)` | `BigSize(len(x)) ‖ x` |
| TLV stream | BOLT 1 records: `BigSize(type) ‖ BigSize(length) ‖ value`, types strictly increasing, no duplicates |
| Entry list | `lp(stream₁) ‖ lp(stream₂) ‖ …`, each stream a nested TLV stream. Used wherever a record holds several items |
| Flag | A record with an empty value; present means true |
| Key | A BIP-340 x-only public key, 32 bytes |
| Signature | A BIP-340 Schnorr signature, 64 bytes. Signers SHOULD use fresh auxiliary randomness; test vectors use 32 zero bytes |
| `b64u(x)` | Base64url without padding (RFC 4648 section 5) |
| empty | The zero-length byte string. Wherever a formula says "or empty", H(empty) is SHA-256 of zero bytes and lp(empty) is the single byte 00. An absent record and a present record with an empty value hash the same, and MUST mean the same. |

**One encoding.** Every socket object on the wire is a TLV stream. Scheme payloads are opaque bytes inside it, so a scheme that speaks JSON or CBOR keeps doing so. The manifest is the one exception: it is JSON, because it is fetched and read by tools that already parse JSON.

**Type ranges.** These apply to top-level socket streams. Nested streams, such as pay entries, use only 0–239, the experimental range and GREASE; the signature over the outer stream covers them.

| Range | Use |
| --- | --- |
| 0–239 | Socket fields defined by this document |
| 240–1000 | Signature records, never covered by any signature or MAC, as in BOLT 12 |
| 1001–999,999,999 | Reserved for future socket fields |
| 1,000,000,000–1,999,999,999 | Experimental; never registered |
| 3,000,000,001–3,000,000,999, odd only | GREASE |
| Every other value | Reserved |

**The even/odd rule.** A receiver that meets an unknown even type MUST reject the object as MALFORMED. It MUST ignore an unknown odd type. In a signed object, such as an Offer or a Response, the signature still covers that record. A Credential is not signed as a whole, so its unknown odd records outside `ext` MUST NOT affect processing in any way. Senders SHOULD add one GREASE record, of random odd type and random short value, to every Offer and Credential, so that receivers keep honouring the rule.

**Sizes.** Unless the manifest's `limits` raise them, an Offer MUST NOT exceed 4,096 bytes, a Credential 16,384 bytes and a Response 8,192 bytes. Larger objects are rejected with TOO\_LARGE before anything beyond the length is parsed. A credential can name its offer by OfferID instead of repeating it (5.1), which keeps most credentials under 2 KiB.

**Time** is Unix seconds. Verifiers allow 60 seconds of clock skew on every expiry check.

## 3. Overview

A gate runs the socket in front of an application. Plugs supply everything the socket does not fix: the scheme that checks a credential, the rail that took the payment, the carrier that names the action, the pricer, the store and the signer.

```
Client                                Gate: socket + plugs                     Application
  | request, no credential  ----------->| carrier computes the action scope
  |<------ 402 + Offer (+ native challenges)
  | request + Credential  ------------->| 1 parse, check the Offer, scope, expiry
  |                                      | 2 scheme.verify -> use IDs, rail IDs, value
  |                                      | 3 price with attestations, check value
  |                                      | 4 commit: every ID + ReplayKey, PENDING, atomic, durable
  |                                      |------- action ----------------------------->|
  |                                      |<------ result ------------------------------|
  |                                      | 5 settle OK or FAILED once; scheme.settle
  |<------ result + Response (signed receipt)
```

The gate holds no state about clients. Its state is the use store, which holds records about credentials, and a small cache of the offers it issued (5.1).

## 4. The Offer

An Offer is a TLV stream, signed by an online offer key, that prices one action or one route and lists every scheme the server accepts for it.

### 4.1 Records

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | version | tu64, 1 for this document | Required |
| 2 | scope | 32 bytes: an action scope or a route scope (4.3) | Required |
| 4 | route\_scope | Flag: `scope` names a route, not one action | Optional |
| 6 | headers | UTF-8, comma-separated lower-case field names the carrier hashes into the action scope, as the route lists them | When the route lists any |
| 8 | metered | Flag: the charge is set at settlement, up to the entry's amount (7) | Optional |
| 10 | expires | tu64 | Required |
| 12 | info | UTF-8 URI of the manifest, on the same origin | Optional |
| 14 | offer\_key | Key that signed this offer | Required |
| 16 | nonce | 16 random bytes | Required |
| 18 | pay | Entry list of pay entries, in preference order | Required unless `attest` holds a waive |
| 20 | attest | Entry list of attest entries | Optional |
| 24 | issued\_at | tu64 | Required when `mac` is absent |
| 26 | native | Entry list of native entries | Exact-scope offers only |
| 240 | offer\_sig | Signature | Required |
| 242 | mac | 32 bytes, HMAC-SHA256 | Required, except in offers published in advance (4.4) |

A **pay entry** is a nested stream:

| Type | Name | Value |
| --- | --- | --- |
| 0 | scheme | UTF-8 scheme ID, unique within `pay`. Required |
| 2 | amount | tu64, in the unit's base denomination; the ceiling in a metered offer. Required |
| 4 | unit | UTF-8: `sat`, `msat`, an ISO 4217 code (minor units) or a CAIP-19 asset ID (smallest indivisible unit). Required |
| 6 | quote\_expires | tu64; defaults to `expires` and MUST NOT exceed it |
| 8 | params | Bytes defined by the scheme's registry entry |
| 10 | rate | tu64: in a metered offer, the price per 1,000 units of the route's meter, in `unit`. Required in metered offers |

An **attest entry** is a nested stream:

| Type | Name | Value |
| --- | --- | --- |
| 0 | scheme | UTF-8 scheme ID, unique within `attest`. Required |
| 2 | effect | tu64: 0 required, 1 waive, 2 discount, 3 quota. Required |
| 4 | value | tu64: basis points for a discount, from 1 to 10,000; actions per epoch for a quota, at least 1 |
| 6 | epoch | tu64 seconds, for a quota, at least 1 |
| 8 | params | Bytes defined by the scheme's registry entry |

An offer with an effect outside 0–3, or a value or epoch out of range, is MALFORMED.

A **native entry** carries an artifact the server made for one pay entry:

| Type | Name | Value |
| --- | --- | --- |
| 0 | pay\_index | tu64, zero-based index into `pay`; that entry's scheme MUST be class O. Required |
| 2 | kind | UTF-8 label from the scheme's registry entry, such as `bolt11` or `l402-macaroon`. Required |
| 4 | data | The artifact's bytes. Required |

### 4.2 OfferID, signature and MAC

The server builds an offer in this order:

1. Write every record except the signature range and `native`. Let `S₀` be their serialization in stream order.
2. Compute `OfferID = H_"bnap/offer"(S₀)`.
3. Make each native artifact so that it embeds the OfferID, in the way its scheme's registry entry defines, such as an invoice description hash, a macaroon caveat or an MPP `id`. Add them as the `native` record.
4. Let `S` be the serialization of every record outside the signature range, natives included. Then `offer_sig = Sign(offer_key, H_"bnap/offer-sig"(S))` and `mac = HMAC-SHA256(K_mac, S)`.

Anyone can recompute the OfferID from the offer bytes by dropping the signature range and `native`. Records of unknown odd type are part of `S₀` and `S`, so nobody can add or remove them unnoticed. The server keeps `K_mac` secret and rotates it no faster than its longest offer lifetime. It keeps each retired key until every offer made under it has expired, and compares MACs in constant time.

### 4.3 Scope modes

**Exact.** Without `route_scope`, `scope` is the carrier's action scope for the one request this offer prices. A credential sent with any other request is WRONG\_SCOPE.

**Route.** With `route_scope`, `scope` is the carrier's route scope, and the offer may be used for any number of requests on that route until it expires. Each credential is still tied to its own request, because the Context includes that request's action scope (5.2). Only schemes of binding class S or A may appear in a route-scope offer, in `pay` or in `attest`. Class O and None artifacts do not cover the Context, so they need an exact-scope offer, and a route-scope offer carries no native record. Route scope is what lets a client pay for a stream of API calls with one round trip each.

### 4.4 Checks

A **client** that receives an offer MUST parse it fully and MUST check:

- that `version` is supported, `expires` is in the future, and `issued_at`, if present, is not in the future;
- that `offer_key` is listed for use `offer` in the origin's pinned manifest and has not expired (9.3). Without a pinned manifest, the client is trusting on first use;
- that `offer_sig` verifies;
- that `info`, if present, is on the origin the offer came from;
- that `scope` matches the request it is about to send, or the manifest route it expects;
- that every pay entry it might use fits its spend policy.

It ignores entries whose scheme it does not know.

A **gate** that receives a credential MUST check the offer inside it before calling any plug, in this order:

1. **Size.** Reject an oversize object with TOO\_LARGE.
2. **Parse and version.** Reject a parse failure with MALFORMED, and an unsupported version with VERSION.
3. **Authenticity.** An offer with `mac` passes only if the MAC verifies under a current or retained `K_mac`. An offer without `mac` was published in advance. It MUST carry `issued_at`, and it passes only if `offer_key` is a key this gate holds for use `offer` and lists in its current manifest, and `offer_sig` verifies under it. A gate MUST NOT trust a key because the offer names it. A failure here is BAD\_OFFER.
4. **Expiry.** Check `expires`, the chosen entry's `quote_expires`, and that `issued_at` is not in the future. A failure is STALE.
5. **Scope.** A mismatch is WRONG\_SCOPE.
6. **Offered schemes.** Every scheme the credential uses MUST appear in the offer, or the result is NOT\_OFFERED.

## 5. The Credential

### 5.1 Records

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | version | tu64, 1 | Required |
| 2 | offer | The Offer, byte for byte as received | Exactly one of `offer` and `offer_id` |
| 4 | pay | Nested stream: 0 scheme, 2 body, 4 witness | At most one |
| 6 | attest | Entry list of nested streams: 0 scheme, 2 body, 4 witness; sorted by scheme ID, bytewise | Optional |
| 8 | binding | 32 bytes: the RFC 9266 `tls-exporter` value of the client's connection | Only if a chosen scheme is class S |
| 10 | ext | A nested TLV stream of extensions | Optional |
| 12 | offer\_id | 32 bytes: the OfferID of an offer the gate issued and still caches | Exactly one of `offer` and `offer_id` |

A credential holds `pay`, `attest`, or both. These are MALFORMED: an attest list out of order or with a scheme twice; a `binding` when no chosen scheme is class S; both or neither of `offer` and `offer_id`.

**Offer by reference.** A gate issues one route-scope offer per route per issuing interval, the same to every client, and caches it until it expires. It also caches exact-scope offers that carry natives (5.4). Nothing an unauthenticated request does adds to the cache beyond that. A client then sends `offer_id` instead of the whole offer. The gate looks the offer up and runs the checks of 4.4 on it as if it had been sent. An unknown OfferID is BAD\_OFFER, and the gate answers with a fresh offer.

**Body and witness.** Every scheme splits what it sends in two. The `body` is everything the scheme needs except signatures made over the Digest; the `witness` holds those signatures. Only class S schemes have a witness. The split is what lets the Digest cover the body without covering the signature that is made over it.

**Everything verified is in the credential.** Everything a scheme verifies MUST be in its body or witness. An adapter for a scheme that natively lives in HTTP fields, such as Web Bot Auth's `Signature` or a DPoP proof, MUST have the client copy those fields into the body. It MUST NOT read them from the request instead, because the Digest would not cover them and anyone in the path could swap them. When such a signature covers request components, the adapter MUST build the signature base from the gate's own Context and the carrier's scope inputs, never from raw request fields.

**Canonical bodies.** A scheme MUST reject a body that contains any byte it does not verify: no padding, no unknown records, no alternative encodings. Otherwise someone on the path could alter a class A or None body, commit it first under a different ReplayKey, and turn the real client's retry into SPENT.

### 5.2 Context and Digest

```
action_scope = the carrier's scope of THIS request (equals the offer's scope in exact mode)

Context   = H_"bnap/ctx"( OfferID ‖ action_scope ‖ lp(pay scheme ID, or empty)
                         ‖ BigSize(n) ‖ lp(attest scheme ID₁) ‖ … ‖ lp(attest scheme IDₙ)
                         ‖ H(ext value, or empty) )

Digest    = H_"bnap/cred"( Context ‖ lp(binding, or empty)
                         ‖ H(pay body, or empty)
                         ‖ H(attest body₁) ‖ … ‖ H(attest bodyₙ) )

n may be 0. "Or empty" is the empty byte string of section 2.
```

Attestations appear in both formulas in the order of the credential's `attest` list, which is sorted.

The **Context** fixes everything the client chose: the offer, the request, the value scheme, every attestation scheme and the extensions. Class A artifacts embed it. The **Digest** adds the TLS binding and every body. Class S witnesses sign it. The gate computes both itself; a scheme plug receives them read-only.

### 5.3 Binding

If `binding` is present, the gate MUST compute the `tls-exporter` value (RFC 9266: label `EXPORTER-Channel-Binding`, empty context, 32 bytes) of the connection the request arrived on and reject a mismatch with BINDING. A gate that cannot see the client's TLS session, because a front terminates it, MUST reject credentials that carry a binding, and its routes MUST NOT require one. Binding is in the Digest but not in the Context, so a client retrying on a new connection re-signs a new Digest under the same Context and ReplayKey, and the retry is recognized (6.4). Only class S credentials are TLS-bound.

### 5.4 Native credentials

A client may pay through a scheme's own header, with no BNAP Credential. The scheme's adapter then MUST:

- recover the OfferID from the native artifact, which embeds it, and authenticate the artifact without state: a macaroon, an HMAC'd MPP id, an invoice its own node issued;
- recover the Offer itself, either from the artifact or from a cache of offers the gate issued with natives, keyed by OfferID and kept until they expire.

The gate then runs the same checks as for a Credential (4.4) and builds a synthetic envelope:

```
Context = H_"bnap/ctx-native"( OfferID ‖ action_scope ‖ lp(scheme ID) )
Digest  = H_"bnap/cred-native"( Context ‖ H(native credential bytes) )
```

The scheme's registry entry defines the native credential bytes, such as the L402 `macaroon:preimage` token. From here, use IDs, rail IDs, commit, replay and the receipt work exactly as for a Credential. The receipt goes in the BNAP response header next to the scheme's own. A request carrying more than one value credential, native or BNAP, is MALFORMED.

## 6. Uses and the use store

### 6.1 Identifiers

A scheme's `verify` returns local IDs: bytes that its registry entry defines, such as a note's `Y` or an L402 payment hash. The gate turns each into a socket ID itself, so no scheme can name an ID in another scheme's space:

```
UseId     = H_"bnap/use"(  lp(scheme ID) ‖ local ID )
RailId    = H_"bnap/rail"( lp(rail kind) ‖ canonical payment bytes )
ReplayKey = H_"bnap/replay"( Context ‖ H(pay body, or empty) ‖ H(attest body₁) ‖ … ‖ H(attest bodyₙ)
                           ‖ BigSize(m) ‖ id₁ ‖ … ‖ idₘ )          ids sorted bytewise
```

The ReplayKey is the Digest without the binding, plus every UseId and RailId of every scheme in the request, whatever its use model. It therefore names one credential, sent for one request. Two clients that send the same request with different credentials never share a ReplayKey. A retry of the same credential on a new connection does share it.

A credential that yields no ID under the single model, such as one carrying only reusable attestations, is protected from re-running only while its outcome record exists. The gate MUST NOT admit such a credential unless its offer expires at least 60 seconds before that record can be deleted: `expires + 60 ≤ now + replay_window`.

**Rail IDs.** Schemes are untrusted, so the canonical payment bytes come from the rail plug, which is operator-trusted. A scheme returns a rail reference: the rail kind and its own reference to the payment, such as a payment hash or a transaction. The gate asks that rail to confirm the payment, and the rail returns the canonical bytes, from which the gate computes the RailId. A scheme MUST return a rail reference for every payment its credential relies on. A scheme that mints credit from a payment, such as notes funded over Lightning, MUST have the gate commit that payment's RailId when it mints. Because the RailId is the same whichever scheme refers to the payment, one Lightning payment offered under L402, MPP and x402 admits one action, not three. Initial rail kinds:

| Kind | Canonical payment bytes |
| --- | --- |
| `ln` | Payment hash, 32 bytes |
| `onchain` | txid, 32 bytes ‖ output index as 4 bytes big-endian |
| `evm` | lp(CAIP-2 chain ID) ‖ token contract, 20 bytes ‖ payer, 20 bytes ‖ authorization nonce, 32 bytes |
| `card` | lp(processor name) ‖ lp(processor's payment ID) |

### 6.2 Use models

| Model | Store key | Rule |
| --- | --- | --- |
| single | UseId | One record. Kept for as long as the scheme's local artifact could still verify under any offer, which for a note means for as long as its keyset is accepted; forever if that has no end |
| rate(k, epoch) | `H_"bnap/rate"(UseId ‖ tu64(k) ‖ tu64(epoch) ‖ tu64(⌊now / epoch⌋))` | A counter of at most k |
| reusable | none | Nothing consumed beyond the outcome record. Any limit comes from a `quota` attestation (7) |

A quota attestation counts in `H_"bnap/quota"(UseId ‖ tu64(value) ‖ tu64(epoch) ‖ tu64(⌊now / epoch⌋))`, at most `value`. Its UseId MUST name a stable identity, such as a key or an account, which the scheme's registry entry declares as `quota_id`. A scheme whose IDs change with every token, as with Privacy Pass, cannot carry a quota.

RailIds are always single. The registry sets each scheme's model as the socket enforces it, which can be stricter than the native scheme: L402 tokens are reusable natively but single in BNAP.

### 6.3 Commit

The store MUST run the commit as one serializable transaction and MUST make it durable before the action starts:

```
commit(rk, singles, counters):          singles = single UseIds and RailIds; counters = (key, limit)
  if outcome[rk] exists:                 return Replay(outcome[rk])
  for id in singles:  if used[id] exists:                 abort, return SPENT
  for (key, limit) in counters: if counter[key] >= limit:  abort, return RATE_LIMITED
  for id in singles:  used[id] = rk
  for (key, limit) in counters: counter[key] += 1
  outcome[rk] = { status: PENDING, created: now, counters: [keys], charged: none,
                  scheme_result: none, response: none }
  return New
```

An abort consumes nothing, so a client whose commit fails keeps its credential and may retry it while the offer is valid.

If the store cannot be reached, the gate fails closed with UNAVAILABLE and never runs the action.

### 6.4 Settle and replay

**Settle.** The gate first computes the charge and calls the scheme's `settle`, which is deterministic: the same verified credential, outcome and charge always give the same `scheme_result`. It then writes status, charge and `scheme_result` to `outcome[rk]` in one conditional update that succeeds only from PENDING, so the status changes exactly once. On FAILED, single uses stay spent, the value scheme refunds as its registered refund property allows, and the counters listed in the outcome are given back. If the gate crashes between the action and this write, the outcome stays PENDING. Because `settle` is deterministic, a replay can recompute the change it would have returned. The gate MUST NOT send the Response, or any change in it, before this write is durable; otherwise a crash followed by the timeout would pay the client twice.

**Timeout.** An outcome still PENDING after the manifest's `pending_timeout` moves to FAILED, with the refund that implies. The gate MUST stop or discard any action still running at that point, so `pending_timeout` MUST exceed the route's longest action, streams included. A crash that leaves a finished action PENDING therefore costs the operator, never the client.

**Replay.** Before commit, the gate has already verified the credential and its binding against this request. If the commit finds `outcome[rk]`, the request is the same credential for the same request:

- A PENDING outcome returns PENDING with a `retry_after`.
- An OK or FAILED outcome inside `replay_window` gets the stored response, if the carrier kept one, with `replayed` set; the action never runs twice.
- A carrier that did not keep the response returns the receipt alone, with the `scheme_result` recorded at settlement. The scheme MUST NOT pay out anything beyond that recorded result.

After `replay_window` the outcome record may be deleted, but the single-use records remain, so a later replay is SPENT. Replaying a credential is also how a client fetches a receipt it missed, for example at the end of a stream that had no trailer.

A replay hands the stored response to whoever presents the same valid credential, so the response is only as confidential as the scheme's theft property allows.

## 7. Pricing, attestations and metering

The offer is the quote. The Pricer runs when the gate builds an offer and writes one amount per pay entry, converting between units as it likes. At verification time the gate uses only what the offer says, so a client can predict a fixed price exactly, and can check a metered charge against the offer's rate:

```
price(base):                        base = entry.amount, or the metered amount at settlement
  p = base
  for each verified attestation, in offer order, effect waive:     p = 0
  for each verified attestation, in offer order, effect discount:  p = p - ⌊p × value / 10000⌋
  if p > 0: for the first verified quota attestation, in offer order, whose counter has room:
                                                                    p = 0, and add its counter to the commit
  return p

admit:
  for each required attestation in the offer: if not verified      -> POLICY
  p = price(entry.amount, or 0 if the credential has no pay)
  if p > 0 and no pay                                               -> UNDERPAID
  if the scheme's verified value < p                                -> UNDERPAID
```

An attestation that fails verification and is not required has no effect, and causes no error.

Discounts multiply, so two 20% discounts give about 36% off, never 40%. Each step rounds down the amount taken off, so the order is fixed by the offer and the result is exact. Only attestations of binding class S, A or O may waive, discount or carry a quota, and the gate MUST NOT build an offer that breaks this. A route's `require` applies to attestations exactly as to value schemes. Attestation use IDs and quota counters commit in the same transaction as the value IDs (6.3). If a quota had room at pricing but is full at commit, the commit aborts with RATE\_LIMITED and consumes nothing.

**Metering.** A metered route names its meter in the manifest, such as `tokens`. In a metered offer, each pay entry's `amount` is a ceiling and its `rate` is the price per 1,000 meter units. The credential must carry value of at least `price(amount)`. At settlement the gate counts the units used, computes `charged = min(price(⌈units × rate / 1000⌉), price(amount))`, and reports both `metered_units` and `charged` in the Response, so the client can check the arithmetic. The gate computes it in arbitrary precision, so a product beyond 2⁶⁴ simply yields the ceiling. Settlement reuses the attestation results and quota decision made at admission; it never consumes a quota again. The client cannot check the unit count itself; that is trust in the operator, which the signed receipt makes attributable.

The scheme returns the rest of the value: notes as change outputs, a facilitator scheme by settling the lower amount. A pay entry may appear in a metered offer only if its scheme's registry entry has `refund = "atomic"` or `upto = true`. On a metered route, other schemes get non-metered exact-scope offers priced at the ceiling.

**Overpayment.** If the value exceeds the price in a non-metered offer, a scheme that can return change does so; otherwise the excess is kept. Clients SHOULD pay exact amounts.

## 8. Response, receipt and errors

### 8.1 Response

Every request that reached commit gets a Response, whichever scheme paid:

| Type | Name | Value | Presence |
| --- | --- | --- | --- |
| 0 | version | tu64, 1 | Required |
| 2 | status | tu64: 0 OK, 1 FAILED | Required |
| 4 | replayed | Flag | On replays |
| 6 | charged | tu64, in `unit` | Required; 0 when nothing was charged |
| 8 | unit | UTF-8, the chosen entry's unit | Required when the credential has `pay` |
| 10 | offer\_id | 32 bytes | Required |
| 12 | digest | 32 bytes, the Digest of the request this Response answers | Required |
| 14 | metered\_units | tu64, the meter's count | Required in metered offers |
| 16 | scheme\_result | Bytes defined by the scheme: change signatures, a settlement reference | Optional |
| 18 | receipt\_key | Key | Required |
| 20 | settled\_at | tu64 | Required |
| 240 | ack | Signature by `receipt_key` over `H_"bnap/ack"(every record outside 240–1000)` | Required |

A replay is signed afresh over the replaying request's Digest, with `replayed` set. It keeps the original `settled_at`, `charged` and `scheme_result`, so a receipt fetched late still shows when the action was settled.

**Using a receipt as proof.** A Response, the manifest that lists its `receipt_key`, and the Credential it answers let a third party check three things: that the operator of the origin acknowledged this outcome for this credential, at this time, for this charge. A client keeps every Response it paid for.

### 8.2 Errors

Errors are TLV streams too: 0 version, 2 code (tu64), 4 scheme\_code (UTF-8, namespaced, such as `bnap:notes/OUTPUT_REUSED`), 6 detail (UTF-8, at most 256 bytes, for logs only), 8 retry\_after (tu64 seconds). Errors are not signed. A client MUST NOT treat any error as proof of anything.

| Code | Name | Meaning | HTTP |
| --- | --- | --- | --- |
| 1 | VERSION | Unsupported socket version | 400 |
| 2 | MALFORMED | Bad encoding, order or framing | 400 |
| 3 | TOO\_LARGE | Over a size limit | 413 |
| 4 | BAD\_OFFER | Offer MAC or signature fails | 402, fresh offer |
| 5 | STALE | Offer or quote expired | 402, fresh offer |
| 6 | WRONG\_SCOPE | Offer is for another action or route | 402, fresh offer |
| 7 | NOT\_OFFERED | A scheme the offer does not list | 402 |
| 8 | POLICY | Properties or a required attestation missing | 403 |
| 9 | UNDERPAID | Value below the effective price | 402 |
| 10 | BAD\_CREDENTIAL | The scheme rejected the credential; see `scheme_code` | 402 |
| 11 | BINDING | TLS binding mismatch or not checkable | 400 |
| 12 | SPENT | A use ID is already committed under another ReplayKey | 409 |
| 13 | PENDING | The same credential is still in flight | 409, `retry_after` |
| 14 | RATE\_LIMITED | A rate counter is full | 429, `retry_after` |
| 15 | UNAVAILABLE | Store, signer or verifier unreachable; the gate fails closed | 503 |
| 16 | REQUIRED | The route needs a credential and none was sent | 402, fresh offer |

Codes up to 1,000 are reserved for this document; the registry assigns the rest.

## 9. Manifest and pinning

### 9.1 Document

The manifest is a JSON object served at `https://<origin>/.well-known/bnap` with media type `application/json`. It holds only strings, booleans, objects, arrays and integers no larger than 2⁵³.

| Member | Value |
| --- | --- |
| `bnap` | 1 |
| `origin` | The origin it covers, serialized as in RFC 6454: lower case, IDNA A-labels, default port omitted |
| `seq` | Integer; increases with every change |
| `issued` | Unix time |
| `max_age` | Seconds; at most 2,592,000 (30 days) |
| `root` | Hex key that signs this manifest |
| `backup` | Hex key of the offline key that may sign the next root's manifest |
| `keys` | Online keys: `[{"kid": hex key, "use": "offer" or "receipt", "not_after": time}]` |
| `required` | Boolean, the `bnap-required` flag (9.3) |
| `limits` | `replay_window`, `pending_timeout` (seconds); `max_offer`, `max_credential`, `max_response` (bytes) |
| `carriers` | Carrier names, such as `["http", "mcp"]` |
| `routes` | `[{"id", "match", "scope": "exact" or "route", "metered", "meter", "price": {unit: amount}, "pay": [scheme IDs], "attest": [{"scheme", "effect", "value", "epoch"}], "require": {property: value}, "headers": [field names]}]` |
| `sig` | Hex signature by `root` over `H_"bnap/manifest"(JCS(manifest without sig))` |

JCS is the JSON Canonicalization Scheme of RFC 8785. Member names are ASCII, so sorting them by code point equals JCS order. A route's `match` is a method, one space, and a path, compared with the request path without its query; a path ending in `/*` matches every path below it. A route listed with `"scope": "route"` gets route-scope offers for its class S and A schemes, and exact-scope offers for the rest. `headers` lists request fields that the HTTP carrier hashes into the scope (10.1).

### 9.2 Keys

The root key stays offline and signs only manifests. Online offer and receipt keys SHOULD expire within 30 days and are replaced by publishing a new manifest with a higher `seq`.

A manifest is always signed by the key in its own `root` member. A manifest signed by the current root MUST keep the same `backup`, so a stolen root cannot also take the recovery path. To retire the root, the operator signs a manifest with the backup key, which that manifest names as its `root`, and names a fresh `backup`. A stolen backup is as bad as a stolen root, so the backup is kept offline and apart from the root.

A client that missed a rotation still holds the old pin, and accepts only manifests signed by the keys it pinned. Operators MUST NOT rotate twice within 30 days. A client that cannot validate any manifest keeps the pinned keys until its pin lapses, then trusts on first use again.

### 9.3 Client rules

```
fetch(origin):                            HTTPS only, certificate valid for origin; at most once per 5 minutes
  m = GET https://origin/.well-known/bnap
  require m.bnap == 1, m.origin == origin, m.sig valid under m.root
  require m.issued - 60 <= now <= m.issued + m.max_age + 60
  if pin[origin] is live:
      require m.root == pin.root and m.backup == pin.backup,
           or m.root == pin.backup                              a rotation
      require m.seq > pin.seq, or H(m bytes) == pin.hash
  pin[origin] = {root: m.root, backup: m.backup, seq: m.seq, hash: H(m bytes),
                 required: m.required, keys: m.keys,
                 until: min(m.issued + m.max_age, now + 30 days)}

on an offer:   offer_key listed in the pin with use "offer", not_after >= now;
               otherwise fetch(origin), then reject
on a receipt:  receipt_key listed in the pin with use "receipt", not_after >= settled_at;
               without replayed, settled_at within 60 s of the client's clock on arrival
on a 402 from an origin pinned with required = true:
               pay only through a BNAP offer that passes 4.4, never through a native header,
               until the pin lapses
always:        pay a native challenge only if its bytes equal a native entry of an offer
               that passes 4.4, or the client has no pin for the origin
```

**What pinning does and does not do.** Clients pin the root and its backup, never per-route scheme lists, which change whenever a rail goes down. `offer_sig` already stops anyone removing a scheme from an offer. `required` is the only defence against deleting the BNAP header so that a client falls back to a native scheme, and it protects only clients that fetched the manifest before. First contact is trust on first use. The 30-day cap bounds how long a hostile first contact can pin a key. Operators who want more publish the root key out of band, in DNS, on Nostr or in their documentation.

## 10. The HTTP carrier

### 10.1 Scopes

```
action scope = H_"bnap/scope/http"( lp(method) ‖ lp(target) ‖ lp(content hash, or empty)
                                   ‖ BigSize(h) ‖ lp(name₁) ‖ lp(value₁) ‖ … ‖ lp(nameₕ) ‖ lp(valueₕ) )
route scope  = H_"bnap/route/http"( lp(origin) ‖ lp(route id from the manifest) )
```

- **method** is the request method exactly as sent; methods are case-sensitive.
- **target** is the manifest's `origin` followed by the request-target in origin form, exactly as received: path and query bytes unchanged, with no normalization. The gate MUST forward that same request-target to the application, so the action that was paid for is the action that runs. Using the manifest origin, not the scheme and authority the gate sees, keeps the scope the same behind a TLS-terminating front.
- **content hash** is the raw SHA-256 of the request content as sent, after any content coding, or empty when there is no content. Clients SHOULD also send `Content-Digest` (RFC 9530), so intermediaries can check the body, but the gate always hashes the body itself.
- **headers** are the fields the route lists in the manifest, in that order, for requests whose meaning depends on more than the body, such as `anthropic-version` or `Accept`. The name is in lower case, and the value is the field value as received, with repeated fields combined as in RFC 9110 section 5.3. A listed field that is absent has an empty value. Exact-scope offers repeat the list in record 6, so a client without the manifest can compute the scope. Most routes list none, so h = 0.

### 10.2 Header fields

| Field | Direction | Value |
| --- | --- | --- |
| `WWW-Authenticate: BNAP offer="…"` | Response, with 402 | `b64u(Offer)`. A 402 MAY carry several BNAP challenges, such as a route offer and an exact offer, next to native challenges in their own fields |
| `BNAP-Credential` | Request | `b64u(Credential)` |
| `BNAP-Context` | Request, optional | `b64u(Context)`, for schemes whose native signature covers header fields, such as Web Bot Auth. The signature, with this field among its covered components, is copied into the attest body (5.1). The gate MUST reject the request as MALFORMED if this field differs from the Context it computed |
| `BNAP-Receipt` | Response | `b64u(Response)` on every response to a request that reached commit |
| `BNAP-Error` | Response | `b64u(Error)`, with the HTTP status from 8.2 |

The credential has its own field, not `Authorization`. That keeps `Authorization` free for the API's own credentials, such as an LLM API key. Native schemes that use `Authorization`, such as L402, still clash with an API key there; such clients must choose one. On BNAP routes, gates MUST accept a `BNAP-Credential` field of at least 12,288 bytes, enough for a credential that carries a 4,096-byte offer inline. Clients SHOULD send `offer_id` rather than the whole offer, which keeps a notes credential far below that.

**Caching.** The credential is not in `Authorization`, so RFC 9111's rule against storing authorized responses in shared caches does not apply automatically. Every response to a request that carried `BNAP-Credential` MUST include `Cache-Control: private, no-store`, and the gate MUST add it if the application did not.

**Streaming.** When the charge is known only at the end, as with a streamed LLM completion, the receipt cannot travel in the response header:

- If the client sent `TE: trailers`, the gate sends the receipt as an HTTP trailer `BNAP-Receipt`.
- Otherwise, for `text/event-stream`, it sends a final event `bnap-receipt` whose data is `b64u(Response)`. The gate MUST strip any `bnap-receipt` event the application itself emits.
- Otherwise the client fetches the receipt by replaying the credential after the stream ends (6.4).

A client that disconnects mid-stream is charged for what was produced. A stream that would outlast `pending_timeout` is cut off at that point, so routes with long streams need a long `pending_timeout`.

### 10.3 Example: the LLM inference proxy

The operator puts the gate in front of an OpenAI-compatible endpoint. Its manifest has one route, `chat`, metered in `tokens`. It gets route-scope offers for `bnap:notes`, at 500 sat per 1,000 tokens up to 2,100 sat per call, with a 20% discount for agents that sign with Web Bot Auth. Exact-scope, non-metered L402 offers at the ceiling serve clients that have no BNAP code.

```http
POST /v1/chat/completions HTTP/1.1
Host: api.example
Content-Type: application/json

{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}

HTTP/1.1 402 Payment Required
WWW-Authenticate: BNAP offer="AAEBAiCGLWQeZ4E_bniyCoGqkpUZ5mqXjmnopNPicoCZBpfzoAQACAAKBGrLLUwM…"
WWW-Authenticate: BNAP offer="…"                       (exact scope: L402, 2,100 sat, with native)
WWW-Authenticate: L402 macaroon="<caveat bnap_offer = OfferID>", invoice="lnbc…"
BNAP-Error: AAEBAgEQ                                     (REQUIRED)

POST /v1/chat/completions HTTP/1.1
Host: api.example
Content-Type: application/json
BNAP-Context: <b64u Context>
BNAP-Credential: AAEBAv0BMQABAQIghi1kHmeBP254sgqB…          offer, notes worth 1,680 sat with change outputs,
                                                          Web Bot Auth body over BNAP-Context, binding

HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: private, no-store

data: {"choices":[{"delta":{"content":"Hello"}}]}
…
event: bnap-receipt
data: AAEBAgAGAgFUCANzYXQKIFyGQCYfbx3jIGounNHC…                 OK, 850 tokens, charged 340 sat
```

The ceiling after the discount is 2,100 − 420 = 1,680 sat, so the client sends notes worth 1,680 sat. The call used 850 tokens: ⌈850 × 500 / 1000⌉ = 425 sat before the discount and 340 sat after it, so the notes scheme signs 1,340 sat of change. Every later call sends `offer_id` instead of the offer and reuses it until it expires, so each call is one round trip.

## 11. Registry entries

A scheme plugs into the socket only through a registry entry. The entry tells the gate everything it needs, so the gate never trusts a plug's own description of itself. An entry for a value scheme:

```toml
[scheme."bnap:notes"]
role        = "value"                  # value | attestation | both
spec        = "https://…/bnap-notes"
binding     = "S"                      # S | A | O | none
use         = "single"                 # single | rate | reusable, as the socket enforces it
local_id    = "Y of each input, 33-byte compressed point"
quota_id    = ""                       # attestations only: the stable identity a quota counts against
rail_refs   = "none at spend; the funding payment at minting, confirmed by the rail"
body        = "TLV, section 3 of the scheme spec"
witness     = "one BIP-340 signature per input, over the Digest"
native      = []                       # kinds, how each embeds the OfferID, native credential bytes
units       = ["sat"]
refund      = "atomic"                 # none | out-of-band | atomic
upto        = false
properties  = { theft = "key-witnessed", link-payment = "unlinkable", link-actions = "unlinkable",
                issuer = "self-issued", verify = "offline", finality = "final-on-verification",
                custody = "operator-iou", pq = "no", maturity = "experimental" }
conformance = "https://…/results/bnap-notes.json"
```

Rails and verifiers have entries too, with their rail kind, canonical payment bytes, finality and custody. The gate computes each pay entry's effective property vector as the per-property minimum over its scheme, rail and verifier entries, with unknown counted as weakest. To be listed, an entry needs:

- a public specification;
- test vectors;
- passing conformance results;
- review by the designated expert.

The maintainer is the designated expert until two independent implementations exist; the registry then moves to IANA.

## 12. Security considerations

The threat table in the first tab still applies. These points are specific to the bytes:

- **Coverage.** Offer signatures and MACs, and Response acks, cover every record outside 240–1000, unknown odd ones included. A Credential is not signed as a whole. The Digest covers its offer, schemes, extensions, bodies and binding, and class S witnesses sign that. Anything else in a Credential is ignored. Every hash is tagged, so a value from one context can never be reused in another.
- **Offers published in advance** are accepted only under keys the gate itself holds and lists (4.4). Without that rule, anyone could mint a cheaper offer.
- **Order of checks.** The gate checks size, encoding, version, authenticity, expiry and scope before any plug sees the bytes (4.4), so a hostile plug never receives unauthenticated offers.
- **Route-scope offers** can be reused until they expire. That is safe only because the Context includes the action scope, and only class S and A schemes may use them. A gate MUST NOT list a class O or None scheme, or any native, in a route-scope offer.
- **Class O** credentials are bearer within their offer, and the registry records their theft property as bearer.
- **Untrusted schemes, trusted rails.** Canonical payment bytes come from the rail, never from the scheme (6.1), so a broken scheme cannot make one payment count twice.
- **Durability.** A commit that is not durable when the action starts can let a crash re-admit a spent credential. Stores MUST make commits durable synchronously.
- **Fail closed.** An unreachable store, signer, rail or verifier means UNAVAILABLE, never admission.
- **Retention.** Single-use records live as long as the artifact could verify under any offer; deleting them early re-enables double spending.
- **Work before authentication.** A reusable route offer lets anyone make the gate call a scheme plug with garbage. The gate MUST bound the plug work and the native challenges that unauthenticated requests can cause, per client address and per offer. It SHOULD rate-limit verification, run cheap checks first, and mint native challenges at most once per offer nonce, only on request or under a rate limit.
- **Caches.** Paid responses carry `Cache-Control: private, no-store` (10.2).
- **Time.** Expiry checks allow 60 seconds of skew. Offer lifetimes SHOULD be minutes for exact scope and hours at most for route scope.
- **Side channels.** MACs are compared in constant time. The `detail` text of an error never reaches a model or a user as instructions.
- **Privacy.** Offers carry a random nonce and no client identifier. Clients never send capability lists. GREASE keeps parsers honest.

## 13. Registry considerations

This document asks for these registries, held in the BNAP repository until they move to IANA:

| Registry | Initial contents | Policy |
| --- | --- | --- |
| Socket TLV types | Sections 4, 5 and 8 | Standards action |
| Error codes | Section 8.2 | Specification required, codes above 1,000 |
| Rail kinds | `ln`, `onchain`, `evm`, `card` | Specification required |
| Schemes, rails, verifiers | As section 11 | Expert review |
| Carriers | `http`; `mcp` by the MCP carrier note | Specification required |

To IANA directly: the HTTP authentication scheme, used for challenges only, `BNAP`; the header fields `BNAP-Credential`, `BNAP-Receipt` and `BNAP-Error`, plus BNAP-Context; the well-known URI `bnap`.

## 14. Test vectors

These vectors come from a reference encoder of about 360 lines of standard-library Python (`bnap_ref.py`). Its BIP-340 code reproduces the official BIP-340 vector 0. Secret keys are SHA-256 of the strings shown, and auxiliary randomness is 32 zero bytes. Scheme bodies are placeholders, because no scheme is part of this document; the note's Y, for instance, is a 32-byte stand-in for a 33-byte point. An independent reviewer has reproduced these vectors from the prose alone. The full set, with every intermediate value, is in `vectors.json`.

| Vector | Input | Output |
| --- | --- | --- |
| Tagged hash | `H_"bnap/offer"("")` | `4d1dac84920fd0e91e9cdf1788ac22fed3a61f72bab6752010b0b191b05367ed` |
| BigSize | 0, 252, 253, 65535, 65536, 2³² | `00`, `fc`, `fd00fd`, `fdffff`, `fe00010000`, `ff0000000100000000` |
| tu64 | 0, 1, 256, 1791700000 | empty, `01`, `0100`, `6acb2c20` |
| HTTP action scope | POST, target `https://api.example/v1/chat/completions`, the body in 10.3, no listed headers | `02be38b55551b02bee2daab2ca3d752e9538cc288f57a6dea67ccaf6971b3717` |
| HTTP route scope | origin `https://api.example`, route `chat` | `862d641e67813f6e78b20a81aa929519e66a978e69e8a4d3e27280990697f3a0` |
| Offer key | SHA-256("bnap test offer key") | `b28dad5f717c5144bdb0aa6db94bb6c79afa9b8bd9bc84825a2c1baafe64add9` |
| OfferID | The route offer below | `5c8640261f6f1de3206a2e9cd1c2599a2e9256547242061c95f9d2e06cf6696d` |
| Context | OfferID, the action scope above, `bnap:notes`, `httpsig:web-bot-auth`, empty ext | `e9f5603656d8e54dd25f9f7cee291c56e01cc8e6a80536185d69b1ed12158e6d` |
| Digest | That Context, binding SHA-256("tls-exporter placeholder") | `7c8f6196ad3adb3cf3199c1ebb79ef8b84ae26d20a01f3a89e336666d530d4c9` |
| Digest, other connection | The same, binding SHA-256("other connection") | `c9ef748b8fd377c66e6392311fe2e69adcdc30439c6c486444c11dada36a207a` |
| UseIds | notes Y = SHA-256("note secret 1"); bot key SHA-256("bot key thumbprint") | `b7ca97d6…232b6456`, `381a38d9…4bc2fb5e` |
| ReplayKey | That Context, both bodies, both UseIds | `74bd8a797c022ff864706809c6e9b23e9affd1829a093db365178db29b0c2771`, the same on both connections |
| Attestation only | Exact offer `2511ffa4…f3dadfc8` whose only entry is an `httpauth:DPoP` waive; no pay, ext or binding | Context `04500cf8…1d5231ca`, Digest `475c3682…550c3f47`, ReplayKey `c9248cf0…8961be9c` |
| Native envelope | Exact offer `919103b5…6a2e7562`, `payment:lightning/charge`, bytes "MPP credential placeholder" | Context `38a036b6…6cbb1b78`, Digest `198cd8d6…f0a2a04e` |
| RailId | `ln`, payment hash SHA-256("preimage") | `5f210bd3b07d0ff1fc78e2f6715ddcad5dcb2bc0147b06d0261c5703f1867744` |
| Native invariance | That exact offer with and without a `native` record | Same OfferID, different `offer_sig` |

The route offer used above, 305 bytes: route scope, metered, `bnap:notes` up to 2,100 sat at 500 sat per 1,000 tokens, a 20% Web Bot Auth discount, a GREASE record of type 3,000,000,001, and the signature and MAC:

```
0001010220862d641e67813f6e78b20a81aa929519e66a978e69e8a4d3e27280990697f3a0040008000a046acb2d4c
0c2468747470733a2f2f6170692e6578616d706c652f2e77656c6c2d6b6e6f776e2f626e61700e20b28dad5f717c51
44bdb0aa6db94bb6c79afa9b8bd9bc84825a2c1baafe64add91010000102030405060708090a0b0c0d0e0f121a1900
0a626e61703a6e6f7465730202083404037361740a0201f4141e1d0014687474707369673a7765622d626f742d6175
7468020102040207d0f040fa3a850dff40a2fe54f5662580783b3e4d63fbc3a99ea4832465d60427d849cf31d35c75
9da7958591b12c2fc51a4aee30288636999720a9813b714d996d2d3af220a29714a6310d1153b6477c0a06e297d0d1
8f614a52d2bf31926900693620fc13feb2d05e01020a0a
```

The Response for that call, 850 tokens and 340 sat charged, signed with the receipt key SHA-256("bnap test receipt key"):

```
00010102000602015408037361740a205c8640261f6f1de3206a2e9cd1c2599a2e9256547242061c95f9d2e06cf669
6d0c207c8f6196ad3adb3cf3199c1ebb79ef8b84ae26d20a01f3a89e336666d530d4c90e020352101d6368616e6765
207369676e61747572657320706c616365686f6c64657212205f49b61a80a8105a2f727c4c53ee1718252b1e8bc05f
6c62f0242e56286b83db14046acb2c4af040c1d4270a82036d4b4c89f0d39ad62ea3a541fcd299eca075a02a7b1e04
ee01ef784a08eba0996365ae8acb460ae0ee7474602381eba209456ab629bfef6f70f7
```

The conformance suite will add negative vectors:

- a non-minimal BigSize, records out of order and an unknown even type;
- a flipped bit in each signed record;
- an offer without `mac` signed by a key the gate does not hold;
- a class O scheme or a native in a route-scope offer;
- an attest list out of order, and a binding with no class S scheme;
- one payment referred to by two schemes;
- two clients sending the same request with different reusable attestations;
- a replay with a changed binding;
- a replay of an OK outcome whose response was not kept;
- a manifest rollback and a double rotation.

## 15. Changes from v0.5.1

This draft changes the first tab's design in these places. The first tab will be brought into line.

| Change | Why |
| --- | --- |
| The Credential is TLV, not CBOR | One encoding for every socket object; one parser to harden |
| Scheme payloads split into body and witness | v0.5.1's Digest hashed the payload that holds the signature over the Digest, which is circular |
| The Context includes the request's action scope; offers may name a route | One round trip per call for the LLM proxy; still one request per credential |
| Signature range 240–1000, as in BOLT 12 | Room for more signature types later |
| The credential travels in `BNAP-Credential`, the receipt in `BNAP-Receipt` | `Authorization` stays free for the API's own key |
| Receipts can arrive in a trailer or a final stream event | Metered, streamed completions know their charge only at the end |
| New error codes UNDERPAID, BAD\_CREDENTIAL, BINDING and UNAVAILABLE, all numbered | Every failure path in the algorithms has a code |
| The ack signs the whole Response stream | Same fields as v0.5.1's formula, and extensible |
| The ReplayKey covers bodies and every ID, not only committed ones | Review of draft-00: two clients with reusable credentials could share a ReplayKey and receive each other's responses |
| Rails, not schemes, supply canonical payment bytes | Schemes are untrusted; a wrong RailId would let one payment count twice |
| Metered offers carry a rate, and Responses the metered units | A client can check the charge, not only its ceiling |
| Credentials may name their offer by OfferID | Keeps credentials inside common header limits |
| The HTTP target is hashed exactly as received, plus listed headers | Normalization was ambiguous and could pay for one action and run another |
| The manifest backup changes only through a rotation; the issued time is checked | Stops rollback, and stops a stolen root from also taking the recovery key |

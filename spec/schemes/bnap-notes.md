<!--
  Source doc: WJztndZC9mY1jogSMesi8n (Claude Docs)
  Tab: "bnap:notes scheme (from v0.4)" (tab 17b34e12-61bc, body node f4ed9723-955a)
  Doc rev exported: 23
  Export date: 2026-10-13
  Spec text licensed CC-BY-4.0, (c) BNAP contributors
  Transcribed verbatim to GitHub-flavoured Markdown from the doc's own markdown export.
  Chips: the date chip is a plain date, the mention is "Dominic".
-->

# BNAP: an admission layer for priced actions — Draft Specification v0.4

2026-10-10 · Dominic

*Since v0.5 this tab is the detailed specification of one credential scheme, `bnap:notes`, the default scheme. Where it differs from the v0.5 socket, v0.5 wins: its CHALLENGE is the socket's Offer, its witnesses sign the socket's Digest, and commit, replay and receipts are owned by the socket.*

## Abstract and status

BNAP lets an online service put a small price, in sats, on an action such as an API call, a post or a signup, and check payment offline without learning who paid. It is a Cashu profile: the service runs its own Cashu-style issuer, sells prepaid credit over Lightning, and accepts that credit back as Notes, each bound to one specific request. BNAP aims to be a small, stable admission layer that many carriers and value rails can share without changes to the core.

**Terminology.** BNAP ("bee-nap", Blind-Note Admission Protocol) is the protocol; Caparra is its Rust reference implementation. A slash means "funded over", with the lower layer on the right; a plus means "carried in".

| Written | Read as |
| --- | --- |
| BNAP/LN | BNAP credit funded over Lightning |
| BNAP/Ark | BNAP credit funded over Ark (experimental) |
| HTTP+BNAP | HTTP carrying BNAP in its authentication slot |
| HTTP+BNAP/LN | HTTP with BNAP, funded over Lightning |
| SASL+BNAP | Mail, chat or MQTT carrying BNAP through SASL |
| BNAP-W, BNAP-B | The withdrawal and deposit extensions |

**Status.** Pre-draft, version 0.4. A third expert round checked v0.3 against what Cashu, Lightning and the IETF have shipped by October 2026: an ecash cryptographer, an anonymous-credentials expert, a Lightning engineer and a Bitcoin protocol reviewer. Earlier versions stay in the archive tabs. Key words follow BCP 14 (RFC 2119, RFC 8174).

| Owner decision | Choice |
| --- | --- |
| Name | BNAP |
| Framing | A layered spec with modest framing; the TCP/IP analogies live in Appendix A |
| Ecosystem | A Cashu profile: Notes are valid Cashu proofs, and buying credit is Cashu's Lightning mint flow |
| Withdrawal | An optional extension, BNAP-W, off by default |
| First deployment | AI agents and paid APIs |

**What round 3 changed.**

- Notes reuse Cashu verbatim: the secret is the hex of the note key, keyset IDs are Cashu's version-2 IDs, and DLEQ proofs follow NUT-12.
- Wallets recover from a seed (NUT-13 derivation); in v0.3 a lost device meant lost funds.
- Credit is bought through Cashu's Lightning mint flow (NUT-23, NUT-04, NUT-20), and a first-time agent can fund and act in one round trip.
- Refunds by operator signature (ack-refund) are gone: a failed action returns refund outputs the client supplied, signed in the same response.
- A spend costs about 300 bytes on disk, including the signed outputs Cashu restore needs, and replies to retries are recomputed rather than stored.
- Agents with no BNAP code can still pay per action through L402 or MPP challenges in the same 402 response.

## Why BNAP exists

BNAP removes actions that are only profitable at a price of zero: agents hammering free APIs, scraping, slop posts, spam and bulk signups. An automated action stops paying the moment its price exceeds its value to the actor:

```latex
p > v_{action}
```

The price is per action, not per actor, so splitting into many identities saves nothing. BNAP does not tell humans from machines; it makes each action cost something, and only low-value actions disappear.

**In plain terms, BNAP is** prepaid site credit, priced in sats, issued and redeemed by one site, never transferable between sites, and withdrawable only where the operator opts in. Each spend is bound to one request and cannot be linked to the purchase that funded it.

| Existing scheme | What it does | What BNAP adds |
| --- | --- | --- |
| L402 (Lightning Labs) | One Lightning payment per request, proved by preimage and macaroon | Pay once, spend offline many times; spends unlinkable to the payment |
| x402, MPP | Stablecoin or card payment per request | Bitcoin-native credit with no facilitator, unlinkable spends |
| Cashu NUT-22 blind auth | Single-use ecash tokens for access | A price, change, receipts, and theft resistance by binding each note to its request |
| Cashu NUT-24 | HTTP 402 paid with ecash | A self-issued mint, request binding and receipts; NUT-24 uses an X-Cashu header with NUT-18 payment requests and lists no implementations yet |
| Privacy Pass (RFC 9576–9578) | Unlinkable tokens from an attester | Value and change, funded by payment instead of attestation |

**Non-goals:** proving personhood; stopping well-funded attackers or volumetric floods; replacing the operator's abuse classifier; being a token or a payment network.

## Design principles

Eight principles decide every trade-off; the first is new in v0.4.

1. **Reuse before inventing.** Every object Cashu, Lightning or the IETF already defines is used verbatim. BNAP adds only the request binding, the price rules and the receipt.
2. **One small core.** Many value rails below, many carriers above, one object in the middle: the Note.
3. **End to end.** Abuse is judged by the application; BNAP only makes a price verifiable.
4. **No per-client state.** The server stores records about notes, never about people.
5. **Pay rarely, spend offline.** Money moves when credit is bought; each action is a local check.
6. **The relying party is its own issuer.** A service accepts only notes it signed, so there are no allowlists and no fake mints.
7. **Sign everything once.** Each note key signs a hash of the whole spend, outputs included.
8. **It's OK to be odd.** An unknown even extension is rejected, an unknown odd one is ignored, and clients send GREASE so the rule never rusts.

## Architecture (informative)

BNAP admits one action at one origin when the request carries unspent notes issued by that origin, worth the posted price and signed over the whole request, checked offline and without learning who paid.

> *Figure: HTTP+BNAP/LN agent flow · tier 1.* The source tab shows this as an interactive diagram (widget `node/83a7fbbc-e1ed`); it is not part of this export. See the source doc.

Only the first request touches Lightning, and only it is linkable to the payment; every later request is a local check at the gateway.

BNAP lives in the authentication slot of existing protocols, as SASL mechanisms and HTTP authentication schemes do, because it must know which request is an action and what it costs. It needs no new URI scheme and no TLS change.

| Layer | Contents | Responsible for |
| --- | --- | --- |
| Policy | Prices, abuse judgement, sessions, deposits | Everything that needs application meaning |
| Carrier | HTTP authentication scheme (first), SASL, Nostr | Putting the bytes into a protocol slot |
| **Admission** | **BNAP: Notes and three verbs** | **Proving issuer-scoped value was spent once, for this request** |
| Value | Lightning through Cashu mint quotes; Ark and Cashu tokens experimental | Moving value |
| Settlement | Bitcoin | Final settlement |

**What BNAP does not do:**

- A valid spend is necessary, not sufficient; the operator may still queue or refuse.
- It moves no money; value rails do that.
- It sets no prices; it carries the operator's quote.
- It identifies nobody and judges no abuse.
- It provides no confidentiality; TLS does.
- It does not stop volumetric floods or attackers who earn more per action than they pay.

## Notes: the Cashu profile

A Note is a Cashu proof whose secret is the hex encoding of a public key K, so only the holder of K's private key can spend it. Everything else about the Note is Cashu as the NUTs specify it.

```
k_n, r   = NUT-13 version-2 derivation (seed, full keyset ID, counter, type 0x02)
K        = x-only public key of k_n (BIP-340)
secret   = lowercase hex of K, 64 characters
Y        = hash_to_curve(UTF-8 secret)              NUT-00
B'       = Y + r·G                                   sent at purchase or as change
C'       = k_a·B' with a NUT-12 DLEQ proof           returned by the issuer
C        = C' − r·A                                  unblinded signature
Proof    = {id, amount, secret, C}                   a valid Cashu proof
witness  = BIP-340 signature by k_n over the spend Digest
```

### Cashu pieces reused verbatim

| Piece | NUT | Use in BNAP |
| --- | --- | --- |
| Blind signatures and hash\_to\_curve | 00 | Note math and test vectors |
| Keysets, version-2 IDs, final expiry, input fees | 01, 02 | Keyset identity, rotation and fees |
| DLEQ proofs with deterministic nonce | 12 | Purchase and change proofs; the deterministic nonce is a MUST in BNAP |
| Deterministic secrets | 13 | Note keys, blinding factors, recovery |
| Restore and state check | 09, 07 | Recovery and multi-device checks |
| Lightning mint quotes with signed locks | 04, 20, 23, 25 | Buying credit |
| Info endpoint | 06 | Discovery and prices |
| V4 token (cashuB) | 00 | Wallet storage format; notes are not transferable, since spending also needs K's private key |

### Rules beyond Cashu

- **Spends need the key.** A BNAP issuer MUST accept its notes only through a BNAP SPEND with a valid witness, never through a plain Cashu swap or melt, because hex(K) would otherwise read as an unlocked secret.
- **Key isolation.** BNAP keysets MUST NOT be served by a mint that allows plain swaps or melts: NUT-03 swap and NUT-05 melt are disabled for them (BNAP-W melts carry witnesses), and BNAP keys never appear in any other Cashu keyset.
- **Keyset IDs.** The wire may carry the 8-byte short ID; the Digest and all derivation use the full version-2 ID, and an ambiguous short ID is rejected.
- **Outputs.** Every B' must be a valid point other than infinity, and a B' signed before is rejected unless a retry reproduces the original response.
- **No signature aggregation.** One BIP-340 signature per K; batch verification is fine. Purchase never proves knowledge of K's private key, so a summed key could steal someone else's note.
- **Consistent keys.** Operators publish a keyset at least 30 days before issuing from it, and clients compare full key lists from a second vantage point to catch per-user tagging keys. A standby keyset is always pre-published, so a compromised keyset can be replaced at once.
- **Denominations.** Amounts are powers of two; each K is used at one origin, once.

### Recovery

A wallet holds one BIP-39 seed. Note keys and blinding factors come from NUT-13 version-2 derivation with derivation type 0x02 (to be requested from the Cashu maintainers), and the high 16 bits of the counter name a device or agent slot, so two devices never collide. A wallet restores by asking the issuer to re-sign its blinded outputs (NUT-09) and checking which notes are spent (NUT-07); because every priced spend leaves unsigned refund outputs, restore scans each device slot recorded in the backup until 3 × max\_outputs consecutive counters come back unsigned. Issuers MUST keep every signed blinded output with its signature until the keyset's final expiry, as NUT-09 requires. The wallet's list of sites is backed up encrypted, as Cashu wallets back up their mint lists.

### Suites

Inputs carry a suite tag. Suite 0 is this Cashu profile and is mandatory. Three suites are reserved, each defining its own value rules:

| Suite | Construction | Why |
| --- | --- | --- |
| 1 | RFC 9497 VOPRF with RFC 9380 hash-to-curve | A form the IETF can standardize |
| 2 | Anonymous Credit Tokens (ACT) | One credential holds a hidden balance, removing power-of-two change |
| 3 | Cashu KVAC research | Amount-hiding ecash |

## The protocol: three verbs

CHALLENGE and SPEND run on every priced action; ISSUE runs rarely and is Cashu's mint flow.

### Encoding

Objects travel as CBOR, the encoding of Cashu's V4 tokens, and as base64url on text carriers. The bytes that get signed are a deterministic binary SigningBody built from those objects: big-endian integers, BigSize lengths and counts, and TLV streams in strictly ascending type order with no duplicates (Lightning BOLT 1). Hashes are BIP-340 tagged hashes: H\_tag(x) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ x).

### CHALLENGE (server to client)

A challenge is a TLV stream that the server MACs, so it keeps no state between CHALLENGE and SPEND.

| Type | Field | Meaning |
| --- | --- | --- |
| 0 | `version` | Protocol version, 1 |
| 2 | `scope` | 32-byte hash of the action; each carrier defines it to cover the action's content and its recipient |
| 4 | `amount` | The price, in the keyset unit |
| 6 | `unit` | Unit string, normally `sat` |
| 8 | `keysets` | Accepted keyset IDs |
| 10 | `expires` | Unix time after which the quote lapses |
| 12 | `info` | URI of the issuer's info endpoint |
| 14 | `op_key_id` | Which operator key signs acknowledgements |
| 16 | `nonce` | 16 random bytes |
| 18 | `mac` | Server MAC over every other record |
| 20 | `issued_at` | Self-issued challenges only: creation time |
| 22 | `fund_quote` | Optional: a NUT-23 mint quote id the client asked for |

**Self-issued challenges.** Carriers without a round trip, such as Nostr events, let a client build a challenge itself with `version`, `scope`, `amount`, `unit`, `keysets`, its own `nonce` and `issued_at`, and no `mac`, where the manifest allows it. The operator accepts it if `amount` is at least its published price and the age is within that carrier's `max_age_s`.

### SPEND (client to server)

```
SPEND          = {v, challenge, binding, inputs, outputs, refund_outputs, fund?, ext}   (CBOR)
input          = {suite, s_id, amount, secret, C, witness}   a Note with its witness
output         = {s_id, amount, B'}                          a Cashu blinded message
fund           = {quote, signature}                          a paid NUT-23 quote
s_id           = first 8 bytes of the version-2 keyset ID, as in Cashu V4 tokens

Digest         = H_"bnap/spend"(SigningBody)                 byte layout below
witness        = BIP-340 signature by each K over Digest
fund.signature = BIP-340 signature over Digest by the quote's NUT-20 key (a BNAP use of that key)

Response       = {status, replayed, signatures, ack}
status         = OK or FAILED; replayed = true when answering a retry
signatures     = C' and NUT-12 DLEQ proof for each signed output, in order
ack            = BIP-340 signature by the operator key over
                 H_"bnap/ack"(Digest ‖ status ‖ amount ‖ signatures)
```

| SigningBody field | Bytes |
| --- | --- |
| version | 1 |
| challenge | BigSize length, then the challenge TLV bytes as received |
| binding | BigSize length (0 or 32), then the bytes |
| inputs | BigSize count; per input: suite (1) ‖ full keyset ID (33) ‖ amount (8, big-endian) ‖ K (32) ‖ C (33, compressed); sorted by K |
| outputs | BigSize count; per output: full keyset ID (33) ‖ amount (8) ‖ B' (33); in client order |
| refund\_outputs | Same layout as outputs |
| fund | BigSize length, then the UTF-8 quote id; length 0 when absent |
| ext | TLV stream built from the `ext` map, in ascending type order |

**Amount rule.** Inputs + paid quote − input fees − outputs = amount, exactly. Input fees follow the keysets' `input_fee_ppk` (NUT-02); a fund quote pays no input fee. Whenever amount > 0, `refund_outputs` MUST be present and sum to exactly amount, so its presence never fingerprints a wallet. A SPEND MUST contain at least one input or a fund, and `max_outputs` counts outputs and refund outputs together.

The server checks a SPEND cheapest first:

1. **Parse.** Version, total size, `max_inputs` and `max_outputs`; at least one input or a fund.
2. **Replay lookup.** If every input's Y, and the quote if any, is recorded with this Digest's tag and the record is inside the manifest's `replay_window_s`: re-verify every witness over the full Digest, then answer with the recorded status and `replayed = true`, or with `PENDING` if the action is still running. The carrier MUST NOT perform the action again. Replays are rate-limited per client network. If any Y is recorded with a different tag, or the window has passed, fail with `SPENT`.
3. **Challenge.** The MAC is valid and unexpired, or the self-issued fields are acceptable; the scope and the binding match this request.
4. **Keysets and outputs.** Every keyset is known, inside its final expiry and in the challenge's unit; every amount exists in its keyset; no K or B' repeats; no B' was signed before (`OUTPUT_REUSED`). Outputs and refund outputs use keysets that are still issuing.
5. **Amount.** The amount rule holds, with checked arithmetic.
6. **Signatures.** Every Note satisfies C = k·hash\_to\_curve(secret); every witness covers the Digest; a fund quote is paid, not yet issued, and its key signed the Digest.
7. **Commit.** In one atomic step, record every Y and the quote with the Digest tag and status PENDING, and mark the quote ISSUED so NUT-04 refuses it. Then run the action.

**Outcomes.**

- **OK:** the server moves PENDING to OK and signs `outputs`, the change.
- **FAILED:** the action failed after commit because of a server-side fault. The server moves PENDING to FAILED and signs `outputs` and `refund_outputs`, returning inputs + quote − fees in full. Servers MUST fully validate an action before commit, so FAILED is reserved for their own faults.
- **Errors before commit** spend nothing, as in Cashu NUT-22.

The status changes exactly once, from PENDING to OK or FAILED, so a replay can never flip the outcome. Signing is deterministic: BNAP makes NUT-12's deterministic DLEQ nonce a MUST, and BIP-340 signatures use zero auxiliary randomness, so replies are recomputed instead of stored. The ack is the receipt: one 64-byte operator signature over what was paid, for which action, and what came back. Binding is empty, or the RFC 9266 `tls-exporter` value; agents and native clients MUST bind, while browsers cannot.

**Linkability.** A SPEND that carries `fund` links this one action to the Lightning payment; every note issued as change is unlinkable. Wallets that need full unlinkability buy credit in a separate ISSUE first.

### ISSUE, swap and restore

- **ISSUE** is Cashu's mint flow: a NUT-23 BOLT11 quote locked to a client key (NUT-20), paid, then minted with NUT-04; BOLT12 through NUT-25 is optional. A paid quote can instead be redeemed inside a SPEND as `fund`; the commit marks it ISSUED, and NUT-04 refuses it afterwards. If that SPEND fails before commit, the quote stays mintable through NUT-04.
- **Swap.** Re-denominating notes is a SPEND with amount 0 sent to the info endpoint's swap URL, with scope = H\_"bnap/scope/swap"(origin). A plain Cashu swap is never accepted, because spends need witnesses.
- **Restore** uses NUT-09, and **state checks** use NUT-07, both keyed by Y.

### Errors

| Code | Meaning | Client action |
| --- | --- | --- |
| `VERSION` | Unsupported version | Use one from the manifest |
| `MALFORMED` | Bad encoding, an unknown even TLV, or no input and no fund | Fix and resend |
| `TOO_LARGE` | Over a size, input or output limit | Swap into fewer notes first |
| `UNKNOWN_KEYSET` | Keyset unknown, expired or revoked | Refresh keysets, swap notes |
| `UNIT_MISMATCH` | A note or output is in another unit | Use the challenge's unit |
| `BAD_CHALLENGE` | MAC invalid, or self-issued not allowed | Get a challenge from the server |
| `STALE` | Challenge expired or too old | Get a new challenge |
| `WRONG_SCOPE` | Challenge or binding is for another action | Get the right challenge |
| `WRONG_AMOUNT` | The amount rule fails | Fix change or refund outputs |
| `BAD_SIGNATURE` | A note, witness or quote signature failed | Drop the bad input |
| `OUTPUT_REUSED` | A blinded output was signed before | Derive fresh outputs |
| `SPENT` | A note was spent in another SPEND, or the replay window passed | Drop that note, resend the rest |
| `QUOTE_UNPAID` | The fund quote is not paid, or already issued | Pay it, or drop it |
| `PENDING` | The original spend is still running | Retry after Retry-After |
| `RATE_LIMITED` | Too many replays or open quotes | Retry later |

Error responses SHOULD carry an operator signature over the Digest and the code.

### Discovery

The issuer's Cashu info endpoint (NUT-06) carries a `bnap` section, and `/.well-known/bnap` points to it. Keysets come from the standard Cashu keyset endpoints.

```json
"bnap": {
  "versions": [1],
  "prices": { "table_version": 7,
              "POST /v1/chat": { "sat": 21, "ref": "EUR 0.012" },
              "POST /v1/search": { "sat": 4 } },
  "limits": { "max_inputs": 16, "max_outputs": 16, "max_bytes": 5000 },
  "max_fund": 10000,
  "replay_window_s": 86400,
  "op_keys": { "k1": "02ab…" },
  "self_issued": { "allowed": false },
  "swap": "/v1/bnap/swap",
  "withdrawal": false
}
```

A 5,000-byte SPEND is about 6.7 KB in base64url, under common 8 KB header limits.

### State and storage

BNAP keeps no per-client state. For each spent note the server stores a 16-byte prefix of Y with a 16-byte Digest tag and a status byte, and the same for redeemed quotes. As NUT-09 requires, it also stores every signed blinded output with its signature, which enforces the no-reuse rule as well. A typical spend with two change outputs takes about 300 bytes on disk.

| Deployment | Spends per year | Storage per year |
| --- | --- | --- |
| Mid-size API, 20,000 spends a day | 7.3 million | about 2.2 GB |
| Large service, 5 million spends a day | 1.8 billion | about 550 GB |

Keysets issue for about 3 months and expire about 15 months after they start, so storage is bounded by spend rate times 15 months. A spend record is deleted when its keyset expires, and an expired keyset is never accepted again. If the spend store is lost, notes spent since the last durable copy can be spent again until expiry; without withdrawal that costs only free actions, never bitcoin. The issuer key lives in a separate signer process, derived from a cold seed, and a standby keyset is always pre-published so a compromised keyset can be revoked and replaced at once.

### Extensibility

The TLV stream at the end of a SPEND carries extensions. An unknown even type is rejected with `MALFORMED`; an unknown odd type is ignored. Clients SHOULD send one GREASE record per SPEND, a random type from the reserved odd range with a 4-byte random value; servers MUST ignore it and MUST NOT require it. The version, suite and TLV registries each reserve GREASE values.

## HTTP binding and the agent profile

The first deployment is AI agents and paid APIs: a gateway in front of an API, and a client any agent can call. One 402 response offers BNAP next to per-action Lightning schemes, so agents with no BNAP code can still pay.

```http
POST /v1/chat HTTP/1.1
Host: api.example
Content-Digest: sha-256=:X48E9q…:
BNAP-Fund: amount=2100, pubkey=02c4…

HTTP/1.1 402 Payment Required
WWW-Authenticate: BNAP challenge="<base64url TLV>", amount="21", unit="sat",
    fund-quote="<base64url NUT-23 quote>", info="/v1/info"
WWW-Authenticate: L402 macaroon="…", invoice="lnbc210n1…"
WWW-Authenticate: Payment id="…", method="lightning", intent="charge", request="…"

(the agent checks the quote's key and amount, saves it, then pays through NWC)

POST /v1/chat HTTP/1.1
Host: api.example
Content-Digest: sha-256=:X48E9q…:
Authorization: BNAP <base64url SPEND with fund, outputs, refund_outputs>

HTTP/1.1 200 OK
Authentication-Info: bnap="<base64url Response>"
```

### Rules

- **Scope.** scope = H\_"bnap/scope/http"(method ‖ 0x00 ‖ absolute URI normalized per RFC 3986 ‖ 0x00 ‖ the raw 32-byte SHA-256 digest from Content-Digest, empty when there is no body). A spend therefore names its origin and its exact content.
- **Funding is opt-in and capped.** The server embeds a NUT-23 quote only when the request carries `BNAP-Fund` with an amount and a client key, never above the manifest's `max_fund`, and rate-limits open quotes per client network. A scraper gets a challenge, never an invoice.
- **Zero-code agents.** An HTTP+BNAP server SHOULD also offer an L402 challenge or an MPP Lightning `charge` challenge for one action at the same price. The macaroon or MPP request MUST carry the scope hash, payment hashes are kept in their own namespace until the invoice expires, and a request carrying more than one payment scheme is rejected. Unlike common L402 use, these tokens admit exactly one action.
- **Credentials.** The SPEND rides as token68 after `BNAP`. If `Authorization` already carries application auth, the client sends `BNAP-Authorization` instead. `amount`, `unit` and `info` in the challenge are readable copies that MUST match the encoded challenge.
- **Status codes.** OK returns the action's own status. FAILED returns 502 with all signatures in `Authentication-Info`. PENDING returns 409 with `Retry-After`. A replay returns the stored action result if the gateway cached it, which it SHOULD for the replay window; otherwise 200 with an empty body and `Authentication-Info`.
- **Errors** come back as 402 with `BNAP-Error` and a fresh challenge.
- **Sessions** are ordinary cookies a server MAY set after a successful SPEND.
- **Binding.** Agents and native clients MUST bind to the TLS exporter; browsers cannot and send an empty binding.

### Agent tiers

| Tier | The agent has | How it pays | What links to the payment |
| --- | --- | --- | --- |
| 0 | Any L402 or MPP client, such as lnget | Lightning per action | Every action |
| 1 | The `bnap` CLI or MCP server and an NWC wallet connection | Funds once inside the 402, then spends notes offline | Only the first action |
| 2 | A full wallet with its own seed | Buys credit in a separate ISSUE, then spends notes | Nothing |

**Agent wallets MUST:**

- enforce spending caps per origin and per task in code, not in the model's prompt;
- use a fresh key per quote, check that the quote's key and invoice amount match what they sent, and never pay more than their `BNAP-Fund` amount;
- save the quote and its key before paying, so a failed SPEND can still mint the paid quote through NUT-04;
- keep per-site balances small (default cap 5,000 sat), because credit is the operator's IOU.

**Tools.** `bnap get <url>` works like curl: it answers 402s, funds over NWC within budget, spends notes and retries. The MCP server exposes `fetch_with_bnap` and `budget` to any agent framework.

## Value layer: buying credit

Buying credit is Cashu's Lightning mint flow, used verbatim; BNAP defines no payment protocol of its own.

1. **Quote.** The client asks for a NUT-23 quote locked to its key (NUT-20), or receives one inside a 402.
2. **Pay.** Any Lightning wallet pays the BOLT11 invoice, including Cashu, Ark, Spark and Fedimint wallets, which can all pay BOLT11.
3. **Mint.** The client mints notes with NUT-04, or redeems the paid quote inside its next SPEND as `fund`.

BOLT11 is mandatory because the issuer is always online and every payer stack accepts it, including NWC, lnget, MPP and Cashu melt. BOLT12 through NUT-25 is optional, because not every Lightning implementation supports offers natively yet.

### Operator receive backends

The wire fixes only BOLT11; the backend is the operator's choice. Caparra defines one interface, `InvoiceSource { create, status }`.

| Backend | Custody | Effort | Fit |
| --- | --- | --- | --- |
| Receive-only NWC connection (Alby Hub or any NWC wallet) | Depends on the wallet | Paste one connection string | Caparra default; it can never be drained |
| LDK Node with an LSP | Self-custodial | Run a node library | The sovereign tier |
| Phoenixd | Self-custodial | One daemon; liquidity fees on the first receives | Small operators |
| Custodial API | Custodial | Easiest | Brings KYC |

**Other value-in types.** Ark VTXOs (bark has been on mainnet since June 2026) and Cashu tokens from operator-listed mints are experimental. Hashcash is dropped: proof-of-work favours attackers with GPUs.

**Units.** Notes are in sat. Prices may carry a fiat reference that the operator re-converts at each price-table version; the challenge amount is always in sat. The smallest top-up is max(4 × price, 21 sat), because routing a few hundred sats costs almost nothing while the operator's inbound liquidity is the real cost.

## Withdrawal extension (BNAP-W)

Withdrawal is optional and off by default. Without it, a stolen issuer key or a lost spend store yields only free actions, never bitcoin; with it, both become theft. An operator that enables BNAP-W MUST:

- write spend records synchronously to durable, replicated storage before answering;
- cap withdrawals per epoch and per request;
- pay out through a melt (NUT-05) that carries BNAP witnesses, to a Lightning invoice;
- keep the issuer key in a separate signer process.

Paying out to arbitrary invoices moves an operator from merchant toward money transmitter, so BNAP-W needs legal review in each jurisdiction.

**Without BNAP-W,** wallets cap each site's balance, and operators announce shutdown or keyset retirement at least 30 days ahead through the keyset's final expiry. Refunds at shutdown are a consumer-law matter outside the protocol.

## Security and privacy considerations

Each threat found across three debate rounds and two reviews maps to one rule above; what remains is economic, legal or accepted on purpose.

| Threat | Closed by |
| --- | --- |
| Double spend | Each Y recorded atomically before the action runs |
| One payment replayed for many actions | A known Digest returns the recorded status; the action never runs again |
| Replays as denial of service | A replay window, rate limits, and at least one input or fund per SPEND |
| A spend reused with another body or at another origin | The scope covers content and origin; the Digest covers the scope |
| Note theft from logs, proxies or CDNs | A witness by K is required |
| Change or refund theft by a proxy | The Digest covers outputs, refund outputs and the quote |
| A fund quote redeemed twice | The commit marks it ISSUED; NUT-04 refuses it afterwards |
| A quote swapped by a proxy | Wallets check the quote's key and amount before paying |
| Forged replay through a tag collision | 16-byte tags, and full re-verification before any replay |
| One payment admitting two actions across schemes | Scope inside the macaroon or MPP request; one scheme per request |
| Theft with a summed key | One signature per K, no aggregation |
| Redeeming a note through a plain Cashu swap | Swap and melt disabled for BNAP keysets |
| Paying a cheap challenge for a costly action | Scope inside the challenge MAC |
| Mixed units or overflow | One unit per spend, checked arithmetic |
| Bloating the store with free swaps | Per-keyset input fees |
| Admission minted by someone else | The operator accepts only its own keysets |
| Issuer linking a spend to a purchase | Blinding; DLEQ proofs are never presented |
| Per-user tagging keys | Keysets published 30 days ahead and cross-checked |
| Wallet fingerprinting | Powers of two and mandatory refund outputs |
| Lost device | Seed recovery through NUT-13, NUT-09 and NUT-07 |
| Invoice-minting denial of service | Funding only on `BNAP-Fund`, capped and rate-limited |
| Ossification | Even/odd TLV rule and GREASE |

**Accepted residual risks:**

- **Linkable first action.** A SPEND carrying `fund`, and every tier-0 Lightning payment, is linkable to its payment.
- **Small operators** can still link visitors by IP address, TLS fingerprint and timing; BNAP promises unlinkable notes, not anonymity.
- **Operator credit.** An operator that disappears takes unspent credit with it; wallets keep balances small.
- **Store loss.** Without BNAP-W, notes spent since the last durable copy can be spent again until keyset expiry, costing free actions only.
- **Key compromise.** A stolen issuer key forges notes, so the keyset is revoked and replaced at once; keys live in a separate signer process.
- **Suite 0 is not post-quantum** for forgery; blinding keeps past spends private.
- **Unflagged abuse** pays only the price; BNAP-B adds deposits where an operator can detect abuse.
- **Regulation.** Non-withdrawable prepaid credit for one's own service reads closer to a merchant voucher than to custody; BNAP-W changes that. Both readings need EU counsel.

## Extensions and roadmap

The core is Suite 0 notes, three verbs and the HTTP binding; everything else is a separate, optional document.

| Document | What it adds | Status |
| --- | --- | --- |
| BNAP core | Suite 0 notes, CHALLENGE, SPEND, refund outputs | Mandatory |
| HTTP binding and agent profile | 402 challenge, content-covering scope, `BNAP-Fund` | Mandatory for HTTP servers |
| Buying credit | Cashu NUT-23, NUT-04 and NUT-20, referenced verbatim | Mandatory for issuers |
| L402 and MPP fallback | Per-action Lightning for zero-code agents | Recommended for HTTP |
| BNAP-W | Withdrawal | Optional, off by default |
| BNAP-B | Deposits with release or forfeit, forfeit log, claim rates | Experimental |
| Nostr NIP | Priced relay writes with self-issued challenges | Second deployment |
| SASL+BNAP, ESMTP | Mail, chat and MQTT carriers | Optional |
| Ark and Cashu-token value-in | Funding without Lightning | Experimental |
| Suites 1 to 3 | VOPRF, ACT, KVAC | Reserved |
| x402 scheme | Interop with x402 clients | Optional |
| Pricing and wallet guidance | Load-based prices, ceilings, budgets | Informational |
| TLS/QUIC admission | Pricing handshake floods | Deferred |
| Hashcash, ack-refund, sessions, linkable mode | — | Removed |

## Reference implementation: Caparra

Caparra is built on CDK, the Cashu Development Kit, so the cryptography, keysets and mint flows are existing, reviewed code; Caparra adds only the BNAP profile and the agent tooling.

| Crate | Responsibility |
| --- | --- |
| `bnap` | Profile types: SigningBody, Digest, witnesses, challenge TLVs, scope functions, test vectors |
| `caparra-issuer` | A CDK mint configured as a BNAP issuer: spend store, deterministic replies, separate signer process |
| `caparra-gate` | Reverse proxy and Tower middleware for paid APIs; emits BNAP, L402 and MPP challenges |
| `caparra-wallet` | Agent wallet with seed recovery, budgets and NWC funding; the `bnap` CLI and MCP server |
| `caparra-ln` | The `InvoiceSource` interface; receive-only NWC by default, LDK Node optional |
| `caparra-w`, `caparra-nostr`, … | One crate per extension |

**Build order:** `bnap` with test vectors, then `caparra-issuer`, then `caparra-gate` in front of one real paid API, then the CLI and MCP server, then the NUT pull requests, then the Nostr plugin.

**Targets to measure:** p95 verification under 2 ms per spend at the default limits, excluding the durable commit, and about 300 bytes of storage per spend.

## Standardization and adoption

No part of BNAP is a BIP or a bLIP: nothing touches Bitcoin consensus or the Lightning protocol. It ships as Cashu NUTs first, with running code, and goes to the IETF only after two independent implementations.

| Order | Document | Venue |
| --- | --- | --- |
| 1 | NUT-XX "Key-secret proofs with context signatures" (\~3 pages): secret = hex(K), witness over a tagged Digest, the new NUT-13 derivation type | Cashu NUTs; pitched as making NUT-22 blind-auth tokens theft-proof |
| 2 | NUT-XX "HTTP 402 with a self-issued mint", extending NUT-24 and aligned with its X-Cashu header and NUT-18 payment requests: scope, spend, refund outputs, ack, funding in the 402 | Cashu NUTs |
| 3 | Agent interop note: BNAP, L402 and MPP in one 402 | Agent tooling communities |
| 4 | NIP-XX "Priced relay writes" | Nostr NIPs |
| 5 | Internet-Draft with Suite 1, after two implementations | IETF Privacy Pass or HTTP authentication |

**Socialize in this order:** the Cashu developer chat and call with a CDK branch and cashu-ts test vectors; the NUT pull requests; a Delving Bitcoin post asking for a privacy critique of request-bound blind spends; agent tooling builders; the IETF last.

**Minimum lovable deployment.** `caparra-gate` in front of one real paid API, such as a search or inference endpoint, with the `bnap` CLI and MCP server so agents fund over NWC.

| After 90 days, it worked if | Target |
| --- | --- |
| Operators other than the author | At least one |
| Funded agents that top up a second time | At least 30% |
| Abusive free-tier traffic | Down at least 80%, without losing paying users |
| p95 verification time | Under 2 ms |
| Independent implementations passing the test vectors | At least one, not in Rust |

**Allies:** CDK and Nutshell maintainers, Alby (NWC), OpenSats for grants, and agent-tooling builders. Lightning Labs and the x402 camp are bridge partners, not targets.

**Licensing and governance.** Code is MIT/Apache-2.0; NUT text follows the Cashu repository. A single maintainer runs public proposals until two independent implementations exist; no maintainer ever holds funds or runs a default issuer.

## Appendix A: Rationale (informative)

BNAP is shaped like the protocols that lasted: one small object in the middle, many things below and above it. This appendix explains the shape; it makes no claim that BNAP has earned the comparison, which only deployments can do.

> *Figure: The BNAP hourglass · informative.* The source tab shows this as an interactive diagram (widget `node/dd7aab73-de90`); it is not part of this export. See the source doc.

Money crosses the waist only through ISSUE, rarely; every priced action crosses it through SPEND, with no payment.

- **Narrow waist.** IP succeeded because it assumes almost nothing, so anything can carry it and anything can run on it. BNAP's waist is the Note: value rails below, carriers above.
- **Pay rarely, check cheaply.** TLS separates an expensive handshake from a cheap record layer. BNAP separates buying credit on a value rail from spending it with a local check.
- **Protocol and implementation.** HTTP is a protocol; Apache is one program that speaks it. BNAP is the protocol; Caparra is one implementation, and others must be able to replace it.
- **End to end.** Saltzer, Reed and Clark (1984) argued that functions needing application knowledge belong at the ends. Judging abuse is such a function, so BNAP leaves it to the application.

## Appendix B: Debate record

### Round 3, 10 October: Bitcoin development state of the art

An ecash cryptographer, an anonymous-credentials expert, a Lightning engineer and a Bitcoin protocol reviewer each reviewed v0.3, then answered each other's strongest points. Where they still disagreed, the owner decided.

| Question | Positions | Verdict |
| --- | --- | --- |
| Note secret | Raw K bytes (v0.3) or hex(K) as a Cashu secret | hex(K), with a key-isolation rule |
| Keyset ID | Custom 8 bytes or Cashu version-2 | Version-2, short ID allowed on the wire |
| Recovery | None (v0.3) or NUT-13 | NUT-13 seed recovery; rated critical |
| Wire format | Custom binary or Cashu CBOR | CBOR objects; binary only for the signed bytes |
| Refund after failure | ack-refund, delete it, or check the database | Client-supplied refund outputs, signed only on FAILED |
| Replay storage | Full responses or recomputation | Recompute; 16-byte tags; re-verify first |
| First funding | Four steps, fund token in the 402, or a NUT-23 quote in the 402 | NUT-23 quote, embedded on opt-in |
| Zero-code agents | Bridge extension or a SHOULD in core | SHOULD offer L402 or MPP |
| Credential type | ACT by default, or notes | Notes mandatory; ACT a reserved suite |
| Mandatory rail | BOLT11 or BOLT12 | BOLT11; BOLT12 optional |
| Fees | None or `input_fee_ppk` | Per-keyset input fees |
| Hashcash | Keep or drop | Dropped |
| Withdrawal | Experts: never in v1 | Owner: optional BNAP-W, off by default |
| Framing | Experts: drop "foundational" | Owner: layered spec, modest framing, rationale in Appendix A |
| First deployment | Experts: a Nostr relay | Owner: AI agents and paid APIs; Nostr second |

### Earlier rounds

- **Round 1, 9 October:** the operator issues its own notes, so no global mint allowlist exists; per-action prices beat refundable bonds; application carriers come before transport.
- **Round 2, 10 October:** one primitive and three verbs; the spend signature covers the whole message; bonds, the forfeit log and the TLS binding leave the core.
- **Independent reviews** of v0.1 and v0.3 found eight blockers between them, all fixed, including the DLEQ linking leak, bearer session ids and replayable retries.

**Independent review of the first v0.4 draft** found three blockers: the commit order contradicted the FAILED status, a paid fund quote could be redeemed twice, and the signed bytes were not defined to the byte. It also found eight major gaps, including a spend store that Cashu restore could not use, a MAC that missed two fields, uncapped funding, ambiguous L402 single use, restore gaps, a key-rotation contradiction, unbounded replays and HTTP header limits. All are fixed in this version through the PENDING state, the ISSUED quote rule, the SigningBody table and the rules around them.

## Open questions

Most open items now need running code or other people, not more design.

- [ ] **First API.** Pick the real paid API that `caparra-gate` fronts first.
- [ ] **Cashu maintainers.** Request NUT numbers and NUT-13 derivation type 0x02; agree how BNAP aligns with NUT-24.
- [ ] **Header syntax.** Check the L402 and MPP Lightning challenge formats against their current specs before shipping the fallback.
- [ ] **EU legal reading** of non-withdrawable credit, and of BNAP-W.
- [ ] **Suite 1.** Confirm the RFC 9380 secp256k1 hash-to-curve suite for the IETF track.
- [ ] **ACT.** Measure verification at a 24-bit range and watch CFRG adoption before promoting Suite 2.
- [ ] **Wallet partners** for NWC funding, such as Alby.
- [ ] **Name checks:** IANA service names, the `caparra` crate, EU trademarks.
- [ ] **Test vectors and benchmarks** for every encoding, against the 2 ms target.

### Sources

Opened during round 3:

- [Cashu NUTs index](https://github.com/cashubtc/nuts) and NUT-00, 02, 11, 12, 13, 19, 22, 24, 28, 29
- [Keyset ID collision write-up, March 2026](https://uncensoredtech.substack.com/p/two-birds-one-stone)
- [cashu-kvac](https://github.com/lollerfirst/cashu-kvac) and [OpenSats on ecash research](https://opensats.org/blog/advancements-in-ecash)
- [Multi-verifier KVAC, ePrint 2025/2156](https://eprint.iacr.org/2025/2156)
- [draft-schlesinger-privacypass-act-01](https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01) and [draft-schlesinger-cfrg-act-01](https://www.ietf.org/ietf-ftp/internet-drafts/draft-schlesinger-cfrg-act-01.txt)
- [draft-ietf-privacypass-arc-crypto-01](https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-arc-crypto-01)
- [Lightning Labs: agent tools and lnget](https://lightning.engineering/posts/2026-02-11-ln-agent-tools/)
- [MPP reference](https://mpp.dev/llms-full.txt)
- [Second launches bark on mainnet](https://bitcoinmagazine.com/news/second-launches-bark-on-bitcoin-mainnet)
- [Block adds Lightning to x402](https://crypto.news/block-joins-x402-with-lightning-support/)
- [bLIP-26: L402](https://github.com/lightning/blips/blob/master/blip-0026.md)
- [BOLT12 adoption](https://www.spark.money/research/lightning-bolt12-adoption-progress) and [Lightning in 2026](https://www.spark.money/research/lightning-network-2026-state), both published by Spark, a competing protocol

Sources for rounds 1 and 2 are listed in the archive tabs.

<!--
  Source doc: WJztndZC9mY1jogSMesi8n (Claude Docs)
  Tab: "BNAP v0.5 (current)" (tab 046fe68a-f2db, body node b931f496-4f7c)
  Doc rev exported: 33
  Export date: 2026-10-13
  Spec text licensed CC-BY-4.0, (c) BNAP contributors
  Transcribed verbatim to GitHub-flavoured Markdown from the doc's own markdown export.
  Chips: the date chip is a plain date, the mention is "Dominic".
-->

# BNAP: a universal plug for priced and permissioned actions — Draft Specification v0.5.1

2026-10-11 · Dominic

## Abstract and status

BNAP is a universal plug for priced and permissioned actions: a small socket every deployment shares, and plug points for everything else. A service can accept any credential scheme, take payment over any rail, speak any carrier, choose its own pricing, storage and key custody, and serve agents built on any model or framework; BNAP does not choose for it. Whatever is plugged in, the socket guarantees four things: an offer the server signed, a credential bound to one offer and, where the scheme allows, one request, an outcome recorded once, and a uniform signed receipt.

**Terminology.** BNAP ("bee-nap", Blind-Note Admission Protocol) names the protocol; blind notes are its default scheme, not its only one. Caparra is the Rust reference implementation.

| Term | Meaning |
| --- | --- |
| Socket | The rules every deployment shares |
| Plug | Any swappable block: a scheme, rail, carrier, store, signer, pricer, wallet or agent adapter |
| Scheme | A way to prove payment or a property, such as blind notes, L402, x402 or Privacy Pass |
| Badge | A label for plug mixes guaranteed to interoperate, such as Core-1 |
| HTTP+BNAP/LN | BNAP carried in HTTP, funded over Lightning |

**Status.** Pre-draft, version 0.5.1. A fourth design round set a plug architect against a flexibility skeptic and tested the result against the systems in the plug catalogue. An independent review of v0.5 then found four blockers, all fixed in this revision: one payment could be redeemed through several schemes, the Context was circular for artifacts the server makes, payments through native headers bypassed the socket, and the plugin-safety claim was overstated. The v0.4 Cashu profile is now the `bnap:notes` scheme, specified in the second tab. Key words follow BCP 14.

| Owner decision | Choice |
| --- | --- |
| Architecture | A universal plug: one socket, plugs for everything else |
| Baseline | A badge, not a gate: any mix that keeps the socket rules is BNAP; Core-1 labels the mix guaranteed to interoperate |
| Non-Bitcoin rails | Pluggable with guardrails: off by default, own unit, held until final |
| Name | Blind-Note Admission Protocol; blind notes are the default scheme |
| Earlier decisions kept | Modest framing; withdrawal is the optional BNAP-W; first deployment AI agents and paid APIs |
| Next step (11 October) | Draft the core socket spec with exact byte layouts and test vectors (third tab) |
| First gateway | An LLM inference proxy: per-call, metered pricing in front of an OpenAI-compatible endpoint |
| Agent-1 | No x402 on Lightning until its spec is published |

**What v0.5 changed.**

- The core is no longer a Cashu profile but a scheme-agnostic socket; the profile is now one scheme, `bnap:notes`, the recommended default.
- Fourteen plug points cover every block, from credential schemes to AI-agent adapters.
- L402, MPP, x402, Privacy Pass, Web Bot Auth, OAuth and more plug in as peer schemes or attestations; all but two of the systems tested fit, most through adapters that follow conventions already allowed by the native spec.
- The server signs its offer set, so no proxy can strip a strong scheme from a BNAP offer, and clients that have seen the manifest refuse to fall back to native headers.
- Route policies check scheme properties from a registry, not brand names, so a weak scheme can never silently satisfy a strong requirement.
- One payment admits one action, whichever schemes share it: the socket commits each payment's rail ID alongside the scheme's use IDs.
- Plugs never hold keys or write the use store. A hostile scheme can wrongly admit actions only on routes that enable it; it cannot touch other schemes' uses, keys or receipts.

## Why BNAP exists

Agents, scrapers and spammers act at machine speed, and putting a price or a permission on each action stops the actions that are only worth doing for free:

```latex
p > v_{action}
```

Many schemes now solve part of this: L402, x402, MPP, Cashu, Privacy Pass, Web Bot Auth, API keys. Each has its own headers, replay rules, receipts and wallets, so an operator who wants several must build and secure each one, and an agent must speak them all.

BNAP is the socket they share. It replaces none of them and adds four guarantees on top: signed offers, request binding, once-only outcomes and a uniform receipt. Its default scheme, blind notes, adds what none of the others offer together: prepaid credit, spent offline, unlinkable to the payment that funded it.

**Non-goals:** proving personhood (attestation schemes may do that), stopping well-funded attackers or volumetric floods, replacing the operator's abuse classifier, and being a token or payment network.

## Design principles

- **Plug anything, check everything.** Plugs propose; the socket decides.
- **Properties, not brands.** A route requires properties such as single-use, request-bound or unlinkable; any scheme with those properties qualifies.
- **Label, don't gate.** Any mix of plugs that keeps the socket rules is BNAP; badges say which mixes are guaranteed to interoperate.
- **Reuse existing names.** Schemes keep their native identifiers and wire formats; BNAP wraps them, never renames them.
- **Contain plugs, trust few.** The socket alone computes digests, prefixes and commits use IDs and rail IDs, checks value against price and builds every message the signer signs. Only the store, the signer and the rails are trusted, and the operator supplies them.
- **The model never chooses.** No language model picks a scheme, sets a cap or holds a key; spending policy lives in code.
- **End to end.** Abuse is judged by the application; BNAP only makes prices and permissions verifiable.
- **No per-client state.** The server stores records about credentials, never about people.
- **It's OK to be odd.** Unknown even extensions are rejected, unknown odd ones ignored, and GREASE keeps the rule alive.

## Architecture: one socket, fourteen plugs

The socket is the only part every deployment shares; every other block is a plug the operator or the client chooses.

> *Figure: The universal plug · one socket, fourteen plug points.* The source tab shows this as an interactive diagram (widget `node/aeebbc11-bb14`); it is not part of this export. See the source doc.

Plugs propose and the socket decides: schemes plug in from the registry, carriers carry the result, and client and server plugs supply everything else.

| Plug | Side | What it does | On the wire | Examples |
| --- | --- | --- | --- | --- |
| Credential scheme | Both | Proves value, yields use IDs, settles change or refunds | Yes | `bnap:notes`, L402, MPP Lightning, x402, ACT, Cashu NUT-24 |
| Attestation scheme | Both | Proves a property that waives, discounts or meters a price | Yes | Privacy Pass, ARC, Web Bot Auth, OAuth with DPoP, NIP-98, World ID |
| Funding rail | Server | Creates payment requests and reports their status. Operator-trusted | Partly | Phoenixd, LDK Node, NWC, LND, CLN, Ark, Fedimint, Spark, Cashu mints, x402 facilitators, Stripe or Tempo |
| Verifier | Server | Checks a credential locally or through a facilitator, in two phases: verify, then settle | No | Local, x402 facilitator, MPP processor |
| Carrier | Both | Defines the scope and carries offers, credentials and receipts | Yes | HTTP, MCP, SASL, Nostr, gRPC, WebSocket, A2A |
| Pricer | Server | Maps an action to a price | Price only | Static table, load-based, per-token metering, fiat-reference feed |
| Judge | Server | Admits, queues or refuses before commit; hooks for abuse after | No | Rules, WASM policy, classifier sidecar |
| Use store | Server | Atomic records for single-use, rate-limited and reusable credentials and for rail payments. Operator-trusted | No | Postgres, SQLite, FoundationDB, Redis with append-only log |
| Signer | Server | Signs only messages the socket built, and blind signatures up to the change cap the socket set; keys stay in its process. Operator-trusted | Key IDs only | File, separate process, HSM, seed wrapped at rest by a KMS, threshold signer |
| Front | Server | Puts the gate in front of an existing API | No | Tower layer, standalone proxy, Envoy ext\_authz, Caddy forward\_auth, nginx auth\_request |
| Pay source | Client | Pays a payment request | No | NWC, LDK, lnget, Cashu, Ark, Spark or Fedimint wallets, custodial APIs, cards via MPP |
| Spend policy | Client | Caps, allowed schemes, required properties | No | Budget files, NWC budgets, AP2 mandates |
| Wallet | Client | Picks an offer and builds the credential | No | Notes wallet, L402 client, x402 signer |
| Agent adapter | Client | Gives any model the same three tools: paid fetch, budget, receipts | No | MCP server, OpenAI, Anthropic or Gemini tool definitions, LangChain, LlamaIndex, CLI |

## The socket

The socket is five objects and their rules: the Offer, the Credential envelope, the use record, the Receipt and the manifest. Every deployment MUST implement them exactly; everything else is a plug.

**Normative text.** Byte layouts, algorithms and test vectors now live in the Socket spec draft-00 tab, which wins where the two differ. Its section 15 lists the differences, among them: TLV instead of CBOR for the Credential, a body and witness split, a ReplayKey that covers bodies, route-scope offers, and rail IDs supplied by the rail rather than the scheme.

### Offer

The Offer generalizes v0.4's CHALLENGE. It is a TLV stream (Lightning BOLT 1 encoding, BIP-340 tagged hashes) that lists every scheme the server accepts for this action.

| Type | Field | Meaning |
| --- | --- | --- |
| 0 | version | Socket version, 1 |
| 2 | scope | 32-byte hash of the action, defined by the carrier to cover content and recipient |
| 8 | metered | Optional: the final charge is set at settlement, up to the chosen entry's amount. Only entries whose scheme refunds atomically or has an up-to mode may appear |
| 10 | expires | Unix time after which the offer lapses |
| 12 | info | URI of the manifest |
| 14 | op\_key\_id | Which online offer key, listed in the manifest, signed this offer |
| 16 | nonce | 16 random bytes |
| 18 | pay | Accepted value schemes in preference order. Each entry: scheme ID, amount, unit (sat, an ISO 4217 code or a CAIP-19 asset), quote expiry and scheme parameters |
| 20 | attest | Accepted attestations: scheme ID, parameters, and effect (required, waive, discount or quota) |
| 24 | issued\_at | Self-issued offers only |
| 26 | native | Artifacts the server made for one pay entry, such as an invoice, a macaroon or x402 requirements. Excluded from the OfferID; each embeds it |
| odd, reserved | GREASE | Ignored by every receiver; servers SHOULD include one |
| 240 | offer\_sig | BIP-340 signature by the online offer key over every record below 240 |
| 242 | mac | Server MAC over every record below 240, so the server stays stateless |

Types 240 to 255 are signature records, as in BOLT 12. The server builds an offer in two steps. It first computes OfferID = H\_"bnap/offer"(every record below 240 except `native`), then makes each native artifact so that it embeds the OfferID: an invoice's description hash, an L402 caveat, an MPP `id`, an x402 `extra` field. `offer_sig` and `mac` then cover everything below 240, natives included, so a client can check that the whole offer set is complete and authentic, and the server can check without state that it issued it. Each pay entry carries its own amount and unit: a route priced in sat and in USDC lists both, and the Pricer converts when it builds the offer. A credential's value is compared only with its own entry. Clients MUST ignore unknown schemes.

### Credential envelope

```
Credential  = {v, offer, pay?, attest[], binding, ext}           deterministic CBOR
pay         = {scheme, payload}                                   at most one
attest      = {scheme, payload}                                   zero or more

OfferID     = H_"bnap/offer"(offer records below 240, natives excluded)
Context     = H_"bnap/ctx"(OfferID ‖ value scheme ID ‖ sorted attestation scheme IDs ‖ H(ext))
Digest      = H_"bnap/cred"(Context ‖ binding ‖ H(pay payload) ‖ H(each attest payload))
ReplayKey   = H_"bnap/replay"(Context ‖ sorted socket use IDs)       32 bytes, stored with every use
```

A request carries at most one value proof and any number of attestations. A scheme that was not in the signed offer is rejected with NOT\_OFFERED. The Context covers every chosen scheme and the extensions, so nobody who sees a credential in transit can strip an attestation or change `ext` without breaking it. Binding is empty or the RFC 9266 `tls-exporter` value. It enters the Digest but not the Context or the ReplayKey: only class S credentials are TLS-bound, and a retry on a new connection is still recognized as the same credential. Fronts that terminate TLS outside the gate, such as Envoy ext\_authz and nginx auth\_request, cannot pass the exporter value today, so routes behind them MUST NOT require TLS binding.

Every scheme ties its credential to the offer, and where it can to the request, in one of four registered binding classes. Who makes the artifact decides the class: an artifact the client makes after choosing can embed the Context, while one the server made before the client chose can only embed the OfferID.

| Class | How the credential is tied | Examples |
| --- | --- | --- |
| S | A signature over the Digest: offer, chosen schemes, extensions, payloads and TLS binding | bnap:notes, ACT |
| A | A client-made artifact embeds the Context: offer, chosen schemes and extensions | x402 exact on EVM with nonce = Context, NIP-98 tags, a DPoP claim, a Web Bot Auth signed component, World ID signal, Hashcash |
| O | A server-made artifact embeds the OfferID: one offer and its scope, but not the client's other choices | L402 macaroon caveat, MPP challenge id, Lightning invoices (payment:lightning/charge, x402 on Lightning), Privacy Pass and ARC redemption contexts |
| None | A bearer credential | Allowed only at price 0, and never with a waive or discount effect |

Class O credentials are bearer within their offer: anyone who sees one before the server does can spend it on that action, so the registry records their theft property as bearer. The gate MUST NOT list in `pay` a scheme whose class is weaker than the route requires.

### Uses and outcomes

Every credential yields use IDs. The socket prefixes each with the scheme ID itself, so no scheme can write into another's namespace: `bnap:notes:<Y>`, `httpauth:L402:<payment hash>`. A scheme that relies on a rail payment MUST also report that payment's canonical rail ID, such as `ln:<payment hash>` or `evm:<chain>:<token>:<from>:<nonce>`, and so MUST any scheme that mints credit from a payment. The socket commits rail IDs in the same atomic step as use IDs, so one Lightning payment offered under L402, MPP and x402 at once still admits one action. The scheme's registered use model says how use IDs count:

| Use model | Rule | Examples |
| --- | --- | --- |
| `single` | Each use ID admits one action | Blind notes, per-action Lightning, Privacy Pass |
| `rate(k, epoch)` | At most k actions per use ID per epoch | ARC, World ID nullifiers |
| `reusable(quota)` | A metered allowance per use ID | OAuth tokens, API keys, Web Bot Auth keys |

The socket owns one use store and one outcome model for all schemes:

- **Verify.** Each scheme checks its credential without side effects. A value scheme returns use IDs, rail IDs and a value in its pay entry's unit; an attestation returns use IDs and its effect.
- **Price.** The Pricer sets the price in the chosen entry's unit. Attestations then apply in offer order: every waive first, then discounts, multiplied (two 20% discounts give 36% off, not 40%). Only attestations of class S, A or O may waive or discount. `require` applies to attestations as to value schemes.
- **Commit.** The socket checks value against the effective price and records every value, attestation and rail use ID with the ReplayKey and status PENDING, in one transaction. Any conflict aborts the whole commit.
- **Act.** The carrier runs the action and keeps the response for the replay window. A carrier that cannot keep it answers a replay with the stored receipt alone, never a further refund (draft-00, section 6.4).
- **Settle.** Status moves exactly once to OK or FAILED. For metered actions, the charge is the amount used. On FAILED, value uses stay spent and the scheme refunds as its refund property allows; single-use attestations stay spent; rate counters are given back. A use still PENDING after the manifest's `pending_timeout` (default 300 s) moves to FAILED.
- **Replay.** A request whose use IDs are already committed is a replay only if its ReplayKey matches the record. The socket re-verifies the credential and checks its binding fresh, then returns the recorded outcome with `replayed = true`; the action never runs twice. Any other match is SPENT. A replay hands the response to whoever presents a valid credential, so the response is only as private as the scheme's theft property.

### Receipt

Every response carries the same receipt, whichever scheme paid:

```
Response = {status, replayed, scheme_result, ack}
ack      = BIP-340 signature by an online receipt key over
           H_"bnap/ack"(Digest ‖ status ‖ charged ‖ unit ‖ H(scheme_result))
```

An operator whose keys live in an HSM MAY add an ES256 signature as well; BIP-340 stays mandatory.

### Errors

The socket's codes are `VERSION`, `MALFORMED`, `TOO_LARGE`, `BAD_OFFER`, `STALE`, `WRONG_SCOPE`, `NOT_OFFERED`, `POLICY` (properties not met), `SPENT`, `PENDING` and `RATE_LIMITED`. Scheme errors are namespaced, such as `bnap:notes/OUTPUT_REUSED`.

### Manifest and pinning

`/.well-known/bnap` is signed by an offline root key. It lists versions; the short-lived online offer and receipt keys, with their expiry; one backup root key; routes with prices and offers in preference order; carriers; limits such as `replay_window` and `pending_timeout`; a sequence number `seq`; and a `max_age` of at most 30 days.

Clients pin the root key and its backup, never per-route scheme lists. Scheme lists change whenever an operator pulls a broken adapter or a rail goes down, and pinning them would lock clients out, as HPKP did; `offer_sig` already stops anyone stripping a scheme from a BNAP offer. A client that meets an offer key it does not know refetches the manifest over HTTPS and accepts it if the root or the backup signed it with a higher `seq`.

A manifest MAY set `bnap-required`. A client that has seen it MUST NOT pay that origin through native headers until `max_age` lapses, as with HSTS. This is the only defence against the real downgrade, deleting the BNAP header so a client falls back to L402, MPP or x402, and a tier-0 client that never saw the manifest cannot detect it. First contact is trust on first use; operators who want more publish the root key out of band, in DNS, on Nostr or in their documentation.

### Extensibility

TLV records follow the even/odd rule: an unknown even type is rejected, an unknown odd type ignored. GREASE TLV types are odd, so receivers keep ignoring them; scheme IDs and carrier names reserve GREASE values too. Types 240 to 255 hold signatures. Carriers that use JSON, such as MCP, canonicalize it with RFC 8785.

## Scheme properties and route policy

Every registered scheme carries a property vector, and a route admits a scheme only if every property meets the route's requirement. This is how flexibility stays safe: an operator can plug in any scheme, but a weak one can never quietly satisfy a strong requirement.

| Property | Values, weakest to strongest |
| --- | --- |
| use | reusable → rate-limited → single, as the socket enforces it |
| binding | none → O → A → S |
| theft | bearer → key-witnessed |
| link-payment | linkable to the payment → unlinkable from it |
| link-actions | linkable across actions → unlinkable across them |
| issuer, as the server trusts it | third party → facilitator → self-issued |
| verify | online facilitator → offline |
| finality | reversible → freezable → final at settlement → final on verification |
| custody, as the client trusts it | third-party custodial → operator IOU → client self-custody |
| refund | none → out of band → atomic in protocol |
| pq | no → yes |
| maturity | experimental → standard |

**Rules:**

- Property vectors come from registry entries, set from conformance results. Plugins MUST NOT declare properties at runtime.
- Schemes, rails and verifiers each have entries. The gate computes each pay entry's effective vector as the per-property minimum over its scheme, its rail and its verifier: notes funded by card are reversible and linkable to the payer, and x402 through a custodial facilitator is custodial.
- An unknown or missing property counts as its weakest value.
- The check is per property; there is no overall score. Link is two properties because an EVM address can be linkable to the payment and across actions at once.
- Units are not a property: each pay entry carries its own, and a route's `price` is a map of units.
- The gate never lists in `pay` an entry whose effective vector fails the route's `require`, and refuses to start if a route can be satisfied by none of its enabled schemes.
- Experimental schemes need `allow_experimental` on each route that uses them.

```toml
[[route]]
match   = "POST /v1/chat"
price   = { sat = 21 }                       # a map of units; the Pricer converts
require = { use = "single", binding = "O", link-actions = "unlinkable" }
accept  = ["bnap:notes", "payment:lightning/charge", "httpauth:L402"]
attest  = [{ scheme = "httpsig:web-bot-auth", effect = "discount", percent = 20 }]
```

Here a reusable bearer token could never admit a chat request, however it was configured. Blind notes (class S) and per-action Lightning through MPP or L402 (class O) all qualify, and all three share one rail ID per payment. Raise the route to `binding = "A"` and the gate offers blind notes alone.

## Negotiation

The server signs the list of what it accepts; the client picks one and never says what it supports. One 402 response carries the BNAP Offer plus each foreign scheme's own native challenge, so clients that only speak L402, MPP or x402 still work unchanged.

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: BNAP offer="<base64url Offer: scope, expires, nonce,
    pay=[bnap:notes 21 sat, payment:lightning/charge 21 sat, httpauth:L402 21 sat, GREASE],
    native=[invoice with description hash = OfferID, macaroon], offer_sig, mac>",
    info="/.well-known/bnap"
WWW-Authenticate: Payment id="<embeds OfferID>", realm="api.example", method="lightning",
    intent="charge", expires="…", request="…"
WWW-Authenticate: L402 macaroon="<caveat bnap_offer = OfferID>", invoice="lnbc210n1…"

POST /v1/chat …  Authorization: BNAP <base64url Credential{offer, pay: bnap:notes, binding}>
HTTP/1.1 200 OK  Authentication-Info: bnap="<base64url Response with ack>"
```

**Client choice, in order:**

1. Verify `offer_sig` with an offer key the pinned root signed; on an unknown key, refetch the manifest.
2. Keep the offers the client can use.
3. Drop offers its spend policy forbids. By default a linkable scheme is used only when no unlinkable one is offered, or the user has opted in.
4. Rank by total cost: each entry's own amount converted to the budget's unit, rail fees and a linkability penalty. The server's order breaks ties.
5. Send exactly one value credential and any attestations.

**Native credentials.** A tier-0 client pays through a scheme's own header and sends no envelope. Every adapter MUST therefore embed the OfferID in its native artifact and check it on redemption, and the artifact must be one the server can authenticate without state (a macaroon, an HMAC'd MPP id, an invoice its own node issued); otherwise the server keeps the offer in a short cache keyed by nonce. The socket then builds a synthetic envelope: Context = H\_"bnap/ctx"(OfferID ‖ scheme ID) and Digest = H\_"bnap/cred"(Context ‖ H(native credential bytes)). Use IDs, rail IDs, replay and the BNAP receipt follow from it, and the receipt goes in Authentication-Info next to the scheme's own. A request carrying more than one value credential, native or BNAP, is rejected.

**Native challenges and abuse.** Native challenges cost the server an invoice and a signature, so they must not turn an anti-spam protocol into an amplifier. A server MUST mint at most one invoice per offer nonce, MAY reuse one native challenge per scope for a short TTL, and SHOULD rate-limit minting per client address. It MAY instead send only the BNAP offer and mint natives when a client asks for a scheme, at the cost of tier-0 clients.

## Plug catalogue

The abstraction was tested against every system in the table below, some rows covering several related systems. All but two fit as scheme, attestation, rail, carrier or client plugs: Cloudflare pay-per-crawl, whose payment side is closed, and AP2 as a direct per-action payment, though AP2 mandates work as a client spend policy. "Adapter" means the scheme fits once its artifact carries a BNAP value, such as an L402 caveat, an MPP id or an x402 nonce. Each is a convention the native spec already allows, but both sides must follow it.

| System | Plugs into | Binding | Use model | Fit |
| --- | --- | --- | --- | --- |
| Blind notes (bnap:notes) | Credential | S | single | Native, the default |
| L402 (bLIP-26) | Credential + funding | O, OfferID caveat | single, enforced by the socket | Adapter |
| MPP (draft-httpauth-payment) | Credential envelope + methods | O, OfferID in the HMAC'd id | single | Adapter |
| x402 on EVM chains | Credential + facilitator verifier | A, client nonce = Context | single | Adapter, guarded rail |
| x402 on Lightning | Credential + facilitator verifier | O, invoice | single | Pending a published spec |
| Cashu NUT-24, NUT-18, NUT-26 | Credential + carrier | O when locked to the operator's key, else None | single | Adapter; unlocked only at price 0 |
| Cashu NUT-22 blind auth | Credential | None, bearer | single | Native at price 0 |
| ACT | Credential | S | single | Native, reserved |
| Privacy Pass (RFC 9576–9578) | Attestation | O, redemption context | single | Native |
| ARC | Attestation | O, presentation context | rate | Native |
| Web Bot Auth | Attestation | A, Context as a signed component | reusable | Adapter |
| OAuth and API keys, with DPoP | Attestation | A with a DPoP claim, else None | reusable | Adapter; without DPoP, never waive or discount |
| NIP-98 | Attestation + Nostr carrier | A, tags | reusable | Adapter |
| World ID | Attestation | A, signal | rate | Adapter |
| Hashcash, Anubis | Credential, unit work | A | single | Adapter, weak |
| NWC (NIP-47) | Pay source, funding rail | — | — | Native |
| Fedimint, Ark, Spark | Pay source, funding rail | — | — | Adapter |
| MCP, A2A | Carrier, agent adapter | Scope from tool and arguments | — | Adapter |
| AP2 mandates | Client spend policy | — | — | Adapter |
| Cloudflare pay-per-crawl | Pricer signal only | — | — | Does not fit |

### Naming and the registry

Scheme IDs reuse existing registries as `<registry>:<id>[@<qualifier>]`, so BNAP never renames anything:

| Prefix | Source registry | Examples |
| --- | --- | --- |
| `bnap:` | BNAP's own schemes | `bnap:notes` |
| `payment:` | HTTP Payment Methods and Intents (draft-httpauth-payment) | `payment:lightning/charge` |
| `x402:` | x402 schemes and networks as x402 names them: CAIP-2 for EVM chains; lnbtc is x402's own label, not CAIP-2 | `x402:exact@lnbtc`, `x402:exact@eip155:8453` |
| `pp:` | Privacy Pass token types | `pp:0x0002` |
| `httpauth:` | HTTP authentication schemes | `httpauth:L402`, `httpauth:DPoP` |
| `httpsig:` | HTTP message signature tags | `httpsig:web-bot-auth` |
| `cashu:`, `nip:` | Cashu NUTs, Nostr NIPs | `cashu:nut24`, `nip:98` |
| `vnd.` | Unregistered vendor schemes | `vnd.example.pow` |

The registry starts as a file in the BNAP repository: each entry needs a public specification, a property vector set by conformance results, and the maintainer's review as designated expert. It moves to IANA once two independent implementations exist.

## The default scheme: bnap:notes

`bnap:notes` is the v0.4 Cashu profile, now one plug among many and the recommended default, because it is the only scheme that is unlinkable, verified offline and refunded atomically, all at once. Its full specification is the second tab; the changes for v0.5 are small.

**How it works, in one paragraph.** The service runs its own Cashu-style issuer. A client buys credit over Lightning (Cashu NUT-23, NUT-04, NUT-20) and holds it as Notes: Cashu proofs whose secret is the hex of a public key K. To spend, it signs the socket's Digest with each K and sends blinded outputs for change and refunds. The issuer checks the notes offline, and the socket records each note's Y as a single-use ID. Wallets recover from a seed through NUT-13, NUT-09 and NUT-07.

| Property | Value |
| --- | --- |
| use / binding / theft | single / S / key-witnessed |
| link-payment / link-actions | unlinkable, except that the first action after funding can be correlated by timing / unlinkable |
| issuer / verify | self-issued / offline |
| finality / custody | final on verification / operator IOU |
| refund | atomic in protocol |
| pq / maturity | no / experimental until the NUTs are accepted |

These are the scheme's own entries. Funded by a card or another reversible rail, the effective vector drops to reversible and linkable to the payer, as the rule on effective vectors requires. The notes unit is sat.

**What moved into the socket:** the CHALLENGE became the Offer, with the notes-specific `fund_quote` now a parameter of the notes offer; witnesses sign the socket Digest; commit, replay, receipts and the core error codes are the socket's; scheme errors are namespaced `bnap:notes/…`.

**What stays in the scheme:** the Note format, key isolation, input fees, refund outputs, funding inside the 402, seed recovery, the spend-store layout and the BNAP-W withdrawal extension.

## Value rails

Rails are plugs: BNAP fixes how a payment request is asked for and confirmed, never which network or provider carries it. Lightning BOLT11 is the default rail and part of the Core-1 badge; everything else is the operator's choice.

| Rail | Finality | Status in the reference implementation |
| --- | --- | --- |
| Lightning (Phoenixd, LDK Node, NWC, LND, CLN, LSPs) | Final | Default |
| Ark, Spark, Fedimint, Cashu mints | Final once settled; custody varies | Optional plugs |
| On-chain Bitcoin | Final after confirmations | Optional plug |
| Stablecoins (x402 on EVM chains, Tempo) | Final at settlement, freezable by the issuer | Guarded, off by default |
| Cards (MPP through Stripe) | Reversible for months | Guarded, off by default |

**Guardrails for non-Bitcoin rails.** These rails plug in freely, under rules that keep them from weakening anyone else:

- They are off by default: a build feature plus an explicit setting turns each one on.
- Credit they fund carries its own unit (`usd`, `eur` or a CAIP-19 asset) and is never mixed into `sat` credit.
- A reversible rail may only fund credit, never admit an action directly, and that credit is held until the payment is final or capped per epoch. A stolen card must not be able to buy spam.
- The manifest marks every such rail with its finality and custody properties, so clients and route policies see them.
- Facilitators (x402) are verifier plugs with their trust level declared: non-custodial relay, custodial, or merchant of record.

## Carriers

A carrier defines two things: the scope function that names one action, and where offers, credentials and receipts travel. Any protocol with a slot for them can carry BNAP.

| Carrier | Scope covers | Offer, credential and receipt travel in | Status |
| --- | --- | --- | --- |
| HTTP | Method, normalized absolute URI, Content-Digest | `WWW-Authenticate`, `Authorization`, `Authentication-Info` | Core-1 |
| MCP | Server URI, tool name, RFC 8785 canonical JSON of the arguments | JSON-RPC error data, request `_meta`, result `_meta` | Agent-1 badge |
| SASL | Service, mechanism and server nonce | SASL challenge and response | Optional |
| Nostr | Relay URL and event ID | Event tag and relay `OK` message; offers self-issued | Optional |
| gRPC | Service, method and message digest | Metadata | Optional |
| WebSocket | Endpoint and message digest | Per-message envelope | Optional |
| A2A | Agent card and task digest | Task metadata | Optional |

Recent MCP revisions favour stateless servers, which suits BNAP: an Offer carries everything needed to verify the credential later. TLS binding is not available through most MCP hosts, so MCP credentials rely on scope binding.

## Agents and clients

BNAP never names a model, a framework or a wallet. Every agent adapter exposes the same three tools to any model that can call tools: `fetch_paid`, `budget` and `receipts`.

| Client plug | Choices |
| --- | --- |
| Agent adapter | MCP server, OpenAI, Anthropic or Gemini tool definitions, LangChain, LlamaIndex, the `bnap` CLI |
| Wallet | Notes wallet with seed recovery, L402 client, x402 signer, any third-party wallet that implements a scheme |
| Pay source | NWC, LDK, lnget, Cashu, Ark, Spark or Fedimint wallets, custodial APIs, cards through MPP |
| Spend policy | Budget files, NWC budgets, AP2 mandates, organisation rules |

**Rules for every client, whatever its plugs:**

- Spending caps per origin and per task are enforced in code. A model never picks a scheme, sets a cap or holds a key, and a prompt-injected "pay with X" goes through the same policy check as anything else.
- The client verifies `offer_sig` with a key its pinned root signed before paying, and honours bnap-required.
- It never advertises which schemes it supports.
- It keeps the receipt of every paid action.

| Tier | The client has | Example |
| --- | --- | --- |
| 0 | Any single-scheme client | lnget for L402, an x402 or MPP client |
| 1 | A BNAP wallet plus any pay source | `bnap get` with an NWC connection |
| 2 | A BNAP wallet with its own seed and several schemes | Picks per route by properties and cost |

## Reference implementation: Caparra as a plug host

Caparra is a host for plugs: the socket in one small crate, every plug point a Rust trait, and three ways to load a plug so that no operator is tied to Rust or to the project's own choices.

| Crate | Role |
| --- | --- |
| `bnap-core` | The socket: Offer, envelope, Digest, use store logic, outcome state machine, receipts, test vectors |
| `bnap-plug` | The plug traits, plus the WIT interface definition generated from them |
| `bnap-scheme-*` | `notes`, `l402`, `mpp`, `x402`, `privpass`, `webbotauth`, `oauth` |
| `bnap-rail-*` | `nwc`, `phoenixd`, `ldk`, `lnd`, `ark`, `fedimint`, plus off-by-default `x402-evm` and `mpp-card` |
| `bnap-store-*`, `bnap-signer-*`, `bnap-carrier-*` | Postgres and SQLite; file, process and KMS-unwrap signers; HTTP, MCP, SASL, Nostr |
| `caparra-gate`, `caparra-wallet`, `bnap-mcp`, `bnap-cli` | The gateway, the client wallet, the MCP server and the CLI |

```rust
#[async_trait] pub trait CredentialScheme: Send + Sync {
    fn id(&self) -> SchemeId;                         // properties come from the registry, not from here
    async fn offer(&self, cx: &OfferCtx) -> Result<SchemeOffer>;        // any native artifact embeds cx.offer_id
    async fn verify(&self, c: &Credential, cx: &VerifyCtx) -> Result<Verified>;  // no side effects; cx.now, cx.signer
    async fn settle(&self, v: &Verified, out: Outcome, s: &CappedSigner) -> Result<SchemeResult>;
}
pub struct Verified { pub use_ids: Vec<LocalUseId>,  // bnap-core prefixes these with the scheme ID
                      pub rail_ids: Vec<RailId>,     // ln:<payment hash>, evm:<chain>:…; committed with the use IDs
                      pub value: Amount }            // in the chosen pay entry's unit

pub trait Carrier { fn scope(&self, r: &Request) -> Scope; fn extract(&self, r: &Request) -> Option<RawCredential>;
                    fn offer(&self, o: &SignedOffer) -> Response; fn receipt(&self, r: &Receipt, out: &mut Response); }
#[async_trait] pub trait FundingRail { async fn request(&self, a: Amount, memo: [u8; 32]) -> Result<PayRequest>;
                                      async fn status(&self, id: &PayId) -> Result<PayState>; }   // operator-trusted
#[async_trait] pub trait UseStore {                                                              // operator-trusted
    async fn commit(&self, ids: &[UseId], key: ReplayKey) -> Result<Commit>;     // New | Replay | Conflict, all or nothing
    async fn finalize(&self, ids: &[UseId], key: ReplayKey, s: Final) -> Result<()>;
    async fn expire_pending(&self, older_than: Duration) -> Result<u64>; }      // PENDING past pending_timeout -> FAILED
#[async_trait] pub trait Signer {                                                                // operator-trusted
    async fn schnorr(&self, k: KeyRef, msg: [u8; 32]) -> Result<Sig>;            // msg built by bnap-core only
    async fn verify_unblinded(&self, ks: KeysetId, y: Point, c: Point) -> Result<bool>;
    async fn blind_sign(&self, ks: KeysetId, outs: &[(Amount, Point)], cap: Amount) -> Result<Vec<(Point, Dleq)>>; }
    // refuses when outs sum above cap; bnap-core sets cap = value - charged
#[async_trait] pub trait Pricer { async fn price(&self, a: &Action, unit: &Unit) -> Result<Amount>; }
#[async_trait] pub trait Judge  { async fn admit(&self, a: &Action, p: &Properties) -> Decision; }
#[async_trait] pub trait PaySource { async fn pay(&self, r: &PayRequest, b: &Budget) -> Result<PayProof>; }
```

Only bnap-core computes the OfferID, Context, Digest and ReplayKey, prefixes use IDs, compares value with price, commits uses and builds every message the signer signs. A scheme gets a `CappedSigner` that can verify notes and sign blinded outputs up to the change cap bnap-core computed, and nothing more. Every other plug gets read access to what it needs and returns data.

**Three ways to load a plug:**

| Way | For | Isolation | Release |
| --- | --- | --- | --- |
| Compiled in (Cargo features) | First-party plugs | Same process | v0.5 |
| Sidecar over gRPC or HTTP, same interface | Any language, heavy dependencies such as an x402 facilitator, LND or a Python classifier | Separate process | v0.6 |
| WASM component (WIT world `bnap:plug`, WASI 0.3) | Third-party schemes, pricers and judges | Sandbox with fuel and memory limits, no ambient network | v0.7 |

**Fronts and bindings.** Operators on any stack put `caparra-gate` in front as a standalone proxy, Envoy ext\_authz, Caddy forward\_auth or nginx auth\_request, so they need no Rust at all. Client libraries ship through UniFFI (Swift, Kotlin, Python), napi-rs (Node) and wasm-bindgen (browsers).

**One config, any mix:**

```toml
[gate]     origin = "https://api.example"; front = "envoy-ext-authz"; replay_window_s = 86400; pending_timeout_s = 300
[manifest] root_key = "file:/etc/caparra/root.pub"; backup_key = "file:/etc/caparra/backup.pub"; max_age_s = 604800; bnap_required = true
[store]    kind = "postgres"; url = "env:DATABASE_URL"; durability = "sync"
[signer]   kind = "process"; socket = "unix:///run/caparra-signer.sock"; seed_wrapped_by = "aws-kms"
[[rail]]   id = "ln";  kind = "phoenixd"; url = "http://127.0.0.1:9740"
[[rail]]   id = "ln2"; kind = "nwc"; uri = "env:NWC_RECEIVE_ONLY"
[[scheme]] id = "bnap:notes";               rails = ["ln", "ln2"]; max_fund_sat = 10000
[[scheme]] id = "httpauth:L402";            rail = "ln"
[[scheme]] id = "x402:exact@eip155:8453";   unit = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
                                            facilitator = "https://fac.example"; enabled = false
[[attest]] id = "httpsig:web-bot-auth"
[pricing]  kind = "table"; file = "prices.toml"
[judge]    kind = "sidecar"; url = "grpc://classifier:7001"
```

## Plugin security

Plugs may come from anyone, so the host assumes any plug can be buggy or hostile and limits what it can reach.

- **Two trust levels.** The use store, the signer and the funding rails are operator-trusted: the operator supplies them and the gate runs only versions it pinned. Schemes, attestations, verifiers, carriers, pricers and judges are contained.
- **What a hostile scheme can do.** It can admit unpaid actions on the routes that enable it, as any broken payment check could. It cannot write another scheme's use IDs, because bnap-core prefixes them. It cannot reuse a payment another scheme used, because bnap-core commits rail IDs. It cannot get a signature on a message bnap-core did not build, or blind signatures above the change cap. Enable third-party schemes only on routes whose losses you accept.
- **No keys.** No plug sees an issuer key or a note key. The signer itself verifies unblinded notes and signs blinded outputs.
- **Sandboxes.** Third-party plugs run as WASM components with only the capabilities their WIT world declares, CPU and memory limits, and no ambient network or files. The host passes the current time in each call, so expiry checks still work. No plug runs inside the signer process.
- **Supply chain.** Plugs are signed (Sigstore), logged in a transparency log and built reproducibly. The gate pins plug hashes and checks a revocation list, and refuses a known-broken version even when configured.
- **Safe defaults.** Experimental schemes and non-Bitcoin rails stay off until turned on per route.

## Badges, profiles and conformance

Any deployment that keeps the socket rules is BNAP, whatever its plugs. Badges label the mixes that are guaranteed to work together, so flexibility never costs interoperability for those who want it.

| Badge | Requires, on server and client | Guarantees |
| --- | --- | --- |
| Core-1 | The socket, bnap:notes, HTTP, Lightning BOLT11 funding | Any two Core-1 parties can transact with notes that are unlinkable across actions. Provisional until the notes NUTs are accepted; until then Core-1 is the one place an experimental scheme is on by default |
| Agent-1 | Core-1 plus the MCP carrier and httpauth:L402 or payment:lightning/charge | Agents with no BNAP code can pay over Lightning, and MCP tools can be priced. payment:lightning joins as of right once it is registered; x402 on Lightning once its spec is published |
| Fiat-Funding | A separate unit, credit held until final | Cards and stablecoins can fund credit without weakening sat credit |
| Nostr-1, SASL-1 | The carrier profile | Priced relay writes; priced mail and chat |

An L402-only or x402-only deployment that keeps the socket rules is still BNAP, just without a badge.

**Conformance is the product.** A badge is earned by passing the public test suite, not by a claim. The suite includes negative tests: stripped offers, cross-scheme replay, a wrong scope, a status flip on replay, an unsatisfiable route, and a plug trying to sign or commit.

## Security and privacy considerations

Flexibility adds threats a single scheme does not have; each has a socket rule.

| Threat | Closed by |
| --- | --- |
| A proxy strips the strong scheme from an offer | Signed offers; the chosen schemes inside the Context |
| A proxy deletes the BNAP header so the client pays natively | bnap-required for clients that saw the manifest. A tier-0 client cannot detect it |
| A weak scheme satisfies a strong route | Registry vectors, effective vectors over scheme, rail and verifier, per-property checks, unknown = weakest |
| One payment admits actions through several schemes | Canonical rail IDs committed with the use IDs; one value credential per request |
| An observer re-sends a credential with altered ext or attestations | The Context covers attestation IDs and ext; bearer attestations cannot waive or discount; class O is registered as bearer |
| A reusable token treated as single-use | Use model from the registry, enforced by the use store |
| Stolen cards fund spam | Reversible rails fund credit only, in their own unit, held until final |
| A hostile scheme admits unpaid actions | Contained to the routes that enable it; prefixed use IDs, rail IDs and the change cap keep it from anything else |
| A hostile plug forges receipts or inflates notes | No plug reaches a key; the signer signs only bnap-core's messages and change within the cap |
| Native challenges used as a DoS amplifier | One invoice per offer nonce, cached or lazy natives, rate limits |
| A first-contact attacker pins a hostile key | Pinning only for HTTPS-fetched manifests, max\_age capped at 30 days, backup key, higher seq replaces |
| A crash leaves uses PENDING | pending\_timeout moves them to FAILED |
| A route that nothing can satisfy | The gate refuses to start |
| Prompt injection steers an agent's payment | Spend policy in code; the model never chooses |
| Clients fingerprinted by their schemes | Clients never advertise capabilities |
| Privacy split across many schemes | At most one privacy-bearing scheme per unit per origin is RECOMMENDED |

The scheme-level threats and residual risks of blind notes stay as specified in the second tab. Two residual risks are new: each linkable scheme an operator enables lowers the privacy of the clients who use it, and each facilitator or custodial rail adds a party who can censor or freeze payments. Route policies and client policies make both visible; they cannot remove them.

## Roadmap and standardization

The socket ships first, with the plugs agents need on day one; the plug runtimes and the registry grow with adoption.

| Release | Adds |
| --- | --- |
| v0.5 | The socket in `bnap-core`; compiled-in plugs: `bnap:notes`, `payment:lightning/charge`, `httpauth:L402`; OAuth with DPoP and Web Bot Auth as attestations; HTTP and MCP carriers; NWC and Phoenixd rails; the conformance suite |
| v0.6 | Sidecar plugs over gRPC or HTTP; the x402 adapter, on Lightning once its spec is published; SASL and Nostr carriers; Ark and Fedimint rails; guarded fiat funding behind the Fiat-Funding badge |
| v0.7 | WASM component plugs; Privacy Pass, ARC and ACT schemes |

**Documents, in order:**

1. **The BNAP socket** (about 15 pages): Offer, envelope, use and outcome model, receipt, manifest, properties, registry rules. Published in the repository, later an IETF individual draft.
2. **NUT-XX key-secret proofs** and **NUT-XX HTTP 402 with a self-issued mint**: the `bnap:notes` scheme, for the Cashu NUTs.
3. **HTTP Payment Method registration** of `cashu`, and support for registering `lightning`, in the empty registries of draft-httpauth-payment.
4. **The MCP carrier note**, aligned with the MPP and x402 MCP transports.
5. **NIP-XX priced relay writes**, then SASL.

The registry lives in the repository with the maintainer as designated expert until two independent implementations exist; then it moves to IANA.

## Appendix A: Debate record

### Round 4, 11 October: the universal plug

A plug architect designed the socket and plug points, a flexibility skeptic attacked them, and an ecosystem mapper tested them against the systems in the plug catalogue. Where they still differed, the owner decided.

| Question | Positions | Verdict |
| --- | --- | --- |
| Where can plugs attach? | Architect: anywhere. Skeptic: anywhere except the credential, which only registered suites may fill | Anywhere, but credential and attestation schemes need registry entries with property vectors |
| Who states a scheme's properties? | The plugin, or a registry | The registry, set by conformance results; unknown counts as weakest |
| Offer authentication | Unsigned (v0.4), or a signed offer set plus pinning | Signed offer set plus pinning; a blocker even before v0.5 |
| Baseline | Notes mandatory everywhere, or no baseline | Owner: a badge, not a gate (Core-1) |
| Non-Bitcoin rails | Into sat credit, a separate unit held until final, or none | Owner: pluggable with guardrails |
| Credentials per request | One scheme, or one payment plus attestations | One value credential plus any attestations |
| Reusable credentials | Exclude them, or model them | Use models: single, rate-limited, reusable |
| Scheme names | A new namespace, or existing registries | Existing registries with prefixes |
| Plug runtime | Native only, or WASM for third parties | Compiled now, sidecars next, WASM after |
| Name | Rename, or keep | Owner: keep Blind-Note Admission Protocol |

### Earlier rounds

| Round | Settled |
| --- | --- |
| 1, 9 October | The operator issues its own notes; per-action prices over refundable bonds; application carriers first |
| 2, 10 October | One primitive, three verbs; the signature covers the whole spend; bonds and transport binding leave the core |
| 3, 10 October | Notes become a Cashu profile with seed recovery, NUT-23 funding, refund outputs and recomputed replies |

Independent reviews of v0.1, v0.3, v0.4 and v0.5 found fifteen blockers between them, all fixed.

### Review of v0.5, 11 October

| Finding | Fix in v0.5.1 |
| --- | --- |
| Blocker: one Lightning payment offered under L402, MPP and x402 could admit one action per scheme | Schemes report canonical rail IDs; the socket commits them with the use IDs |
| Blocker: the Context was circular for artifacts the server makes before the client chooses | OfferID; class O replaces N; class A only for client-made artifacts |
| Blocker: payments through native headers had no Context, Digest or replay | Adapters embed the OfferID; the socket builds a synthetic envelope |
| Blocker: "a hostile plugin can never cheat" was false | Trusted store, signer and rails; prefixed use IDs; a capped signer for change; the claim restated |
| Digest malleable by anyone who saw the credential | Context covers attestation IDs and ext; no waive or discount for bearer attestations |
| Attestation effects undefined | Waive, then multiplied discounts; one transaction for every use ID; rules on FAILED |
| Replay broken across connections and crashes | ReplayKey without binding; re-verification; cached responses; pending\_timeout |
| One unit per offer | Amount and unit per pay entry; price as a map of units |
| Metered actions overpaid | Only refundable or up-to schemes; the ack covers the charge |
| Pinning scheme lists repeats HPKP | Pin the root key only; bnap-required; tier-0 limit stated |
| Properties depend on rail and facilitator | Effective vectors computed by the gate |
| Invoices as a DoS amplifier | One invoice per nonce, cached or lazy natives, rate limits |
| Minor | Two link properties, viewpoints labelled; None rule aligned with Cashu; lnbtc labelled; badges provisional; catalogue claim corrected; odd GREASE, signature range, RFC 8785; fronts without TLS binding; KMS wraps the seed at rest; time passed to WASM |

## Open questions

- [ ] **Socket byte layout.** Define the Offer's `pay` and `attest` record encodings and publish test vectors.
- [ ] **Foreign headers.** Verify the current x402 v2 header names and the L402 and MPP challenge syntax before shipping their adapters.
- [ ] **Registry seed.** Write the first property vectors for every scheme in the catalogue and the conformance tests behind them.
- [ ] **First gateway routes.** The first gateway is an LLM inference proxy: set metered prices per model, the maximum tokens per offer, and which schemes each route accepts.
- [ ] **Cashu maintainers:** NUT numbers, the NUT-13 derivation type, alignment with NUT-24.
- [ ] **HTTP Payment Methods:** draft the `cashu` registration.
- [ ] **KMS signing.** AWS KMS cannot produce BIP-340 signatures, so the seed is KMS-wrapped at rest and lives in the signer process; confirm that is acceptable, or use a threshold signer. x402 on Lightning: confirm its network label and whether a client can choose a nonce, which would move it from class O to A.
- [ ] **Legal reading** of non-withdrawable credit, BNAP-W, and fiat-funded credit.

### Sources

Opened during round 4:

- [draft-httpauth-payment-01](https://datatracker.ietf.org/doc/html/draft-httpauth-payment-01) and [paymentauth.org](https://paymentauth.org)
- [MPP reference](https://mpp.dev/llms-full.txt)
- [x402 specification v2](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md) and [x402 network support](https://docs.cdp.coinbase.com/x402/network-support.md)
- [Block adds Lightning to x402](https://crypto.news/block-joins-x402-with-lightning-support/)
- [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html) and [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html)
- [RFC 7457: TLS attacks, including stripping](https://www.rfc-editor.org/rfc/rfc7457.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [Logjam](https://weakdh.org/)
- [Web Bot Auth draft](https://www.ietf.org/archive/id/draft-meunier-webbotauth-httpsig-protocol-00.html)
- [AAIF: MCP and payments](https://aaif.io/blog/who-told-the-agent-it-could-spend)
- [Cashu NUT-24](https://github.com/cashubtc/nuts/blob/main/24.md)
- [Cloudflare pay-per-crawl](https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/what-is-pay-per-crawl/)
- [Spark on AP2](https://www.spark.money/research/google-ap2-agent-payment-protocol), published by a competing protocol
- [WASI 0.3 release](https://wasi.dev/releases/wasi-p3)

Sources for earlier rounds are listed in the other tabs.

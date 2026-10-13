# NUT-XX: HTTP 402 with a self-issued mint

`optional`

`uses: NUT-06, NUT-07, NUT-09, NUT-12, NUT-13, NUT-18, NUT-26`

`depends on: NUT-24, NUT-XX (key-secret proofs), NUT-04, NUT-20, NUT-23`

---

[NUT-24][24] lets a server ask for ecash in an HTTP 402 response. This NUT covers the case where the server is its own mint: it accepts only proofs it issued itself, for its own origin. That makes four things possible that NUT-24 leaves open:

- **Request binding.** Every proof is a [key-secret proof][xx-keys] whose witness signs a digest of the exact request, so a payment copied from a log or a proxy cannot pay for anything else.
- **Change and refunds.** The wallet sends blinded outputs with its proofs, and the server signs exactly the unspent value back in the response, also when the action fails.
- **Funding inside the 402.** A wallet with no proofs yet gets a [NUT-23][23] Lightning quote in the 402, pays it, and redeems it in its next request.
- **Receipts.** Every paid response carries a signed receipt.

The envelope that carries the payment is the BNAP socket ([draft-bnap-socket][socket]): a signed offer in the 402, a credential in the retried request, and a signed response. The Cashu side is the `bnap:notes` scheme ([bnap-notes][notes]). This NUT states what a Cashu wallet and a Cashu mint must do to take part, and leaves the byte layouts to those two documents.

## Roles

- The **server** is an HTTP origin, such as a paid API, with a gate in front of it.
- The **issuer** is the server's own mint. It is reached at an `https` URL on the server's origin, and its keysets are [key-secret keysets][xx-keys] with unit `sat` that sign for this origin only.
- The **wallet** holds proofs of that issuer and pays the server with them.

## The 402 response

A server answers a request that needs payment with status 402 and these fields:

1. `X-Cashu`: a payment request as [NUT-24][24] defines it, encoded as [NUT-18][18] (`creqA`) or [NUT-26][26] (`creqB`), with:
   - `a`: the price in sat; for a metered action, the most it can cost;
   - `u`: `"sat"`;
   - `m`: a one-element list, the issuer's URL;
   - `s`: `true`;
   - `i`: the lowercase hex of the BNAP OfferID of the offer in item 2;
   - no transport, because the payment travels in-band, and no `nut10`, because key-secret proofs replace locking.
2. `WWW-Authenticate: BNAP offer="..."`: the BNAP offer ([socket][socket], section 4). It is signed by the server's offer key and lists `bnap:notes` with the issuer URL, the keysets it accepts, their input fees and which of them sign change ([notes][notes], section 5).
3. Any other challenges the server offers, such as L402 or the `Payment` scheme.

For the `chat` route of the BNAP examples, the decoded `X-Cashu` request is

```json
{
  "i": "5c8640261f6f1de3206a2e9cd1c2599a2e9256547242061c95f9d2e06cf6696d",
  "a": 2100,
  "u": "sat",
  "s": true,
  "m": ["https://api.example/cashu"]
}
```

which is 113 bytes of CBOR before the `creqA` encoding.

The issuer advertises this NUT in its [NUT-06][06] info, next to the info of [key-secret proofs][xx-keys] with an empty `contexts` list:

```json
"XX": {
  "supported": true,
  "origin": "https://api.example"
}
```

A NUT-24 wallet that does not implement this NUT sees a request whose only mint issues key-secret proofs, and cannot pay it with plain proofs. A server **MAY** offer other schemes in the same 402 for such wallets.

## Paying

A wallet that implements this NUT:

1. verifies the BNAP offer as the socket requires ([socket][socket], section 4.4): its signature under a key of the origin's pinned manifest, its expiry, and its scope;
2. checks that the `i` of the `X-Cashu` request equals the OfferID of the offer, and uses the offer, not the payment request, for everything that follows;
3. builds a `bnap:notes` credential body ([notes][notes], section 3): its proofs as inputs, a set of blinded outputs whose amounts are 1, 2, 4, ... up to the highest power of two in the value it sends, and, when it redeems a funding quote, the quote ID;
4. signs the socket's Digest ([socket][socket], section 5.2) with the key of each proof, which is the external context of [key-secret proofs][xx-keys], and with the quote's [NUT-20][20] key when it redeems a quote;
5. retries the request with the credential in the `BNAP-Credential` field.

The wallet **MUST NOT** send the proofs in `X-Cashu` or anywhere else outside the credential, because they would travel without their witnesses. A server **MUST** answer key-secret proofs sent in `X-Cashu` with status 400, as NUT-24 does for a token it cannot accept, and **MUST NOT** redeem them.

## Verifying and settling

The server checks the credential as the socket and the scheme require ([notes][notes], section 6): the keysets, the amounts, each witness over the Digest, each proof's `C`, the output ladder, and the funding quote if there is one. It then commits every proof's `Y` once, atomically and durably, before the action runs, so a proof can never pay twice. A repeat of the same credential for the same request is a replay and gets the stored response instead of running the action again. The socket answers even a replay with `STALE` once its offer has expired, so the server stops admitting new credentials `pending_timeout` plus 60 seconds before an offer expires, and every request it accepted can still collect its refund by replaying ([notes][notes], section 5.4). A wallet replays a request that got no final answer before the offer expires.

At settlement the server knows the charge: the price for a fixed-price action, the metered charge for a metered one, and 0 when the action failed. It signs blinded outputs worth exactly the value sent minus the charge, chosen by a fixed rule the wallet can recompute ([notes][notes], section 7), with [NUT-12][12] DLEQ proofs made with the deterministic nonce. A failed action therefore returns the whole value, less input fees.

## The receipt

Every response to a request that reached the commit carries `BNAP-Receipt`: the BNAP response ([socket][socket], section 8.1), signed by the server's receipt key. It holds the status, the charge, the unit, the OfferID, the Digest it answers and, as the scheme result, one entry per signed output: its index, `C_`, and the DLEQ proof (`e`, `s`).

The wallet checks the receipt key against the pinned manifest, recomputes which outputs had to be signed, verifies each DLEQ proof against the issuer's key for that amount, and only then unblinds its change. It keeps every receipt: together with the credential, a receipt proves what the operator acknowledged for that request.

## Funding inside the 402

A wallet without proofs asks for funding with its first request:

```
BNAP-Fund: amount=2100, pubkey="02c4..."
```

`amount` is the most it will pay in sat, and `pubkey` a fresh compressed key for [NUT-20][20]. The server **MAY** then create a [NUT-23][23] BOLT11 mint quote for at most that amount, locked to `pubkey`, and put it in its offer ([notes][notes], section 8). The server **MUST** create at most one quote per offer, **MUST** rate-limit quote creation per client address, and **MUST NOT** create a quote for a request that did not ask for one.

The wallet checks that the quote is locked to its key and that the invoice amount matches, saves the quote and its key, pays the invoice from any Lightning wallet, and then either:

- redeems the quote inside its next credential, signing the Digest with the quote key. The quote's amount joins the value, and the change comes back as proofs; or
- mints the quote through [NUT-04][04] as usual, with its [NUT-20][20] signature.

Whichever happens first wins: the issuer records the payment once, and the other path is refused. A request that fails before the commit leaves the quote mintable.

A credential that redeems a quote is linkable to that Lightning payment. Change proofs are not. A wallet that wants every request unlinkable mints first and pays only with proofs.

## Issuer rules

The issuer:

- issues only key-secret keysets ([key-secret proofs][xx-keys]) with unit `sat`, version `01` keyset IDs and a `final_expiry`;
- serves [NUT-01][01], [NUT-02][02], [NUT-04][04] with [NUT-20][20] required, [NUT-06][06], [NUT-07][07], [NUT-09][09], [NUT-12][12] and [NUT-23][23];
- refuses [NUT-03][03] swaps and [NUT-05][05] melts of its keysets' proofs, unless it implements a withdrawal extension that requires witnesses;
- answers [NUT-07][07] from the server's record of committed `Y` values, and [NUT-09][09] from its record of signed outputs, which it keeps until the keyset's final expiry;
- publishes a keyset at least 30 days before it signs with it, and always keeps a standby keyset published, so that a compromised keyset can be replaced at once.

Wallets **SHOULD** swap proofs out of a keyset that nears its final expiry, through a request on the server's swap route priced at 0 ([notes][notes], section 11).

## Errors

Errors travel in `BNAP-Error` with the HTTP status the socket assigns ([socket][socket], section 8.2). Errors from the Cashu side are code 10 (`BAD_CREDENTIAL`, status 402) with a `bnap:notes/...` code, such as `bnap:notes/BAD_OUTPUTS` or `bnap:notes/QUOTE_UNPAID` ([notes][notes], section 13). A proof spent before gives code 12 (`SPENT`, status 409). Errors are not signed, and a wallet **MUST NOT** treat one as proof of anything.

## Alignment with NUT-24, NUT-18 and NUT-26

| NUT-24                                                | This NUT                                                                   |
| ----------------------------------------------------- | -------------------------------------------------------------------------- |
| 402 with `X-Cashu` holding a NUT-18 or NUT-26 request | The same, plus the signed BNAP offer it names in `i`                       |
| `a`, `u`, `m`                                         | Price (the ceiling when metered), `"sat"`, the server's own mint only      |
| `s`, `i`                                              | `true`; the OfferID in hex                                                 |
| `nut10` locking                                       | Absent: key-secret proofs bind each proof to its request                   |
| Retry with a `cashuB` token in `X-Cashu`              | Retry with a `BNAP-Credential`; key-secret proofs in `X-Cashu` are refused |
| Status 400 for a token the server cannot accept       | `BNAP-Error` with socket and `bnap:notes` codes                            |
| No change                                             | Change and refunds as blind signatures in the receipt                      |
| No receipt                                            | A signed BNAP response on every paid request                               |
| No replay rule                                        | Each `Y` committed once; a replay returns the stored response              |

## Security considerations

- **Request binding.** The witness signs the socket's Digest, which covers the offer, the request, the proofs and the blinded outputs, so a payment cannot be moved to another request and change cannot be redirected.
- **Theft.** Proofs copied in transit are useless without their keys ([key-secret proofs][xx-keys]).
- **Operator credit.** Proofs of a self-issued mint are a promise by the operator, redeemable only at that origin. Wallets **SHOULD** keep small balances per origin; 5,000 sat is a reasonable default cap.
- **Invoice abuse.** The server creates funding quotes only on request, at most one per offer, and rate-limited per client address, so a scraper gets an offer, never an invoice.
- **Linkability.** Proofs are unlinkable to the purchase that funded them. A credential that redeems a quote is linkable to that payment, and small operators can still correlate requests by address and timing.
- **Spend policy.** Agents and wallets **MUST** enforce spending caps per origin and per task in code; a model's prompt never decides what to pay.

## Test vectors

The key-secret vectors are in [key-secret proofs][xx-keys]. The vectors for the socket are in the BNAP repository ([vectors][vectors]); the `bnap:notes` vectors, which this NUT relies on for the body, the change selection and the receipt, are specified in section 18 of [bnap-notes][notes].

[01]: 01.md
[02]: 02.md
[03]: 03.md
[04]: 04.md
[05]: 05.md
[06]: 06.md
[07]: 07.md
[09]: 09.md
[12]: 12.md
[18]: 18.md
[20]: 20.md
[23]: 23.md
[24]: 24.md
[26]: 26.md
[xx-keys]: xx-key-secret-proofs.md
[socket]: https://github.com/bnap-protocol/bnap/blob/develop/spec/socket-draft-00.md
[notes]: https://github.com/bnap-protocol/bnap/blob/develop/spec/schemes/bnap-notes-draft-00.md
[vectors]: https://github.com/bnap-protocol/bnap/blob/develop/vectors/vectors.json

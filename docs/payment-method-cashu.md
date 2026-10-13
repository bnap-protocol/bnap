# The "cashu" payment method (draft registration)

Draft text registering a `cashu` method in the "HTTP Payment Methods" registry that [draft-httpauth-payment-01][payment] creates (its Section 12.3, policy "Specification Required"). The registry asks for a specification pointer, and the draft's Section 9.1 says what such a specification MUST define: a method identifier, a request schema, a payload schema, a verification procedure, a settlement procedure and security considerations. Section 2 below is that specification; Section 1 is the registration itself.

The method lets a server take plain Cashu ecash ([Cashu NUTs][nuts]) from any mint it lists, through the `Payment` HTTP authentication scheme. It is independent of BNAP; Section 3 says how BNAP uses it.

Status: draft, written 2026-10-13 against draft-httpauth-payment-01. Spec text licensed CC-BY-4.0, (c) BNAP contributors.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 1. Registration

| Field | Value |
| --- | --- |
| Method Identifier | `cashu` |
| Description | Cashu ecash: bearer tokens of Chaumian blind signatures on secp256k1, issued by a Cashu mint and redeemed at that mint. The payer sends a NUT-00 V4 token; the server redeems it with a NUT-03 swap |
| Specification pointer | Section 2 of this document, `docs/payment-method-cashu.md` in https://github.com/bnap-protocol/bnap, and the Cashu NUTs it cites |
| Registrant Contact | BNAP contributors, https://github.com/bnap-protocol/bnap/issues |

## 2. Method specification

### 2.1 Method identifier

`cashu`, in lowercase ASCII letters as Section 12.3 of the draft requires. Clients and servers compare it exactly.

### 2.2 Intent

This specification defines the method for the intent `charge`: one payment of `amount` for the request the challenge answers. Draft-01's intent registry starts empty and no intent specification defines `charge` yet; until one does, `charge` here means exactly that, and when one does, this method follows it.

### 2.3 Request schema

The `request` auth-parameter is the base64url, unpadded, of the JCS-serialized (RFC 8785) JSON object below, as the draft's Section 5.1 requires.

| Member | Type | Presence | Meaning |
| --- | --- | --- | --- |
| `amount` | integer | Required | The price, in `unit`, that the token must be worth after the mint's input fees (NUT-02) |
| `unit` | string | Required | A unit of the listed mints' keysets (NUT-01), such as `sat` |
| `mints` | array of strings | Required, at least one | The mint URLs the server accepts tokens from. The list is strict: a token from any other mint is refused |
| `nut10` | object | Optional | A NUT-10 spending condition every proof MUST carry, in the form NUT-18 uses: `{"k": kind, "d": data, "t": [[tag, value, ...], ...]}`. A server sets it to lock tokens to a key of its own (NUT-11 `P2PK`) |
| `methodDetails` | object | Optional | `{"version": 1}`; absent means version 1, as the draft's Section 9.2.2 allows |

Every integer is at most 2^53 - 1, so that JCS serializes it exactly. Example, decoded:

```json
{ "amount": 21, "mints": ["https://mint.example"], "unit": "sat" }
```

### 2.4 Payload schema

The `payload` member of the credential (the draft's Section 5.2) is a JSON object:

| Member | Type | Presence | Meaning |
| --- | --- | --- | --- |
| `token` | string | Required | A NUT-00 V4 token (`cashuB...`) holding proofs of one mint listed in `mints`, in `unit` |

The credential's `source` member SHOULD be omitted: a Cashu payment needs no payer identifier, and sending one gives up the privacy blind signatures provide. An example credential, decoded, with the challenge echo shortened:

```json
{
  "challenge": {
    "id": "...",
    "realm": "api.example",
    "method": "cashu",
    "intent": "charge",
    "request": "eyJhbW91bnQiOjIxLCJtaW50cyI6WyJodHRwczovL21pbnQuZXhhbXBsZSJdLCJ1bml0Ijoic2F0In0"
  },
  "payload": { "token": "cashuB..." }
}
```

### 2.5 Verification procedure

A server that receives a `cashu` credential MUST, in this order:

1. verify the echoed challenge and its `id` as the draft's Section 5.1.2.1 requires, and that `method` is `cashu`;
2. decode `token` as a NUT-00 V4 token, and reject it if it is malformed, holds proofs of more than one mint, or holds no proof;
3. check that the token's mint is in `mints` and its unit is `unit`;
4. compute the input fees of the proofs from the mint's keysets (NUT-02) and check that the sum of the proof amounts minus the fees is at least `amount`;
5. if the request set `nut10`, check that every proof's secret is a NUT-10 secret of that kind, with that data and those tags, and that the condition lets the server, and only the server, redeem the proof (for `P2PK`, that the server holds the key the condition names);
6. redeem the proofs as Section 2.6 describes, and admit the request only if the redemption succeeds.

Unless the server is itself the token's mint, a Cashu token cannot be verified offline: whether its proofs are unspent is known only to the mint. A server MAY ask the mint for the proofs' state first (NUT-07) to fail early, but only a successful swap admits the request.

Failures map to the draft's error codes (its Section 8.2), all with status 402 and a fresh challenge: a token that cannot be decoded is `malformed-credential`; a mint not listed, a wrong unit or a failed spending condition is `verification-failed`; a value below `amount` is `payment-insufficient`; and proofs the mint reports as already spent are `verification-failed`.

### 2.6 Settlement procedure

The server settles by swapping the proofs at their mint (NUT-03) for new proofs whose blinded messages it generated itself, adding the witnesses its spending condition requires (for `P2PK`, NUT-11 signatures by its key). The swap is the settlement:

- **Single use.** The mint accepts each proof in exactly one swap, atomically, so a token admits at most one request, as the draft's Section 11.3 requires. Two concurrent requests with the same token race at the mint; one swap succeeds and the other fails, so at most one request is admitted and at most one response delivered (Section 11.5).
- **Finality.** Once the swap succeeds, the payment is final: the server holds new proofs that only it knows the secrets of. It then runs the action. If the action fails, a refund is a new payment from the server, outside this method.
- **Failures.** If the mint cannot be reached, the server MUST NOT admit the request; it answers 503, or 402 with a fresh challenge. If the swap returns signatures but the connection fails before the server has stored them, the server recovers them with NUT-09 restore or NUT-19 cached responses, and admits the request only once it holds them.

On success the server SHOULD send a `Payment-Receipt` (the draft's Section 5.3) with `status` `"success"`, `method` `"cashu"`, `timestamp`, and as `reference` the lowercase hex of the smallest `Y` (NUT-00 `hash_to_curve` of the secret, compressed) among the redeemed proofs. It MAY add `mint` (the mint URL) and `amount` (the value after fees).

### 2.7 Security considerations

- **Bearer tokens.** An unlocked Cashu token is a bearer instrument: anyone who reads it before the server redeems it can spend it. Credentials travel only over TLS, and servers SHOULD set `nut10` to lock tokens to a key of their own (NUT-11), which makes a copied token useless to anyone but the server. A wallet then has to swap its proofs into locked ones before paying, and MAY add a NUT-11 locktime and refund key so it can take back a token the server never redeems.
- **Request binding.** A token, locked or not, names no request. Within the challenge, the draft's binding of `id` to the challenge parameters is the only link between the payment and the request; a server that needs the payment tied to the request itself needs a scheme that signs the request, such as the BNAP `bnap:notes` scheme.
- **Mint trust.** The server takes the mint's word for every proof, and holds the mint's IOU after the swap. The `mints` list is strict for this reason, and a server lists only mints it is prepared to hold balances at.
- **Availability.** Verification needs the mint online. A mint that is down, or slow, blocks admission; servers fail closed (Section 2.6) and SHOULD bound the time they wait.
- **Denial of service.** Every credential costs the server a call to the mint. Servers SHOULD run the cheap checks of Section 2.5 first and rate-limit credentials per client.
- **Privacy.** The mint's blind signatures keep the server and the mint from linking a token to its issuance. The method sends no payer identifier, and `source` SHOULD stay absent. Amounts and timing remain visible to the server and, through the swap, to the mint.
- **Fees.** Input fees are the mint's, and `amount` is net of them, so a payer adds them. A server that swaps immediately pays nothing further.

## 3. Use with BNAP (informative)

In BNAP the method appears under the `payment:` prefix of the overview's naming rules, as the scheme ID `payment:cashu/charge`, through the MPP adapter: the gate embeds the OfferID in the challenge `id` (draft-00 section 4.2) and recovers the offer from it (section 5.4). The scheme's local IDs are the `Y` of each redeemed proof, under the use model `single`. Its binding class is O when the request sets a `nut10` lock to the operator's key, so that a token is bearer within its offer only, and None otherwise; a None scheme is admissible only at price 0 (DECISIONS row 25). The overview's plug catalogue records the same rule for NUT-24 tokens.

Payments in this method go to any mint the server lists. The `bnap:notes` scheme instead uses the server's own mint and request-bound key-secret proofs; see [`../nuts/`](../nuts/) and [`../spec/schemes/bnap-notes-draft-00.md`](../spec/schemes/bnap-notes-draft-00.md).

## References

- [draft-httpauth-payment-01][payment]: B. Ryan, J. Moxey, T. Meagher, J. Weinstein and S. Kaliski, "The 'Payment' HTTP Authentication Scheme", Internet-Draft, September 2026.
- [Cashu NUTs][nuts]: NUT-00 (tokens, `hash_to_curve`), NUT-01 and NUT-02 (keysets, fees), NUT-03 (swap), NUT-07 (state check), NUT-09 (restore), NUT-10 and NUT-11 (spending conditions, P2PK), NUT-18 (payment requests), NUT-19 (cached responses).
- RFC 2119, RFC 8174 (key words); RFC 8785 (JCS).

[payment]: https://datatracker.ietf.org/doc/html/draft-httpauth-payment-01
[nuts]: https://github.com/cashubtc/nuts

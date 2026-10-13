# NUT-XX: Key-secret proofs

`optional`

`depends on: NUT-00, NUT-01, NUT-02, NUT-12, NUT-13`

`uses: NUT-03, NUT-05, NUT-06, NUT-07, NUT-09, NUT-22`

---

This NUT defines key-secret proofs: proofs whose `secret` is the hexadecimal encoding of a public key, and which can only be spent with a signature by that key over a digest that the spending context defines. A copied key-secret proof is useless without the key, so proofs that travel through logs, proxies or HTTP headers cannot be stolen. A mint marks the keysets whose proofs are key-secret proofs, and accepts their inputs only with a valid witness.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119][RFC2119] and [RFC 8174][RFC8174] when, and only when, they appear in all capitals.

## Key-secret proofs

A key-secret proof is a [NUT-00][00] `Proof` whose secret is derived from a key pair:

```
k       = the proof's private key, a secp256k1 scalar
K       = the BIP-340 x-only public key of k, 32 bytes
secret  = lowercase hex of K, 64 characters
Y       = hash_to_curve(secret)             as in NUT-00
```

Everything else is unchanged: the wallet blinds `Y` into `B_`, the mint signs it, and the wallet unblinds `C` as [NUT-00][00] describes. The proof is

```json
{
  "amount": int,
  "id": hex_str,
  "secret": "<64 lowercase hex characters: K>",
  "C": hex_str,
  "witness": "<optional, see below>"
}
```

A key-secret proof is spent by presenting it together with a **witness**: one [BIP-340][BIP340] Schnorr signature by `k` over a 32-byte digest `D`. The spending context defines `D` (see [Contexts](#contexts)). `D` MUST commit to everything the spend depends on, at least the operation, its outputs and, where the proof pays for something, that thing.

To a mint that does not know the keyset is a key-secret keyset, the secret looks like an ordinary random secret. That is on purpose, since key-secret proofs are indistinguishable from other proofs at rest. It is also why [key isolation](#key-isolation) is a MUST.

## Key-secret keysets

A keyset is either a key-secret keyset or not; every proof of a key-secret keyset is a key-secret proof.

- A key-secret keyset MUST use a version `01` keyset ID ([NUT-02][02]).
- A key-secret keyset SHOULD set `final_expiry` ([NUT-02][02]), so that the mint can bound how long it keeps spent `Y` values.
- The mint advertises its key-secret keysets in its [NUT-06][06] info:

```json
"XX": {
  "supported": true,
  "keysets": ["01a4ee...", "01b7c9..."],
  "contexts": ["swap", "melt"]
}
```

`keysets` lists every key-secret keyset the mint has, active or not. `contexts` lists the built-in contexts of this NUT that the mint accepts for them; an empty list means the proofs are spent only in external contexts.

### Key isolation

- The mint MUST refuse every input from a key-secret keyset that comes without a valid witness, in every operation it offers ([NUT-03][03], [NUT-05][05] and any other), and in every context it does not list in `contexts`.
- A key-secret keyset's keys MUST NOT appear in any other keyset.
- A wallet MUST NOT present a key-secret proof without its witness, and MUST NOT send it to any mint other than the one that issued it.

## Witness

The witness is one 64-byte BIP-340 signature by `k` over `D`. In the built-in contexts it travels in the proof's `witness` field as a JSON string, in the form [NUT-11][11] uses:

```json
{
  "signatures": ["<128 hex characters>"]
}
```

An external context MAY carry the signature in its own encoding.

A verifier MUST check, for every key-secret input:

1. `secret` is exactly 64 lowercase hex characters and decodes to a valid x-only public key `K` (a field element below the field size for which a curve point exists).
2. The witness holds exactly one signature, and it verifies under `K` over `D`.
3. `C` is a valid signature on `hash_to_curve(secret)` under the keyset's key for `amount`, as for any proof.

Signatures are never aggregated: every input carries its own signature, even when several inputs share one operation. Batch verification is fine. A mint never learns that a wallet knows `k` when it signs `B_`, so a sum of keys could otherwise spend another holder's proof.

## Contexts

A context fixes `D`. Every digest in this NUT is a BIP-340 tagged hash, `tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)`, with a tag that no other context uses. In the formulas below, `||` is byte concatenation, `u16` is a 2-byte and `u64` an 8-byte big-endian integer, `secret` is the 64 ASCII bytes of the secret, and points (`C`, `B_`) are 33-byte compressed points. Inputs and outputs are taken in request order.

### swap

For a [NUT-03][03] swap whose inputs include key-secret proofs:

```
inputs  = u16(number of inputs)  || for each input:  secret || C
outputs = u16(number of outputs) || for each output: u64(amount) || keyset ID (33 bytes) || B_
D       = tagged_hash("Cashu_KeySecret_Swap_v1", inputs || outputs)
```

Every output MUST be on a version `01` keyset. One `D` covers the whole swap, and each key-secret input carries its own signature over it.

### melt

For a [NUT-05][05] melt whose inputs include key-secret proofs:

```
quote   = u16(length of the quote ID) || quote ID as UTF-8
D       = tagged_hash("Cashu_KeySecret_Melt_v1", quote || inputs || outputs)
```

`inputs` and `outputs` are as in the swap context; `outputs` are the blank outputs for fee return, if any, and `u16(0)` when there are none.

### External contexts

Another specification MAY spend key-secret proofs outside NUT-03 and NUT-05, for example to pay for an HTTP request. It then defines `D` and MUST make sure that:

- `D` is 32 bytes and is computed by the verifier itself, never taken from the sender;
- `D` commits to everything the spend depends on: the action paid for, the amount, and any outputs the verifier will sign in return;
- `D` is domain-separated from every tag of this NUT and from every other use of the same keys.

The BNAP socket is one such context: its `Digest`, `H_"bnap/cred"(...)`, covers the offer, the request, the chosen schemes, the proofs and the blinded change outputs, and its `bnap:notes` scheme spends key-secret proofs with one signature per proof over that digest ([HTTP 402 with a self-issued mint][xx-402]).

### Blind authentication tokens

Key-secret proofs make [NUT-22][22] blind authentication tokens theft-resistant. A mint MAY issue its blind auth keyset as a key-secret keyset and advertise it in `keysets`. A wallet then derives each blind auth token as a key-secret proof and, with every protected request, signs

```
D = tagged_hash("Cashu_KeySecret_Auth_v1", u16(len(method)) || method || u16(len(path)) || path || SHA256(request body))
```

where `method` and `path` are the HTTP method and path of the protected endpoint as UTF-8. It adds the signature to the token as `"w": "<128 hex characters>"` next to `id`, `secret` and `C`. A token copied from a log can then not be replayed for another request.

## Deterministic secrets

A wallet derives the key `k` of a key-secret proof with the [NUT-13][13] derivation for version `01` keysets, with derivation type `0x02`:

```
k = HMAC_SHA256(seed, "Cashu_KDF_HMAC_SHA256" || keyset_id || u64(counter) || 0x02) mod n
r = HMAC_SHA256(seed, "Cashu_KDF_HMAC_SHA256" || keyset_id || u64(counter) || 0x01) mod n
```

`r` is the NUT-13 blinding factor; the NUT-13 secret type `0x00` is not used, because the secret is `hex(K)`. If `k` or `r` is 0, the wallet skips the counter value. This NUT requests derivation type `0x02` for this use.

Restore ([NUT-09][09]) and state checks ([NUT-07][07]) work unchanged: the wallet regenerates `B_` from `k` and `r`, and checks `Y`. A wallet MUST NOT reuse a counter value once its `B_` has been sent, signed or not, because the same `B_` in two requests links them.

## DLEQ proofs

A mint that signs outputs for key-secret keysets SHOULD use the deterministic nonce of [NUT-12][12], so that it can recompute a response it has already sent. Specifications that require recomputed responses, such as the BNAP socket, make it a MUST. Wallets MUST NOT reveal `r` or a proof's DLEQ proof to the mint, because either links a spend to its issuance.

## Wallet rules

- A wallet uses each key once, for one proof, at one mint.
- A key-secret proof is not transferable offline: the holder can hand over `k` together with the proof, which makes the recipient trust the sender, or spend it into an output the recipient chose.
- Wallets MAY store key-secret proofs in V4 tokens ([NUT-00][00]) for backup. A token holding them is not a payment: without `k` nobody can spend it.

## Security considerations

- **Theft.** A proof copied from a log, a proxy or a CDN cannot be spent: spending needs a signature by `k` over a digest that names the operation.
- **Front-running.** Whoever sees a witnessed spend in transit sees only a signature over that one `D`. A verifier that computes `D` itself never accepts it for another operation.
- **Summed keys.** One signature per input, verified under that input's own `K`, closes the attack in which a wallet offers a key that is the sum of its own and someone else's.
- **Key isolation.** If a mint accepted a key-secret proof without its witness, `hex(K)` would read as an ordinary secret and anyone holding the proof could spend it. Key isolation makes that impossible by construction.
- **Privacy.** Key-secret proofs look like other proofs at rest. The witness reveals `K`, which is in the secret anyway, and nothing else. A spend is linkable to its issuance only if the wallet reveals `r` or the DLEQ proof.

## Test vectors

Generated by [`tools/key_secret_vectors.py`](tools/key_secret_vectors.py), which also checks `hash_to_curve` against the NUT-00 vectors. Private keys are SHA-256 of the strings shown, and BIP-340 auxiliary randomness is 32 zero bytes.

**Proof.** `k = SHA256("key-secret test note key")`:

```
k      = f11469879513e580a342d47eba7c1b92131b28d084a1b35703813bf8f085fa74
K      = 635cf1dd995dd0d5c8736c009b32b8ed6ded5c1cdaf758d135bc203465c13d31
secret = "635cf1dd995dd0d5c8736c009b32b8ed6ded5c1cdaf758d135bc203465c13d31"
Y      = 0297d97466d57fc764ff42032746603bc0daeead6f4493e7e68d083e29385f5580
```

**External context.** `D = SHA256("example context digest")`:

```
D         = 560bd34f3119539c1b9845c3e781faf43d3443c1054e6bc319811e320cc2e13c
signature = e0293cdfa3e34773c69011e61b202309969f55759228a83e37f65fa4a2cf551d
            112a11daa62d8a9e05f543ebdd32430bc9efa318d4d57506cfeac8a6fe856e33
```

**Swap context.** The mint key is `a = SHA256("key-secret test mint key")`, the input is the proof above with `C = a·Y`, and the one output has amount 8, keyset ID `0x01 || SHA256("key-secret test keyset")` and `B_ = hash_to_curve("key-secret test output secret") + r·G` with `r = SHA256("key-secret test blinding factor")`:

```
A         = 0329021aaae306cd787bf12dcdbef7ab11b03e3c31f32313e0f7ce875e99bb39a6
C         = 03de62aa76313ca17767357cd28fefb6bc9f52fd7653442927f6d810a2f4dd1f41
id        = 01a4eeaa521685e029adfe8734a9440b81df7bdccb987f4c0fff6505f38117d91b
B_        = 02659242bd484a3595f8d5e7015f47701aa422a4237876796b19499ea6e482b277
msg len   = 175 bytes
D         = c25f78ccaa2b35f37c156c14759a4a06af9543fdb3c8892bac11d6a3e3e083f0
signature = ed0b1a90aff885e9d23b0c71dd375f3da5c80428c28ec3f8358898f3315fa051
            8a1685e47238712ec2d35f779f19687c914235a7bf3905e9ecaee9a57478cec2
```

The signatures are split over two lines here only for width; each is 64 bytes.

[00]: 00.md
[02]: 02.md
[03]: 03.md
[05]: 05.md
[06]: 06.md
[07]: 07.md
[09]: 09.md
[11]: 11.md
[12]: 12.md
[13]: 13.md
[22]: 22.md
[xx-402]: xx-http-402-self-issued-mint.md
[BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174

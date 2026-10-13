# Cashu NUT proposals

Two proposals for the Cashu specifications ([cashubtc/nuts](https://github.com/cashubtc/nuts)) that the `bnap:notes` scheme ([`../spec/schemes/bnap-notes-draft-00.md`](../spec/schemes/bnap-notes-draft-00.md)) is built on:

| File                                                                 | Proposal                                 | What it adds to Cashu                                                                                                                                                                                                                              |
| -------------------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`xx-key-secret-proofs.md`](xx-key-secret-proofs.md)                 | NUT-XX: Key-secret proofs                | Proofs whose secret is the hex of a public key and that are spent only with a signature by that key over a digest the spending context defines; key-secret keysets and key isolation; NUT-13 derivation type `0x02`; theft-resistant NUT-22 tokens |
| [`xx-http-402-self-issued-mint.md`](xx-http-402-self-issued-mint.md) | NUT-XX: HTTP 402 with a self-issued mint | A profile of NUT-24 for a server that is its own mint: request-bound payments, change and refunds, funding inside the 402 and signed receipts, carried by the BNAP socket                                                                          |

[`tools/key_secret_vectors.py`](tools/key_secret_vectors.py) regenerates the key-secret test vectors from the BNAP reference encoder (`python3 -I nuts/tools/key_secret_vectors.py reference/python`, from the repository root). It checks `hash_to_curve` against the NUT-00 vectors first.

The files follow the conventions of the NUTs repository: the header block (title, `optional`, `depends on:`, `uses:`, a rule), RFC 2119 key words, and relative links such as `[00]: 00.md` that resolve only inside that repository. "XX" stands for the numbers the maintainers will assign.

## Submission plan

1. **Issue first.** Open one issue in cashubtc/nuts that presents both proposals together, links these drafts, the BNAP socket and the `bnap:notes` scheme, and asks for:
   - two NUT numbers;
   - NUT-13 derivation type `0x02` for key-secret proof keys;
   - feedback on the NUT-24 alignment (keeping `X-Cashu` with a NUT-18 or NUT-26 request next to the BNAP offer) and on making NUT-22 tokens key-secret.
     The design is settled in the issue before any pull request, as this repository's contributing guide asks for its own normative changes.
2. **Discuss in the open.** Present the proposals in the Cashu developer chat and on a developer call, with running code and the test vectors.
3. **Then one pull request per NUT**, against cashubtc/nuts, each:
   - renaming `xx-...md` to the assigned number and replacing every "NUT-XX";
   - adding the NUT to the table in that repository's README;
   - turning the links to BNAP documents into links to a tagged release, so the NUT does not follow a moving branch;
   - passing Prettier (`npx prettier --check '*.md'`), which this directory is already clean against.
4. **Two implementations before merge.** The pull requests stay drafts until two independent implementations pass the vectors: Caparra (Rust, built on CDK) is the first; the second must be another code base in another language, for example a wallet built on cashu-ts or Nutshell. Each implementation reports which vectors it passes in the pull request.
5. **After merge**, the cashubtc/nuts text is the canonical one. `bnap:notes` then cites the merged NUTs by number, and these drafts are replaced by a pointer.

Until the issue is answered, the texts here track `bnap:notes` draft-00. A change to that scheme that touches key-secret proofs, the change outputs or funding inside the 402 needs the matching change here.

## Related registration

[`../docs/payment-method-cashu.md`](../docs/payment-method-cashu.md) drafts the registration of a `cashu` method in the "HTTP Payment Methods" registry of draft-httpauth-payment-01, for plain Cashu tokens from any listed mint. It is independent of these two NUTs.

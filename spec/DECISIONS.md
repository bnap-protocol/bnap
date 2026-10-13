# Provisional decisions (pending owner review)

These resolve the ERRATA rows marked "owner decision needed". The build follows them until the owner overrides one; an override becomes a spec edit plus a code change.

| ERRATA # | Topic | Provisional decision |
|---|---|---|
| 13 | Metered route in the manifest | The manifest carries the price ceiling only. The per-unit rate travels in the pay entry parameters of the offer. No new manifest member. |
| 21 | Timeout defaults | `pending_timeout` defaults to 300 s and `replay_window` to 86,400 s when the manifest omits them. |
| 22 | ES256 co-signature | Not in v0.5. No record type is assigned; BIP-340 stays the only receipt signature. Revisit with an HSM signer. |
| 23 | GREASE for scheme IDs and carrier names | Not in v0.5. Odd GREASE TLV types stay mandatory-to-ignore and servers keep sending one. |
| 24 | Native challenge minting | Treated as MUST: at most one invoice per offer nonce, plus a per-address mint rate limit. Stricter than draft-00 SHOULD, safe against amplification. |
| 25 | Class None value schemes | Added to section 7: a binding-class None scheme is admissible only at price 0 and never with a waive or discount effect. |
| 30 | Credential size on HTTP | The HTTP carrier caps a Credential at 9,216 bytes (12,288 base64url characters). Larger credentials are refused with TOO_LARGE. |
| 31 | bnap:notes vs draft-00 | The notes scheme is rewritten in draft-00 terms (`spec/schemes/bnap-notes-draft-00.md`). Its body encoding is TLV, like every socket object. |

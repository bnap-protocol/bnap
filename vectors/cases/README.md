# Conformance cases

Spec text licensed CC-BY-4.0, (c) BNAP contributors.

Wycheproof-style test cases for [socket draft-00](../../spec/socket-draft-00.md), one file per area, each with a JSON Schema in [schema/](schema/). They are generated: never edit them by hand. `python3 -I conformance/gen_cases.py` writes them and `--check` fails if any file differs from what the generator produces, byte for byte.

| File | Area |
| --- | --- |
| [bigsize.json](bigsize.json) | BigSize and tu64, minimal encodings |
| [tlv.json](tlv.json) | TLV streams, the even/odd rule, nested type ranges, entry lists, base64url |
| [offer.json](offer.json) | Offer records, class rules, OfferID and offer_sig, the client and gate checks of 4.4 |
| [credential.json](credential.json) | Credential records, Context, Digest, ReplayKey, UseId, RailId, counter keys, native envelope, witnesses, value-credential count, canonical DPoP bodies |
| [response.json](response.json) | Response records and ack, the client's receipt rules, the Error TLV and its HTTP statuses |
| [manifest.json](manifest.json) | Manifest document rules, strict I-JSON, JCS, pinning, native challenges, fetch limits |
| [http-scope.json](http-scope.json) | Action and route scopes, route matching, manifest origin |
| [pricing.json](pricing.json) | price(), admit, metering, offer-building rules |
| [outcomes.json](outcomes.json) | Commit, replay, settle and timeout as state-machine traces; the reusable admission window |

## Format

```
{ "bnapCases": 1, "area", "title", "schema", "generator", "source", "numberOfTests",
  "header": [lines], "notes": { FLAG: { "bugType", "description" } },
  "testGroups": [ { "type", "section", "description", "tests": [ test, ... ] } ] }

test = { "tcId", "comment", "flags", "sections", "inputs", "result",
         "error"?, "errorCode"?, "acceptableErrors"?, "reason"?, "expected"? }
```

- **tcId** is unique and sequential within a file.
- **inputs** depends on the group type; the schema names every field. Byte strings are lower-case hex; 64-bit values that may exceed 2^53 are decimal strings.
- **result**: `valid` means an implementation must accept the input and produce every value in `expected`. `invalid` means it must refuse it with `error` (or one of `acceptableErrors`). `acceptable` means draft-00 does not settle the case; either answer passes, and the flag's note says why.
- **error** is a section 8.2 code name, with `errorCode` its number, or one of two client labels with no socket code: `CLIENT_REJECT` (a client refuses an object or an action) and `MANIFEST_REJECT` (a client refuses a manifest under 9.1 and 9.3). `reason` is the library's label for the refusal, informative only.
- **flags** name entries of `notes`; **sections** are the draft-00 sections a case tests.

## Keys and times

The secret keys are SHA-256 of the labels the headers name, as in [vectors.json](../vectors.json): `bnap test offer key`, `bnap test receipt key`, `bnap test root key`, `bnap test backup key`, `bnap test mac key`, `bnap test note key`, plus `bnap conformance ...` keys for strangers, retired MAC keys and rotations. The fixed time is 1,791,700,100 unless a case says otherwise. BIP-340 signatures use 32 zero bytes of auxiliary randomness; the DPoP profile uses RFC 6979 ECDSA, normalized to low-S (s <= n/2), which the profile requires.

## Reference consumer

[conformance/tests/test_cases.py](../../conformance/tests/test_cases.py) reads every case through one small evaluator per group type and checks verdicts and expected values; it is the shortest description of how each group is meant to be run.

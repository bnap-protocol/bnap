# Integration notes: node N2, the scheme property registry

Branch `node/n2` of the spec repository, based on `develop` at `5dee21d`. This node owns `registry/` and nothing else; `spec/` is untouched, so the errata found here are listed below for whoever owns the spec.

## What was built

| Path | Content |
| --- | --- |
| `registry/README.md` | Policy (RFC 8126 Specification Required, maintainer as designated expert, IANA after two independent implementations), how properties are set, ID rules, entry format, statuses, gate rules, how to validate and propose |
| `registry/properties.toml` | The twelve properties, values weakest first, location in an entry, and the kinds each applies to |
| `registry/schemes.toml` | 20 entries: 11 credentials, 7 attestations, 2 does-not-fit |
| `registry/rails.toml` | 4 rail kinds (`ln`, `onchain`, `evm`, `card`) and 13 rail entries |
| `registry/verifiers.toml` | 5 verifiers: `local`, `mpp-processor`, three x402 facilitator trust levels |
| `registry/carriers.toml` | 4 carriers: `http`, `mcp`, `a2a`, `nostr` (a fourth file, since carriers are a draft-00 section 13 registry and the catalogue lists MCP and A2A) |
| `registry/schema.json` | JSON Schema 2020-12 for each source file |
| `registry/validate.py` | Validator, exporter and effective-vector calculator; stdlib only, Python 3.11+ |
| `registry/test_validate.py` | 27 tests: the real registry passes, broken copies fail |
| `registry/generated/registry.json` | The canonical export (about 63 KB) |

Commands, from the repository root (any Python 3.11 or later; the system `python3` on this machine is 3.9, so use the Homebrew one):

```sh
python3 -I registry/validate.py              # validate
python3 -I registry/validate.py --export     # validate and regenerate the export
python3 -I registry/validate.py --check      # CI: fail if the export is stale
python3 -I registry/test_validate.py         # tests
python3 -I registry/validate.py --effective bnap:notes --rail ln:phoenixd --verifier local \
    --require use=single,binding=A
```

## Public API: the export contract

`registry/generated/registry.json` is what the Rust code embeds. It is one JSON object holding only strings, booleans, arrays, objects and the integer `format`.

| Member | Type | Content |
| --- | --- | --- |
| `format` | integer | 1 |
| `generated_by` | string | `registry/validate.py --export` |
| `digest` | string | hex SHA-256 of the RFC 8785 (JCS) serialization of the whole object without `digest` |
| `properties` | array | In vector order. Each: `id`, `label`, `location` (`entry` or `properties`), `applies_to` (array of kinds), `description`, `values` (array of `{id, label}`, weakest first) |
| `rail_kinds` | map by ID | `name`, `canonical`, `spec`, `status` |
| `schemes` | map by scheme ID | See below |
| `rails` | map by rail ID | `name`, `kind` = `rail`, `rail_kind`, `status`, `source`, `spec`, `properties`, `vector`, `units`, `guarded` (bool), `conformance`, `notes` |
| `verifiers` | map by verifier ID | `name`, `kind` = `verifier`, `trust`, `status`, `source`, `spec`, `properties`, `vector`, `conformance`, `notes` |
| `carriers` | map by carrier ID | `name`, `kind` = `carrier`, `status`, `source`, `spec`, `scope`, `transport`, `tls_binding` (bool), `notes` |

A scheme has `name`, `kind` (`credential` or `attestation`), `role` (`value`, `attestation` or `both`), `status`, `source`, `spec`, `notes` and `vector` always. Unless it is `does-not-fit` it also has `binding`, `use`, `properties`, `local_id`, `quota_id`, `body`, `witness`, `verifiers` (array) and `conformance`; a credential adds `refund`, `upto` (bool), `rail_refs`, `rail_kinds` (array), `native` (array of `{kind, embeds, credential}`) and `units` (array). A `does-not-fit` scheme has `reason` instead and an empty `vector`. In serde terms: make every field after the first seven an `Option`, or split the type by status.

`vector` is the entry's full property map: every property that applies to its kind, with `binding`, `use` and `refund` merged in from the top level. Use `vector`, not `properties`, which holds only the nine non-top-level ones. A value's strength is its index in `properties[i].values`.

**Effective vector of a pay entry** (what the gate must compute, and what `--effective` prints):

```
for each property p that applies to the scheme's kind:
    parts = [scheme] + every rail the scheme is configured with + [its verifier]
    ranks = [rank(p, part.vector[p]) for part in parts if part.kind in p.applies_to]
    effective[p] = p.values[min(ranks)]
rank(p, v) = index of v in p.values, or 0 if v is missing or unknown
a rail or verifier ID with no entry counts as an entry with an empty vector (all weakest)
```

**Route `require`** is checked per property: admitted if `rank(effective[p]) >= rank(required)` for every listed property. A property absent from the effective vector (only possible for attestations: `link-payment`, `finality`, `custody`, `refund`) does not constrain it.

**Start-up refusals:** a route naming an unknown ID or a `does-not-fit` entry; a rail whose `rail_kind` is not in the scheme's `rail_kinds`; a verifier not in the scheme's `verifiers`; a guarded rail without its build feature and setting; a route no enabled scheme satisfies; an experimental entry (by `maturity`) without `allow_experimental`; a scheme with empty `units` in a pay entry.

**IDs the Caparra stub crates map to:** `bnap-scheme-notes` = `bnap:notes`, `bnap-scheme-l402` = `httpauth:L402`, `bnap-scheme-mpp` = `payment:lightning/charge`, `bnap-scheme-dpop` = `httpauth:DPoP`, `bnap-scheme-webbotauth` = `httpsig:web-bot-auth`; `bnap-rail-phoenixd` = `ln:phoenixd`, `bnap-rail-lnd` = `ln:lnd`, `bnap-rail-nwc` = `ln:nwc`; `bnap-carrier-http` = `http`, `bnap-carrier-mcp` = `mcp`. `bnap-rail-fake` has no entry on purpose: a gate treats it as unknown, so tests that need a strong rail should load a test registry or use `ln:lnd`'s vector.

**Native kind labels** (Offer record 26, `kind`): `bolt11`, `l402-macaroon` (L402), `mpp-challenge` (MPP), `x402-requirements` (x402 on Lightning), `cashu-request` (Cashu NUT-24 locked).

## What downstream nodes must know

1. **Embed, do not re-derive.** Copy `registry/generated/registry.json` into Caparra (for example next to the crate that owns registry lookups) and `include_str!` it. Verify `digest` in a test: JCS via `serde_json_canonicalizer` and SHA-256 via `sha2`, both already workspace dependencies. Never take a property from plug code.
2. **IDs compare byte for byte.** `httpauth:DPoP`, `httpauth:L402`, `httpauth:Bearer` keep their IANA spelling. The registry rejects case variants, so a case-insensitive lookup can never find two entries, but the wire form must be the registered one.
3. **Class rules the entries rely on:** natives only for class O; route-scope offers only for class S and A; metered pay entries only with `refund = atomic` or `upto = true`; class none only at price 0, never waive, discount or quota; a quota only with a non-empty `quota_id`.
4. **Units:** a scheme's `units` lists what it can be offered in, and a rail's `units` what the credit it funds is denominated in. Non-sat credit never mixes into sat credit.
5. **The registry is regenerated, not edited.** Changes go into the TOML, then `validate.py --export`, then a fresh copy into Caparra.

## Decisions made

1. **Property tokens** that draft-00 does not spell out were fixed here (`rate`, `linkable`, `third-party`, `facilitator`, `online`, `reversible`, `freezable`, `final-at-settlement`, `third-party-custodial`, `self-custody`, `bearer`, `no`, `yes`, `experimental`, `standard`). They appear on the wire in a manifest's `require`.
2. **Entry layout follows draft-00 section 11:** `binding`, `use`, `refund` at the top level, the other nine in `properties`; the export adds the merged `vector`.
3. **Applicability:** each property names the entry kinds that carry it (properties.toml `applies_to`, pinned in validate.py). Every entry must state every applicable property and no other, so "unknown" never comes from the registry itself.
4. **Seeding is conservative:** where a value depends on the deployment or the specification leaves it open, the entry takes the weakest value. Every entry is `provisional` with an empty `conformance`.
5. **Theft:** only class S entries are `key-witnessed`; class O and none are `bearer` (draft-00 12, enforced), and class A is seeded as `bearer` too.
6. **Two IDs where one system has two classes:** `cashu:nut24` (locked, O) and `cashu:nut24@unlocked` (none); `httpauth:DPoP` (A) and `httpauth:Bearer` (none).
7. **IDs outside any source registry** go in the `vnd.` tree: `vnd.cfrg.act`, `vnd.cfrg.arc`, `vnd.world.world-id`, `vnd.hashcash.v1`, `vnd.techaro.anubis`, `vnd.cloudflare.pay-per-crawl`, `vnd.google.ap2`.
8. **x402 on Lightning** uses the mainnet network identifier the published spec gives: `x402:exact@lnbtc:000000000019d6689c085ae165831e93`. Its facilitator moves no funds and the resource server makes the invoice, so it is class O, self-issued and offline, with the facilitator as an optional verifier.
9. **Rail IDs** are `<rail kind>:<system>`, one per implementation the plug table names (Phoenixd, LND, LDK Node, CLN, NWC, Fedimint, Ark, Spark, Cashu mint), plus `onchain:bitcoin`, `evm:eip-3009`, `evm:tempo`, `card:stripe`. Non-Bitcoin and reversible rails must be `guarded`.
10. **Verifiers:** `local` is the neutral element (strongest everywhere); the three x402 facilitator trust levels from the overview are separate entries.
11. **Status:** `provisional`, `experimental`, `standard`, `does-not-fit`. A listed entry's status equals its `maturity` and needs a `conformance` URL.
12. **Spec examples are tests.** validate.py fails unless the data reproduces: the draft-00 section 11 `bnap:notes` entry; notes funded by card come out reversible and linkable; x402 through a custodial facilitator comes out custodial; the overview route example admits exactly notes, MPP Lightning and L402 at binding O and notes alone at binding A, and never a reusable bearer token; L402 is single; the draft-00 10.3 and 14 offers' class, metering and native constraints.
13. **ASCII only** in every registry file, enforced by the validator, which also keeps typographic dashes out.
14. **Export format:** sorted keys, two-space indent, trailing newline, so diffs stay readable; the JCS digest gives a stable identity for the content.

## Known gaps

- No conformance suite and no per-scheme test vectors exist, so nothing is listed; every vector is the expert seed.
- `vnd.cfrg.act`, `vnd.hashcash.v1`, `vnd.techaro.anubis` and the `evm:tempo` rail have empty `units` and cannot be offered or fund credit yet.
- Only one EVM network (Base, USDC), one MPP method (`lightning/charge`), one Privacy Pass token type (`0x0002`) and only x402 Lightning mainnet are registered.
- No rail kind exists for third-party ecash (Cashu NUT-24 tokens, Fedimint, Ark and Spark native transfers); `cashu:nut24` therefore returns no rail reference, which draft-00 6.1 requires (errata N2-13).
- `bnap:notes` lists only `sat` and the `ln` rail kind, as the draft-00 example does; Fiat-Funding notes need more (errata N2-15).
- How some adapters embed the OfferID or the Context is left to their adapter specs: the Cashu locking condition, the DPoP claim name, ARC and ACT details.
- The socket TLV type and error code registries of draft-00 section 13 are not in `registry/` yet.
- SASL, gRPC and WebSocket carriers are not registered: they are not in the plug catalogue and have no carrier note.
- `spec/README.md` and the root `README.md` do not link `registry/`; this node does not own them.

## Errata found (for the spec owner; spec/ERRATA.md was not edited)

| # | where | draft-00 says | other source or reading | registry's provisional resolution | owner decision needed |
| --- | --- | --- | --- | --- | --- |
| N2-1 | draft-00 11; overview, Scheme properties | Spells tokens for use, binding, refund and the strong values of its notes example | The overview names the other values in prose only | Tokens fixed in registry/README.md "Property tokens"; draft-00 should list them, since a manifest's `require` carries them | yes |
| N2-2 | draft-00 11 | Effective vector = per-property minimum over scheme, rail and verifier entries, unknown counted as weakest | Read literally, a rail entry without `binding` would make every effective binding `none` | Each property lists the kinds it applies to; only those entries take part | yes |
| N2-3 | draft-00 7 | "A route's require applies to attestations exactly as to value schemes" | `refund`, `finality`, `custody` and `link-payment` mean nothing for an attestation; literally, a `refund = atomic` route would reject every attestation | Those properties do not apply to attestations and do not constrain them | yes |
| N2-4 | draft-00 11 | "its scheme, rail and verifier" | A scheme can be configured with several rails (overview Caparra config: notes with `rails = ["ln", "ln2"]`) | Minimum over every configured rail, since a credential cannot show which one funded it | no |
| N2-5 | draft-00 13; overview, Naming | Rails and verifiers are registered; prefix rules cover scheme IDs only | No ID format for rail, verifier or carrier entries | Rails `<rail kind>:<system>`, verifiers `<name>[:<variant>]`, carriers the manifest names | yes |
| N2-6 | draft-00 11, 13 | Section 13: schemes, rails, verifiers by "Expert review" | Section 11 requires a public spec, vectors, conformance results and expert review, which is RFC 8126 Specification Required plus more | Specification Required with section 11's listing requirements | no |
| N2-7 | overview, Plug catalogue | One entry has one binding class | Cashu NUT-24 is "O when locked, else None"; OAuth is "A with DPoP, else None" | One ID per class: `cashu:nut24` and `cashu:nut24@unlocked`; `httpauth:DPoP` and `httpauth:Bearer` | yes |
| N2-8 | draft-00 4.1; overview, Plug catalogue | Units are sat, msat, ISO 4217 or CAIP-19 | Hashcash and Anubis are "Credential, unit work" | `units = []`: they cannot be offered until a work unit is defined | yes |
| N2-9 | draft-00 6.2; overview, Plug catalogue | `rate(k, epoch)` counts per UseId | ARC is "rate", but ARC tags differ per presentation, so no counter can be keyed on them | Keeps `use = rate` (the weaker reading); the limit is ARC's own presentation limit | yes |
| N2-10 | overview, Naming and Plug catalogue | IDs reuse source registries | ACT, ARC, World ID, Hashcash, Anubis, Cloudflare pay per crawl and AP2 have no ID in any listed registry | `vnd.` IDs (decision 7); ACT and ARC move to `pp:` once they get token types | yes |
| N2-11 | draft-00 12 | Class O is recorded as bearer | Nothing says what class A is; a class A artifact carries no TLS binding, so whoever sees it first can present it for the same request | Class A seeded as `bearer`; only class S is `key-witnessed` | yes |
| N2-12 | overview, Naming; ERRATA row 32 | n/a | Overview example `x402:exact@lnbtc`, "lnbtc is x402's own label, not CAIP-2"; the published spec names mainnet `lnbtc:000000000019d6689c085ae165831e93`, which is CAIP-2 shaped | `x402:exact@lnbtc:000000000019d6689c085ae165831e93`, following the rule "as x402 names them" | yes |
| N2-13 | draft-00 6.1 | A scheme MUST return a rail reference for every payment its credential relies on; kinds `ln`, `onchain`, `evm`, `card` | Third-party ecash (Cashu NUT-24 tokens from another mint) is itself the payment and fits no kind | `rail_kinds = []` and a note; a rail kind for ecash is needed | yes |
| N2-14 | draft-00 11 | `quota_id` is "attestations only" | Its own value-scheme example carries `quota_id = ""` | Present on every scheme entry, always empty when `role = value` | no |
| N2-15 | draft-00 11; overview, Value rails and Fiat-Funding | The notes example has `units = ["sat"]` | The overview funds notes credit by card or stablecoin in its own unit | The entry keeps `sat` and `ln`; Fiat-Funding notes need more units and rail kinds here, or a separate entry | yes |
| N2-16 | draft-00 4.1, 5.4; overview, Plug catalogue | Natives only for class O | x402 on EVM is class A because the client sets nonce = Context; tier-0 x402 clients choose their own nonce | No native path for x402 on EVM: only BNAP-aware clients can pay it. A consequence worth stating in the catalogue | no |

## Stop condition evidence

`python3 -I registry/validate.py` on the real files: `registry: valid (12 properties, 20 schemes, 13 rails, 5 verifiers, 4 carriers)`, exit 0, and `--check` confirms the committed export is current.

Broken copies made under the session scratch directory in `/tmp` (`<scratch>/broken/...`), each a copy of the registry with one change:

| Copy | Change | Output | Exit |
| --- | --- | --- | --- |
| `wrong-order` | `final-at-settlement` listed before `freezable` | `properties.toml: property[7] finality: values in the wrong order: weakest first must be reversible < freezable < final-at-settlement < final-on-verification, found reversible < final-at-settlement < freezable < final-on-verification` | 1 |
| `unknown-property` | `speed = "fast"` in `card:stripe`'s properties | `rails.toml: rail."card:stripe".properties: unknown property 'speed'` | 1 |
| `duplicate-id` | a second `[scheme."bnap:notes"]` table | `schemes.toml: TOML error: Cannot declare ('scheme', 'bnap:notes') twice (at line 442, column 21)` | 1 |
| `duplicate-id-case` | a copy of `httpauth:Bearer` as `httpauth:bearer` | `schemes.toml: scheme."httpauth:bearer": duplicate ID: schemes.toml: scheme."httpauth:Bearer" already uses it, ignoring case` | 1 |

`registry/test_validate.py` repeats these and covers the other checks (unknown values, missing and inapplicable properties, duplicate property definitions, prefix rules, class O theft, natives on class A, dangling references, guarded rails, units, unknown fields, non-ASCII text, a pinned `applies_to`, the spec's worked examples, a stale export): 27 tests, all passing.

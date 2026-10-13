# BNAP registry

Spec text licensed CC-BY-4.0, (c) BNAP contributors. Code (`validate.py`, `test_validate.py`) is MIT OR Apache-2.0.

This directory is the registry that [socket draft-00](../spec/socket-draft-00.md) sections 11 and 13 ask for: the scheme properties and their order, and one entry per credential scheme, attestation scheme, rail, verifier and carrier. A gate learns everything it trusts about a plug from here, never from the plug. The design comes from the overview's [Scheme properties and route policy](../spec/overview-v0.5.md#scheme-properties-and-route-policy) and [Naming and the registry](../spec/overview-v0.5.md#naming-and-the-registry) sections; draft-00 wins where they differ.

**Status:** pre-alpha. Every entry is `provisional`: no conformance suite exists yet, so no entry is listed in the sense of draft-00 section 11.

## Policy

- **Specification Required** ([RFC 8126 section 4.6](https://www.rfc-editor.org/rfc/rfc8126.html#section-4.6)), with a designated expert. The maintainer of this repository is the designated expert.
- To be **listed**, an entry needs all four things draft-00 section 11 names: a public specification, test vectors, passing conformance results, and review by the designated expert.
- The registry lives in this repository until two independent implementations of the socket exist. It then moves to IANA, with every ID, value and order carried over unchanged.
- Rail kinds and carriers follow the same policy (draft-00 section 13). The socket TLV types (Standards Action) and error codes above 1,000 (Specification Required) are registries too, but they are not in this directory yet.

Draft-00 section 13 calls the scheme registry "Expert review"; section 11's listing requirements are Specification Required plus more, so this registry applies section 11.

## How properties are set

- **From conformance results.** When an entry is listed, the designated expert sets each property to what the conformance results show. Where the suite cannot show a property, the entry takes the weakest value the scheme's specification guarantees.
- **Never by plugins at runtime.** A gate reads property vectors from the export compiled into it, keyed by scheme, rail and verifier ID. Whatever a plug says about itself is ignored (draft-00 section 11; the overview's `CredentialScheme::id` comment: "properties come from the registry, not from here").
- **Seed entries** (`provisional`) were set by the designated expert from each system's specification, before any suite existed, and conservatively: where a value depends on the deployment, or the specification does not settle it, the entry takes the weakest value. Each entry's `notes` says why where that matters.
- **Changing a value** is a pull request. Raising a value needs evidence (conformance results, or a specification change). Lowering one needs only a credible report, because an overstated property lets a weak scheme satisfy a strong route.

## Files

| File | Holds |
| --- | --- |
| [properties.toml](properties.toml) | The twelve properties, their values weakest first, where each lives in an entry, and the entry kinds it applies to |
| [schemes.toml](schemes.toml) | Credential and attestation schemes (`[scheme."<id>"]`), including systems that do not fit |
| [rails.toml](rails.toml) | Rail kinds (`[rail_kind.<id>]`) and rail entries (`[rail."<id>"]`) |
| [verifiers.toml](verifiers.toml) | Verifiers (`[verifier."<id>"]`) |
| [carriers.toml](carriers.toml) | Carriers (`[carrier.<id>]`) |
| [schema.json](schema.json) | JSON Schema (2020-12) for each file, read as JSON |
| [validate.py](validate.py) | The validator and exporter; standard library only, Python 3.11 or later |
| [test_validate.py](test_validate.py) | Its tests: the real registry passes, broken copies fail |
| [generated/registry.json](generated/registry.json) | The canonical export the Rust code embeds. Generated; never edit it by hand |

All registry files are ASCII; `validate.py` rejects any other byte.

## Properties

Values are listed weakest first. The order is security relevant: a route that requires a value admits that value and every stronger one. `validate.py` pins the order to the spec, so a reordering fails validation.

| Property | Values, weakest first | Applies to |
| --- | --- | --- |
| `use` | `reusable`, `rate`, `single` | credential, attestation |
| `binding` | `none`, `O`, `A`, `S` | credential, attestation |
| `theft` | `bearer`, `key-witnessed` | credential, attestation |
| `link-payment` | `linkable`, `unlinkable` | credential, rail |
| `link-actions` | `linkable`, `unlinkable` | credential, attestation |
| `issuer` | `third-party`, `facilitator`, `self-issued` | credential, attestation, verifier |
| `verify` | `online`, `offline` | credential, attestation, verifier |
| `finality` | `reversible`, `freezable`, `final-at-settlement`, `final-on-verification` | credential, rail, verifier |
| `custody` | `third-party-custodial`, `operator-iou`, `self-custody` | credential, rail, verifier |
| `refund` | `none`, `out-of-band`, `atomic` | credential |
| `pq` | `no`, `yes` | credential, attestation, rail |
| `maturity` | `experimental`, `standard` | credential, attestation, rail, verifier |

Units are not a property: each pay entry carries its own unit, and a scheme entry lists the units it supports.

**Property tokens.** Draft-00 section 11 spells out `single`, `rate`, `reusable`; `S`, `A`, `O`, `none`; `none`, `out-of-band`, `atomic`; and the strong values in its `bnap:notes` example. The overview names the rest in prose. This registry fixes those as `linkable`, `third-party`, `facilitator`, `online` (the overview's "online facilitator"), `reversible`, `freezable`, `final-at-settlement`, `third-party-custodial`, `self-custody` (the overview's "client self-custody"), `bearer`, `no`, `yes`, `experimental` and `standard`.

## Rules a gate applies

1. **Unknown counts as weakest.** A property an entry should state but does not, a value the gate does not recognize, and a rail or verifier with no entry all count as the property's weakest value. The registry itself never leaves a property unknown: every entry states every property that applies to its kind.
2. **Effective vector.** For each pay entry, the gate takes the per-property minimum over its scheme, its rails and its verifier (draft-00 section 11). Notes funded by card come out reversible and linkable to the payer; x402 through a custodial facilitator comes out custodial.
3. **Applicability.** The effective vector has the properties that apply to the scheme's kind. For each one, only the entries whose kind it applies to take part: a rail adds nothing to `binding`, a verifier nothing to `link-payment`.
4. **Several rails.** When a scheme is configured with several rails, all of them take part, because a credential cannot show which rail funded it.
5. **Route policy** (`require`) is checked per property; there is no overall score. A property that does not apply to an entry, such as `refund` for an attestation, does not constrain it.
6. **Experimental** entries, by `maturity`, need `allow_experimental` on each route that uses them.
7. **Configuration errors stop the gate.** A route that names an ID with no entry, a `does-not-fit` entry, a rail whose kind the scheme does not list, or a verifier the scheme does not list, is refused at start, and so is a route no enabled scheme can satisfy.
8. **Rules the entries encode.** A metered pay entry needs `refund = atomic` or `upto = true` (draft-00 7). Route-scope offers carry class S and A schemes only (draft-00 4.3). Natives exist only for class O. Class none is admissible only at price 0 and never waives, discounts or carries a quota (draft-00 7 and DECISIONS row 25). A quota needs a non-empty `quota_id`.

`validate.py --effective` computes rules 1 to 5 for one pay entry:

```sh
python3 -I registry/validate.py --effective bnap:notes --rail ln:phoenixd --verifier local \
    --require use=single,binding=A,link-actions=unlinkable
```

## IDs

IDs are unique across all files, compared without regard to case.

**Scheme IDs** reuse existing registries as `<registry>:<id>[@<qualifier>]`, so BNAP never renames anything:

| Prefix | Source registry | Rule | Examples |
| --- | --- | --- | --- |
| `bnap:` | BNAP's own schemes | `bnap:<name>`, lower case | `bnap:notes` |
| `payment:` | HTTP Payment Methods and Intents (draft-httpauth-payment) | `payment:<method>/<intent>`, lower case | `payment:lightning/charge` |
| `x402:` | x402 schemes and networks | `x402:<scheme>@<network>`; the network is required, as x402 names it (CAIP-2 for EVM chains) | `x402:exact@eip155:8453` |
| `pp:` | Privacy Pass token types | `pp:0x` and four lower-case hex digits | `pp:0x0002` |
| `httpauth:` | HTTP Authentication Schemes | spelled as the IANA registry spells it | `httpauth:L402`, `httpauth:DPoP` |
| `httpsig:` | HTTP message signature tags | lower case | `httpsig:web-bot-auth` |
| `cashu:` | Cashu NUTs | `cashu:nut<NN>` | `cashu:nut24` |
| `nip:` | Nostr NIPs | `nip:<NN>`, digits and upper-case hex as the NIPs repository numbers them | `nip:98` |
| `vnd.` | Unregistered vendor schemes | `vnd.<vendor>.<name>`, lower case | `vnd.cfrg.act` |

Any ID may end in `@<qualifier>`; this registry uses one for a second binding class of the same system (`cashu:nut24@unlocked`). Scheme IDs are compared byte for byte on the wire (offers, Context), so the registered spelling is the only one: HTTP treats `DPoP` and `dpop` as the same scheme, and so does the uniqueness check here.

**Rail IDs** are `<rail kind>:<system>`, such as `ln:phoenixd`; the prefix must be a registered rail kind and equal the entry's `rail_kind`. **Verifier IDs** are `<name>[:<variant>]`, such as `x402-facilitator:custodial`. **Carrier IDs** are the names the manifest's `carriers` member uses (draft-00 9.1), such as `http`.

## Entry format

Every entry has `name`, `kind`, `status`, `source` (where in the spec the system comes from), `spec` (a public reference URL) and `notes`. An entry with status `does-not-fit` adds `reason` and carries no property vector.

**Scheme entries** (`schemes.toml`) follow the layout of draft-00 section 11:

| Field | Value |
| --- | --- |
| `kind` | `credential` or `attestation` |
| `role` | draft-00's role: `value` (with kind credential), `attestation`, or `both` |
| `binding`, `use`, `refund` | Property values, at the top level as in draft-00 section 11. `refund` is for credentials only |
| `properties` | The other properties that apply to the entry's kind |
| `upto` | Credentials: whether the scheme can settle a lower amount than it authorized |
| `local_id` | What the scheme's `verify` returns as local IDs |
| `quota_id` | Attestations: the stable identity a quota counts against, or empty if the scheme cannot carry a quota. Always empty for `role = "value"` |
| `rail_refs` | Credentials: the rail references the scheme returns |
| `rail_kinds` | Credentials: the rail kinds it may be configured with |
| `verifiers` | The verifier IDs it may be configured with |
| `body`, `witness` | What the scheme puts in each half of its credential (draft-00 5.1) |
| `native` | Credentials of class O: native artifact kinds, each with how it embeds the OfferID and what the native credential bytes are (draft-00 4.1 and 5.4) |
| `units` | Credentials: the units it can be offered in. Empty means it cannot be offered yet |
| `conformance` | URL of the conformance results, or empty |

**Rail kinds** (`[rail_kind.<id>]` in `rails.toml`) have `name`, `canonical` (the canonical payment bytes of draft-00 6.1), `spec` and `status`.

**Rail entries** add `rail_kind`, `properties`, `units` (what the credit they fund is denominated in), `guarded` (off by default; required for every non-Bitcoin or reversible rail) and `conformance`.

**Verifier entries** add `trust` (`local`, `non-custodial-relay`, `custodial` or `merchant-of-record`, the levels the overview asks facilitators to declare), `properties` and `conformance`.

**Carrier entries** add `scope`, `transport` and `tls_binding` (whether a gate on this carrier can usually see the client's TLS session). Carriers have no property vector.

## Statuses

| Status | Meaning |
| --- | --- |
| `provisional` | Seeded by the designated expert from the system's specification; no conformance results yet. Gates may use it; nothing better exists yet |
| `experimental` | Listed, with conformance results; its `maturity` is `experimental` |
| `standard` | Listed, with conformance results; its `maturity` is `standard` |
| `does-not-fit` | Tested against the socket and cannot plug in; `reason` says why. Kept so that nobody files it again. A gate never loads it |

A listed entry's status always equals its maturity, and it always has a `conformance` URL.

## Validating and exporting

```sh
python3 -I registry/validate.py            # validate; exit 1 and one line per error if invalid
python3 -I registry/validate.py --export   # validate, then write generated/registry.json
python3 -I registry/validate.py --check    # validate, and fail if the export is stale
python3 -I registry/test_validate.py       # the tests
```

`validate.py` checks each file against `schema.json` (it implements the JSON Schema keywords the schema uses and refuses any other), then the value orders against the spec, each entry's vector against the kinds each property applies to, the prefix rules, uniqueness, cross references, the invariants draft-00 states about classes, natives and quotas, and the worked examples in the spec, which the data must reproduce.

**The export** is one JSON object: `format`, `generated_by`, `properties` (in vector order, each with its values weakest first), `rail_kinds`, `schemes`, `rails`, `verifiers` and `carriers` (maps by ID), and `digest`. Each scheme, rail and verifier carries its source fields plus `kind` and `vector`, the full map of the properties that apply to its kind; a `does-not-fit` entry's vector is empty. The file is written with sorted keys and two-space indentation, so the same registry always gives the same bytes. `digest` is the hex SHA-256 of the RFC 8785 (JCS) serialization of the export without `digest`, so a gate can name the registry it runs.

## Proposing an entry

1. Open an issue naming the system and linking its public specification.
2. Add the entry in a pull request: the ID under the prefix rules, every applicable property, and the evidence for each value. Without conformance results the entry is `provisional`.
3. Run `validate.py --export` and commit the regenerated export with the entry.
4. The designated expert reviews it. An entry is listed, and becomes `experimental` or `standard`, once its test vectors and conformance results are published.

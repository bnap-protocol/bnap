# Changelog

All notable changes to the BNAP specification and this repository are
recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The specification
is versioned by draft number (draft-00), not by semantic versioning.

## [Unreleased]

Nothing has been released. What exists on `develop`:

### Added

- `spec/socket-draft-00.md`, the normative socket specification (doc
  rev 39), and `spec/overview-v0.5.md`, the design overview v0.5.1.
- `spec/schemes/bnap-notes-draft-00.md`, the `bnap:notes` scheme in
  draft-00 terms, next to the superseded v0.4 profile.
- `spec/ERRATA.md` (35 rows; row 35: the MPP OfferID goes in `opaque`
  under the HMAC'd `id`, and a `bolt11` entry is optional for MPP) and `spec/DECISIONS.md` (8 provisional
  decisions awaiting owner review).
- The v0.2 and v0.3 archives under `spec/history/`.
- `reference/python/bnap_ref.py`, the standard-library reference encoder,
  and `vectors/vectors.json`, which it reproduces byte for byte.
- `registry/`: schemes, rails, verifiers, carriers and properties in TOML,
  a validator with tests, and the generated export
  `registry/generated/registry.json`. Every entry is provisional.
- `conformance/`: a client library, 535 generated cases in
  `vectors/cases/`, the black-box runner `run.py` with client, server and
  gateway profiles, a mock gate with injectable faults (among them
  `mpp-opaque-wrong` and `mpp-header-differs`, caught by
  `OFR-NATIVE-EMBED` and `OFR-NATIVE-MATCH`), an lnd payer
  wrapper, and a coverage map of every BCP 14 sentence of draft-00.
- `ietf/`: the Internet-Draft `draft-bnap-socket`, generated from
  draft-00.
- `nuts/`: two Cashu NUT proposals (key-secret proofs, HTTP 402 with a
  self-issued mint) with their vector tools.
- `docs/payment-method-cashu.md`, a draft registration of the `cashu` HTTP
  payment method.
- The mdBook at <https://bnap-protocol.github.io/bnap/>, CI (leak guard,
  DCO, vectors, registry, book) and the repository templates.

[Unreleased]: https://github.com/bnap-protocol/bnap/commits/develop

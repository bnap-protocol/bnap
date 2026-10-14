"""bnap_conf: a BNAP socket draft-00 client library for conformance testing.

Built only from spec/socket-draft-00.md, spec/ERRATA.md, spec/DECISIONS.md,
the registry export and the reference encoder (reference/python/bnap_ref.py),
which it imports for every primitive. Standard library only, Python 3.11+.
Not constant time: a test tool.

Modules:
  codec       BigSize, tu64, TLV streams, entry lists, base64url, Error TLV
  crypto      BIP-340 (from the reference) and ECDSA P-256 (for DPoP)
  offer       Offer parse, rules, OfferID, offer_sig, client and gate checks (4)
  credential  Credential parse and build, Context, Digest, ReplayKey, UseId,
              RailId, native envelope (5, 6.1)
  response    Response parse, ack, client receipt checks (8.1, 9.3)
  manifest    strict JSON, JCS, root signature, document checks, pinning (9)
  http        HTTP scopes, route matching, challenges, SSE, a raw client (10)
  pricing     price(), admit, metering (7)
  store       the use store as a state machine (6.3, 6.4)
  client      client choice rules, bnap-required, native challenges (4.4, 9.3)
  dpop        the httpauth:DPoP adapter profile used by the suite
  lightning   BOLT 11, L402 macaroons, the MPP profile used by the suite
  notes       bnap:notes stub (the draft-00 notes spec is not on develop)
  registry    the scheme registry export
"""
from . import codec, crypto, offer, credential, response, manifest, http, pricing, store  # noqa: F401
from . import client, dpop, lightning, notes, registry  # noqa: F401

__all__ = ["codec", "crypto", "offer", "credential", "response", "manifest", "http", "pricing",
           "store", "client", "dpop", "lightning", "notes", "registry"]

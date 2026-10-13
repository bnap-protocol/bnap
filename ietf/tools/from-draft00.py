#!/usr/bin/env python3
"""Derive the Internet-Draft source draft-bnap-socket.md from spec/socket-draft-00.md.

Standard library only. Run from the ietf/ directory:

    python3 -I tools/from-draft00.py ../spec/socket-draft-00.md > draft-bnap-socket.md

The normative text of draft-00 is kept. The script only:

- adds the kramdown-rfc front matter, the abstract and the references;
- turns "## N. Title" headings into kramdown-rfc sections (same order, so the
  section numbers of draft-00 stay valid);
- transliterates the non-ASCII symbols to ASCII (see CONVERSIONS below);
- re-wraps the twelve code blocks to at most 72 columns (BLOCKS below);
- replaces the BCP 14 sentence with the kramdown-rfc boilerplate, turns
  "RFC NNNN" into citations, and cites other documents at first mention;
- renames sections 1, 12 and 13 to the names an Internet-Draft needs and adds
  the IANA registration templates and a short security paragraph.

If draft-00 changes, rerun this script and review the diff. A code block whose
source changed makes the script stop, so the hand-wrapped copy cannot go stale.
"""
import hashlib
import re
import sys

# ---------------------------------------------------------------- front and back matter

FRONT = r'''---
title: "BNAP: A Socket for Priced and Permissioned Actions"
abbrev: "BNAP Socket"
category: exp
docname: draft-bnap-socket-latest
submissiontype: IETF
number:
date:
consensus: false
v: 3
keyword:
 - payment
 - HTTP 402
 - admission control
 - receipts
venue:
  github: "bnap-protocol/draft-bnap-socket"
  latest: "https://bnap-protocol.github.io/draft-bnap-socket/draft-bnap-socket.html"

author:
 -
    org: BNAP contributors
    email: bnap-protocol@users.noreply.github.com

normative:
  RFC2104:
  RFC4648:
  RFC6234:
  RFC6454:
  RFC8615:
  RFC8785:
  RFC9110:
  RFC9111:
  RFC9266:
  RFC9530:
  BIP340:
    title: "Schnorr Signatures for secp256k1"
    target: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    author:
      - name: Pieter Wuille
      - name: Jonas Nick
      - name: Tim Ruffing
    date: 2020-01-19
  BOLT1:
    title: "BOLT #1: Base Protocol"
    target: https://github.com/lightning/bolts/blob/master/01-messaging.md
    author:
      - org: Lightning Network specification contributors
  ISO4217:
    title: "Codes for the representation of currencies"
    author:
      - org: International Organization for Standardization
    seriesinfo:
      ISO: "4217:2015"
    date: 2015-08
  CAIP2:
    title: "CAIP-2: Blockchain ID Specification"
    target: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
    author:
      - org: Chain Agnostic Standards Alliance
  CAIP19:
    title: "CAIP-19: Asset Type and Asset ID Specification"
    target: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-19.md
    author:
      - org: Chain Agnostic Standards Alliance

informative:
  RFC8126:
  RFC8792:
  RFC9449:
  RFC9576:
  BOLT12:
    title: "BOLT #12: Negotiation Protocol for Lightning Payments"
    target: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
    author:
      - org: Lightning Network specification contributors
  BNAP-OVERVIEW:
    title: "BNAP: a universal plug for priced and permissioned actions, Draft Specification v0.5.1"
    target: https://github.com/bnap-protocol/bnap/blob/develop/spec/overview-v0.5.md
    author:
      - org: BNAP contributors
    date: 2026-10
  BNAP-NOTES:
    title: "bnap:notes, scheme draft-00"
    target: https://github.com/bnap-protocol/bnap/blob/develop/spec/schemes/bnap-notes-draft-00.md
    author:
      - org: BNAP contributors
    date: 2026-10
  BNAP-REF:
    title: "BNAP socket draft-00 reference encoder"
    target: https://github.com/bnap-protocol/bnap/blob/develop/reference/python/bnap_ref.py
    author:
      - org: BNAP contributors
    date: 2026-10
  BNAP-VECTORS:
    title: "BNAP socket draft-00 test vectors"
    target: https://github.com/bnap-protocol/bnap/blob/develop/vectors/vectors.json
    author:
      - org: BNAP contributors
    date: 2026-10
  BNAP-REPO:
    title: "BNAP specification repository"
    target: https://github.com/bnap-protocol/bnap
    author:
      - org: BNAP contributors
    date: 2026-10
  CASHU-NUTS:
    title: "Cashu NUTs (Notation, Usage, and Terminology)"
    target: https://github.com/cashubtc/nuts
    author:
      - org: Cashu contributors
  L402:
    title: "bLIP-26: L402, the Lightning HTTP 402 Protocol (open pull request)"
    target: https://github.com/lightning/blips/pull/26
    author:
      - org: Lightning Labs
  MPP:
    title: "The \"Payment\" HTTP Authentication Scheme"
    target: https://datatracker.ietf.org/doc/html/draft-httpauth-payment-01
    author:
      - ins: B. Ryan
      - ins: J. Moxey
      - ins: T. Meagher
      - ins: J. Weinstein
      - ins: S. Kaliski
    seriesinfo:
      Internet-Draft: draft-httpauth-payment-01
    date: 2026-09-09
  X402:
    title: "x402 Specification, version 2"
    target: https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md
    author:
      - org: x402 contributors
  WEB-BOT-AUTH:
    title: "HTTP Message Signatures for automated traffic"
    target: https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/
    author:
      - ins: T. Meunier
      - ins: S. Major
    seriesinfo:
      Internet-Draft: draft-meunier-webbotauth-httpsig-protocol-02
  MCP:
    title: "Model Context Protocol Specification"
    target: https://modelcontextprotocol.io/specification
    author:
      - org: Model Context Protocol contributors

--- abstract

This document defines the BNAP socket: the part every deployment of
the Blind-Note Admission Protocol shares.  A gate in front of an
application answers an unpaid request with a signed Offer that prices
one action or one route and lists every credential scheme the server
accepts.  The client returns a Credential that names the offer, binds
itself to the exact request, and carries at most one value proof plus
any number of attestations.  The gate verifies it through scheme
plugs, prices it, commits every use ID once in a durable use store,
runs the action, and returns a signed Response that serves as a
receipt.  The document specifies the byte layouts, the hashing and
replay rules, pricing with attestations and metering, errors, a signed
manifest with key pinning, and an HTTP carrier.  It defines no
credential scheme itself.

--- middle
'''

NOTE_TO_READERS = '''
This Internet-Draft is the IETF rendering of the BNAP socket draft-00
kept in the BNAP repository {{BNAP-REPO}}, file
`spec/socket-draft-00.md` at doc revision 39.  The normative text is
the same.  Symbols are written in ASCII (`||` for concatenation,
`ceil()` and `floor()` for rounding, `_1` for subscripts), and long
code lines are wrapped.  Comments that draft-00 sets off from code by
spacing alone are marked with `#` here, so that a comment moved onto
its own line cannot be read as a statement.  Where the two differ,
the repository file is the reference until this draft replaces it.
'''

SECURITY_ADDITION = '''
Each credential scheme, rail and verifier carries its own security
considerations in its registry specification; for the default scheme
see {{BNAP-NOTES}}.  Schemes are untrusted by design (Section 6.1),
so this document's guarantees do not depend on any one of them.
'''

IANA_ADDITION = '''
## HTTP Authentication Scheme {#iana-auth-scheme}

IANA is asked to register the following in the "HTTP Authentication
Schemes" registry ({{Section 16.4.1 of RFC9110}}):

Authentication Scheme Name:
: BNAP

Reference:
: Section 10.2 of this document

Notes:
: Used in challenges only.  Credentials travel in the BNAP-Credential
  field, so that the Authorization field stays free for the
  application's own credentials.

## HTTP Field Names {#iana-fields}

IANA is asked to register the following in the "Hypertext Transfer
Protocol (HTTP) Field Name Registry" ({{Section 16.3.1 of RFC9110}}):

| Field Name | Status | Structured Type | Reference |
| --- | --- | --- | --- |
| BNAP-Credential | provisional | | Section 10.2 of this document |
| BNAP-Receipt | provisional | | Section 10.2 of this document |
| BNAP-Error | provisional | | Section 10.2 of this document |
| BNAP-Context | provisional | | Section 10.2 of this document |

## Well-Known URI {#iana-well-known}

IANA is asked to register the following in the "Well-Known URIs"
registry ({{RFC8615}}):

URI Suffix:
: bnap

Change Controller:
: IETF

Specification Document:
: Section 9.1 of this document

Status:
: provisional

Related Information:
: None

## BNAP Registries {#iana-bnap-registries}

The registries in the table above are held in the BNAP repository
{{BNAP-REPO}}, with the maintainer as designated expert, until two
independent implementations exist.  At that point this document asks
IANA to create a "Blind-Note Admission Protocol (BNAP)" registry
group holding them, with the policies listed above as defined in
{{RFC8126}}: "Standards Action" for socket TLV types, "Specification
Required" for error codes above 1,000, rail kinds and carriers, and
"Expert Review" for schemes, rails and verifiers.  The initial
contents are the values this document defines: the type ranges of
Section 2, the records of Sections 4.1, 5.1 and 8.1, the codes of
Section 8.2, the rail kinds of Section 6.1, and the carrier `http` of
Section 10.

A scheme, rail or verifier entry follows the form of Section 11.
Experts check that the entry has a public specification, test
vectors and passing conformance results, and that its property vector
matches those results.
'''

BACK = '''
--- back

# Acknowledgments
{:numbered="false"}

This document grew out of four design rounds and independent reviews
recorded in the BNAP overview {{BNAP-OVERVIEW}}.  The reference
encoder {{BNAP-REF}} and the vectors {{BNAP-VECTORS}} were reproduced
from the prose by an independent reviewer.
'''

# ---------------------------------------------------------------- headings

RENAME = {
    "Status and scope": "Introduction",
    "Security considerations": "Security Considerations",
    "Registry considerations": "IANA Considerations",
}

# ---------------------------------------------------------------- symbol conversions

SUB = {"₀": "_0", "₁": "_1", "₂": "_2", "ₙ": "_n", "ₕ": "_h", "ₘ": "_m"}
SUP = {"2⁶⁴": "2^64", "2³²": "2^32", "2⁵³": "2^53"}
SIMPLE = {"…": "...", "–": "-", "≤": "<=", "−": "-", "×": "*"}


def ascii_code(s):
    """Transliterate inside code (spans or blocks): no markdown escaping."""
    s = re.sub(r"⌈(.*?)⌉", r"ceil(\1)", s)
    s = re.sub(r"⌊(.*?)⌋", r"floor(\1)", s)
    for a, b in SUP.items():
        s = s.replace(a, b)
    for a, b in SIMPLE.items():
        s = s.replace(a, b)
    for a, b in SUB.items():
        s = s.replace(a, b)
    return s.replace("‖", "||")


def ascii_text(s, in_table):
    """Transliterate markdown text: escape what markdown would interpret."""
    s = re.sub(r"⌈(.*?)⌉", r"ceil(\1)", s)
    s = re.sub(r"⌊(.*?)⌋", r"floor(\1)", s)
    for a, b in SUP.items():
        s = s.replace(a, b)
    s = s.replace("×", "\\*")
    for a, b in SIMPLE.items():
        s = s.replace(a, b)
    for a, b in SUB.items():
        s = s.replace(a, b.replace("_", "\\_"))
    return s.replace("‖", "\\|\\|" if in_table else "||")


def code_to_table_text(span):
    """A code span holding a concatenation, inside a table row: kramdown
    splits cells on pipes, so the span becomes escaped text."""
    inner = ascii_code(span[1:-1])
    for ch in "\\_*|[]":
        inner = inner.replace(ch, "\\" + ch)
    return inner


def cite(s):
    s = re.sub(r"RFC (\d{4}) section (\d+(?:\.\d+)*)", r"{{Section \2 of RFC\1}}", s)
    s = re.sub(r"RFC (\d{4})", r"{{RFC\1}}", s)
    return s


# First-mention citations: (regex on markdown text, replacement). Applied once.
FIRST = [
    (r"BIP-340(?! signature)", r"BIP-340 {{BIP340}}"),
    (r"BOLT 1(?!\d)", r"BOLT 1 {{BOLT1}}"),
    (r"BOLT 12", r"BOLT 12 {{BOLT12}}"),
    (r"SHA-256", r"SHA-256 {{RFC6234}}"),
    (r"ISO 4217 code", r"ISO 4217 {{ISO4217}} code"),
    (r"CAIP-19 asset ID", r"CAIP-19 {{CAIP19}} asset ID"),
    (r"CAIP-2(?!\d)", r"CAIP-2 {{CAIP2}}"),
    (r"HMAC-SHA256", r"HMAC-SHA256 {{RFC2104}}"),
    (r"Web Bot Auth(?!')", r"Web Bot Auth {{WEB-BOT-AUTH}}"),
    (r"DPoP proof", r"DPoP proof {{RFC9449}}"),
    (r"Privacy Pass", r"Privacy Pass {{RFC9576}}"),
    (r"x402", r"x402 {{X402}}"),
    (r"the MCP carrier note", r"the MCP {{MCP}} carrier note"),
]

# Exact phrases replaced once, in markdown text (after transliteration).
PHRASES = [
    ("It turns the design in the first tab (v0.5.1) into",
     "It turns the design of the BNAP v0.5.1 overview {{BNAP-OVERVIEW}} into"),
    ("Where this draft and the first tab differ,", "Where this draft and the overview differ,"),
    ("It does not define any credential scheme: `bnap:notes`, L402, MPP and the rest",
     "It does not define any credential scheme: `bnap:notes` {{BNAP-NOTES}}, L402 {{L402}}, "
     "MPP {{MPP}} and the rest"),
    ("Nothing in this draft depends on Cashu,", "Nothing in this draft depends on Cashu {{CASHU-NUTS}},"),
    ("The threat table in the first tab still applies.",
     "The threat table of the overview {{BNAP-OVERVIEW}} still applies."),
    ("This draft changes the first tab's design in these places. The first tab will be brought into line.",
     "This draft changes the design of the overview {{BNAP-OVERVIEW}} in these places. "
     "The overview will be brought into line."),
    ("of standard-library Python (`bnap_ref.py`).", "of standard-library Python (`bnap_ref.py` {{BNAP-REF}})."),
    ("is in `vectors.json`.", "is in `vectors.json` {{BNAP-VECTORS}}."),
    ("so {{RFC9111}}'s rule against storing", "so the rule of {{RFC9111}} against storing"),
]

# ---------------------------------------------------------------- code blocks, re-wrapped

# (fence info, replacement text), in the order the blocks appear in draft-00
BLOCKS = [
    ("ascii-art", r"""
Client                  Gate: socket + plugs             Application
  |                          |                                 |
  |-- request, no credential |                                 |
  |------------------------->| carrier computes the            |
  |                          |   action scope                  |
  |<-- 402 + Offer ----------|                                 |
  |    (+ native challenges) |                                 |
  |-- request + Credential ->| 1 parse, check the Offer,       |
  |                          |   scope, expiry                 |
  |                          | 2 scheme.verify -> use IDs,     |
  |                          |   rail IDs, value               |
  |                          | 3 price with attestations,      |
  |                          |   check value                   |
  |                          | 4 commit: every ID + ReplayKey, |
  |                          |   PENDING, atomic, durable      |
  |                          |----------- action ------------->|
  |                          |<---------- result --------------|
  |                          | 5 settle OK or FAILED once;     |
  |                          |   scheme.settle                 |
  |<-- result + Response ----|                                 |
  |    (signed receipt)      |                                 |
"""),
    ("pseudocode", r"""
action_scope = the carrier's scope of THIS request
               (equals the offer's scope in exact mode)

Context = H_"bnap/ctx"( OfferID || action_scope
                        || lp(pay scheme ID, or empty)
                        || BigSize(n) || lp(attest scheme ID_1) || ...
                        || lp(attest scheme ID_n)
                        || H(ext value, or empty) )

Digest  = H_"bnap/cred"( Context || lp(binding, or empty)
                         || H(pay body, or empty)
                         || H(attest body_1) || ...
                         || H(attest body_n) )

n may be 0. "Or empty" is the empty byte string of section 2.
"""),
    ("pseudocode", r"""
Context = H_"bnap/ctx-native"( OfferID || action_scope
                               || lp(scheme ID) )
Digest  = H_"bnap/cred-native"( Context
                                || H(native credential bytes) )
"""),
    ("pseudocode", r"""
UseId     = H_"bnap/use"( lp(scheme ID) || local ID )
RailId    = H_"bnap/rail"( lp(rail kind) || canonical payment bytes )
ReplayKey = H_"bnap/replay"( Context || H(pay body, or empty)
                             || H(attest body_1) || ...
                             || H(attest body_n)
                             || BigSize(m) || id_1 || ... || id_m )
            # ids sorted bytewise
"""),
    ("pseudocode", r"""
commit(rk, singles, counters):
    # singles = single UseIds and RailIds; counters = (key, limit)
  if outcome[rk] exists:           return Replay(outcome[rk])
  for id in singles:
      if used[id] exists:          abort, return SPENT
  for (key, limit) in counters:
      if counter[key] >= limit:    abort, return RATE_LIMITED
  for id in singles:               used[id] = rk
  for (key, limit) in counters:    counter[key] += 1
  outcome[rk] = { status: PENDING, created: now, counters: [keys],
                  charged: none, scheme_result: none,
                  response: none }
  return New
"""),
    ("pseudocode", r"""
price(base):
    # base = entry.amount, or the metered amount at settlement
  p = base
  for each verified attestation, in offer order, effect waive:
      p = 0
  for each verified attestation, in offer order, effect discount:
      p = p - floor(p * value / 10000)
  if p > 0: for the first verified quota attestation, in offer
            order, whose counter has room:
      p = 0, and add its counter to the commit
  return p

admit:
  for each required attestation in the offer:
      if not verified                                 -> POLICY
  p = price(entry.amount, or 0 if the credential has no pay)
  if p > 0 and no pay                                 -> UNDERPAID
  if the scheme's verified value < p                  -> UNDERPAID
"""),
    ("pseudocode", r"""
fetch(origin):
    # HTTPS only, certificate valid for origin; at most once per
    # 5 minutes
  m = GET https://origin/.well-known/bnap
  require m.bnap == 1, m.origin == origin, m.sig valid under m.root
  require m.issued - 60 <= now <= m.issued + m.max_age + 60
  if pin[origin] is live:
      require m.root == pin.root and m.backup == pin.backup,
           or m.root == pin.backup               # a rotation
      require m.seq > pin.seq, or H(m bytes) == pin.hash
  pin[origin] = {root: m.root, backup: m.backup, seq: m.seq,
                 hash: H(m bytes), required: m.required,
                 keys: m.keys,
                 until: min(m.issued + m.max_age, now + 30 days)}

on an offer:   offer_key listed in the pin with use "offer",
               not_after >= now; otherwise fetch(origin), then
               reject
on a receipt:  receipt_key listed in the pin with use "receipt",
               not_after >= settled_at; without replayed,
               settled_at within 60 s of the client's clock on
               arrival
on a 402 from an origin pinned with required = true:
               pay only through a BNAP offer that passes 4.4,
               never through a native header, until the pin
               lapses
always:        pay a native challenge only if its bytes equal a
               native entry of an offer that passes 4.4, or the
               client has no pin for the origin
"""),
    ("pseudocode", r"""
action scope = H_"bnap/scope/http"( lp(method) || lp(target)
                   || lp(content hash, or empty)
                   || BigSize(h) || lp(name_1) || lp(value_1) || ...
                   || lp(name_h) || lp(value_h) )
route scope  = H_"bnap/route/http"( lp(origin)
                   || lp(route id from the manifest) )
"""),
    ("http-message", r"""
=============== NOTE: '\' line wrapping per RFC 8792 ================

POST /v1/chat/completions HTTP/1.1
Host: api.example
Content-Type: application/json

{"model":"m-1","messages":[{"role":"user","content":"hi"}],\
"max_tokens":256}

HTTP/1.1 402 Payment Required
WWW-Authenticate: BNAP offer="AAEBAiCGLWQeZ4E_bniyCoGqkpUZ5mqX..."
WWW-Authenticate: BNAP offer="..."
# (exact scope: L402, 2,100 sat, with native)
WWW-Authenticate: L402 macaroon=\
"<caveat bnap_offer = OfferID>", invoice="lnbc..."
BNAP-Error: AAEBAgEQ
# (REQUIRED)

POST /v1/chat/completions HTTP/1.1
Host: api.example
Content-Type: application/json
BNAP-Context: <b64u Context>
BNAP-Credential: AAEBAv0BMQABAQIghi1kHmeBP254sgqB...
# offer, notes worth 1,680 sat with change outputs,
# Web Bot Auth body over BNAP-Context, binding

HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: private, no-store

data: {"choices":[{"delta":{"content":"Hello"}}]}
...
event: bnap-receipt
data: AAEBAgAGAgFUCANzYXQKIFyGQCYfbx3jIGounNHC...
# OK, 850 tokens, charged 340 sat
"""),
    ("toml", r'''
[scheme."bnap:notes"]
role        = "value"        # value | attestation | both
spec        = "https://.../bnap-notes"
binding     = "S"            # S | A | O | none
use         = "single"       # single | rate | reusable, as the
                             # socket enforces it
local_id    = "Y of each input, 33-byte compressed point"
quota_id    = ""             # attestations only: the stable
                             # identity a quota counts against
rail_refs   = """none at spend; the funding payment at minting, \
                 confirmed by the rail"""
body        = "TLV, section 3 of the scheme spec"
witness     = "one BIP-340 signature per input, over the Digest"
native      = []             # kinds, how each embeds the OfferID,
                             # native credential bytes
units       = ["sat"]
refund      = "atomic"       # none | out-of-band | atomic
upto        = false
properties  = { theft = "key-witnessed", link-payment = "unlinkable",
                link-actions = "unlinkable", issuer = "self-issued",
                verify = "offline",
                finality = "final-on-verification",
                custody = "operator-iou", pq = "no",
                maturity = "experimental" }
conformance = "https://.../results/bnap-notes.json"
'''),
    (None, "HEX"),  # the 305-byte offer, re-wrapped
    (None, "HEX"),  # the Response, re-wrapped
]

# First 8 hex digits of the SHA-256 of each original block's text (between
# the fences), so a change in draft-00 cannot leave a stale hand-wrapped copy.
EXPECTED = [
    "7f98bd98", "c9ee0935", "2fab283d", "5ec26e29", "87ecf87b", "59abe8dd",
    "15697d6a", "dc7c70a3", "618acef5", "50df131a", "087eae9d", "aae35312",
]


def hexwrap(text, width=64):
    h = "".join(text.split())
    assert re.fullmatch(r"[0-9a-f]+", h), "hex block expected"
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def slug(title):
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s or "section"


def main(path, check_hashes=True):
    src = open(path, encoding="utf-8").read()
    lines = src.split("\n")
    # Drop the export comment, the title and the date line.
    i = 0
    if lines[0].startswith("<!--"):
        while not lines[i].rstrip().endswith("-->"):
            i += 1
        i += 1
    body = lines[i:]
    out, blocks, parent = [], [], None
    in_block, buf, k = False, [], 0
    first_done = set()
    phrases_done = set()

    def text_line(line):
        nonlocal first_done
        in_table = line.startswith("|")
        parts = re.split(r"(`[^`]*`)", line)
        res = []
        for p in parts:
            if p.startswith("`") and p.endswith("`") and len(p) >= 2:
                if in_table and "‖" in p:
                    res.append(code_to_table_text(p))
                else:
                    res.append(ascii_code(p))
            else:
                t = cite(ascii_text(p, in_table))
                for idx, (rx, rep) in enumerate(FIRST):
                    if idx in first_done:
                        continue
                    t2, n = re.subn(rx, rep, t, count=1)
                    if n:
                        first_done.add(idx)
                        t = t2
                res.append(t)
        return "".join(res)

    for line in body:
        if line.startswith("```"):
            if not in_block:
                in_block, buf = True, []
                continue
            in_block = False
            original = "\n".join(buf)
            digest = hashlib.sha256(original.encode()).hexdigest()[:8]
            blocks.append(digest)
            info, repl = BLOCKS[k]
            if repl == "HEX":
                text = hexwrap(original)
                fence = "~~~"
            else:
                text = repl.strip("\n")
                fence = "~~~ " + info if info else "~~~"
            for l in text.split("\n"):
                assert len(l) <= 72, "line over 72 columns in block %d: %r" % (k + 1, l)
                assert all(ord(c) < 128 for c in l), "non-ASCII in block %d" % (k + 1)
            out += [fence, text, "~~~"]
            k += 1
            continue
        if in_block:
            buf.append(line)
            continue
        if line.startswith("# BNAP socket") or re.match(r"^\d{4}-\d{2}-\d{2} ", line):
            continue
        m = re.match(r"^## (\d+)\. (.*)$", line)
        if m:
            title = RENAME.get(m.group(2), m.group(2))
            parent = slug(title)
            out.append("# %s {#%s}" % (title, parent))
            continue
        m = re.match(r"^### (\d+)\.(\d+) (.*)$", line)
        if m:
            title = m.group(3)
            out.append("## %s {#%s-%s}" % (title, parent, slug(title)))
            continue
        if line.startswith("The key words MUST, MUST NOT, REQUIRED"):
            out.append("{::boilerplate bcp14-tagged}")
            continue
        t = text_line(line)
        for idx, (a, b) in enumerate(PHRASES):
            if idx not in phrases_done and a in t:
                t = t.replace(a, b, 1)
                phrases_done.add(idx)
        out.append(t)

    assert k == len(BLOCKS), "expected %d code blocks, found %d" % (len(BLOCKS), k)
    if check_hashes and blocks != EXPECTED:
        sys.stderr.write("code block hashes changed: %s\n" % blocks)
        sys.stderr.write("review the hand-wrapped copies in BLOCKS, then update EXPECTED\n")
        sys.exit(1)
    missing = [a for idx, (a, b) in enumerate(PHRASES) if idx not in phrases_done and a != b]
    assert not missing, "phrases not found: %r" % missing
    # The example in 10.3 is wrapped as RFC 8792 describes; say so in the prose.
    text = "\n".join(out)
    text = text.replace(
        "Exact-scope, non-metered L402 offers at the ceiling serve clients that have no BNAP code.",
        "Exact-scope, non-metered L402 offers at the ceiling serve clients that have no BNAP code. "
        "Long lines in the example are wrapped as {{RFC8792}} describes, and lines that start "
        "with `#` are annotations, not part of the messages.", 1)
    # Note to readers, at the end of the introduction (before Conventions).
    text = text.replace("\n# Conventions {#conventions}", NOTE_TO_READERS + "\n# Conventions {#conventions}", 1)
    # Security addition before the IANA section; IANA templates before Test vectors.
    text = text.replace("\n# IANA Considerations {#iana-considerations}",
                        SECURITY_ADDITION + "\n# IANA Considerations {#iana-considerations}", 1)
    text = text.replace("\n# Test vectors {#test-vectors}", IANA_ADDITION + "\n# Test vectors {#test-vectors}", 1)
    text = FRONT + "\n" + text.strip("\n") + "\n" + BACK
    bad = sorted({c for c in text if ord(c) > 127})
    assert not bad, "non-ASCII left: %r" % bad
    sys.stdout.write(text)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    main(args[0] if args else "../spec/socket-draft-00.md", check_hashes="--no-hash-check" not in sys.argv)

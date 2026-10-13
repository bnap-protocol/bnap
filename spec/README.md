# BNAP specification

Spec text licensed CC-BY-4.0, (c) BNAP contributors.

Everything in this directory was exported on 2026-10-13 from the Claude Doc `WJztndZC9mY1jogSMesi8n`, one file per tab, transcribed verbatim. Each file starts with an HTML comment naming its source tab and the doc revision it was exported at.

## Files

| File | Source tab | Rev | Status |
| --- | --- | --- | --- |
| [socket-draft-00.md](socket-draft-00.md) | Socket spec draft-00 | 39 | Normative: the socket every deployment shares (byte layouts, algorithms, test vectors) |
| [overview-v0.5.md](overview-v0.5.md) | BNAP v0.5 (current) | 33 | Design overview, v0.5.1; informative where draft-00 covers the same ground |
| [schemes/bnap-notes.md](schemes/bnap-notes.md) | bnap:notes scheme (from v0.4) | 23 | The default credential scheme, still in its v0.4 form |
| [history/v0.3.md](history/v0.3.md) | v0.3 archive | 35 | Superseded; kept unchanged |
| [history/v0.2.md](history/v0.2.md) | v0.2 archive | 53 | Superseded; kept unchanged (working name Caparra, "CPR") |
| [ERRATA.md](ERRATA.md) | (written for this repo) | | Differences between draft-00, the reference code and vectors, and the overview |

Outside this directory:

- [../reference/python/bnap_ref.py](../reference/python/bnap_ref.py): the standard-library Python reference encoder that draft-00 section 14 cites.
- [../vectors/vectors.json](../vectors/vectors.json): the test vectors it generates. `python3 -I reference/python/bnap_ref.py` reproduces the file byte for byte.

## Precedence

`socket-draft-00.md` wins wherever it and `overview-v0.5.md` differ. Both documents say so: the overview says the draft-00 tab "wins where the two differ", and draft-00 section 1 says "this draft wins and the difference is listed in section 15". Draft-00 section 15 lists the known differences; [ERRATA.md](ERRATA.md) records the rest, plus the points that need an owner decision.

## Reading tab references

The texts are verbatim, so they still point at tabs, not files:

- "the first tab" (in draft-00) means `overview-v0.5.md`.
- The overview's "second tab" means the bnap:notes scheme, `schemes/bnap-notes.md`, and its "third tab" means `socket-draft-00.md`. These follow an older tab order; the doc now lists the overview, draft-00, bnap:notes, v0.3, v0.2.
- In the archives, "the first tab" means whichever version was current when that archive was made.

## Not exported

Seven figures are interactive diagrams in the source doc: one in the overview, two each in bnap-notes, v0.3 and v0.2. Each file keeps the figure's caption and its widget id in a quoted note where the figure stood. Draft-00 has no figures. Everything else, every table, code block and formula included, is in the files.

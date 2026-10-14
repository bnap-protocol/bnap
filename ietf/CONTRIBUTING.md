# Contributing

This directory relates to activities in the Internet Engineering Task Force
([IETF](https://www.ietf.org/)). All material in it is considered a
Contribution to the IETF Standards Process, as defined in the intellectual
property policies of the IETF currently designated as
[BCP 78](https://www.rfc-editor.org/info/bcp78),
[BCP 79](https://www.rfc-editor.org/info/bcp79) and the
[IETF Trust Legal Provisions (TLP) Relating to IETF Documents](https://trustee.ietf.org/trust-legal-provisions.html).

Any edit, commit, pull request, issue, comment or other change made to this
directory is a Contribution to the IETF Standards Process
(see the [Note Well](https://www.ietf.org/about/note-well/)).

You agree to comply with all applicable IETF policies and procedures, including
BCP 78 and BCP 79, the TLP, and the TLP rules regarding code components (such as
in [Section 4](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/)).

## How to contribute

The text of this draft is generated from `spec/socket-draft-00.md` in the
[BNAP repository](https://github.com/bnap-protocol/bnap) (see
[README.md](README.md)), so changes start there:

* Open an issue in the BNAP repository describing the problem, before writing text
  for any normative change.
* Send a pull request against `develop` that changes `spec/socket-draft-00.md`
  and regenerates `ietf/draft-bnap-socket.md`. Commits carry a DCO sign-off, as the
  repository's own [CONTRIBUTING.md](../CONTRIBUTING.md) explains.
* Changes that only concern the Internet-Draft form (front matter, references,
  IANA templates, wrapping) go to `ietf/tools/from-draft00.py`.

There is no working group yet; discussion happens in the BNAP repository's
issues.

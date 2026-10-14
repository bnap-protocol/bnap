"""bnap:notes client: stubbed.

DECISIONS row 31 says the notes scheme is rewritten in draft-00 terms as
spec/schemes/bnap-notes-draft-00.md. That file is not on develop yet (the
tree only has spec/schemes/bnap-notes.md, the v0.4 profile with a CBOR SPEND
that ERRATA row 31 says no longer fits the socket). Without the draft-00
body and witness layout there is nothing to build a wallet against, so the
notes value flows are skipped with this reason.
"""
from ._ref import REPO_ROOT

SPEC = REPO_ROOT / "spec" / "schemes" / "bnap-notes-draft-00.md"

SKIP_REASON = ("bnap:notes value flows need a wallet built from "
               "spec/schemes/bnap-notes-draft-00.md, which is not on develop yet "
               "(DECISIONS row 31, ERRATA row 31)")


def available():
    return SPEC.is_file()


class NotesWallet:
    def __init__(self, *_a, **_k):
        raise NotImplementedError(SKIP_REASON)

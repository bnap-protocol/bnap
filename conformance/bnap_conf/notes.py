"""bnap:notes client: the spec has landed, the wallet is not built yet.

DECISIONS row 31 rewrites the notes scheme in draft-00 terms. That text,
spec/schemes/bnap-notes-draft-00.md, is on develop since the N13 merge, so the
body, witness, change-output and fund-quote layouts a wallet needs now exist.
The suite has no notes wallet client yet: minting notes over Lightning
(NUT-23, NUT-04, NUT-20), building a body with blinded change outputs,
signing the Digest with each note key and unblinding the change are not
implemented. The notes value flows therefore skip with SKIP_REASON:
NOTES-VALUE, PAY-METERED on a notes entry, and the draft-00 6.1 check that
the gate commits a payment's RailId when it mints. This module is where that
wallet goes.
"""
from ._ref import REPO_ROOT

SPEC = REPO_ROOT / "spec" / "schemes" / "bnap-notes-draft-00.md"

SKIP_REASON = ("bnap:notes value flows need a notes wallet client: spec/schemes/bnap-notes-draft-00.md has "
               "landed (DECISIONS row 31), but the suite's wallet is not built yet")

MISSING_REASON = ("bnap:notes value flows need spec/schemes/bnap-notes-draft-00.md (DECISIONS row 31), which "
                  "this checkout does not have")


def available():
    """True when the notes draft-00 text is in this checkout."""
    return SPEC.is_file()


def skip_reason():
    """Why the notes value flows do not run here."""
    return SKIP_REASON if available() else MISSING_REASON


class NotesWallet:
    def __init__(self, *_a, **_k):
        raise NotImplementedError(SKIP_REASON)

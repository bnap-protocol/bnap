"""Load the reference encoder (reference/python/bnap_ref.py) by path.

The client library extends the reference encoder: hashing, BIP-340 and the
builders come from it unchanged, so the conformance code and the published
vectors share one implementation of every primitive. This module finds the
file relative to the repository layout and imports it under the name
``bnap_ref`` without touching sys.path.
"""
import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
REF_PATH = REPO_ROOT / "reference" / "python" / "bnap_ref.py"


def _load():
    if "bnap_ref" in sys.modules:
        return sys.modules["bnap_ref"]
    if not REF_PATH.is_file():
        raise ImportError("reference encoder not found at " + str(REF_PATH))
    spec = importlib.util.spec_from_file_location("bnap_ref", REF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bnap_ref"] = mod
    spec.loader.exec_module(mod)
    return mod


ref = _load()

"""Read the scheme registry export (registry/generated/registry.json).

A gate and a client learn every class, use model and refund property from
the registry, never from a plug (draft-00 section 11). Unknown schemes have
no class here; callers decide what unknown means (a client ignores an entry
whose scheme it does not know, 4.4).
"""
import json

from ._ref import REPO_ROOT

REGISTRY_PATH = REPO_ROOT / "registry" / "generated" / "registry.json"

CLASSES = ("none", "O", "A", "S")


class Registry:
    def __init__(self, data):
        self.data = data
        self.schemes = {k: v for k, v in data.get("schemes", {}).items()
                        if v.get("status") != "does-not-fit"}

    @classmethod
    def load(cls, path=REGISTRY_PATH):
        with open(path, "rb") as f:
            return cls(json.loads(f.read()))

    def known(self, scheme):
        return scheme in self.schemes

    def binding(self, scheme):
        """Binding class S, A, O or none; None when the scheme is unknown."""
        e = self.schemes.get(scheme)
        return e.get("binding") if e else None

    def use(self, scheme):
        e = self.schemes.get(scheme)
        return e.get("use") if e else None

    def role(self, scheme):
        e = self.schemes.get(scheme)
        return e.get("role") if e else None

    def refund(self, scheme):
        e = self.schemes.get(scheme)
        return e.get("refund") if e else None

    def upto(self, scheme):
        e = self.schemes.get(scheme)
        return bool(e.get("upto")) if e else False

    def quota_id(self, scheme):
        e = self.schemes.get(scheme)
        return e.get("quota_id", "") if e else ""

    def native_kinds(self, scheme):
        e = self.schemes.get(scheme)
        return [n["kind"] for n in e.get("native", [])] if e else []

    def can_value(self, scheme):
        return self.role(scheme) in ("value", "both")

    def can_attest(self, scheme):
        return self.role(scheme) in ("attestation", "both")

    def meterable(self, scheme):
        """A metered pay entry needs refund = atomic or upto = true (7)."""
        return self.refund(scheme) == "atomic" or self.upto(scheme)


_DEFAULT = None


def default():
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Registry.load()
    return _DEFAULT

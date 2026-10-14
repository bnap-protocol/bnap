"""Pricing, admission and metering (draft-00 section 7).

attests is a list of dicts in offer order:
  {"scheme", "effect": "required"|"waive"|"discount"|"quota", "value", "epoch",
   "verified": bool, "room": bool (quota counters only), "class": "S"|"A"|"O"|"none"}

Reading taken for a credential without pay. The 7 pseudo-code writes
"p = price(entry.amount, or 0 if the credential has no pay)" and then
"if p > 0 and no pay -> UNDERPAID", which can never fire with a base of 0
and would admit any attestation-only credential for free. Whether a price
reaches 0 does not depend on which positive base it starts from (a waive,
a 10,000 bp discount or a quota with room make every base 0; nothing else
makes any base 0), so this module prices a credential without pay from a
base of 1. See notes/n11-conformance.md.
"""

EFFECT_RANK = ("required", "waive", "discount", "quota")


class PriceResult:
    def __init__(self, price, quota_index=None):
        self.price = price
        self.quota_index = quota_index


def price(base, attests, quota_index=None, reuse_quota=False):
    """7 price(). reuse_quota: settlement reuses the admission quota decision."""
    p = base
    for a in attests:
        if a.get("verified") and a["effect"] == "waive":
            p = 0
    for a in attests:
        if a.get("verified") and a["effect"] == "discount":
            p = p - (p * a["value"]) // 10000
    used = None
    if p > 0:
        if reuse_quota:
            if quota_index is not None:
                p, used = 0, quota_index
        else:
            for i, a in enumerate(attests):
                if a.get("verified") and a["effect"] == "quota" and a.get("room", True):
                    p, used = 0, i
                    break
    return PriceResult(p, used)


class Admission:
    def __init__(self, ok, code=None, price=None, quota_index=None):
        self.ok = ok
        self.code = code
        self.price = price
        self.quota_index = quota_index

    def __repr__(self):
        return f"Admission(ok={self.ok}, code={self.code}, price={self.price})"


def admit(attests, *, amount=None, value=None):
    """7 admit. amount: the chosen pay entry's amount, None when there is no pay.

    value: the scheme's verified value (ignored without pay).
    """
    for a in attests:
        if a["effect"] == "required" and not a.get("verified"):
            return Admission(False, "POLICY")
    has_pay = amount is not None
    r = price(amount if has_pay else 1, attests)
    if r.price > 0 and not has_pay:
        return Admission(False, "UNDERPAID", r.price)
    if has_pay and (value or 0) < r.price:
        return Admission(False, "UNDERPAID", r.price)
    return Admission(True, None, r.price if has_pay else 0, r.quota_index)


def ceil_div(a, b):
    return -(-a // b)


def metered_charge(units, rate, amount, attests, quota_index=None):
    """charged = min(price(ceil(units * rate / 1000)), price(amount)), exact integers."""
    used = price(ceil_div(units * rate, 1000), attests, quota_index, reuse_quota=True).price
    ceiling = price(amount, attests, quota_index, reuse_quota=True).price
    return min(used, ceiling)


def class_rule_violations(entries):
    """Offer-building rules of 7 and DECISIONS row 25.

    entries: [{"role": "pay"|"attest", "scheme", "class", "effect", "amount"}].
    """
    out = []
    for e in entries:
        c = e.get("class")
        if e["role"] == "attest" and e.get("effect") in ("waive", "discount", "quota") and c not in ("S", "A", "O"):
            out.append(f"class-{c}-{e['effect']}")
        if e["role"] == "pay" and c == "none" and e.get("amount", 0) > 0:
            out.append("class-none-priced")
    return out

"""Client choice rules: which offer and entry to use, pinning, bnap-required,
and when a native challenge may be paid (draft-00 4.4 and 9.3).
"""
from .offer import client_check_offer


class SpendPolicy:
    """Units the client can pay and the most it pays per action, per unit."""

    def __init__(self, max_per_action=None, schemes=None):
        self.max_per_action = dict(max_per_action or {})
        self.schemes = set(schemes) if schemes is not None else None

    def fits(self, entry, registry=None):
        if self.schemes is not None and entry.scheme not in self.schemes:
            return False
        if registry is not None and not registry.known(entry.scheme):
            return False
        cap = self.max_per_action.get(entry.unit)
        return cap is not None and entry.amount <= cap


def usable_offers(offer_blobs, *, now, origin, pin, scope, route_scope, registry):
    """Return [(blob, OfferCheck)] for the offers that pass 4.4, in order."""
    keys = pin.keys if pin is not None and pin.live(now) else None
    out = []
    for blob in offer_blobs:
        chk = client_check_offer(blob, now=now, origin=origin, pin_keys=keys, scope=scope,
                                 route_scope=route_scope, registry=registry)
        if chk.ok:
            out.append((blob, chk))
    return out


def choose_entry(offer, policy, registry):
    """The first pay entry, in preference order, whose scheme the client knows
    and whose price fits the policy. Unknown schemes are ignored (4.4)."""
    for e in offer.pay:
        if registry.known(e.scheme) and policy.fits(e, registry):
            return e
    return None


def native_header_allowed(pin, now):
    """9.3: from an origin pinned with required = true, pay only through a BNAP
    offer that passes 4.4, never through a native header, until the pin lapses."""
    return not (pin is not None and pin.live(now) and pin.required)


def may_pay_native(native_bytes, passing_offers, pin, now):
    """9.3 always: pay a native challenge only if its bytes equal a native entry
    of an offer that passes 4.4, or the client has no pin for the origin."""
    if pin is None or not pin.live(now):
        return True
    for o in passing_offers:
        for n in o.native:
            if n.data == native_bytes:
                return True
    return False


def decide_native(native_bytes, passing_offers, pin, now, via_header):
    """Combine both rules for one native artifact. Return (allowed, reason)."""
    if via_header and not native_header_allowed(pin, now):
        return False, "bnap-required-pin"
    if not may_pay_native(native_bytes, passing_offers, pin, now):
        return False, "native-not-in-passing-offer"
    return True, None

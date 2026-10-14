"""The use store as an abstract state machine (draft-00 sections 6.3 and 6.4).

This is the reference model the outcomes vectors are generated from and the
mock gate runs on. One lock makes every commit one serializable transaction;
"durable" is out of scope for an in-memory model.
"""
import threading

PENDING, OK, FAILED = "PENDING", "OK", "FAILED"


class Outcome:
    def __init__(self, created, counters):
        self.status = PENDING
        self.created = created
        self.counters = list(counters)
        self.charged = None
        self.scheme_result = None
        self.response = None
        self.settled_at = None
        self.extra = {}

    def snapshot(self):
        return {"status": self.status, "charged": self.charged,
                "scheme_result": self.scheme_result.hex() if isinstance(self.scheme_result, bytes) else self.scheme_result,
                "settled_at": self.settled_at}


class CommitResult:
    def __init__(self, kind, outcome=None):
        self.kind = kind  # New | Replay | SPENT | RATE_LIMITED | UNAVAILABLE
        self.outcome = outcome

    def __repr__(self):
        return f"CommitResult({self.kind})"


class UseStore:
    def __init__(self, replay_window=86400, pending_timeout=300):
        self.replay_window = replay_window
        self.pending_timeout = pending_timeout
        self.used = {}
        self.counter = {}
        self.outcome = {}
        self.available = True
        self.lock = threading.RLock()

    def _expire(self, rk, now):
        o = self.outcome.get(rk)
        if o is not None and o.status == PENDING and now - o.created > self.pending_timeout:
            o.status = FAILED
            o.charged = 0
            o.settled_at = now
            o.extra["timed_out"] = True
            self._give_back(o)

    def _give_back(self, o):
        for key in o.counters:
            if self.counter.get(key, 0) > 0:
                self.counter[key] -= 1

    def commit(self, rk, singles, counters, now):
        with self.lock:
            if not self.available:
                return CommitResult("UNAVAILABLE")
            self._expire(rk, now)
            if rk in self.outcome:
                return CommitResult("Replay", self.outcome[rk])
            for i in singles:
                if i in self.used:
                    return CommitResult("SPENT")
            for key, limit in counters:
                if self.counter.get(key, 0) >= limit:
                    return CommitResult("RATE_LIMITED")
            for i in singles:
                self.used[i] = rk
            for key, _ in counters:
                self.counter[key] = self.counter.get(key, 0) + 1
            o = Outcome(now, [k for k, _ in counters])
            self.outcome[rk] = o
            return CommitResult("New", o)

    def settle(self, rk, status, now, charged=0, scheme_result=None, response=None):
        """Conditional update from PENDING. Return True if this call settled it."""
        with self.lock:
            if not self.available:
                return False
            self._expire(rk, now)
            o = self.outcome.get(rk)
            if o is None or o.status != PENDING:
                return False
            o.status = status
            o.charged = charged
            o.scheme_result = scheme_result
            o.response = response
            o.settled_at = now
            if status == FAILED:
                self._give_back(o)
            return True

    def get(self, rk, now):
        with self.lock:
            self._expire(rk, now)
            return self.outcome.get(rk)

    def purge(self, now):
        """Delete outcome records older than replay_window; single uses stay."""
        with self.lock:
            for rk in list(self.outcome):
                o = self.outcome[rk]
                if o.status != PENDING and now - o.created > self.replay_window:
                    del self.outcome[rk]

    def counter_value(self, key):
        with self.lock:
            return self.counter.get(key, 0)


def apply_trace(steps, replay_window=86400, pending_timeout=300):
    """Run a vectors/cases/outcomes.json trace; return one expect dict per step."""
    s = UseStore(replay_window, pending_timeout)
    out = []
    for step in steps:
        op = step["op"]
        if op == "commit":
            r = s.commit(step["rk"], step.get("singles", []), [tuple(c) for c in step.get("counters", [])], step["at"])
            e = {"result": r.kind}
            if r.kind == "Replay":
                e["status"] = r.outcome.status
                e["gate"] = "PENDING" if r.outcome.status == PENDING else (
                    "replay-with-response" if r.outcome.response is not None else "replay-receipt-only")
                if r.outcome.status != PENDING:
                    e["replayed"] = True
                    e["scheme_result"] = r.outcome.scheme_result
            elif r.kind == "New":
                e["gate"] = "run-action"
            else:
                e["gate"] = r.kind
            out.append(e)
        elif op == "settle":
            ok = s.settle(step["rk"], step["status"], step["at"], step.get("charged", 0), step.get("scheme_result"),
                          step.get("response"))
            out.append({"settled": ok})
        elif op == "get":
            o = s.get(step["rk"], step["at"])
            out.append({"status": o.status if o else None})
        elif op == "purge":
            s.purge(step["at"])
            out.append({})
        elif op == "store":
            s.available = step["available"]
            out.append({})
        elif op == "counter":
            out.append({"value": s.counter_value(step["key"])})
        else:
            raise ValueError("unknown trace op " + op)
    return out

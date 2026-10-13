#!/usr/bin/env python3
"""Validate the BNAP registry and export it as canonical JSON.

Usage:
  python3 -I registry/validate.py [--dir DIR]
      Validate the registry files in DIR (default: this script's directory).
  python3 -I registry/validate.py --export
      Validate, then write generated/registry.json.
  python3 -I registry/validate.py --check
      Validate, and fail if generated/registry.json is missing or stale.
  python3 -I registry/validate.py --effective SCHEME [--rail RAIL]... [--verifier V]
                                  [--require PROP=VALUE,...]
      Validate, then print the effective property vector of one pay entry
      (draft-00 section 11) and, with --require, whether a route admits it.

Checks: every file against schema.json; property value orders against the
spec; every property applicable to an entry's kind present and valid, and no
other; scheme ID prefix rules; rail, verifier and carrier ID rules; IDs
unique across all files, ignoring case; cross references; the invariants
draft-00 states about binding classes, natives and quotas; and the worked
examples the spec gives, which the registry data must reproduce.

Exit status: 0 valid, 1 invalid (each error on stderr), 2 usage error.
Standard library only. Needs Python 3.11 or later for tomllib.
"""

import sys

if sys.version_info < (3, 11):
    sys.stderr.write(
        "validate.py needs Python 3.11 or later (tomllib); this is %s\n"
        % sys.version.split()[0]
    )
    sys.exit(2)

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path

FORMAT = 1

# File key -> (file name, schema definition). Order is the export order.
FILES = {
    "properties": ("properties.toml", "propertiesFile"),
    "schemes": ("schemes.toml", "schemesFile"),
    "rails": ("rails.toml", "railsFile"),
    "verifiers": ("verifiers.toml", "verifiersFile"),
    "carriers": ("carriers.toml", "carriersFile"),
}
SCHEMA_FILE = "schema.json"
EXPORT_FILE = Path("generated") / "registry.json"

# The twelve properties, their location in an entry and their values, weakest
# first, as the spec fixes them: the order and the meaning come from the
# overview's "Scheme properties and route policy" table, the layout and the
# tokens from draft-00 section 11. properties.toml MUST match this exactly.
# Reordering values inverts what a route admits, so a change here is a spec
# change, never a data fix.
SPEC_PROPERTIES = [
    ("use", "entry", ["reusable", "rate", "single"]),
    ("binding", "entry", ["none", "O", "A", "S"]),
    ("theft", "properties", ["bearer", "key-witnessed"]),
    ("link-payment", "properties", ["linkable", "unlinkable"]),
    ("link-actions", "properties", ["linkable", "unlinkable"]),
    ("issuer", "properties", ["third-party", "facilitator", "self-issued"]),
    ("verify", "properties", ["online", "offline"]),
    ("finality", "properties",
     ["reversible", "freezable", "final-at-settlement", "final-on-verification"]),
    ("custody", "properties", ["third-party-custodial", "operator-iou", "self-custody"]),
    ("refund", "entry", ["none", "out-of-band", "atomic"]),
    ("pq", "properties", ["no", "yes"]),
    ("maturity", "properties", ["experimental", "standard"]),
]

# Which entry kinds carry each property. This is the registry's reading of
# draft-00 section 11 (see README, "Rules a gate applies"), pinned here for
# the same reason as the orders: dropping a kind from a property silently
# changes every effective vector that kind takes part in.
APPLIES_TO = {
    "use": ["credential", "attestation"],
    "binding": ["credential", "attestation"],
    "theft": ["credential", "attestation"],
    "link-payment": ["credential", "rail"],
    "link-actions": ["credential", "attestation"],
    "issuer": ["credential", "attestation", "verifier"],
    "verify": ["credential", "attestation", "verifier"],
    "finality": ["credential", "rail", "verifier"],
    "custody": ["credential", "rail", "verifier"],
    "refund": ["credential"],
    "pq": ["credential", "attestation", "rail"],
    "maturity": ["credential", "attestation", "rail", "verifier"],
}

ENTRY_KINDS = ("credential", "attestation", "rail", "verifier", "carrier")
FILE_KINDS = {
    "schemes": ("credential", "attestation"),
    "rails": ("rail",),
    "verifiers": ("verifier",),
    "carriers": ("carrier",),
}
TABLE_OF = {"schemes": "scheme", "rails": "rail", "verifiers": "verifier", "carriers": "carrier"}
LISTED = ("experimental", "standard")

# Scheme ID prefix rules (overview, "Naming and the registry"): the prefix
# names the source registry, the rest is that registry's own identifier.
# Every ID may end in @<qualifier>; for x402 the qualifier is the network and
# is required.
QUALIFIER = r"(?:@[A-Za-z0-9][A-Za-z0-9:._-]*)?"
PREFIX_RULES = [
    ("bnap:", r"bnap:[a-z][a-z0-9-]*", True, "bnap:<name>, BNAP's own schemes"),
    ("payment:", r"payment:[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*", True,
     "payment:<method>/<intent>, HTTP Payment Methods and Intents"),
    ("x402:", r"x402:[a-z0-9][a-z0-9-]*@(?:[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}|[a-z0-9][a-z0-9-]*)",
     False, "x402:<scheme>@<network>, the network as x402 names it"),
    ("pp:", r"pp:0x[0-9a-f]{4}", True, "pp:0x<token type>, four lower-case hex digits"),
    ("httpauth:", r"httpauth:[A-Za-z0-9][A-Za-z0-9._-]*", True,
     "httpauth:<scheme>, spelled as in the IANA HTTP Authentication Scheme registry"),
    ("httpsig:", r"httpsig:[a-z0-9][a-z0-9-]*", True, "httpsig:<tag>, an HTTP message signature tag"),
    ("cashu:", r"cashu:nut[0-9]{2,}", True, "cashu:nut<NN>, a Cashu NUT"),
    ("nip:", r"nip:[0-9A-F]{2,}", True, "nip:<NN>, a Nostr NIP"),
    ("vnd.", r"vnd\.[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+", True,
     "vnd.<vendor>.<name>, an unregistered vendor scheme"),
]

# Scheme IDs the draft-00 test vectors and manifest use. They must exist.
VECTOR_SCHEMES = [
    "bnap:notes",
    "httpsig:web-bot-auth",
    "httpauth:DPoP",
    "payment:lightning/charge",
    "httpauth:L402",
]

# The bnap:notes entry draft-00 section 11 gives as its example.
NOTES_EXAMPLE = {
    "role": "value",
    "binding": "S",
    "use": "single",
    "refund": "atomic",
    "upto": False,
    "quota_id": "",
    "native": [],
    "units": ["sat"],
    "properties": {
        "theft": "key-witnessed", "link-payment": "unlinkable", "link-actions": "unlinkable",
        "issuer": "self-issued", "verify": "offline", "finality": "final-on-verification",
        "custody": "operator-iou", "pq": "no", "maturity": "experimental",
    },
}


# --------------------------------------------------------------- reporting

class Report:
    def __init__(self):
        self.errors = []

    def err(self, where, msg):
        self.errors.append(f"{where}: {msg}")


def jpath(base, key):
    if isinstance(key, int):
        return f"{base}[{key}]"
    if re.fullmatch(r"[A-Za-z0-9_-]+", key):
        return f"{base}.{key}" if base else key
    return f'{base}."{key}"' if base else f'"{key}"'


# --------------------------------------------------------------- JSON Schema subset

SCHEMA_KEYWORDS = {
    "$schema", "$id", "$defs", "$comment", "title", "description", "$ref",
    "type", "enum", "const", "pattern", "minLength", "properties", "required",
    "additionalProperties", "propertyNames", "items", "minItems", "uniqueItems",
    "allOf", "anyOf", "not", "if", "then", "else",
}


class SchemaError(Exception):
    pass


def _strict_equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_strict_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _type_ok(inst, t):
    return {
        "object": lambda: isinstance(inst, dict),
        "array": lambda: isinstance(inst, list),
        "string": lambda: isinstance(inst, str),
        "boolean": lambda: isinstance(inst, bool),
        "integer": lambda: isinstance(inst, int) and not isinstance(inst, bool),
        "number": lambda: isinstance(inst, (int, float)) and not isinstance(inst, bool),
        "null": lambda: inst is None,
    }[t]()


def _type_name(inst):
    for t in ("boolean", "integer", "number", "string", "array", "object", "null"):
        if _type_ok(inst, t):
            return t
    return type(inst).__name__


_PATTERNS = {}


def _pattern_match(pattern, s):
    # ECMA-262 semantics: unanchored search, and "$" matches only at the very
    # end (Python's "$" would also match before a final newline).
    rx = _PATTERNS.get(pattern)
    if rx is None:
        p = pattern[:-1] + r"\Z" if pattern.endswith("$") and not pattern.endswith("\\$") else pattern
        rx = _PATTERNS[pattern] = re.compile(p)
    return rx.search(s) is not None


def _show(inst):
    s = json.dumps(inst, ensure_ascii=True)
    return s if len(s) <= 70 else s[:67] + "..."


class SchemaValidator:
    def __init__(self, root):
        self.root = root
        self._audit(root, "#")

    def _audit(self, node, where):
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            raise SchemaError(f"{where}: a schema must be an object or a boolean")
        for k in node:
            if k not in SCHEMA_KEYWORDS:
                raise SchemaError(f"{where}: keyword {k!r} is not implemented by validate.py")
        for k in ("$defs", "properties"):
            for name, sub in node.get(k, {}).items():
                self._audit(sub, f"{where}/{k}/{name}")
        for k in ("additionalProperties", "propertyNames", "items", "not", "if", "then", "else"):
            if k in node:
                self._audit(node[k], f"{where}/{k}")
        for k in ("allOf", "anyOf"):
            for i, sub in enumerate(node.get(k, [])):
                self._audit(sub, f"{where}/{k}/{i}")
        if "$ref" in node:
            self._resolve(node["$ref"])

    def _resolve(self, ref):
        if not ref.startswith("#/"):
            raise SchemaError(f"only local references are supported: {ref}")
        node = self.root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise SchemaError(f"unresolvable reference: {ref}")
            node = node[part]
        return node

    def errors(self, inst, schema, path):
        out = []
        self._v(inst, schema, path, out)
        return out

    def definition(self, name):
        return self._resolve(f"#/$defs/{name}")

    def _v(self, inst, s, path, out):
        where = path or "(top level)"
        if s is True:
            return
        if s is False:
            out.append(f"{where}: not allowed here")
            return
        if "$ref" in s:
            self._v(inst, self._resolve(s["$ref"]), path, out)
        if "type" in s and not _type_ok(inst, s["type"]):
            out.append(f"{where}: expected {s['type']}, found {_type_name(inst)}")
            return
        if "const" in s and not _strict_equal(inst, s["const"]):
            out.append(f"{where}: must be {_show(s['const'])}, found {_show(inst)}")
        if "enum" in s and not any(_strict_equal(inst, e) for e in s["enum"]):
            allowed = ", ".join(_show(e) for e in s["enum"])
            out.append(f"{where}: must be one of {allowed}; found {_show(inst)}")
        if isinstance(inst, str):
            if "minLength" in s and len(inst) < s["minLength"]:
                out.append(f"{where}: must not be empty" if s["minLength"] == 1
                           else f"{where}: shorter than {s['minLength']} characters")
            if "pattern" in s and not _pattern_match(s["pattern"], inst):
                out.append(f"{where}: {_show(inst)} does not match {s['pattern']}")
        if isinstance(inst, list):
            if "minItems" in s and len(inst) < s["minItems"]:
                out.append(f"{where}: needs at least {s['minItems']} item(s)")
            if s.get("uniqueItems"):
                for i, x in enumerate(inst):
                    if any(_strict_equal(x, y) for y in inst[:i]):
                        out.append(f"{jpath(path, i)}: duplicate item {_show(x)}")
            if "items" in s:
                for i, x in enumerate(inst):
                    self._v(x, s["items"], jpath(path, i), out)
        if isinstance(inst, dict):
            props = s.get("properties", {})
            for k in s.get("required", []):
                if k not in inst:
                    out.append(f"{where}: missing required field '{k}'")
            for k, v in inst.items():
                kp = jpath(path, k)
                if "propertyNames" in s:
                    sub = self.errors(k, s["propertyNames"], kp)
                    if sub:
                        out.append(f"{kp}: invalid name ({sub[0].split(': ', 1)[1]})")
                if k in props:
                    self._v(v, props[k], kp, out)
                elif "additionalProperties" in s:
                    ap = s["additionalProperties"]
                    if ap is False:
                        out.append(f"{kp}: unknown field '{k}'")
                    else:
                        self._v(v, ap, kp, out)
        for sub in s.get("allOf", []):
            self._v(inst, sub, path, out)
        if "anyOf" in s:
            if all(self.errors(inst, sub, path) for sub in s["anyOf"]):
                msg = f"{where}: {_show(inst)} matches none of the allowed forms"
                if "description" in s:
                    msg += f" ({s['description']})"
                out.append(msg)
        if "not" in s and not self.errors(inst, s["not"], path):
            out.append(f"{where}: {self._describe_not(inst, s['not'])}")
        if "if" in s:
            if not self.errors(inst, s["if"], path):
                if "then" in s:
                    self._v(inst, s["then"], path, out)
            elif "else" in s:
                self._v(inst, s["else"], path, out)

    @staticmethod
    def _describe_not(inst, n):
        forms = n.get("anyOf", [n])
        present = []
        for f in forms:
            if set(f) == {"required"} and isinstance(inst, dict):
                present += [k for k in f["required"] if k in inst]
        if present:
            return "must not have " + ", ".join(f"'{k}'" for k in present)
        return "matches a form that is not allowed here"


# --------------------------------------------------------------- loading

def load_files(directory, rep):
    data = {}
    for key, (fname, _) in FILES.items():
        path = directory / fname
        try:
            raw = path.read_bytes()
        except OSError as e:
            rep.err(fname, f"cannot read: {e.strerror}")
            continue
        for lineno, line in enumerate(raw.split(b"\n"), 1):
            if any(b > 0x7E or (b < 0x20 and b not in (0x09, 0x0D)) for b in line):
                rep.err(f"{fname}:{lineno}",
                        "non-ASCII or control byte; registry files are ASCII only "
                        "(no typographic dashes or quotes)")
        try:
            data[key] = tomllib.loads(raw.decode("utf-8"))
        except UnicodeDecodeError:
            rep.err(fname, "not valid UTF-8")
        except tomllib.TOMLDecodeError as e:
            # Duplicate tables, such as two [scheme."x"] headers, land here.
            rep.err(fname, f"TOML error: {e}")
    return data


def load_schema(directory, rep):
    try:
        root = json.loads((directory / SCHEMA_FILE).read_text("utf-8"))
        return SchemaValidator(root)
    except OSError as e:
        rep.err(SCHEMA_FILE, f"cannot read: {e.strerror}")
    except json.JSONDecodeError as e:
        rep.err(SCHEMA_FILE, f"invalid JSON: {e}")
    except SchemaError as e:
        rep.err(SCHEMA_FILE, str(e))
    return None


# --------------------------------------------------------------- property model

class Prop:
    def __init__(self, pid, location, applies_to, values):
        self.id = pid
        self.location = location
        self.applies_to = list(applies_to)
        self.values = list(values)

    def rank(self, value):
        """Position of value, weakest first; unknown values count as weakest."""
        return self.values.index(value) if value in self.values else 0


def check_properties(doc, rep):
    """Check properties.toml against the spec and return the property model."""
    where = FILES["properties"][0]
    spec = {pid: (loc, vals) for pid, loc, vals in SPEC_PROPERTIES}
    model = {}
    seen = []
    for i, p in enumerate(doc.get("property", []) if isinstance(doc, dict) else []):
        if not isinstance(p, dict) or not isinstance(p.get("id"), str):
            continue
        pid = p["id"]
        w = f"{where}: property[{i}] {pid}"
        if pid in seen:
            rep.err(w, "duplicate property id")
            continue
        seen.append(pid)
        if pid not in spec:
            rep.err(w, "unknown property: the spec defines only "
                    + ", ".join(x for x, _, _ in SPEC_PROPERTIES))
            continue
        loc, spec_vals = spec[pid]
        vals = [v.get("id") for v in p.get("values", []) if isinstance(v, dict)]
        dups = sorted({v for v in vals if vals.count(v) > 1})
        if dups:
            rep.err(w, "duplicate value(s): " + ", ".join(dups))
        elif vals != spec_vals:
            if sorted(vals) == sorted(spec_vals):
                rep.err(w, "values in the wrong order: weakest first must be "
                        + " < ".join(spec_vals) + ", found " + " < ".join(vals))
            else:
                rep.err(w, "values differ from the spec: expected "
                        + ", ".join(spec_vals) + "; found " + ", ".join(map(str, vals)))
        if p.get("location") != loc:
            rep.err(w, f"location must be {loc!r} (draft-00 section 11 entry layout)")
        if p.get("applies_to") != APPLIES_TO[pid]:
            rep.err(w, "applies_to must be " + ", ".join(APPLIES_TO[pid])
                    + " (the registry's applicability rule), found "
                    + ", ".join(map(str, p.get("applies_to", []))))
        # Downstream checks always use the pinned model, so one broken file
        # does not cascade into misleading errors elsewhere.
        model[pid] = Prop(pid, loc, APPLIES_TO[pid], spec_vals)
    missing = [x for x, _, _ in SPEC_PROPERTIES if x not in seen]
    if missing:
        rep.err(where, "missing spec properties: " + ", ".join(missing))
    order = [x for x in seen if x in spec]
    expected = [x for x, _, _ in SPEC_PROPERTIES if x in order]
    if order != expected:
        rep.err(where, "properties out of the spec's order: expected "
                + ", ".join(expected) + "; found " + ", ".join(order))
    for pid, loc, vals in SPEC_PROPERTIES:
        if pid not in model:
            model[pid] = Prop(pid, loc, APPLIES_TO[pid], vals)
    return model


# --------------------------------------------------------------- IDs

def check_scheme_id(sid):
    for prefix, base, qualified, desc in PREFIX_RULES:
        if sid.startswith(prefix):
            rx = base + (QUALIFIER if qualified else "")
            if not re.fullmatch(rx, sid):
                return f"does not follow the {prefix} prefix rule: {desc}"
            return None
    return ("unknown prefix; a scheme ID starts with one of "
            + ", ".join(p for p, _, _, _ in PREFIX_RULES))


def entries_of(data, key):
    table = data.get(key, {}).get(TABLE_OF[key], {}) if isinstance(data.get(key), dict) else {}
    return table if isinstance(table, dict) else {}


def check_ids(data, rep):
    seen = {}
    rail_kinds = data.get("rails", {}).get("rail_kind", {}) if isinstance(data.get("rails"), dict) else {}
    for key in ("schemes", "rails", "verifiers", "carriers"):
        fname = FILES[key][0]
        table = TABLE_OF[key]
        for eid, entry in entries_of(data, key).items():
            w = f"{fname}: {table}.{json.dumps(eid)}"
            if key == "schemes":
                problem = check_scheme_id(eid)
                if problem:
                    rep.err(w, problem)
            elif key == "rails":
                prefix = eid.split(":", 1)[0]
                if prefix not in rail_kinds:
                    rep.err(w, f"rail ID must start with a registered rail kind; {prefix!r} is not one")
                elif isinstance(entry, dict) and entry.get("rail_kind") != prefix:
                    rep.err(w, f"rail_kind must be {prefix!r}, the ID's prefix")
            folded = eid.casefold()
            if folded in seen:
                rep.err(w, f"duplicate ID: {seen[folded]} already uses it"
                        + ("" if seen[folded].endswith(json.dumps(eid)) else ", ignoring case"))
            else:
                seen[folded] = f"{fname}: {table}.{json.dumps(eid)}"


# --------------------------------------------------------------- entries

def entry_kind(key, entry):
    return entry.get("kind") if key == "schemes" else FILE_KINDS[key][0]


def vector_of(entry, kind, props):
    """The entry's full vector: every applicable property it states."""
    vec = {}
    pmap = entry.get("properties", {}) if isinstance(entry.get("properties"), dict) else {}
    for p in props.values():
        if kind not in p.applies_to:
            continue
        v = entry.get(p.id) if p.location == "entry" else pmap.get(p.id)
        if isinstance(v, str):
            vec[p.id] = v
    return vec


def check_vector(w, entry, kind, props, rep):
    pmap = entry.get("properties", {})
    if not isinstance(pmap, dict):
        return
    for name, value in pmap.items():
        p = props.get(name)
        if p is None:
            rep.err(f"{w}.properties", f"unknown property {name!r}")
            continue
        if p.location == "entry":
            rep.err(f"{w}.properties", f"{name!r} belongs at the top level of the entry "
                    "(draft-00 section 11), not in properties")
            continue
        if kind not in p.applies_to:
            rep.err(f"{w}.properties", f"{name!r} does not apply to {kind} entries "
                    f"(applies to: {', '.join(p.applies_to)})")
            continue
        if value not in p.values:
            rep.err(f"{w}.properties.{name}", f"unknown value {value!r}; one of "
                    + ", ".join(p.values) + " (weakest first)")
    for p in props.values():
        if p.location != "entry" or p.id not in entry:
            continue
        if kind not in p.applies_to:
            rep.err(w, f"{p.id!r} does not apply to {kind} entries")
        elif entry[p.id] not in p.values:
            rep.err(f"{w}.{p.id}", f"unknown value {entry[p.id]!r}; one of "
                    + ", ".join(p.values) + " (weakest first)")
    for p in props.values():
        if kind not in p.applies_to:
            continue
        present = p.id in entry if p.location == "entry" else p.id in pmap
        if not present:
            where = "at the top level" if p.location == "entry" else "in properties"
            rep.err(w, f"missing property {p.id!r} {where}: every {kind} entry states it, "
                    "since a gate would count it as its weakest value")


def check_entries(data, props, rep):
    verifier_ids = set(entries_of(data, "verifiers"))
    rails_doc = data.get("rails", {}) if isinstance(data.get("rails"), dict) else {}
    rail_kinds = rails_doc.get("rail_kind", {}) if isinstance(rails_doc.get("rail_kind"), dict) else {}
    for key in ("schemes", "rails", "verifiers", "carriers"):
        fname = FILES[key][0]
        table = TABLE_OF[key]
        for eid, entry in entries_of(data, key).items():
            if not isinstance(entry, dict):
                continue
            w = f"{fname}: {table}.{json.dumps(eid)}"
            try:
                check_entry(key, w, entry, props, verifier_ids, rail_kinds, rep)
            except (TypeError, AttributeError, KeyError):
                rep.err(w, "malformed entry; fix the schema errors above first")


def check_entry(key, w, entry, props, verifier_ids, rail_kinds, rep):
    kind = entry_kind(key, entry)
    if kind not in FILE_KINDS[key]:
        return  # the schema reported it
    status = entry.get("status")
    if status == "does-not-fit":
        if "properties" in entry:
            rep.err(w, "a does-not-fit entry carries no property vector")
        return
    if kind != "carrier":
        check_vector(w, entry, kind, props, rep)
    vec = vector_of(entry, kind, props)

    # Listed entries have conformance results, and their status is
    # their maturity.
    if status in LISTED:
        if not entry.get("conformance"):
            rep.err(w, f"status {status!r} means listed, which needs conformance results")
        if "maturity" in vec and vec["maturity"] != status:
            rep.err(w, f"a listed entry's status equals its maturity ({vec['maturity']!r})")

    if key == "schemes":
        binding = entry.get("binding")
        # draft-00 12: class O is recorded as bearer; class none is a
        # bearer credential by definition.
        if binding in ("O", "none") and vec.get("theft") not in (None, "bearer"):
            rep.err(w, f"binding class {binding} must have theft = bearer (draft-00 12)")
        natives = entry.get("native", [])
        if natives and binding != "O":
            rep.err(w, "native artifacts are only for class O schemes (draft-00 4.1)")
        kinds = [n.get("kind") for n in natives if isinstance(n, dict)]
        for k in sorted({k for k in kinds if kinds.count(k) > 1}):
            rep.err(w, f"native kind {k!r} listed twice")
        if kind == "attestation" and binding == "none" and entry.get("quota_id"):
            rep.err(w, "a class none attestation cannot carry a quota (draft-00 7), "
                    "so quota_id must be empty")
        for rk in entry.get("rail_kinds", []):
            if rk not in rail_kinds:
                rep.err(w, f"rail_kinds names {rk!r}, which is not a registered rail kind")
        for v in entry.get("verifiers", []):
            if v not in verifier_ids:
                rep.err(w, f"verifiers names {v!r}, which has no entry in verifiers.toml")
    elif key == "rails":
        rk = entry.get("rail_kind")
        if rk not in rail_kinds:
            rep.err(w, f"rail_kind {rk!r} is not registered in [rail_kind]")
        # Overview, Value rails: non-Bitcoin rails are off by default,
        # and so is any reversible rail.
        needs_guard = rk not in ("ln", "onchain") or vec.get("finality") == "reversible"
        if needs_guard and entry.get("guarded") is not True:
            rep.err(w, "a non-Bitcoin or reversible rail must be guarded (off by default)")


# --------------------------------------------------------------- effective vectors

def effective(reg, props, scheme_id, rail_ids, verifier_id):
    """Per-property minimum over the scheme, its rails and its verifier
    (draft-00 section 11). The vector has the properties that apply to the
    scheme's kind; for each, only entries whose kind it applies to take part.
    An entry that should state a property but does not, or an unknown entry,
    counts as that property's weakest value. Several rails all take part: a
    credential cannot show which one funded it. Returns (vector, problems).
    """
    problems = []
    scheme = reg["schemes"].get(scheme_id)
    if scheme is None:
        return None, [f"unknown scheme {scheme_id!r}"]
    if scheme.get("status") == "does-not-fit":
        return None, [f"{scheme_id} does not fit the socket: {scheme.get('reason')}"]
    parts = [(scheme["kind"], scheme.get("vector", {}))]
    for rid in rail_ids:
        rail = reg["rails"].get(rid)
        if rail is None:
            problems.append(f"rail {rid!r} has no entry; its properties count as weakest")
            parts.append(("rail", {}))
            continue
        if rail.get("rail_kind") not in scheme.get("rail_kinds", []):
            problems.append(f"{scheme_id} does not use rail kind {rail.get('rail_kind')!r}")
        parts.append(("rail", rail.get("vector", {})))
    if verifier_id is not None:
        ver = reg["verifiers"].get(verifier_id)
        if ver is None:
            problems.append(f"verifier {verifier_id!r} has no entry; its properties count as weakest")
            parts.append(("verifier", {}))
        else:
            if verifier_id not in scheme.get("verifiers", []):
                problems.append(f"{scheme_id} does not list verifier {verifier_id!r}")
            parts.append(("verifier", ver.get("vector", {})))
    vec = {}
    for p in props.values():
        # The scheme's kind fixes which properties the vector has: a
        # verifier's custody, say, says nothing about an attestation.
        if scheme["kind"] not in p.applies_to:
            continue
        ranks = [p.rank(v.get(p.id)) for kind, v in parts if kind in p.applies_to]
        if ranks:
            vec[p.id] = p.values[min(ranks)]
    return vec, problems


def parse_require(text, props):
    req = {}
    for item in filter(None, (x.strip() for x in text.split(","))):
        if "=" not in item:
            raise ValueError(f"--require item {item!r} is not PROPERTY=VALUE")
        k, v = (x.strip() for x in item.split("=", 1))
        if k not in props:
            raise ValueError(f"unknown property {k!r} in --require")
        if v not in props[k].values:
            raise ValueError(f"unknown value {v!r} for {k}; one of " + ", ".join(props[k].values))
        req[k] = v
    return req


def admits(vec, req, props):
    """Per-property check of a route's require (overview: no overall score).
    A property that does not apply to the entry, such as refund for an
    attestation, does not constrain it."""
    result = {}
    for k, need in req.items():
        have = vec.get(k)
        ok = True if have is None else props[k].rank(have) >= props[k].rank(need)
        result[k] = {"need": need, "have": have, "ok": ok}
    return all(r["ok"] for r in result.values()), result


# --------------------------------------------------------------- spec examples

def check_spec_examples(reg, props, rep):
    """The worked examples in the spec, reproduced from the registry data."""
    where = "spec example"
    schemes = reg["schemes"]

    def need(*ids):
        missing = [i for i in ids if i not in schemes and i not in reg["rails"]
                   and i not in reg["verifiers"]]
        for i in missing:
            rep.err(where, f"needs an entry for {i!r}")
        return not missing

    for sid in VECTOR_SCHEMES:
        if sid not in schemes:
            rep.err(where, f"draft-00 section 14 vectors use {sid!r}, which has no entry")

    if need("bnap:notes"):
        e = schemes["bnap:notes"]
        for k, v in NOTES_EXAMPLE.items():
            if not _strict_equal(e.get(k), v):
                rep.err(f"{where} (draft-00 11)", f"bnap:notes {k} must be {_show(v)}, "
                        f"as in the section 11 example; found {_show(e.get(k))}")

    # Overview: "notes funded by card are reversible and linkable to the payer".
    if need("bnap:notes", "card:stripe", "local"):
        vec, _ = effective(reg, props, "bnap:notes", ["card:stripe"], "local")
        if vec.get("finality") != "reversible" or vec.get("link-payment") != "linkable":
            rep.err(f"{where} (overview, effective vectors)",
                    "bnap:notes funded through card:stripe must come out reversible and "
                    f"linkable; got finality {vec.get('finality')}, link-payment {vec.get('link-payment')}")

    # Overview: "x402 through a custodial facilitator is custodial".
    if need("x402:exact@eip155:8453", "evm:eip-3009", "x402-facilitator:custodial"):
        vec, _ = effective(reg, props, "x402:exact@eip155:8453", ["evm:eip-3009"],
                           "x402-facilitator:custodial")
        if vec.get("custody") != "third-party-custodial":
            rep.err(f"{where} (overview, effective vectors)",
                    "x402 through a custodial facilitator must come out third-party-custodial; "
                    f"got {vec.get('custody')}")

    # Overview route example: require { use = single, binding = O,
    # link-actions = unlinkable } admits notes, MPP Lightning and L402, never a
    # reusable bearer token; with binding = A, notes alone.
    trio = ["bnap:notes", "payment:lightning/charge", "httpauth:L402"]
    if need(*trio, "httpauth:Bearer", "ln:lnd", "local"):
        base = {"use": "single", "binding": "O", "link-actions": "unlinkable"}
        for binding, expect in (("O", set(trio)), ("A", {"bnap:notes"})):
            req = dict(base, binding=binding)
            got = set()
            for sid in trio:
                vec, _ = effective(reg, props, sid, ["ln:lnd"], "local")
                if admits(vec, req, props)[0]:
                    got.add(sid)
            if got != expect:
                rep.err(f"{where} (overview, route policy)",
                        f"with binding = {binding} the route must admit exactly "
                        f"{sorted(expect)}; the registry admits {sorted(got)}")
        vec, _ = effective(reg, props, "httpauth:Bearer", [], "local")
        if admits(vec, base, props)[0]:
            rep.err(f"{where} (overview, route policy)",
                    "a reusable bearer token must never admit a use = single route")

    # draft-00 6.2: "L402 tokens are reusable natively but single in BNAP".
    if need("httpauth:L402") and schemes["httpauth:L402"].get("use") != "single":
        rep.err(f"{where} (draft-00 6.2)", "httpauth:L402 must be use = single")

    # draft-00 10.3 and 14: the route offer carries bnap:notes (metered) and a
    # web-bot-auth discount, so both are class S or A, and notes can be
    # metered; L402 gets only exact, non-metered offers.
    if need("bnap:notes", "httpsig:web-bot-auth", "httpauth:L402"):
        for sid in ("bnap:notes", "httpsig:web-bot-auth"):
            if schemes[sid].get("binding") not in ("S", "A"):
                rep.err(f"{where} (draft-00 10.3)", f"{sid} sits in a route-scope offer, so it must be class S or A")
        notes = schemes["bnap:notes"]
        if not (notes.get("refund") == "atomic" or notes.get("upto") is True):
            rep.err(f"{where} (draft-00 7)", "bnap:notes sits in a metered offer, so it needs refund = atomic or upto")
        l402 = schemes["httpauth:L402"]
        if l402.get("refund") == "atomic" or l402.get("upto") is True or l402.get("binding") in ("S", "A"):
            rep.err(f"{where} (draft-00 10.3)", "httpauth:L402 gets exact-scope, non-metered offers only")

    # draft-00 4.1 names the native kinds bolt11 and l402-macaroon, and the
    # native-envelope vector carries a bolt11 for payment:lightning/charge.
    if need("httpauth:L402", "payment:lightning/charge"):
        l402_kinds = {n.get("kind") for n in schemes["httpauth:L402"].get("native", [])}
        mpp_kinds = {n.get("kind") for n in schemes["payment:lightning/charge"].get("native", [])}
        if "l402-macaroon" not in l402_kinds:
            rep.err(f"{where} (draft-00 4.1)", "httpauth:L402 must list the native kind l402-macaroon")
        if "bolt11" not in mpp_kinds:
            rep.err(f"{where} (draft-00 14)", "payment:lightning/charge must list the native kind bolt11")

    # draft-00 14: httpauth:DPoP waives and httpsig:web-bot-auth discounts, which
    # only class S, A or O may do (draft-00 7).
    for sid in ("httpauth:DPoP", "httpsig:web-bot-auth"):
        if sid in schemes and schemes[sid].get("binding") not in ("S", "A", "O"):
            rep.err(f"{where} (draft-00 7)", f"{sid} waives or discounts in the vectors, so it cannot be class none")


# --------------------------------------------------------------- export

def jcs(obj):
    """RFC 8785 serialization. Exact for this data: ASCII member names,
    integers below 2^53, no floats."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_export(data, props):
    def plain(table):
        return {k: dict(v) for k, v in table.items()}

    out = {
        "format": FORMAT,
        "generated_by": "registry/validate.py --export",
        "properties": [],
        "rail_kinds": plain(data["rails"].get("rail_kind", {})),
        "schemes": {},
        "rails": {},
        "verifiers": {},
        "carriers": plain(entries_of(data, "carriers")),
    }
    by_id = {p["id"]: p for p in data["properties"]["property"]}
    for pid, _, _ in SPEC_PROPERTIES:
        p = by_id[pid]
        out["properties"].append({
            "id": pid,
            "label": p["label"],
            "location": p["location"],
            "applies_to": list(p["applies_to"]),
            "description": p["description"],
            "values": [{"id": v["id"], "label": v["label"]} for v in p["values"]],
        })
    for key in ("schemes", "rails", "verifiers"):
        for eid, entry in entries_of(data, key).items():
            e = dict(entry)
            e["kind"] = entry_kind(key, entry)
            e["vector"] = ({} if entry.get("status") == "does-not-fit"
                           else vector_of(entry, e["kind"], props))
            out[key][eid] = e
    for e in out["carriers"].values():
        e.setdefault("kind", "carrier")
    out["digest"] = hashlib.sha256(jcs(out).encode("utf-8")).hexdigest()
    return out


def export_text(export):
    return json.dumps(export, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------- main

def validate(directory):
    rep = Report()
    data = load_files(directory, rep)
    schema = load_schema(directory, rep)
    if schema is not None:
        for key, (fname, definition) in FILES.items():
            if key in data:
                for e in schema.errors(data[key], schema.definition(definition), ""):
                    rep.err(fname, e)
    props = check_properties(data.get("properties", {}), rep)
    check_ids(data, rep)
    check_entries(data, props, rep)
    reg = None
    if len(data) == len(FILES):
        try:
            reg = build_export(data, props)
        except (KeyError, TypeError, AttributeError) as e:
            rep.err("export", f"cannot build the export from malformed data ({e!r})")
    if reg is not None:
        try:
            check_spec_examples(reg, props, rep)
        except (TypeError, AttributeError, KeyError) as e:
            rep.err("spec example", f"cannot run on malformed data ({e!r})")
    return rep, data, props, reg


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="validate.py",
        description="Validate the BNAP registry and export it as canonical JSON.")
    ap.add_argument("--dir", type=Path, default=Path(__file__).resolve().parent,
                    help="registry directory (default: this script's directory)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--export", action="store_true", help="write generated/registry.json")
    mode.add_argument("--check", action="store_true",
                      help="fail if generated/registry.json is missing or stale")
    mode.add_argument("--effective", metavar="SCHEME",
                      help="print the effective vector of one pay entry")
    ap.add_argument("--rail", action="append", default=[], metavar="RAIL",
                    help="with --effective: a rail the scheme is configured with (repeatable)")
    ap.add_argument("--verifier", metavar="VERIFIER", help="with --effective: the verifier")
    ap.add_argument("--require", default="", metavar="P=V,...",
                    help="with --effective: a route's require, checked per property")
    ap.add_argument("-q", "--quiet", action="store_true", help="print errors only")
    args = ap.parse_args(argv)
    if not args.effective and (args.rail or args.verifier or args.require):
        ap.error("--rail, --verifier and --require need --effective")

    directory = args.dir
    rep, data, props, reg = validate(directory)
    if rep.errors:
        for e in rep.errors:
            print(e, file=sys.stderr)
        print(f"registry: INVALID, {len(rep.errors)} error(s) in {directory}", file=sys.stderr)
        return 1

    counts = ", ".join(f"{len(reg[k])} {k}" for k in ("properties", "schemes", "rails", "verifiers", "carriers"))
    target = directory / EXPORT_FILE
    if args.export:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(export_text(reg), "utf-8")
        if not args.quiet:
            print(f"registry: valid ({counts}); wrote {EXPORT_FILE} (digest {reg['digest']})")
        return 0
    if args.check:
        try:
            current = target.read_text("utf-8")
        except OSError:
            current = None
        if current != export_text(reg):
            print(f"registry: {EXPORT_FILE} is missing or stale; run validate.py --export",
                  file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"registry: valid ({counts}); {EXPORT_FILE} is current")
        return 0
    if args.effective:
        try:
            req = parse_require(args.require, props)
        except ValueError as e:
            ap.error(str(e))
        vec, problems = effective(reg, props, args.effective, args.rail, args.verifier)
        if vec is None:
            print("; ".join(problems), file=sys.stderr)
            return 1
        ok, detail = admits(vec, req, props)
        print(json.dumps({
            "scheme": args.effective, "rails": args.rail, "verifier": args.verifier,
            "vector": vec, "require": detail, "admitted": ok, "problems": problems,
        }, indent=2, sort_keys=True))
        return 0 if ok and not problems else 1
    if not args.quiet:
        print(f"registry: valid ({counts})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

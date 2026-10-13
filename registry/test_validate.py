#!/usr/bin/env python3
"""Tests for validate.py: the real registry passes, broken copies fail.

Each negative test copies the registry into a temporary directory, breaks one
thing, runs validate.py on the copy as a separate process and checks that it
exits 1 with the expected message.

Run: python3 -I registry/test_validate.py   (Python 3.11 or later)
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATE = HERE / "validate.py"
SOURCES = ["properties.toml", "schemes.toml", "rails.toml", "verifiers.toml",
           "carriers.toml", "schema.json"]


def run(directory, *args):
    p = subprocess.run([sys.executable, "-I", str(VALIDATE), "--dir", str(directory), *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


class RealRegistry(unittest.TestCase):
    def test_passes(self):
        code, out = run(HERE)
        self.assertEqual(code, 0, out)

    def test_export_is_current(self):
        code, out = run(HERE, "--check")
        self.assertEqual(code, 0, out)

    def test_effective_notes_on_lightning(self):
        code, out = run(HERE, "--effective", "bnap:notes", "--rail", "ln:lnd",
                        "--verifier", "local", "--require", "use=single,binding=A")
        self.assertEqual(code, 0, out)
        self.assertIn('"admitted": true', out)


class BrokenCopy(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="bnap-registry-"))
        for name in SOURCES:
            shutil.copy(HERE / name, self.dir / name)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def edit(self, name, old, new):
        path = self.dir / name
        text = path.read_text("utf-8")
        self.assertEqual(text.count(old), 1, f"test setup: {old!r} must occur once in {name}")
        path.write_text(text.replace(old, new), "utf-8")

    def append(self, name, text):
        with open(self.dir / name, "a", encoding="utf-8") as f:
            f.write(text)

    def assertFails(self, *needles):
        code, out = run(self.dir)
        self.assertEqual(code, 1, out)
        for n in needles:
            self.assertIn(n, out)
        return out

    # value orders

    def test_wrong_value_order(self):
        self.edit("properties.toml",
                  '  { id = "O", label = "O: a server-made artifact embeds the OfferID" },\n'
                  '  { id = "A", label = "A: a client-made artifact embeds the Context" },\n',
                  '  { id = "A", label = "A: a client-made artifact embeds the Context" },\n'
                  '  { id = "O", label = "O: a server-made artifact embeds the OfferID" },\n')
        self.assertFails("property[1] binding: values in the wrong order")

    def test_wrong_value_order_finality(self):
        self.edit("properties.toml",
                  '  { id = "reversible", label = "reversible" },\n'
                  '  { id = "freezable", label = "freezable" },\n',
                  '  { id = "freezable", label = "freezable" },\n'
                  '  { id = "reversible", label = "reversible" },\n')
        self.assertFails("finality: values in the wrong order")

    def test_applies_to_pinned(self):
        self.edit("properties.toml", 'applies_to = ["credential", "rail", "verifier"]\n'
                  'description = "When the value received',
                  'applies_to = ["credential", "verifier"]\n'
                  'description = "When the value received')
        self.assertFails("finality: applies_to must be credential, rail, verifier")

    # unknown properties and values

    def test_unknown_property_in_entry(self):
        self.edit("schemes.toml", 'properties = { theft = "key-witnessed", link-payment = "unlinkable", '
                  'link-actions = "unlinkable", issuer = "self-issued", verify = "offline", '
                  'finality = "final-on-verification", custody = "operator-iou", pq = "no", '
                  'maturity = "experimental" }\nlocal_id = "Y of each input',
                  'properties = { speed = "fast", theft = "key-witnessed", link-payment = "unlinkable", '
                  'link-actions = "unlinkable", issuer = "self-issued", verify = "offline", '
                  'finality = "final-on-verification", custody = "operator-iou", pq = "no", '
                  'maturity = "experimental" }\nlocal_id = "Y of each input')
        self.assertFails("unknown property 'speed'")

    def test_unknown_property_definition(self):
        self.append("properties.toml",
                    '\n[[property]]\nid = "speed"\nlabel = "speed"\nlocation = "properties"\n'
                    'applies_to = ["credential"]\ndescription = "Made up."\n'
                    'values = [{ id = "slow", label = "slow" }, { id = "fast", label = "fast" }]\n')
        self.assertFails("unknown property: the spec defines only")

    def test_unknown_value(self):
        self.edit("schemes.toml", 'source = "overview, Plug catalogue: L402 (bLIP-26)"\n'
                  'spec = "https://github.com/lightning/blips/pull/26"\nbinding = "O"',
                  'source = "overview, Plug catalogue: L402 (bLIP-26)"\n'
                  'spec = "https://github.com/lightning/blips/pull/26"\nbinding = "B"')
        self.assertFails("unknown value 'B'")

    def test_missing_property(self):
        self.edit("rails.toml", 'custody = "self-custody", pq = "no", maturity = "standard" }\n'
                  'units = ["sat"]\nguarded = false',
                  'custody = "self-custody", maturity = "standard" }\n'
                  'units = ["sat"]\nguarded = false')
        self.assertFails('rail."onchain:bitcoin"', "missing property 'pq'")

    def test_property_not_applicable(self):
        self.edit("schemes.toml", 'properties = { theft = "bearer", link-actions = "unlinkable", '
                  'issuer = "third-party", verify = "offline", pq = "no", maturity = "standard" }',
                  'properties = { theft = "bearer", link-actions = "unlinkable", custody = "self-custody", '
                  'issuer = "third-party", verify = "offline", pq = "no", maturity = "standard" }')
        self.assertFails("'custody' does not apply to attestation entries")

    # duplicate IDs

    def test_duplicate_id_table(self):
        self.append("schemes.toml", '\n[scheme."httpauth:L402"]\nname = "L402 again"\n')
        self.assertFails("schemes.toml: TOML error")

    def test_duplicate_id_ignoring_case(self):
        text = (self.dir / "schemes.toml").read_text("utf-8")
        start = text.index('[scheme."httpauth:DPoP"]')
        end = text.index("[scheme.", start + 1)
        self.append("schemes.toml", "\n" + text[start:end].replace('"httpauth:DPoP"', '"httpauth:dpop"'))
        self.assertFails("duplicate ID", "ignoring case")

    def test_duplicate_property(self):
        text = (self.dir / "properties.toml").read_text("utf-8")
        start = text.index('[[property]]\nid = "pq"')
        end = text.index("[[property]]", start + 1)
        self.append("properties.toml", "\n" + text[start:end])
        self.assertFails("duplicate property id")

    # prefix rules

    def test_unknown_prefix(self):
        self.edit("schemes.toml", '[scheme."nip:98"]', '[scheme."nostr:98"]')
        self.assertFails("unknown prefix")

    def test_bad_privacy_pass_id(self):
        self.edit("schemes.toml", '[scheme."pp:0x0002"]', '[scheme."pp:2"]')
        self.assertFails("does not follow the pp: prefix rule")

    def test_rail_id_prefix(self):
        self.edit("rails.toml", '[rail."ln:lnd"]', '[rail."lightning:lnd"]')
        self.assertFails("must start with a registered rail kind")

    # spec invariants

    def test_class_o_must_be_bearer(self):
        self.edit("schemes.toml", 'properties = { theft = "bearer", link-payment = "linkable", '
                  'link-actions = "unlinkable", issuer = "self-issued", verify = "offline", '
                  'finality = "final-on-verification", custody = "self-custody", pq = "no", '
                  'maturity = "experimental" }\nlocal_id = "the payment hash committed',
                  'properties = { theft = "key-witnessed", link-payment = "linkable", '
                  'link-actions = "unlinkable", issuer = "self-issued", verify = "offline", '
                  'finality = "final-on-verification", custody = "self-custody", pq = "no", '
                  'maturity = "experimental" }\nlocal_id = "the payment hash committed')
        self.assertFails("binding class O must have theft = bearer")

    def test_native_needs_class_o(self):
        self.edit("schemes.toml", 'witness = "none: class A; the payer\'s signature sits in the body '
                  'and covers the Context, not the Digest"\nnative = []',
                  'witness = "none: class A; the payer\'s signature sits in the body '
                  'and covers the Context, not the Digest"\nnative = [{ kind = "x", embeds = "e", '
                  'credential = "c" }]')
        self.assertFails("native artifacts are only for class O schemes")

    def test_dangling_verifier(self):
        self.edit("schemes.toml", 'verifiers = ["local", "mpp-processor"]',
                  'verifiers = ["local", "mpp-processor", "nobody"]')
        self.assertFails("verifiers names 'nobody'")

    def test_guarded_rail(self):
        self.edit("rails.toml", 'units = ["USD", "EUR"]\nguarded = true', 'units = ["USD", "EUR"]\nguarded = false')
        self.assertFails("must be guarded")

    def test_bad_unit(self):
        self.edit("rails.toml", 'units = ["USD", "EUR"]', 'units = ["usd", "EUR"]')
        self.assertFails("matches none of the allowed forms")

    def test_schema_unknown_field(self):
        self.edit("carriers.toml", 'tls_binding = true\n', 'tls_binding = true\ncolour = "blue"\n')
        self.assertFails("unknown field 'colour'")

    def test_non_ascii(self):
        self.edit("carriers.toml", 'notes = "Optional carrier; no BNAP carrier note yet."',
                  'notes = "Optional carrier \u2014 no BNAP carrier note yet."')
        self.assertFails("non-ASCII")

    # the spec's worked examples

    def test_spec_route_example(self):
        self.edit("schemes.toml", 'properties = { theft = "bearer", link-payment = "linkable", '
                  'link-actions = "unlinkable", issuer = "self-issued", verify = "offline", '
                  'finality = "final-on-verification", custody = "self-custody", pq = "no", '
                  'maturity = "experimental" }\nlocal_id = "the payment hash committed',
                  'properties = { theft = "bearer", link-payment = "linkable", '
                  'link-actions = "linkable", issuer = "self-issued", verify = "offline", '
                  'finality = "final-on-verification", custody = "self-custody", pq = "no", '
                  'maturity = "experimental" }\nlocal_id = "the payment hash committed')
        self.assertFails("spec example (overview, route policy)")

    def test_spec_card_funding_example(self):
        self.edit("rails.toml", 'finality = "reversible"', 'finality = "final-at-settlement"')
        self.assertFails("spec example (overview, effective vectors)")

    # the export

    def test_stale_export(self):
        (self.dir / "generated").mkdir()
        shutil.copy(HERE / "generated" / "registry.json", self.dir / "generated" / "registry.json")
        self.assertEqual(run(self.dir, "--check")[0], 0)
        self.edit("carriers.toml", 'notes = "Optional carrier; no BNAP carrier note yet."',
                  'notes = "Optional carrier; no BNAP carrier note written yet."')
        code, out = run(self.dir, "--check")
        self.assertEqual(code, 1, out)
        self.assertIn("stale", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)

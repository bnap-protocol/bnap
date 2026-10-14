#!/usr/bin/env python3
"""Check conformance/COVERAGE.md against spec/socket-draft-00.md.

Usage:
  python3 -I conformance/coverage_check.py           check; exit 1 on any gap
  python3 -I conformance/coverage_check.py --list    print every requirement with its ID

Extracts every sentence of draft-00 that uses a BCP 14 key word in capitals
(MUST, MUST NOT, SHOULD, SHOULD NOT, REQUIRED, RECOMMENDED, SHALL), outside
code blocks, the key-word definition itself and the error code named
REQUIRED. Each gets the ID R-<section>-<nn> in document order. The check
then requires, for every ID, a COVERAGE.md row whose quote is taken from
that sentence and which names at least one vector file group or runner case,
or says "untestable black-box" with a reason. Every runner case and vector
group it names must exist.
"""
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
SPEC = REPO / "spec" / "socket-draft-00.md"
COVERAGE = HERE / "COVERAGE.md"
KEYWORDS = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|REQUIRED|RECOMMENDED|SHALL NOT|SHALL)\b")


def clean(s):
    s = s.replace("\\_", "_").replace("**", "").replace("`", "")
    return re.sub(r"\s+", " ", s).strip()


def sentences(text):
    parts = re.split(r"(?<=[.;:])\s+(?=[A-Z0-9(])", text)
    return [p.strip() for p in parts if p.strip()]


def requirements():
    section, out, counters, in_code = "0", [], {}, False
    for line in SPEC.read_text().splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = re.match(r"^#{2,3} (\d+(?:\.\d+)?)\.? ", line)
        if m:
            section = m.group(1)
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) > 1 and cells[1] == "REQUIRED":
                continue
            chunks = [" ".join(cells)]
        else:
            chunks = [re.sub(r"^\s*(?:[-*]|\d+\.)\s+", "", line)]
        for chunk in chunks:
            for s in sentences(clean(chunk)):
                if "The key words" in s:
                    continue
                kws = KEYWORDS.findall(s)
                if not kws:
                    continue
                counters[section] = counters.get(section, 0) + 1
                level = "MUST" if any(k.startswith(("MUST", "REQUIRED", "SHALL")) for k in kws) else "SHOULD"
                out.append({"id": f"R-{section}-{counters[section]:02d}", "section": section, "level": level,
                            "text": s})
    return out


def coverage_rows():
    rows = {}
    for line in COVERAGE.read_text().splitlines():
        if not line.startswith("| R-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows[cells[0]] = cells
    return rows


def known_runner_cases():
    sys.path.insert(0, str(HERE))
    import run
    return {c.id for c in run.CASES}


def known_vector_groups():
    out = {}
    for f in (REPO / "vectors" / "cases").glob("*.json"):
        out[f.name] = {g["type"] for g in json.loads(f.read_text())["testGroups"]}
    return out


def check():
    reqs = requirements()
    rows = coverage_rows()
    cases = known_runner_cases()
    groups = known_vector_groups()
    errors = []
    ids = {r["id"] for r in reqs}
    for r in reqs:
        row = rows.get(r["id"])
        if row is None:
            errors.append(f"{r['id']} ({r['section']}): no row for: {r['text'][:90]}")
            continue
        if len(row) < 7:
            errors.append(f"{r['id']}: row needs 7 cells")
            continue
        quote = clean(row[3]).strip('"').rstrip(".").replace("...", "…")
        pieces = [p.strip() for p in quote.split("…") if p.strip()]
        if not pieces or not all(p in r["text"] for p in pieces):
            errors.append(f"{r['id']}: quote not taken from the sentence: {row[3][:60]}")
        if row[1] != r["section"]:
            errors.append(f"{r['id']}: section {row[1]} should be {r['section']}")
        vec, run_cases, status = row[4], row[5], row[6]
        named = False
        for ref in re.findall(r"`([a-z-]+\.json)#([A-Za-z0-9]+)`", vec):
            named = True
            if ref[0] not in groups or ref[1] not in groups[ref[0]]:
                errors.append(f"{r['id']}: no vector group {ref[0]}#{ref[1]}")
        for cid in re.findall(r"`([A-Z][A-Z0-9-]+)`", run_cases):
            named = True
            if cid not in cases:
                errors.append(f"{r['id']}: no runner case {cid}")
        if not named and "untestable black-box" not in status:
            errors.append(f"{r['id']}: names no vector group or runner case and is not marked untestable")
    for rid in rows:
        if rid not in ids:
            errors.append(f"{rid}: row for a requirement that draft-00 does not have")
    return reqs, errors


def main(argv):
    if "--list" in argv:
        for r in requirements():
            print(f"{r['id']:<10} {r['level']:<6} {r['text']}")
        return 0
    reqs, errors = check()
    for e in errors:
        print("coverage:", e, file=sys.stderr)
    if errors:
        print(f"coverage: {len(errors)} problem(s) over {len(reqs)} requirements", file=sys.stderr)
        return 1
    rows = coverage_rows()
    untestable = sum(1 for r in reqs if "untestable black-box" in rows[r["id"]][6])
    print(f"coverage: {len(reqs)} normative sentences, every one mapped; {untestable} marked untestable black-box")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

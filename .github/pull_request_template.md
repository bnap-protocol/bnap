## What this changes

<!-- One or two sentences. Link the issue it closes. -->

## Spec reference

<!-- The sections, ERRATA or DECISIONS rows, registry entries or conformance
cases this touches. A normative change names the section it changes. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`, Developer Certificate of Origin).
- [ ] Normative changes update the reference encoder and `vectors/vectors.json` (`python3 -I reference/python/bnap_ref.py | diff - vectors/vectors.json`).
- [ ] Registry changes pass `python3 -I registry/validate.py --check` and `python3 -I registry/test_validate.py`.
- [ ] Conformance changes pass `python3 -I -m unittest discover -s conformance/tests`, and `conformance/gen_cases.py --check` and `coverage_check.py` where cases changed.
- [ ] A new spec file has its book page and `SUMMARY.md` entry; `mdbook build book` succeeds.
- [ ] `ERRATA.md`, `DECISIONS.md` and `CHANGELOG.md` are updated where needed.
- [ ] `ops/leak-guard.sh` is clean.

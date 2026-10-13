# Integration notes: N12 (CI, docs and release plumbing), bnap

Branch `node/n12-ci-docs`. N12 does not edit any file under `spec/`,
`reference/` or `vectors/`.

## What N12 added

| Path | What it is |
| --- | --- |
| `.github/workflows/ci.yml` | CI on push and pull request to `develop` and `main` |
| `.github/workflows/pages.yml` | Builds `book/` and deploys it to GitHub Pages on push to `main` |
| `.github/dependabot.yml` | Weekly GitHub Actions updates against `develop` |
| `book/book.toml`, `book/src/` | mdBook 0.5 book that renders the spec files |
| `book/linkcheck.py` | Stdlib checker for broken relative links in the built book |
| `README.md`, `CONTRIBUTING.md` | Docs for the book, the vector check and the CI jobs |

No code API. The contract for downstream nodes is the CI behaviour below.

## CI jobs

| Job | What it does |
| --- | --- |
| Leak guard | `sh ops/leak-guard.sh --pre-push origin` over the tracked files and the commits of the push or PR; on PRs also a `Signed-off-by` check on every non-merge commit (Dependabot skipped) |
| Test vectors (Python 3.11 and 3.x) | `python3 -I reference/python/bnap_ref.py` to a temp file, then `diff` against `vectors/vectors.json` after `python3 -I -m json.tool --sort-keys` normalisation, then a raw `diff` |
| Registry | `python3 registry/validate.py` if the file exists, after `pip install -r registry/requirements.txt` if that exists; otherwise a skip notice |
| Book | coverage check (below), `mdbook build book`, copy `reference/` and `vectors/` into the output, `python3 -I book/linkcheck.py book/book` |

## How the book renders the spec without copying it

- Every file `spec/<path>.md` has a page `book/src/spec/<path>.md` whose only
  line is `{{#include <relative path back to spec/<path>.md>}}`, for example
  `book/src/spec/schemes/bnap-notes.md` holds
  `{{#include ../../../../spec/schemes/bnap-notes.md}}`.
- The page tree mirrors `spec/`, so the spec's own relative links (such as
  `schemes/bnap-notes.md` from `ERRATA.md`) resolve inside the book.
- `[build] use-default-preprocessors = false` with only `[preprocessor.links]`
  enabled. The default `index` preprocessor would turn `spec/README.md` into
  `spec/index.html`, and `ERRATA.md` links to `README.md`. The book's own front
  page is therefore `book/src/index.md`, not `README.md`.
- `create-missing = false`: a SUMMARY entry without a page is an error, and
  mdBook never writes stray empty files.
- The spec links to `../reference/python/bnap_ref.py` and
  `../vectors/vectors.json`. `pages.yml` copies `reference/` and `vectors/`
  next to the built book so those links work on the site; the CI book job does
  the same before the link check.

## What downstream nodes must do

1. **Adding a spec file** (for example `spec/schemes/bnap-notes-draft-00.md`
   from DECISIONS 31): add `book/src/spec/schemes/bnap-notes-draft-00.md` with
   the single line
   `{{#include ../../../../spec/schemes/bnap-notes-draft-00.md}}` and an entry
   in `book/src/SUMMARY.md` (under *Schemes*). The CI coverage step fails
   otherwise, and also fails if a page is anything but that one include line.
2. **Linking from the spec to another top-level directory** (for example
   `../registry/`): add that directory to the `cp -R reference vectors ...`
   step in both `ci.yml` and `pages.yml`, or the link check fails.
3. **Never write a literal `{{#include`, `{{#rustdoc_include`,
   `{{#playground` or `{{#title` in spec text**: the links preprocessor would
   expand it. Escape it as `\{{#include ...}}` if it must appear.
4. **Registry validator** (`registry/validate.py`): CI runs it from the
   repository root as `python3 registry/validate.py` (no `-I`, so it can import
   modules next to it), on the latest Python 3. It must exit non-zero on any
   invalid entry. Third-party packages go in `registry/requirements.txt`; the
   standard library is preferred.
5. **Vectors**: any change to `reference/python/bnap_ref.py` must be followed
   by regenerating `vectors/vectors.json` with
   `python3 -I reference/python/bnap_ref.py > vectors/vectors.json`. CI runs
   the reference on Python 3.11 and the newest 3.x, so it must not depend on
   version-specific output.

## Decisions made

- Pages deploys from `main` only (released text); pull requests and `develop`
  build and link-check the book in CI. The owner must set Settings > Pages >
  Source to "GitHub Actions" once.
- mdBook is pinned to `0.5` in CI (local Homebrew bottle: 0.5.4).
- The CI leak guard uses pre-push mode, so commit metadata is scanned too.
- Dependabot covers GitHub Actions only: the repository has no other package
  manifests.
- Action majors checked against the GitHub releases API on 2026-10-13:
  `actions/checkout@v7`, `actions/setup-python@v7`,
  `actions/configure-pages@v6`, `actions/upload-pages-artifact@v5`,
  `actions/deploy-pages@v5`, `taiki-e/install-action@v2`.

## Known gaps

- Nothing was pushed, so no workflow has run on GitHub yet. YAML parses
  (Ruby Psych); the vector, coverage and link-check steps were run locally.
- MathJax is off; the spec uses Unicode for its formulas and renders fine.
- No edit links on spec pages: they would point at the one-line include pages,
  not at the spec files.

## ERRATA candidates (spec not edited)

| Where | Observation | What N12 did |
| --- | --- | --- |
| `spec/README.md`, `spec/ERRATA.md` | Links to `../reference/` and `../vectors/` leave `spec/`, so they only resolve where those directories sit next to it | The Pages build publishes both directories beside the book |

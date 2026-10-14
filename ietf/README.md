# The BNAP Socket (Internet-Draft)

This is the working area for the individual Internet-Draft "BNAP: A Socket for Priced and Permissioned Actions", `draft-bnap-socket`.

* [Editor's Copy](https://bnap-protocol.github.io/draft-bnap-socket/draft-bnap-socket.html) (once the directory is published as its own repository, see below)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-bnap-socket) (after the first submission)

## Where the text comes from

The normative source is [`../spec/socket-draft-00.md`](../spec/socket-draft-00.md). `draft-bnap-socket.md` is generated from it:

```sh
cd ietf
python3 -I tools/from-draft00.py ../spec/socket-draft-00.md > draft-bnap-socket.md
```

The generator keeps the normative text and only adds the kramdown-rfc front matter, the abstract, the references, the IANA registration templates and a short security paragraph. It writes the symbols in ASCII, re-wraps code blocks to 72 columns, marks with `#` the code comments that draft-00 sets off by spacing alone (so that a comment wrapped onto its own line never reads as a statement), and keeps the section numbers of draft-00, so cross-references such as "section 5.1" stay valid. Each re-wrapped code block is pinned by a hash of its draft-00 original: if draft-00 changes a code block, the generator stops until the copy in `tools/from-draft00.py` is updated. Do not edit `draft-bnap-socket.md` by hand; change draft-00 or the generator and regenerate.

## Layout

The directory follows the [martinthomson/i-d-template](https://github.com/martinthomson/i-d-template) conventions: `Makefile`, `.gitignore`, `.editorconfig` and the four workflows in `.github/workflows/` (`ghpages.yml` builds editor's copies, `publish.yml` submits a tagged version to the Datatracker, `archive.yml` archives issues, `update.yml` refreshes generated files).

GitHub runs workflows only from a repository's root, and the template expects the draft at the root, so these workflows run once the directory is its own repository:

```sh
git subtree split --prefix=ietf -b draft-bnap-socket
# push that branch as main of github.com/bnap-protocol/draft-bnap-socket
```

Until then, [`ci/bnap-monorepo.yml`](ci/bnap-monorepo.yml) builds the draft inside the bnap repository: copy it to `.github/workflows/ietf-draft.yml` at the repository root. It checks that `draft-bnap-socket.md` is in sync with draft-00, then builds text and HTML with kramdown-rfc and xml2rfc and uploads them as an artifact.

## Building locally

With the template (in the split-out repository):

```sh
make
```

This fetches the template into `lib/` and needs Ruby, Python and the tools the template installs. Without the template:

```sh
gem install kramdown-rfc
pipx install xml2rfc
sed 's/^docname: draft-bnap-socket-latest$/docname: draft-bnap-socket-00/' \
  draft-bnap-socket.md > draft-bnap-socket-00.md
kramdown-rfc draft-bnap-socket-00.md > draft-bnap-socket-00.xml
xml2rfc --text --html draft-bnap-socket-00.xml
```

## Before the first submission

* The Datatracker requires at least one person as author; the front matter lists the BNAP contributors as an organization.
* The draft name `draft-bnap-socket` does not follow the `draft-<author>-<topic>` convention for individual submissions, and may need a person's name (for example `draft-<surname>-bnap-socket`).
* The text is CC-BY-4.0 in the repository. Submitting it to the IETF grants the IETF Trust the rights of BCP 78; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

See the [guidelines for contributions](CONTRIBUTING.md).

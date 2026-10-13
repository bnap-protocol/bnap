# Contributing

Thanks for helping with the BNAP specification. This document covers how changes get in.

## Branches

- `develop` is the integration branch. Open pull requests against `develop`.
- `main` holds releases only. It moves forward from `develop` when a release is cut.

## Developer Certificate of Origin

Every commit must carry a DCO sign-off. There is no CLA.

By signing off you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
you wrote the change, or otherwise have the right to submit it under the
project's licenses. Sign off with `git commit -s`, which appends a line like:

```
Signed-off-by: Your Name <you@example.org>
```

Pull requests with unsigned commits cannot be merged. To fix the last commit,
run `git commit --amend -s --no-edit`; for a whole branch, run
`git rebase --signoff develop`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
`type(scope): summary`, for example `feat(core): parse price headers` or
`docs: clarify replay rules`. Common types are `feat`, `fix`, `docs`,
`test`, `refactor`, `chore` and `ci`. Mark breaking changes with `!`
or a `BREAKING CHANGE:` footer.

## Leak guard

The repository ships a pre-push hook that refuses to push private identifiers,
absolute home-directory paths or anything that looks like a secret (private
keys, nsec keys, API tokens, extended private keys, Lightning invoices).
Secret patterns are not checked under `vectors/` and `fixtures/`
directories, where test material lives. Enable the hook once per clone:

```sh
git config core.hooksPath .githooks
```

You can run the same check by hand at any time:

```sh
ops/leak-guard.sh
```

If it reports a finding, remove the offending text (and rewrite the affected
commits if the text is in history) before pushing. Do not bypass it with
`--no-verify`.

## Specification changes

Normative changes to the protocol should start as an issue that explains the
problem, so the design can be discussed before text is written. Changes that
affect behavior need matching updates to the test vectors.

## Licensing of contributions

Unless you explicitly state otherwise, specification text you contribute is
licensed under CC-BY-4.0, and code you contribute is dual-licensed under MIT or
Apache-2.0, as described in the README.

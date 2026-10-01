# Contributing to Research Commons

Thanks for considering it. This document covers licensing of contributions, the
sign-off requirement, and the practical gates a change has to pass.

## Licensing and sign-off

**Code is Apache-2.0. Documentation (`docs/`) is CC-BY-4.0.** By contributing you
agree your contribution is licensed under the same terms as the files it touches.
Apache-2.0 §5 already provides this by default — a contribution intentionally
submitted for inclusion is under the License unless you explicitly state otherwise.

**We use the Developer Certificate of Origin (DCO), not a CLA.** Sign off every
commit:

```bash
git commit -s -m "your message"
```

That appends a `Signed-off-by: Your Name <your@email>` trailer, certifying the
[DCO 1.1](https://developercertificate.org/): that you wrote the patch or
otherwise have the right to submit it under the project's license.

### Why a DCO and not a CLA

A copyright-assigning CLA would make the maintainer the only party able to
relicense the collective work. That is an asymmetry — a small enclosure — in a
project whose whole argument is against enclosure. A DCO certifies *origin* and
transfers *nothing*. Combined with Apache-2.0 §5, it is sufficient.

Note what §3 of Apache-2.0 means for you as a contributor: you grant every
recipient a patent license covering the claims necessarily infringed by your
contribution. It is not a grant of your whole portfolio — only what your
contribution necessarily reads on, and only patents you can license.

## What a change must pass

1. **The full test suite.** `tests/run-all.sh` — hermetic, clears ambient
   `COMMONS_*` env. All suites must be green, and the per-suite counts must not
   silently *drop*: a suite that stops running tests looks identical to a suite
   that passes them. Report before/after counts in the PR.
2. **New behaviour needs regression coverage**, and the test must be shown to go
   red against the unfixed code. A test that passes both ways proves nothing.
3. **No secrets.** `lib/publish_lint.py` runs over published content; run it over
   anything you add. Never commit `registry/peers.json`, `registry/exec-policy.json`,
   private keys, or anything under `store/` that you did not publish through the
   CLI.
4. **Documentation in the same change.** If you alter a command's behaviour,
   update `README.md` and the relevant `docs/` file in the same commit.

## Ground rules that are load-bearing

These come from real incidents. They are not style preferences.

- **Never modify `registry/` or `store/` by hand.** Publish through
  `commons publish`; the manifest and blob are content-addressed and a hand-edit
  desynchronizes them.
- **`comparators/*.py` are published artifacts.** Their file bytes are hashed and
  stored as `sk-…` skills, and `run_comparator` executes the *blob from the
  store*, not the working-tree file. Editing one without republishing makes the
  source and the artifact diverge silently. Same applies to anything else
  published from the tree.
- **Local-only files stay local.** `peers.json` is the trust boundary and
  `exec-policy.json` is execution policy — both are deliberately excluded from
  federation. A peer must never be able to reconfigure your sandbox.
- **Availability is not correctness.** Licensing and obtainability metadata must
  never move a verification tier or a chain grade. They change *who can check*,
  not *what was checked*.
- **Warnings are advisory.** Diagnostics go to stderr and must not change an exit
  code. A warning that breaks scripts gets silenced, and a silenced warning
  protects nobody.

## Reporting security issues

Do not open a public issue for a vulnerability in the trust model, the ingest
gate, or the execution sandbox. Contact the maintainer directly.

Note the threat model: the ingest gate is the security boundary, and `peers.json`
trust levels are the control. Findings that involve a peer escalating trust,
escaping the sandbox, or reconfiguring another peer's execution policy are
high-severity — there is prior art for exactly that class of bug in this
codebase.

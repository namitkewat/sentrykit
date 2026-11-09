# Release process

What happens between pushing a `v*` tag and a version appearing on PyPI, what each stage
proves, and what to do when one of them goes red. The checklist *upstream* of the tag — the
version bump, the changelog, `pixi run release-check`, the optional local rehearsal — lives in
`packaging-standards.md`; this file starts at the tag and ends at the index. ADR-037 records
why the publish path is shaped this way.

One property holds the whole thing together, and every rule below is downstream of it:

> **The artifact published is the artifact tested.** The distribution is built once, in the
> first job. Everything after that downloads the same `sentrykit-dist-<version>` artifact.
> Nothing is ever rebuilt.

---

## The chain

`.github/workflows/release.yml`, four jobs:

| job | runs when | what it does |
| --- | --- | --- |
| `release` | a `v*` tag, or a manual dispatch | Reconciles the tag against `__version__`, runs `pixi run -e all check`, builds the distribution and the documentation, verifies all six release assets, uploads both workflow artifacts, creates the GitHub release. |
| `publish-test` | `needs.release.outputs.publish == 'true'` | Uploads the wheel and sdist to TestPyPI, with `skip-existing: true`. |
| `smoke-test` | the same condition, after `publish-test` | Fetches the wheel back out of TestPyPI, checks its digest against the one this run built, installs it with `[all]` into a clean virtual environment, and exercises it. |
| `publish` | the same condition, after `smoke-test` | Uploads the same wheel and sdist to PyPI. No `skip-existing`. |

`publish` is true only on a tag push. A manual dispatch resolves `publish=false`, which skips
all three publishing jobs, and a dispatch that asks for `dry_run: false` is refused by the
first step of `release` before anything is checked out. **Nothing publishes from a dispatch,
not even to the test index** — see *Why a dispatch stops at the artifacts* below.

The jobs are separate rather than steps in one job because the last of them cannot be undone,
and a `needs:` edge is the only thing that makes "after the gate passed" mechanically true.
Each publishing job declares its own deployment environment and its own `id-token: write`;
each reads `needs.release.outputs.version` to name the artifact it downloads.

---

## What each gate proves, and what it does not

**`pixi run -e all check`, on the tagged commit.** Formatting, lint, types, the test suite with
its coverage floor, and the HTML documentation built under `-W`. It runs again here even though
CI ran it on main, because a tag can point at any commit, including one that never went through
a pull request. What it cannot prove: anything at all about the built artifact. It runs against
the source tree inside a pixi environment where every framework is already installed, which is
precisely the blind spot the rest of the chain exists to cover.

**The asset verification.** That all six release assets exist and are non-empty, and that the
list handed to `gh release create` is the list that was checked — `gh` will quietly skip a glob
that matches nothing, and a release that ships five of six assets is only ever discovered by
the reader who went looking for the PDF. It does not open them: a PDF that exists and renders
badly passes.

**The TestPyPI upload.** That a real Warehouse instance *accepts* the distribution. That is a
narrow claim and a useful one: it covers the core metadata version, the licence declaration,
the file naming, and the Trusted Publisher configuration itself. It says nothing about whether
the result installs.

**The smoke test.** The stage that asks whether a published distribution works. It proves that
the uploaded wheel is retrievable from an index; that what the index serves is byte-identical
to what this run built; that `sentrykit[all]` resolves and installs on the oldest interpreter
`requires-python` advertises, with its dependencies coming from PyPI the way a user's would;
that the shipped Cedar pack travelled as package data, because it asks `load_pack().policies`
for text rather than merely importing something; that all four integration modules import; and
that the `sentrykit` console script executes.

What the smoke test cannot prove:

- **That the sdist builds.** The download is `--only-binary :all:`, so only the wheel is
  exercised. `twine check` inside `pixi run release-check` is what looks at the sdist.
- **The other six extras.** It installs `[all]`. Each extra resolving to exactly what it
  promises is `release-check`'s job, locally and in CI's `extras` job, against a locally built
  wheel.
- **Behaviour.** It is an install-and-touch, not a second test run. The suite already ran in
  `release`, against the source.
- **Other platforms.** One Linux runner. The wheel is pure Python, so the exposure is in
  dependency resolution rather than in sentrykit.

If you want the full extras matrix against *exactly* the file the index served, the script
takes it: `python scripts/release_check.py --skip-build --dist <the download directory>`.

**The PyPI upload.** That PyPI accepted the same artifact, and nothing beyond that. It does
not open the project page, follow its links, or check that the description renders —
`twine check` upstream is what looks at the description, and the three project URLs are
verified by hand against `raw.githubusercontent.com` rather than by any gate in this chain.

---

## One-time setup the maintainer owes

None of this is a commit anybody can make. Until it is done, the publishing jobs fail closed
with the index's own error rather than uploading anything, which is the correct failure but is
not a green release.

**1. Two Trusted Publishers — one on PyPI, one on TestPyPI.** They are separate Warehouse
instances with separate accounts, and neither publisher authorizes anything on the other.
The two are created in **different places**, and following the wrong one produces a publisher
that authorizes nothing:

- **PyPI** has no `sentrykit` project, so its publisher is a *pending* publisher, created under
  *Your account → Publishing*. It converts to an ordinary one when the first upload lands.
- **TestPyPI** already has the project, because it was used to rehearse. Its publisher is added
  to the **existing project**, under *Manage project → Publishing*. The pending-publisher form
  will refuse a name that is already taken.

Check before reaching for a form: if `https://<index>/pypi/sentrykit/json` answers 200, the
project exists and the publisher belongs on it. Each form takes the same four values:

| field | PyPI | TestPyPI |
| --- | --- | --- |
| PyPI project name | `sentrykit` | `sentrykit` |
| Owner / repository | this repository | this repository |
| Workflow name | `release.yml` | `release.yml` |
| Environment name | `pypi` | `testpypi` |

The environment name is part of what is trusted, which is why the two jobs do not share one.

**2. Two deployment environments, under *Settings → Environments*.** `testpypi` needs nothing
beyond existing: the rehearsal leg should run unattended, or the chain stops being a chain.
`pypi` is where configuration buys something — adding a **required reviewer** there puts a
human between pushing a tag and the one action in this repository that has no undo. By the time
that approval is requested, the smoke test has already passed, so the reviewer is approving a
distribution that has been installed and exercised rather than a hope. Nothing in the workflow
depends on the reviewer existing; it is a setting, not a code change.

**3. Nothing else.** There is no API token to mint, store or rotate. The runner mints a
short-lived OIDC token per job and the index exchanges it for upload rights.

---

## When a stage fails

The question that decides the remedy is always the same: **has an index accepted this version
yet?** Before that line, a fix and a re-tag cost nothing. After it, the version number is gone
— on TestPyPI exactly as permanently as on PyPI. Deleting a release does not free its number,
and there is no API for deletion at all, only a web-UI action that does not help anyway.

**`release` fails before the release is created.** Nothing happened outside the repository. Fix
the cause, delete the tag, re-push it. The version is untouched.

A tag/version mismatch is the most common one and is deliberate: the assets would otherwise
carry one version and the release page another, with nothing downstream able to say which was
meant. Reconcile `src/sentrykit/__init__.py` with the tag and re-tag.

**`release` fails at `Create the GitHub release`.** A GitHub release can be deleted and
re-created, so this is recoverable: delete the release if one was partially created, then
re-run. Still no index involved.

**`publish-test` fails.** Check the project's page on the test index before doing anything
else. If the upload was *rejected* — bad metadata, no publisher configured, credentials — then
nothing was accepted, the version is intact, and a re-run after the fix is clean. If the files
are visible there, the version is spent even though the job went red, and the next section
applies.

**`smoke-test` fails. This is the one that matters.** TestPyPI has accepted the version, so
**that version is spent and the retry needs a new one**: bump `src/sentrykit/__init__.py`, move
the changelog section, re-tag. Do not try to replace the file on the index; you cannot, and
`skip-existing` means a re-run of the same tag would skip the upload and then test the old
artifact.

The consolation is the entire point of the stage: **PyPI was never touched.** The broken
distribution stopped one index short of the people who would have installed it.

Two sub-cases read differently:

- **The digest comparison failed.** The index already held this version from an earlier
  attempt, and the build has changed since — an amended commit under a re-pointed tag, most
  likely. Same remedy: a new version. Re-running will not help, because the index copy cannot
  change.
- **The fetch retried out.** Six attempts over roughly two minutes found nothing. That is more
  likely an upload that never landed than a slow cache, so check the test index's project page
  before assuming the version is spent.

**`publish` fails.** If PyPI rejected the upload because the version already exists, stop and
look: this version is already public, and the question is whether the artifact up there is the
right one. There is deliberately no `skip-existing` on this step — "already published" is not a
condition to shrug at. If it was rejected for credentials or a missing publisher, nothing was
accepted; fix the publisher and re-run the workflow from the Actions tab, which replays the
chain from the artifacts without rebuilding. If the upload succeeded and the job failed
afterwards, the release is out: finish by hand rather than re-running.

**Re-running a tag in general.** `skip-existing: true` on the test leg exists so that the
ordinary retry — same tag, same commit, something downstream broke — does not die on an upload
it already completed. Builds are reproducible (hatchling's default, with the builder pinned by
`locked: true`), so the re-run's wheel is byte-identical and the digest comparison passes. Move
the tag to a different commit and that comparison fails instead, which is what it is for.

---

## Why a dispatch stops at the artifacts

A manual dispatch runs `release` and nothing else: the gate, the build, the documentation, the
asset verification and both workflow artifacts, with no GitHub release and no index contacted.
It would be easy to let it rehearse one step further, as far as TestPyPI. It should not, for a
reason stronger than the cost of a wasted version number.

A dispatch has no tag, so it resolves its version from `src/sentrykit/__init__.py` — which is
*the next release's version*, exactly. A rehearsal would therefore spend the very number the
real tag is about to need, and with `skip-existing: true` the real run's upload would then be a
no-op. The TestPyPI gate would still go green, while testing the rehearsal's artifact instead
of the tag's. The one property the chain is built on — the artifact published is the artifact
tested — would be quietly false, and the digest comparison would be left as the only thing
standing between that and a published release. Wiring the cheapest button in the repository to
an irreversible side effect inverts the cost gradient; leaving it alone keeps a single
invariant that can be verified by reading one `if`.

What a rehearsal is actually for is everything upstream of an index, and that is what the
dispatch covers. The test-index step itself is rehearsed locally and deliberately:

```bash
pixi run publish-test
pip download --no-cache-dir --index-url https://test.pypi.org/simple/ --no-deps \
             --only-binary :all: -d /tmp/rehearsal "sentrykit==<version>"
pip install "/tmp/rehearsal/sentrykit-<version>-py3-none-any.whl[all]"
```

Two steps, never a two-index `pip install` in either order — the reason, and the two failures
behind it, are in `packaging-standards.md`. That path spends a version too, which is why the
checklist says to rehearse once, late, on the artifact you intend to ship. It stays the cheaper
rehearsal: the operator chooses when to spend the number, rather than a workflow trigger
choosing for them.

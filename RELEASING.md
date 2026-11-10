# Releasing dolmos

A release is a git tag `vX.Y.Z` plus a GitHub Release. The package version is
derived from the tag by setuptools-scm: there is no version number to edit in
the code.

## One-time setup

1. **PyPI Trusted Publisher.** On https://pypi.org/manage/account/publishing/,
   add a *pending publisher* (the `dolmos` project does not exist yet):
   owner `Dowsers`, repository `dolmos`, workflow `publish-pypi.yml`,
   environment `release`. After the first upload, the pending publisher becomes
   a regular one. Do the same on https://test.pypi.org if you want dry runs.
2. **GitHub environment.** In the repository settings, create the `release`
   environment and add required reviewers, so that a PyPI upload always needs
   an explicit approval.
3. **Docker images.** Run, in this order and once, the workflows
   `Push solvers package`, `Push dolmos-builder package` and
   `Push dolmos package` (each triggers the next one). Then, in the
   organization's *Packages* page, set `solvers`, `dolmos-builder` and `dolmos`
   to **public** and link them to this repository. The CI jobs that run inside
   these images (`test-long`, `test-ffi`, `test-external`) need them.
4. **Tag protection.** Add a ruleset that restricts who can create `v*` tags.

## Release checklist

1. All workflows are green on `main` (`Test`, `Test long`, `Test external`,
   `pre-commit`).
2. Move the entries of `## [Unreleased]` in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading, update the links at the bottom, commit.
3. Optional dry run: run `Publish to PyPI` by hand (*workflow_dispatch*); it
   builds, checks and smoke-tests the distributions without publishing.
4. Tag and push:

   ```sh
   git tag -a vX.Y.Z -m "dolmos X.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag push triggers `Push dolmos package`, which publishes
   `ghcr.io/dowsers/dolmos:X.Y.Z`, `:X.Y` and `:latest`.
5. Create the GitHub Release from the tag, with the changelog section as notes:

   ```sh
   gh release create vX.Y.Z --title "dolmos X.Y.Z" --notes-file <(sed -n '/## \[X.Y.Z\]/,/## \[/p' CHANGELOG.md | sed '$d')
   ```

   Publishing it triggers `Publish to PyPI` (after the `release` environment
   approval), which uploads to PyPI and attaches the wheel and sdist to the
   release.
6. Check: `uv tool install dolmos==X.Y.Z && dolmos --version`, and
   `docker run --rm ghcr.io/dowsers/dolmos:X.Y.Z dolmos --version`.

A version published on PyPI can never be re-uploaded. If a release is broken,
yank it on PyPI and release `X.Y.(Z+1)`.

## Version numbers

- `0.x`: the CLI and the configuration may still change between minor versions.
- Patch releases (`0.1.1`) only contain fixes.

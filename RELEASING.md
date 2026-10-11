# Releasing

Releases are built **only on the maintainer's explicit request**. Pushing to any branch runs the test
suite only ([ci.yml](.github/workflows/ci.yml)); the release pipeline
([release.yml](.github/workflows/release.yml)) fires exclusively when a version tag
`v<MAJOR>.<MINOR>.<PATCH>` is pushed.

## What a release contains

A GitHub Release named `Kemp LoadMaster TLM plugin <version>` with:

| Asset | Purpose |
|---|---|
| `kemp-loadmaster-tlm-plugin-<version>.zip` | Plugin package to upload in TLM (fat JAR + `plugin-meta.json`) |
| `configuration.json` | Connector configuration schema, uploaded together with the ZIP |
| `SHA256SUMS` | Checksums of both files |

The release notes are the `CHANGELOG.md` section of that version.

## Versioning and branches

- Versions are strictly `x.x.x` — TLM accepts no other plugin version format, so no `-alpha`/`-rc`
  suffixes. Every `0.x.y` version is published as a GitHub **pre-release**; the release notes state the
  maturity (e.g. "alpha"). `1.0.0` marks the first stable release and is set only when the maintainer
  announces it.

- SemVer: MINOR for new features, PATCH for bug fixes; MAJOR only when the maintainer announces it.
- Work happens on `dev`, is promoted to `main`, and a release is cut from `main` on a branch
  `release/v<VERSION>`.

## Steps

1. On `dev`: set `<version>` in `pom.xml`, move the `[Unreleased]` entries in `CHANGELOG.md` to a new
   section `## [<VERSION>]` with a short description, and get CI green.
2. Promote `dev` → `main`, create `release/v<VERSION>` from `main`.
3. Tag and push — **only on explicit request**:
   ```bash
   git tag -a v<VERSION> -m "Release v<VERSION>"
   git push origin v<VERSION>
   ```
4. The pipeline checks that the tag points to a commit on `main`, matches `pom.xml` and that `CHANGELOG.md` has a section for the
   version, reruns all tests and `scripts/check-public.sh`, builds, and publishes the GitHub Release.

A failed check stops the pipeline before anything is published; fix it, delete the tag
(`git push --delete origin v<VERSION>`) and tag again.

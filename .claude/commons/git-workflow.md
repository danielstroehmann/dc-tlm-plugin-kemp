# NFR: Git Workflow & Versioning

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent.

## Versioning (SemVer: MAJOR.MINOR.PATCH)

- **MAJOR** — only when the **author announces it**. Never bump the major version
  on your own.
- **MINOR** — incremented for **new features**.
- **PATCH** (third position) — incremented for **bug fixes**.

## Branching

- Keep branching **clean and disciplined**.
- **`dev`** — the development branch; all work happens here.
- Promotion flow: **`dev` → `main` → release**.
  - From `dev`, changes are promoted to **`main`**.
  - From `main`, a release is cut.
- **Release branches** are named **`release/v<VERSION>`** (e.g. `release/v1.4.0`).

## Commits & releases

- Commit and push only when asked. When work belongs on `dev`/a feature branch,
  do not commit directly to `main`.
- A release follows the flow above and a successful test run — tests must pass
  before deploy/release (see [testing.md](testing.md)).

## Release trigger: tag only

- **The full release machine fires ONLY when a version tag is pushed.** An
  ordinary push (to any branch) runs the **test suite only** — fast feedback,
  no build of publishable artifacts, no publish, no version bump.
- Pushing a tag **`v<VERSION>`** starts the release pipeline: it reruns the
  tests and then builds and publishes the artifacts (e.g. container images,
  CLI binaries) under that version. **The released version comes from the
  tag** — never auto-bumped on a normal push.
- This keeps the everyday dev roundtrip fast; the expensive, full build runs
  only at the deliberate tag gate.

# NFR: Testing & Quality

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent. Thorough testing is a top priority — the time for it is
> always available.

## Regression tests are mandatory

- Every feature, bug fix, and change ships with **automated technical tests** —
  not just an in-session check by Claude. The tests live in the repo and run in
  CI / before deploy.
- **Tests MUST pass before any deployment.** A red test blocks the deploy.
- The primary purpose is **regression safety**: new work must not silently break
  existing functionality. This is the #1 recurring pain point in these projects —
  treat "does this break anything that already worked?" as a first-class concern.

## What every test set covers

- **Happy path** — the expected functionality works as intended.
- **Expected error cases** — the known failure modes fail in the expected,
  handled way (not just "it throws something").

## Honest tests only

- **NEVER write self-congratulatory or vanity tests** — no assertions that
  cannot fail, no tests written to inflate a green count. A test must genuinely
  exercise behavior and be capable of failing when the behavior is wrong.
- When reporting test results, state plainly what passed, what failed, and what
  was skipped. Do not overstate coverage.

## Independent test & review agents

Implementation and verification are **separated**. The agent that writes a
change must not be the only one that vouches for it — an in-session "I checked
it myself" by the implementing agent does **not** satisfy these rules.

- **Tests are written and executed by a separate test agent** — a dedicated
  agent instance distinct from the one that implemented the change. It authors
  the test cases and runs them; it is critical of the implementation and
  reports defects rather than papering over them.
- **Every change gets a separate review run by a reviewer agent** before it is
  pushed or merged. The reviewer is independent of the implementer, reviews the
  full diff, and its findings are addressed (or explicitly deferred with the
  author's consent) before the change lands.
- **Executable test levels.** Where the stack allows it, the standard set is
  **unit**, **integration**, **component**, and **smoke** tests — all committed
  to the repo, all runnable, all mandatory in CI. Smoke tests must be runnable
  against a live endpoint so a deployment can be verified from the outside.

## Security testing

- Test against the relevant OWASP classes for the feature, not only the
  functional behavior (see [security.md](security.md)).

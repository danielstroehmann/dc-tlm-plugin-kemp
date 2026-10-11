# NFR: Security & Secrets

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent — never silently. Security is never traded away for speed or
> economy: the time for doing it right is always available.

## Core posture

- **All security implementations are based strictly on established best
  practices. NEVER hand-roll security** (auth, crypto, session handling, token
  signing, hashing, access control). Use vetted, standard libraries — see the
  "no NIH" rule in [code-style.md](code-style.md).
- **OWASP is always in scope**: consider the OWASP Top 10 (injection, broken
  auth, XSS, access-control, misconfiguration, vulnerable dependencies, …) for
  every feature, and **test against it**, not just reason about it (see
  [testing.md](testing.md)).

## Secrets

- **NEVER** commit secrets, keys, or credentials to git — not even throwaway or
  test keys. If a key is needed for testing, the author provides it temporarily
  in chat; it does not enter the repo.
- On the target system, secrets MAY live in `.env`, but **prefer placing them in
  `docker-compose.yml`**. The two files sit next to each other, so splitting them
  adds little real security and costs clarity.
- Deployment scripts generate/populate the `.env`. **On deploy, NEVER overwrite
  existing values**: read the values already present, carry them forward, and
  only prompt for keys that are new or missing. (See [deployment.md](deployment.md).)
- If a secret would ever appear in a diff, stop and warn before proceeding.

## Dependencies & supply chain

- Prefer established, highly-rated standard packages over custom implementations,
  for security and maintainability. Vet a new dependency's reputation before
  adding it. (Rationale and the broader "no NIH" rule live in
  [code-style.md](code-style.md).)

## Input handling & validation

- **Validate everything at trust boundaries** — user input, uploads, responses
  from external APIs. There is no economic exception to this.
- Cover the relevant OWASP injection/XSS classes for the inputs in play.

## Authentication & authorization

- Apps are scoped to **one or two users**. The standard login is a single
  **complex password, no username**.
- **Most apps sit behind Authentik** on the `shared-net` Docker network via the
  reverse proxy — that is the default; the app itself then needs no auth.
- Only when Authentik is **not** placed in front, and only on request, add
  per-app auth using standards (**JWT**) — a **lightweight** implementation, not
  a heavyweight framework, and never a self-built scheme.

## Data & logging

- Verbose logging to the Docker container logs is the standard debugging
  mechanism and is expected by default (see [deployment.md](deployment.md)).
- **All log output is in English** (UI texts are German — see
  [code-style.md](code-style.md)).

## Security review gate

- Run `/security-review` **after every new feature**, before it is considered
  done. The review explicitly includes OWASP Top 10 coverage.

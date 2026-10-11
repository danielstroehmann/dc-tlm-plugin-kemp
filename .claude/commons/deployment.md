# NFR: Deployment & Hosting

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent. Default is always production-ready; prototypes only on
> explicit request.

## Environment

- Projects are hosted in a **home-lab on Apple M3**. **Docker-first**
  architecture is the default — design for containers from the start.

## Data layout

- Persisted / to-be-secured data goes under **`./data`**, organized into
  topic-specific subdirectories. Keep state out of the image.

## Networking

- Containers that need it join the **`shared-net`** Docker network — this is the
  standard. **Authentik and the reverse proxy live there.**
- Expose the **single host port** the app needs; all further routing is handled
  by the reverse proxy inside the Docker network. Most apps are reached through
  the reverse proxy with Authentik in front (see [security.md](security.md)).

## Secrets & .env handling

- Deployment scripts **simplify creation of the `.env`**. Secrets MAY live in
  `.env`, but **prefer `docker-compose.yml`** (the files sit side by side).
- **On deploy, NEVER overwrite existing values.** Read what is already present,
  carry those values forward, and only prompt for keys that are new or missing.
- No secrets in git, ever (see [security.md](security.md)).

## Upgrades & data migration

- **Upgrading to the next version MUST always be clean and lossless.** Pulling
  the newer image and restarting the container (`docker pull` + restart, or the
  `deploy-update.sh` flow) must bring the app up on the **existing** data volume
  with no manual steps and no data loss — never a wipe, never a fresh-init that
  discards state.
- **Persisted state carries a schema version**, and startup runs any pending
  **migrations in order, idempotently**, before serving. A newer version reads
  and upgrades the previous version's on-disk data.
- **Never downgrade silently:** if the on-disk state is newer than the running
  binary understands, fail fast with a clear message instead of corrupting it.
- This is covered by an **automated upgrade test** (not just reasoning): boot the
  previous released version on a volume, then the new version on the *same*
  volume, and assert it comes up healthy with the data intact. Treat "can a user
  still upgrade cleanly?" as a first-class, always-considered concern (see the
  regression-safety rule in [testing.md](testing.md)).

## Logging

- Verbose logging to the **Docker container logs** is the default and is usually
  sufficient for debugging. Logs are in English.

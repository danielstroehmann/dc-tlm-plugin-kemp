# NFR: Agent Efficiency

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent.

## Conserve tokens

- **Conserve tokens.** Treat token usage as a cost to minimize, the same way
  load time or boilerplate is.
- **Offload mechanical work to scripts or tools instead of doing it with model
  reasoning.** Anything deterministic and repeatable — bulk renames, format
  conversions, data transformation, report generation, repeated checks,
  multi-file edits following one pattern — is done by a script or an existing
  CLI tool, not step by step through the model.
- **Whether it is worthwhile is the agent's call.** Offload when the script is
  cheaper than doing the work directly or will be reused; do a genuine one-off
  directly when writing a script would cost more than it saves. No need to ask.
- A script that will be needed again is **kept in the project** (e.g. `scripts/`
  or `bin/`) so later runs cost nothing; a throwaway script is not committed.
- Prefer an existing, well-known tool over writing a new script — see the
  [code-style.md](code-style.md) "no NIH" rule.

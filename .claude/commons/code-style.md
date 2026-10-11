# NFR: Code Style & Craft

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent.

## Lean code

- Write **lean code with no boilerplate**. Prefer the smallest clear solution;
  do not generate scaffolding, ceremony, or speculative abstractions that the
  task does not need.

## Standards over "not invented here"

- **NIH must be zero.** Prefer established, highly-rated external packages over
  self-implementing functionality — for security, maintainability, and
  efficiency. Reach for a self-built solution only when no suitable standard
  exists, and say why.
- This applies with full force to security primitives — never hand-roll them
  (see [security.md](security.md)).

## Comments

- Document the source **cleanly, for human interpretation**: explain the *why*
  and the non-obvious, not a restatement of what the code already says. Keep
  comments accurate and free of noise.

## Language conventions

- **Code, identifiers, and all log output: English.**
- **All UI texts: German, with correct umlauts** (`ä ö ü ß`, never `ae oe ue ss`).
- See [ui-ux.md](ui-ux.md) for the UI side.

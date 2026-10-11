# NFR: UI & UX

> Binding rules. A deviation requires an explicit, reasoned proposal and the
> author's consent. **Usability has absolute priority.**

## Target platforms

- Optimize for exactly two targets:
  1. **iPhone with Chrome** — mobile-optimized, primary touch target.
  2. **Mac with Chrome** — desktop.
- Design and test against these two; do not spend effort on platforms outside
  this set unless asked.

## Look & feel

- **Prefer light themes** over dark themes as the primary appearance.
- Keep interactions simple and obvious; usability wins over cleverness.
- **Build on proven design patterns and established UI libraries** for a standard
  layout — do not hand-roll layout systems or components that a well-rated library
  already provides (this is the [code-style.md](code-style.md) "no NIH" rule
  applied to the UI).

## Cross-project consistency

- The web apps share a **unified, recognizable look and feel across projects**,
  even when they are not content-wise or technically linked. A user moving between
  two unrelated apps should recognize them as part of the same family.
- Achieve this by reusing the **same base UI library, layout conventions,
  spacing, typography, and core components** project to project — consistency
  comes from shared standards, not from coupling the apps.

## Performance

- **Optimize load times** — treat fast first render and responsiveness as a
  feature, not an afterthought.
- **Every web-based UI must score 100 in the Performance category of Google
  PageSpeed Insights** (Lighthouse) — for both the **mobile and desktop**
  analysis. This applies to all web UIs without exception.
- Measure before every release; a score below 100 is a defect to fix, not a
  value to accept. Pick libraries, assets, and rendering strategy with this
  target in mind from the start.

## Language

- **All UI texts in German with correct umlauts** (`ä ö ü ß`). Logs and code stay
  English — see [code-style.md](code-style.md).

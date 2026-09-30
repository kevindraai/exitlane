# ExitLane design-system adoption

ExitLane is classified as a `technical` Tuned.pixel product. The selected theme is
`cobalt-slate` (Cobalt / Slate) because its catalogued use cases are `operations` and
`professional-ui`: the closest match for a self-hosted network appliance with status-heavy
administration views. The Cobalt / Slate semantic colors remain the functional application theme.
The approved ExitLane product accent is reserved for a separate visual review; this namespace
migration does not introduce it into the interface.

The source is the current Tuned.pixel Design Foundation `cobalt-slate` theme at
`kevindraai/tunedpixel/tunedpixel-design-foundation/tokens/tokens.css`. The original adoption used
catalog version `1.0.0`, generated 2026-08-23, at source commit
`e92d5421e34de4166f4cf7d633f971883e00deab`. The current canonical theme uses the `--tp-*`
namespace with the same light and dark semantic values used by ExitLane. The Tuned.pixel site brand
guide and tokens define the approved ExitLane product accent `#4CB4E8`; that accent is not a
replacement for functional status colors or accessible Cobalt text and focus colors.

## Semantic mapping

Application components continue to use ExitLane's concise semantic aliases. Those aliases now
resolve from the selected Tuned.pixel roles declared as `--tp-*` properties at the document root.

| ExitLane concept | Tuned.pixel role |
| --- | --- |
| page background | `background` |
| panels and cards | `surface`, `surface-elevated` |
| control boundaries | `border` |
| primary and muted content | `text`, `text-muted` |
| primary actions and links | `primary`, `primary-hover`, `primary-active`, `primary-contrast` |
| keyboard focus | `focus-ring` |
| operation outcomes | `success`, `warning`, `danger`, `info` |

Component-specific translucent fills, shadows, code surfaces, progress tracks and toast surfaces
remain local derived tokens. They do not form a second theme or introduce component-level seed
colors. Light and dark values are declared independently.

ExitLane places much of its normal text on `surface-elevated`, while the foundation's base
`text-muted` audit covers `background` and `surface`. In dark mode the application therefore uses
the theme's existing `slate-300` (`#B4B4B8`) as `text-muted-elevated`; it reaches 5.91:1 on the
catalogued elevated surface. Text links use the theme's `info` role in dark mode (5.81:1 on the
elevated surface), while cobalt remains the primary action and non-text accent. A regression test
calculates these component-level contrasts rather than assuming the catalog pairings apply to a
different surface.

## Beta.4 audit decisions

The repository-wide UX audit found and addressed these bounded inconsistencies:

- dark mode contained self-referential `--code-background`, `--track-background` and
  `--toast-background` values;
- primary actions did not explicitly use the theme's required contrast color;
- focus styling omitted selects, textareas and programmatically focusable regions;
- page headings were oversized for a dense operational interface;
- the Diagnostics page presented optional individual tools with the same visual weight as the
  primary connection flow;
- several Diagnostics icons silently resolved to the generic fallback because their identifiers
  were absent from the local allowlist;
- the application had no integrated path to its existing user and administrator documentation;
- operational screens lacked contextual links to the relevant local guide.

The change deliberately retains the existing layouts, provider abstraction, status contracts,
dialogs, legal confirmations and vanilla frontend architecture. QR surfaces retain their required
black-on-white rendering for scanner reliability; this is functional encoded content, not a
general interface color token.

## Typography

The interface uses the Tuned.pixel production-safe interface sans stack: Inter when locally
available, followed by system UI, Segoe UI and platform fallbacks. Monospace remains limited to
configuration, recovery codes, commands, logs and other technical identifiers. No candidate font
or remote font dependency is introduced.

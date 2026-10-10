<!--
title: Console design system
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-10
-->

# Console design system

The operator console is one product with one visual system. This page lists that system as it
stands: the tokens, the components and the rules a change follows. The stylesheet
(`crates/console/src/assets/console.css`) and the shared template macros
(`crates/console/src/templates/macros.html`) are the source; where this page and they disagree,
they win and this page is wrong.

New console work is built from these parts. A new pattern needs a stated gap (nothing here does
the job) and is added once, beside its siblings in the stylesheet, with a comment saying why.

## The thesis: temperature is attention

The console exists to answer "does anything need me right now?" and otherwise stay quiet. Colour
is meaning, never decoration:

- grey is a fine row: noise, inventory, counts, labels;
- amber (`--attention`) wants a look (review);
- orange (`--high`) is hands on the keyboard (a captured payload, a detection);
- red (`--alert`) is live intrusion or something broken;
- green (`--good`) is handled.

So a count is ink, not colour; a yes/no answer is ink or dim text, never a red "No"; and colour
appears only on the severity ramp below.

## Tokens

Every colour is a custom property, set once per theme block: Graphite (the default, on bare
`:root`), Cream, System (Cream, or Graphite under a dark OS) and the green 1337 theme, which
collapses the ramp to greens by design. Each block also sets `color-scheme`, so native controls
draw on the right ground.

| Token | Role |
|---|---|
| `--bg`, `--surface`, `--surface-raised` | page ground, panels and cards, heads and column headers |
| `--border`, `--border-bright` | hairlines; chips, hover and the empty strip cell |
| `--text`, `--text-muted`, `--text-faint` | data; labels and secondary text; timestamps and placeholders |
| `--link`, `--link-hover` | links, the active tab and the focus ring |
| `--brand`, `--brand-ink` | the active sort, the nav badge's ink |
| `--attention`, `--high`, `--alert`, `--good`, `--info` | the ramp; each has `-text` (ink on dark) and `-dim` (a tint) |
| `--low` | the ramp's grey rung (noise) |
| `--chart-line`, `--chart-fill`, `--chart-point-border` | Chart.js, read by `assets/charts.js` |
| `--radius`, `--radius-sm`, `--shadow` | panel and card corners; chips, buttons and inputs; elevation |
| `--font-sans`, `--font-mono` | prose and labels; data, addresses, hashes and commands |

The base size is 13px on `html`, so `rem` is 13px. Text sizes are literals, kept to the few the
components use: 0.6875rem for micro-caps labels, 0.82rem for compact tables, panel-body text and
empty states.

## Page

`h1` (the nav's word for the page), an optional `.page-sub` sentence, an optional `.tab-bar`
(with `.tab-count` where the tabs are filters), then panels. A note that explains a table sits
above it as a `.table-note`.

## Components

**Panel.** `div.panel > div.panel-head` then any of: a `table.table-compact`, a `div.panel-body`,
one `p.empty-line`, or the `#load-more-container` row. Nothing else sits directly in a panel; text,
lists, strips and forms go in `.panel-body`, which pads them and sets them at the table's size. A
head carries a title and at most a short `.dim` subtitle or a control (range buttons, a download).
`.panel-head--alert` caps a panel with something wrong in it.

**Empty state.** The panel stays, with its head, and holds one `p.empty-line`: a lowercase fragment
with no full stop ("no vendor submissions for this address"). A panel never disappears when
empty, and no empty line sits outside a panel.

**Status band and stat cards.** `.band` is the row read first on the dashboard and fleet pane.
`.stat-row` of `.stat-card`s heads the IP page. Neither goes inside a panel.

**Tables.** One density, `.table-compact`, in every panel. A key-value list is a two-column
compact table without a header (the IP page's summary, the fleet pane's panels). A table of
attacker addresses adds `.stack`: below 640px each row becomes a card, cells flowing in source
order, a cell's `data-label` naming it, and three roles placing the rest (`.stack-lead` for the
row's subject, `.stack-end`, `.stack-full`). A sortable header stays as the row of its sort links.
Other tables scroll inside their panel.

**Severity tag.** `span.sev` with `.sev--crit`, `.sev--high`, `.sev--watch` or `.sev--low`; a `.sev`
with no modifier is a neutral label chip (an ATT&CK id, a campaign class, a sample's origin).

**Activity strip.** `span.strip` of `i` cells, the console's only sparkline: the dashboard's 24
hours and the campaign and sample pages' hosts per day (`macros.html#day_strip`). Height is
volume; colour is the worst signal, and a day of hosts is the neutral low rung.

**Score.** `macros.html#score_meter`: a short meter on the heat ramp with the number in ink, on
the IP page, Attackers and Search. The review queue shows the number alone, in ink: its rows
were deliberately de-crowded, and the bar was one of the things removed.

**Tier.** `macros.html#tier_pill`: the one Title-case `.tier` pill.

**Review state.** `.state-pill` with `.state-approved`, `.state-rejected` or `.state-snoozed`, and
only for a review decision.

**Yes or no.** `macros.html#yes_no`: "Yes" in ink, "No" dim.

**VirusTotal verdict.** `macros.html#vt_verdict`: detections on the high rung, zero detections a
neutral chip (not proof the file is harmless), pending and not scanned as quiet words.

**Fetch outcome.** `macros.html#fetch_tag`: a capture on the high rung, a URL outside the fetcher's
reach low, the rest amber.

**Sample hash.** `macros.html#hash_link`: twelve characters, linked to the sample's page, the full
digest in the title.

**Campaign reference.** `macros.html#campaign_ref`, wherever an address or sample names its
campaigns.

**IP link.** `macros.html#ip_evidence_link` for every address, so it opens the evidence drawer.

**Repeat count.** `.run-count`, mono ink: `x37`, `x3 identical sessions`, `3 pending`. The nav's
`.badge` is the only count in colour, because waiting work is the one count that asks for the
operator.

**Buttons.** `button` and `a.btn` are the neutral button; `.btn-approve`, `.btn-reject`,
`.btn-snooze` and `.btn-danger` carry an action's intent, and every "Approve all" is
`.btn-approve`. `.range-btn` is the small chip button (chart ranges, external lookups, copy, a
filter toggle with `.active`). `.dl-go` is every download link.

**Disclosure.** Every `details > summary` gets the same muted caret, turning a quarter on open;
components only position it.

**Forms.** `.field` is a micro-caps label over a control, inside a `.filter-form` bar or a panel
body. Inputs, selects and every textarea sit on `--bg` with the hairline border.

**Banners.** `.degraded` names panels that could not be loaded; it is for that, not for
information.

## Enforcement

Rendered pages are checked by `crates/console/tests/markup/mod.rs`, which
`crates/console/tests/campaigns_test.rs#every_page_keeps_the_panel_contract` runs over every
console page from one indexed database:

- `crates/console/tests/markup/mod.rs#panel_violations`: content flush in a panel, a panel table at
  another density, an empty state outside a panel, the retired empty-state styles, and malformed
  tags;
- `crates/console/tests/markup/mod.rs#vocabulary_violations`: a review-state pill used for anything
  else, a bare tier colour, a tier-coloured score, and the retired chip, count and sparkline
  styles;
- `crates/console/tests/markup/mod.rs#stack_violations`: an address table that does not stack;
- `crates/console/tests/markup/mod.rs#form_violations`: a form control outside a styled wrapper.

## Open decisions

- The link hue equals the attention hue in every theme, so links, the active tab and the focus
  ring read as "wants a look"; the original redesign kept links off the heat axis. The owner is
  deciding it.
- In Graphite and Cream `--high` (orange) is nearly the same colour as `--attention` (amber), so
  the ramp's middle rungs are hard to tell apart.

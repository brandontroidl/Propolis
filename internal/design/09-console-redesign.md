# Console redesign: dense grid dashboard

Design spec for the Propolis operator console visual and content redesign. Transforms the
current scaffold-grade UI into a dense, technical, terminal-influenced operator tool focused on
the review workflow and threat picture.

## Constraints

- Server-rendered HTML (axum + minijinja + HTMX). No frontend build toolchain, no JS framework.
- All CSS inlined in base_head.html. No external fonts, stylesheets, or CDN dependencies.
- No new crate dependencies. No charting libraries.
- Dark theme with amber accent palette stays. Visual direction: more technical/terminal - lean
  into monospace, tight grid, high information density.

## Design direction

Primary lens: review workflow (pending IPs, approvals) + threat picture (volume, top attackers,
protocol distribution). Operational health (sensor up/down) is secondary - the operator infers
health from data presence, not a dedicated status board.

Aesthetic: dense grid of compact panels, monospace numbers, tabular-nums, tight padding. Every
panel earns its space or gets cut. Empty states are dim one-line status messages, not centered
text in dashed boxes.

## Shell (base template)

### Top nav bar

- Left: PROPOLIS wordmark (unchanged)
- Center: nav links. "Review queue" link carries a pending-count badge (e.g. `Review queue [3]`)
  so the operator always sees if there's work without navigating.
- Right: uptime since daemon start, version string, "Sign out" link
- Subtle bottom shadow instead of flat border for depth

### Footer

A single dim line, not a block: `propolis v0.1.0 - uptime 2h 14m - 13 sensors configured`.
Terminal status-line feel.

### Favicon

Amber-on-dark shield glyph as an inline SVG data URI. No external dependency.

### Empty states (global pattern)

Replace every centered dashed-border empty box with a left-aligned dim monospace one-liner that
explains what state the system is in, not just that data is absent:
- `waiting for sensor events - start a sensor to begin collecting`
- `queue empty - no IPs have crossed the recommendation threshold yet`
- `feed builder is disabled on this node`
- `feed enabled - first build in ~Xm`

## Dashboard (GET /)

Four zones, top to bottom.

### Top row: stat strip

Six compact cards in a single row (grid auto-fit, smaller minmax than current):
1. **Pending review** - clickable, links to /queue. Amber left-border accent when count > 0.
2. **Total scored IPs**
3. **Approved today**
4. **Events last hour** - new query: `SELECT COUNT(*) FROM event WHERE observed_at >= now() - interval '1 hour'`
5. **Active feed entries** - aggressive + standard combined from manifest.json
6. **Top attacker** - new query: highest effective_score IP, displayed as a linked IP address

Card sizing: uppercase label (0.65rem), monospace value (1.4rem), tighter padding than current.
Values that depend on data that hasn't arrived show `--` not `0`.

### Second row: recent activity log

Compact scrolling table of the last 20 events across all sensors. Columns:
- Timestamp (relative: "3m ago")
- Sensor name
- Signal type
- Source IP (linked to /ip/:ip)

Monospace, tight rows (0.45rem padding), no hover effect. Reads like a log tail. This fills the
void that currently dominates the dashboard.

Query: `SELECT observed_at, sensor, signal_type, host(source_ip) AS source_ip FROM event ORDER BY observed_at DESC LIMIT 20`

### Third row: two side-by-side panels

**Left panel: protocol distribution (24h).** Text table: sensor name, event count for the last
24 hours, sorted descending. No charts.

Query: `SELECT sensor, COUNT(*) AS cnt FROM event WHERE observed_at >= now() - interval '24 hours' GROUP BY sensor ORDER BY cnt DESC`

**Right panel: recent vendor submissions.** The existing table, compact (5 rows not 10).

### Empty state (fresh install)

Activity log shows one dim line: `waiting for sensor events - start a sensor to begin collecting`.
Stat cards show `--` for events/hr and top attacker. Protocol distribution shows same message.

## Review queue (GET /queue)

Structure unchanged (heading + sortable table + HTMX actions).

Changes:
- Tighter row padding (0.45rem)
- Score meter bar: 48px wide, 4px tall (from 64px/6px)
- Notes textarea starts collapsed as a single-line input, expands on focus
- Sort headers get arrow indicators for active direction
- Add "last checked: Xs ago" dim text next to the pending count
- Empty state: `queue empty - no IPs have crossed the recommendation threshold yet` in dim
  monospace, left-aligned

## IP detail (GET /ip/:ip)

Already the most complete page.

Changes:
- Stat cards get compact treatment (same sizing as dashboard cards)
- Evidence timeline adds relative timestamps ("2h ago") alongside absolute
- Add "back to queue" link at top when arriving from /queue (via referer or query param)

## Feed status (GET /feed)

- Feed enabled + has builds: existing tier table with compact treatment
- Feed disabled: `feed builder is disabled on this node`
- Feed enabled, no builds: `feed enabled - first build in ~Xm`

## Login (GET /login)

- Remove the top nav bar entirely (it's dead space on the login page)
- Add dim version line below the sign-in button
- Card stays centered and minimal

## Implementation scope

### Template changes (HTML/CSS only)
- base_head.html: updated CSS (denser cards, compact tables, footer line, nav badge, empty-state
  pattern, collapsed textarea, sort arrows)
- base_tail.html: nav badge for pending count, uptime/version in right side, sign-out link,
  footer status line
- dashboard.html: six-card stat strip, activity log table, two-panel bottom row
- queue.html: compact treatment, collapsed textarea, sort arrows, new empty state
- queue_row.html: tighter padding
- detail.html: compact cards, relative timestamps, back-to-queue link
- feed.html: contextual empty states
- login.html: remove nav, add version line

### Route handler changes
- dashboard.rs: add events_last_hour query, top_attacker query, protocol_distribution query,
  recent_events query (last 20 from event table)
- routes/mod.rs: pass version/uptime to base template context (via middleware or state)
- Add startup timestamp to AppState for uptime calculation
- Add pending_count to base template context (for nav badge on every page)

### No new dependencies, no new routes, no architectural changes.

# Console charts and visualizations

Design spec for adding Chart.js-based charts, server-rendered SVG sparklines, and data
visualizations to the Propolis operator console. Builds on the console redesign
(`internal/design/09-console-redesign.md`).

## Constraints

- Server-rendered HTML (axum + minijinja + HTMX). No frontend build toolchain.
- Chart.js v4 UMD bundle vendored as a single minified JS file alongside htmx.min.js.
- SVG sparklines generated server-side in Rust (no JS library needed).
- No new Rust crate dependencies.
- Dark theme: chart colors match existing CSS variables (amber accent, dim grid lines).
- All chart data serialized as JSON arrays in the template context; Chart.js reads them client-side.

## Chart.js integration

### Vendoring

Download Chart.js v4 UMD minified bundle (`chart.umd.min.js`, ~200KB) into
`crates/console/src/templates/chart.min.js`. Embed via `include_str!` in a `<script>` tag in
`base_head.html`, same pattern as the existing htmx.min.js.

### Global dark theme defaults

A `<script>` block after Chart.js loads, before any chart is rendered, sets global defaults:

```javascript
Chart.defaults.color = '#7c8a8f';
Chart.defaults.borderColor = '#2a3438';
Chart.defaults.font.family = 'ui-monospace, "JetBrains Mono", Consolas, monospace';
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.display = false;
Chart.defaults.animation.duration = 0;
```

These match `--text-dim`, `--border`, and `--font-mono` from the existing CSS. Animation disabled
for a snappy, terminal-like feel.

## Dashboard charts

### Events timeline (24h line chart)

Full-width line chart between the stat strip and the "Recent activity" table.

**Data:** 24 hourly buckets from now-23h through now. Each bucket is a count of events in that
hour. Empty hours show as zero.

**Query:**
```sql
SELECT bucket, COALESCE(cnt, 0) AS cnt
FROM generate_series(
    date_trunc('hour', now()) - interval '23 hours',
    date_trunc('hour', now()),
    interval '1 hour'
) AS bucket
LEFT JOIN (
    SELECT date_trunc('hour', observed_at) AS hour, COUNT(*) AS cnt
    FROM event
    WHERE observed_at >= now() - interval '24 hours'
    GROUP BY hour
) sub ON sub.hour = bucket
ORDER BY bucket
```

**Template data:** Two JSON arrays in the context: `timeline_labels` (hour labels like "14:00",
"15:00") and `timeline_data` (count per bucket).

**Chart config:**
- Type: `line`
- Single dataset, amber line (`#d99a3d`), no fill, 2px line width, 3px point radius
- X-axis: hour labels, no rotation
- Y-axis: integer ticks, starts at 0
- Responsive, maintains aspect ratio (height ~180px via container)
- Tooltip shows exact count

**Template markup:**
```html
<h2 class="section-title">Events (24h)</h2>
<div style="height:180px"><canvas id="chart-timeline"></canvas></div>
<script>
new Chart(document.getElementById('chart-timeline'), {
    type: 'line',
    data: {
        labels: {{ timeline_labels }},
        datasets: [{
            data: {{ timeline_data }},
            borderColor: '#d99a3d',
            borderWidth: 2,
            pointRadius: 3,
            pointBackgroundColor: '#d99a3d',
            tension: 0.3
        }]
    },
    options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }, maintainAspectRatio: false }
});
</script>
```

### Protocol distribution (horizontal bar chart)

Replaces the current text table in the left column of the dashboard's bottom row.

**Data:** Same query as the existing protocol distribution (event count per sensor, last 24h),
already available in the template context as `protocol_dist`.

**Template data:** Two JSON arrays: `proto_labels` (sensor names) and `proto_data` (counts).

**Chart config:**
- Type: `bar` with `indexAxis: 'y'` (horizontal)
- Amber bars (`#d99a3d`), no border
- Y-axis: sensor names
- X-axis: integer ticks, starts at 0
- Height scales with number of sensors (30px per bar + 40px padding)

### Top attackers (horizontal bar chart)

Replaces the vendor submissions panel in the right column of the dashboard's bottom row.
Vendor submissions move to a compact 3-row table below the charts.

**Data:** Top 10 IPs by raw_score from ip_score.

**Query:**
```sql
SELECT host(source_ip) AS ip, raw_score::float8 AS score
FROM ip_score
ORDER BY raw_score DESC
LIMIT 10
```

**Template data:** Two JSON arrays: `attacker_labels` (IP strings) and `attacker_data` (scores).

**Chart config:**
- Type: `bar` with `indexAxis: 'y'` (horizontal)
- Amber bars, bar labels are IPs
- X-axis: score 0-100
- Each bar clickable (via Chart.js onClick handler) linking to `/ip/<ip>`

## Detail page chart

### Per-IP event timeline (7-day line chart)

Small line chart at the top of the "Evidence timeline" section on `/ip/:ip`.

**Data:** 7 daily buckets for this IP's events.

**Query:**
```sql
SELECT bucket::date, COALESCE(cnt, 0) AS cnt
FROM generate_series(
    current_date - interval '6 days',
    current_date,
    interval '1 day'
) AS bucket
LEFT JOIN (
    SELECT date_trunc('day', observed_at)::date AS day, COUNT(*) AS cnt
    FROM event
    WHERE source_ip = $1 AND observed_at >= current_date - interval '6 days'
    GROUP BY day
) sub ON sub.day = bucket::date
ORDER BY bucket
```

**Template data:** `ip_timeline_labels` (date strings) and `ip_timeline_data` (counts).

**Chart config:** Same style as the dashboard timeline but smaller (height ~120px), 7 data
points.

## Stat card sparklines

Tiny inline SVG sparklines rendered server-side in Rust. No Chart.js involved.

### Events/hour sparkline

Inside the "Events / hour" stat card, below the number. A 24-point polyline showing hourly event
counts for the last 24 hours.

**Data:** Same 24-bucket query as the events timeline chart (reuse the data).

**SVG generation:** A Rust helper function that takes a `Vec<i64>` of values and returns an SVG
string:
- Viewbox: `0 0 120 30`
- Polyline: values scaled to fit the 30px height, x-spaced evenly across 120px
- Stroke: `#d99a3d` (amber), 1.5px, no fill
- If all values are zero, render a flat line at the bottom

The SVG string is injected into the stat card template as raw HTML.

### Total scored IPs sparkline

Same approach but for the "Total scored IPs" card. Shows the daily total count over the last 7
days.

**Query:**
```sql
SELECT bucket::date, (SELECT COUNT(*) FROM ip_score WHERE first_seen <= bucket + interval '1 day') AS cnt
FROM generate_series(current_date - interval '6 days', current_date, interval '1 day') AS bucket
ORDER BY bucket
```

This is a cumulative count (total IPs seen by each day), not a per-day delta.

## Empty states

When no event data exists (fresh install):
- Timeline chart renders with all-zero data (a flat line at zero) rather than being hidden
- Protocol distribution and top attackers show `waiting for sensor events` in dim text (no
  empty canvas)
- Sparklines render as flat lines at zero

## Implementation scope

### New files
- `crates/console/src/templates/chart.min.js` (vendored Chart.js v4 UMD)
- `crates/console/src/routes/sparkline.rs` (SVG sparkline generator)

### Modified files
- `crates/console/src/templates/base_head.html` (add Chart.js script + global defaults)
- `crates/console/src/templates/dashboard.html` (3 charts, sparklines in stat cards)
- `crates/console/src/templates/detail.html` (per-IP timeline chart)
- `crates/console/src/routes/dashboard.rs` (timeline bucketed query, top attackers query, JSON
  serialization for chart data)
- `crates/console/src/routes/detail.rs` (per-IP timeline query)
- `crates/console/src/routes/mod.rs` (add sparkline module)

### No new Rust crate dependencies. One new vendored JS file.

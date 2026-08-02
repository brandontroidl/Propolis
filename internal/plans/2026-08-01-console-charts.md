# Console Charts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Chart.js-based charts and server-rendered SVG sparklines to the Propolis operator console dashboard and IP detail page.

**Architecture:** Chart.js v4 UMD vendored as a single JS file, embedded via `include_str!`. Chart data serialized as JSON arrays in template context, rendered client-side. Sparklines generated server-side as inline SVG strings in Rust.

**Tech Stack:** Rust, axum, minijinja, Chart.js v4, HTMX, sqlx (Postgres), chrono.

## Global Constraints

- Rust 2024 edition. `crates/console/`.
- No new Rust crate dependencies. One new vendored JS file (Chart.js v4 UMD).
- Dark theme: chart colors match existing CSS variables (`#d99a3d` amber, `#7c8a8f` dim text, `#2a3438` border).
- All chart data passed as JSON arrays in template context. Charts instantiated in inline `<script>` blocks per page.
- Commits: conventional, lowercase, no AI-attribution trailer.
- Canonical spec: `internal/design/10-console-charts.md`.
- The console redesign (PR #8) is merged. All work builds on that.

---

### Task 1: Vendor Chart.js and set up global dark theme defaults

**Files:**
- Create: `crates/console/src/templates/chart.min.js` (vendored Chart.js v4 UMD)
- Modify: `crates/console/src/templates/base_head.html` (add Chart.js script tag + dark defaults block)
- Modify: `crates/console/src/templates.rs` (register chart.min.js via `include_str!` if templates are loaded there)

**Produces:**
- `Chart` global available on every page
- Dark theme defaults applied (color, borderColor, font, no animation, no legend)

- [ ] Download Chart.js v4 UMD minified. The official CDN URL is `https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js`. Use `curl` to download it to `crates/console/src/templates/chart.min.js`.

- [ ] Check how htmx.min.js is embedded in the templates. Read `crates/console/src/templates.rs` and `base_head.html` to find the `include_str!` and `<script>` pattern.

- [ ] Add Chart.js to the template system using the exact same pattern as htmx: register it in `templates.rs` and add a `<script>` tag in `base_head.html` that outputs it.

- [ ] Add a dark theme defaults `<script>` block immediately after the Chart.js script in `base_head.html`:

```html
<script>
Chart.defaults.color = '#7c8a8f';
Chart.defaults.borderColor = '#2a3438';
Chart.defaults.font.family = 'ui-monospace, "JetBrains Mono", Consolas, monospace';
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.display = false;
Chart.defaults.animation.duration = 0;
</script>
```

- [ ] Run `cargo check -p console` to verify the `include_str!` compiles.

- [ ] Run `cargo test -p console` to verify no regressions.

- [ ] Commit: `feat(console): vendor Chart.js v4 and configure dark theme defaults`

---

### Task 2: SVG sparkline generator

**Files:**
- Create: `crates/console/src/routes/sparkline.rs`
- Modify: `crates/console/src/routes/mod.rs` (add `pub(crate) mod sparkline;`)

**Produces:**
- `sparkline::render(values: &[i64], width: u32, height: u32, color: &str) -> String` returning an inline SVG string

- [ ] Create `crates/console/src/routes/sparkline.rs` with the following function and unit tests:

```rust
pub(crate) fn render(values: &[i64], width: u32, height: u32, color: &str) -> String {
    if values.is_empty() {
        return String::new();
    }
    let max = values.iter().copied().max().unwrap_or(1).max(1) as f64;
    let step = width as f64 / (values.len().max(2) - 1) as f64;
    let points: String = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = i as f64 * step;
            let y = height as f64 - (v as f64 / max * (height as f64 - 2.0)) - 1.0;
            format!("{:.1},{:.1}", x, y)
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "<svg viewBox=\"0 0 {width} {height}\" style=\"width:100%;height:{height}px;display:block\">\
         <polyline points=\"{points}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" stroke-linejoin=\"round\"/>\
         </svg>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_produces_valid_svg() {
        let svg = render(&[0, 5, 3, 8, 2], 120, 30, "#d99a3d");
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("polyline"));
        assert!(svg.contains("#d99a3d"));
    }

    #[test]
    fn render_all_zeros_produces_flat_line() {
        let svg = render(&[0, 0, 0, 0], 120, 30, "#d99a3d");
        assert!(svg.contains("polyline"));
    }

    #[test]
    fn render_single_value() {
        let svg = render(&[5], 120, 30, "#d99a3d");
        assert!(svg.contains("polyline"));
    }

    #[test]
    fn render_empty_returns_empty() {
        assert_eq!(render(&[], 120, 30, "#d99a3d"), "");
    }
}
```

- [ ] Add `pub(crate) mod sparkline;` to `crates/console/src/routes/mod.rs`.

- [ ] Run `cargo test -p console` to verify the sparkline tests pass.

- [ ] Commit: `feat(console): add server-side SVG sparkline generator`

---

### Task 3: Dashboard charts and sparklines

**Files:**
- Modify: `crates/console/src/routes/dashboard.rs` (add timeline bucketed query, top attackers query, sparkline rendering, JSON serialization)
- Modify: `crates/console/src/templates/dashboard.html` (add 3 chart canvases with inline scripts, sparklines in stat cards)

**Consumes:**
- `sparkline::render` from Task 2
- `Chart` global from Task 1
- Existing `protocol_dist` data already in the dashboard context

This is the largest task. The dashboard route handler needs 2 new queries (timeline buckets, top attackers) and must serialize chart data as JSON strings for the template.

- [ ] In `dashboard.rs`, add the 24h timeline bucketed query:

```rust
let timeline_rows = sqlx::query(
    "SELECT bucket, COALESCE(cnt, 0) AS cnt \
     FROM generate_series( \
         date_trunc('hour', now()) - interval '23 hours', \
         date_trunc('hour', now()), \
         interval '1 hour' \
     ) AS bucket \
     LEFT JOIN ( \
         SELECT date_trunc('hour', observed_at) AS hour, COUNT(*) AS cnt \
         FROM event \
         WHERE observed_at >= now() - interval '24 hours' \
         GROUP BY hour \
     ) sub ON sub.hour = bucket \
     ORDER BY bucket"
)
.fetch_all(&state.db)
.await
.unwrap_or_default();
```

Parse into two vectors: `timeline_labels: Vec<String>` (formatted as "HH:00") and `timeline_data: Vec<i64>` (counts).

- [ ] Add the top 10 attackers query:

```rust
let attacker_rows = sqlx::query(
    "SELECT host(source_ip) AS ip, raw_score::float8 AS score \
     FROM ip_score ORDER BY raw_score DESC LIMIT 10"
)
.fetch_all(&state.db)
.await
.unwrap_or_default();
```

Parse into `attacker_labels: Vec<String>` (IPs) and `attacker_data: Vec<f64>` (scores).

- [ ] Convert `protocol_dist` (already queried) into JSON arrays: `proto_labels` and `proto_data`.

- [ ] Generate sparklines:
  - Events/hour sparkline: `sparkline::render(&timeline_data, 120, 24, "#d99a3d")` (reuse timeline_data)
  - Total scored IPs sparkline: needs a new 7-day query:

```rust
let scored_trend = sqlx::query(
    "SELECT bucket::date, (SELECT COUNT(*) FROM ip_score WHERE first_seen <= bucket + interval '1 day') AS cnt \
     FROM generate_series(current_date - interval '6 days', current_date, interval '1 day') AS bucket \
     ORDER BY bucket"
)
.fetch_all(&state.db)
.await
.unwrap_or_default();
```

- [ ] Serialize all chart arrays as JSON strings using `serde_json::to_string`. Pass them to the template context:
  - `timeline_labels`, `timeline_data` (as JSON strings)
  - `proto_labels`, `proto_data` (as JSON strings)
  - `attacker_labels`, `attacker_data` (as JSON strings)
  - `events_sparkline` (raw SVG string)
  - `scored_sparkline` (raw SVG string)

- [ ] Rewrite `dashboard.html` to add:
  - Sparklines inside the "Events / hour" and "Total scored IPs" stat cards (below the value, as `{{ events_sparkline|safe }}`)
  - Events timeline chart canvas and script block between stat strip and recent activity
  - Protocol distribution chart (replacing the text table in the left column)
  - Top attackers chart (replacing vendor submissions in the right column; move vendor submissions to a compact 3-row table below)
  - Empty-state handling: if no events, show `waiting for sensor events` text instead of empty canvases for protocol dist and top attackers; the timeline chart still renders with all zeros (flat line)

- [ ] Run `cargo check -p console`.

- [ ] Run `cargo test -p console`.

- [ ] Commit: `feat(console): add dashboard charts (timeline, protocol dist, top attackers) and sparklines`

---

### Task 4: Detail page per-IP timeline chart

**Files:**
- Modify: `crates/console/src/routes/detail.rs` (add 7-day timeline query, serialize as JSON)
- Modify: `crates/console/src/templates/detail.html` (add chart canvas and script)

**Consumes:** `Chart` global from Task 1.

- [ ] In `detail.rs`, add the per-IP 7-day timeline query:

```rust
let ip_timeline_rows = sqlx::query(
    "SELECT bucket::date, COALESCE(cnt, 0) AS cnt \
     FROM generate_series(current_date - interval '6 days', current_date, interval '1 day') AS bucket \
     LEFT JOIN ( \
         SELECT date_trunc('day', observed_at)::date AS day, COUNT(*) AS cnt \
         FROM event \
         WHERE source_ip = $1 AND observed_at >= current_date - interval '6 days' \
         GROUP BY day \
     ) sub ON sub.day = bucket::date \
     ORDER BY bucket"
)
.bind(ip)
.fetch_all(&state.db)
.await
.unwrap_or_default();
```

Parse into `ip_timeline_labels` (date strings like "Jul 26") and `ip_timeline_data` (counts). Serialize as JSON strings.

- [ ] Add chart canvas and script to `detail.html`, above the evidence timeline table:

```html
<h2 class="section-title">Activity (7 days)</h2>
<div style="height:120px"><canvas id="chart-ip-timeline"></canvas></div>
<script>
new Chart(document.getElementById('chart-ip-timeline'), {
    type: 'line',
    data: {
        labels: {{ ip_timeline_labels }},
        datasets: [{
            data: {{ ip_timeline_data }},
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

- [ ] Run `cargo check -p console` and `cargo test -p console`.

- [ ] Commit: `feat(console): add per-IP 7-day event timeline chart to detail page`

---

### Task 5: Visual verification

**Files:** Read-only verification, possible minor CSS fixes.

- [ ] Build the release binary: `cargo build --release -p propolis`.

- [ ] Deploy to the running daemon: `sudo cp target/release/propolis /usr/local/bin/propolis && sudo systemctl restart propolis`.

- [ ] Open each page in Chrome via claude-in-chrome and screenshot:
  - Dashboard (empty state - flat line, empty charts)
  - Dashboard (with data if available)
  - Detail page (with timeline chart)

- [ ] Verify: charts render with correct dark theme colors, sparklines appear inside stat cards, no layout overflow, responsive on narrow viewports.

- [ ] Fix any visual issues (spacing, chart sizing, label truncation).

- [ ] Run `cargo test -p console`.

- [ ] Commit any fixes: `fix(console): chart visual adjustments`

- [ ] Push branch and create PR.
